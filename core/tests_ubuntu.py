import io
import threading
import time
import urllib.error
from datetime import timedelta
from unittest import mock

from django.test import TestCase, override_settings
from django.utils import timezone

from . import ubuntu
from .models import Cve, Host
from .tasks import _check_progress, resume_interrupted_checks


def record(cve_id, throttle=None):
    return {"priority": "medium", "packages": [{"name": "openssl", "statuses": [{"release_codename": "jammy", "status": "released", "description": "3.0.2-0ubuntu1.15", "pocket": "security"}]}]}


class RefreshTests(TestCase):
    def cves(self, count):
        return [Cve.objects.create(cve_id=f"CVE-2026-{i:04d}") for i in range(count)]

    def test_several_requests_at_a_time_and_writes_in_the_caller(self):
        cves = self.cves(12)
        running, peak, threads = [0], [0], set()
        lock = threading.Lock()

        def slow(cve_id, throttle=None):
            with lock:
                running[0] += 1
                peak[0] = max(peak[0], running[0])
            time.sleep(0.05)
            with lock:
                running[0] -= 1
            return record(cve_id)

        seen = []
        original = ubuntu.apply_record

        def apply(cve, rec):
            threads.add(threading.get_ident())
            original(cve, rec)

        with mock.patch("core.ubuntu.fetch", side_effect=slow), mock.patch("core.ubuntu.apply_record", side_effect=apply):
            counts = ubuntu.refresh(cves, progress=lambda done, total: seen.append((done, total)), workers=4)
        self.assertEqual(counts["ok"] + counts["not_found"], 12)
        self.assertGreater(peak[0], 1)
        self.assertLessEqual(peak[0], 4)
        self.assertEqual(threads, {threading.get_ident()})  # the database is only written here
        self.assertEqual(seen[-1], (12, 12))

    def test_records_are_saved(self):
        cves = self.cves(3)
        with mock.patch("core.ubuntu.fetch", side_effect=record):
            ubuntu.refresh(cves)
        self.assertEqual(Cve.objects.filter(ubuntu_status=Cve.NvdStatus.OK).count(), 3)
        self.assertEqual(Cve.objects.first().ubuntu_packages["openssl"]["jammy"]["fixed"], "3.0.2-0ubuntu1.15")

    @override_settings(UBUNTU_ERROR_RETRY_MINUTES=60, UBUNTU_REFRESH_HOURS=24)
    def test_failed_cves_are_not_asked_at_every_check(self):
        now = timezone.now()
        fresh_error = Cve.objects.create(cve_id="CVE-2026-1000", ubuntu_status=Cve.NvdStatus.ERROR, ubuntu_fetched_at=now - timedelta(minutes=5))
        old_error = Cve.objects.create(cve_id="CVE-2026-1001", ubuntu_status=Cve.NvdStatus.ERROR, ubuntu_fetched_at=now - timedelta(hours=2))
        pending = Cve.objects.create(cve_id="CVE-2026-1002")
        fresh = Cve.objects.create(cve_id="CVE-2026-1003", ubuntu_status=Cve.NvdStatus.OK, ubuntu_fetched_at=now - timedelta(hours=1))
        stale = Cve.objects.create(cve_id="CVE-2026-1004", ubuntu_status=Cve.NvdStatus.OK, ubuntu_fetched_at=now - timedelta(hours=30))
        due = set(ubuntu.due_for_refresh())
        self.assertEqual(due, {old_error, pending, stale})
        self.assertNotIn(fresh_error, due)
        self.assertNotIn(fresh, due)
        # "Check Now" asks again for every failed CVE.
        self.assertIn(fresh_error, set(ubuntu.due_for_refresh(retry_errors=True)))

    def test_too_many_requests_pauses_then_retries(self):
        busy = urllib.error.HTTPError(ubuntu.URL, 429, "Too Many Requests", {"Retry-After": "7"}, io.BytesIO())
        answer = mock.MagicMock()
        answer.__enter__.return_value = io.BytesIO(b'{"packages": []}')
        throttle = ubuntu.Throttle()
        with mock.patch("core.ubuntu.urllib.request.urlopen", side_effect=[busy, answer]), mock.patch("core.ubuntu.time.sleep") as sleep:
            self.assertEqual(ubuntu.fetch("CVE-2026-0001", throttle), {"packages": []})
        waited = sum(call.args[0] for call in sleep.call_args_list)
        self.assertGreaterEqual(waited, 6.5)

    def test_progress_is_recorded_on_the_host(self):
        host = Host.objects.create(hostname="web.example.test", ip_address="10.0.0.1")
        progress = _check_progress(host.pk, every_seconds=3600)
        progress(1, 50)  # first call: recorded
        progress(2, 50)  # too soon: skipped
        host.refresh_from_db()
        self.assertEqual((host.patch_check_done, host.patch_check_total), (1, 50))
        progress(50, 50)  # the last one always
        host.refresh_from_db()
        self.assertEqual(host.patch_check_done, 50)


class ResumeTests(TestCase):
    def test_interrupted_checks_are_queued_again(self):
        stuck = Host.objects.create(hostname="a.example.test", ip_address="10.0.0.1", patch_check_state="running")
        Host.objects.create(hostname="b.example.test", ip_address="10.0.0.2", patch_check_state="done")
        with mock.patch("core.tasks.check_host_patches.delay") as delay:
            self.assertEqual(resume_interrupted_checks(), 1)
        delay.assert_called_once_with(stuck.pk)

    def test_only_the_interactive_worker_resumes(self):
        from pvm.celery import _resume_interrupted_checks

        with mock.patch("core.tasks.resume_interrupted_checks") as resume:
            _resume_interrupted_checks(sender=mock.Mock(hostname="background@vm"))
            resume.assert_not_called()
            _resume_interrupted_checks(sender=mock.Mock(hostname="celery@vm"))
            resume.assert_called_once()

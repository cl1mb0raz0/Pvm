from unittest import mock

from django.test import TestCase, override_settings

from pvm.celery import app as celery_app

from . import nvd, tasks
from .models import Cve


class RoutingTests(TestCase):
    def test_long_jobs_go_to_the_background_queue(self):
        routes = celery_app.conf.task_routes
        for name in ("core.tasks.refresh_nvd", "core.tasks.refresh_kev", "core.tasks.check_all_patches"):
            self.assertEqual(routes[name]["queue"], "background", name)
        # What users wait for stays on the default, interactive queue.
        for name in ("core.tasks.process_scan_import", "core.tasks.check_host_patches"):
            self.assertNotIn(name, routes)
        self.assertEqual(celery_app.conf.task_default_queue, "celery")
        self.assertEqual(celery_app.conf.worker_prefetch_multiplier, 1)


@override_settings(NVD_ENABLED=True, KEV_ENABLED=True)
class MisroutedTaskTests(TestCase):
    """A background task delivered to the interactive worker (e.g. queued before the split) moves itself."""

    def run_delivered_on(self, task, routing_key, **kwargs):
        task.push_request(delivery_info={"routing_key": routing_key}, is_eager=False, called_directly=False)
        try:
            with mock.patch.object(task, "apply_async") as apply_async:
                task.run(**kwargs)
        finally:
            task.pop_request()
        return apply_async

    def test_nvd_refresh_on_the_interactive_queue_is_moved(self):
        with mock.patch("core.nvd.refresh") as refresh:
            apply_async = self.run_delivered_on(tasks.refresh_nvd, "celery", force=True)
        apply_async.assert_called_once_with(args=(), kwargs={"cve_ids": None, "force": True}, queue="background")
        refresh.assert_not_called()

    def test_nvd_refresh_on_the_background_queue_runs(self):
        with mock.patch("core.nvd.refresh", return_value={}) as refresh, mock.patch("core.tasks._nvd_lock", return_value=None):
            apply_async = self.run_delivered_on(tasks.refresh_nvd, "background")
        apply_async.assert_not_called()
        refresh.assert_called_once()

    def test_kev_and_nightly_check_are_moved_too(self):
        with mock.patch("core.kev.refresh") as refresh:
            self.run_delivered_on(tasks.refresh_kev, "celery").assert_called_once()
        refresh.assert_not_called()
        self.run_delivered_on(tasks.check_all_patches, "celery").assert_called_once()

    def test_direct_calls_are_never_moved(self):
        with mock.patch("core.kev.refresh", return_value=5) as refresh:
            self.assertEqual(tasks.refresh_kev(), 5)
        refresh.assert_called_once()


class NvdLockTests(TestCase):
    def test_heartbeat_before_every_request(self):
        cves = [Cve.objects.create(cve_id=f"CVE-2000-000{i}") for i in range(3)]
        beats = []
        with mock.patch("core.nvd.fetch", return_value=None):
            nvd.refresh(cves, sleep=lambda s: None, heartbeat=lambda: beats.append(1))
        self.assertEqual(len(beats), 3)

    def test_lock_is_short(self):
        # Renewed while the refresh runs; an orphaned lock frees itself in minutes.
        self.assertLessEqual(tasks.NVD_LOCK_SECONDS, 900)


class ParallelRefreshTests(TestCase):
    """NVD and the Ubuntu tracker update the same Cve rows from two workers."""

    def test_neither_refresh_overwrites_the_other(self):
        import json
        from pathlib import Path

        from . import ubuntu

        fixtures = Path(__file__).parent / "fixtures"
        Cve.objects.create(cve_id="CVE-2021-44790")
        # The NVD refresh loads its objects first and saves them minutes later...
        stale_for_nvd = Cve.objects.get(cve_id="CVE-2021-44790")
        # ...meanwhile a host check fetches the Ubuntu record.
        ubuntu.apply_record(Cve.objects.get(cve_id="CVE-2021-44790"), json.loads((fixtures / "ubuntu_CVE-2021-44790.json").read_text()))
        nvd.apply_record(stale_for_nvd, json.loads((fixtures / "nvd_CVE-2021-44228.json").read_text())["vulnerabilities"][0]["cve"])

        cve = Cve.objects.get(cve_id="CVE-2021-44790")
        self.assertEqual(cve.ubuntu_status, Cve.NvdStatus.OK)
        self.assertIn("apache2", cve.ubuntu_packages)
        self.assertEqual(cve.nvd_status, Cve.NvdStatus.OK)
        self.assertIsNotNone(cve.cvss_score)

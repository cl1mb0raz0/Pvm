from datetime import date, datetime, timedelta

from django.test import TestCase, override_settings
from django.utils import timezone

from core import sla
from core.importers import pipeline
from core.importers.qualys_csv import Detection
from core.models import Perimeter, ScanImport, SLAPolicy, VulnerabilityFinding
from pvm.startup import require_real_secret_key

Status = VulnerabilityFinding.Status


def detection(host="web01.example.test", qid="100", severity="critical", qualys_severity=5):
    return Detection(
        ip="192.0.2.10", hostname=host, qualys_host_id="", os="", qid=qid, title="Example",
        severity=severity, qualys_severity=qualys_severity,
    )


class SLAPolicyTests(TestCase):
    def setUp(self):
        self.perimeter = Perimeter.objects.get(slug="internal")

    def scan(self, day, *detections):
        when = timezone.make_aware(datetime(2026, 9, day, 10, 0))
        scan_import = ScanImport.objects.create(source="manual", perimeter=self.perimeter, scanned_at=when)
        pipeline.run(scan_import, list(detections), {})

    def finding(self, host="web01.example.test"):
        return VulnerabilityFinding.objects.get(host__hostname=host, vulnerability_definition__qid="100")

    def test_defaults_exist(self):
        self.assertEqual(dict(SLAPolicy.objects.values_list("severity", "target_days")),
                         {"critical": 7, "high": 30, "medium": 90, "low": 180})

    def test_new_finding_gets_the_policy_due_date(self):
        self.scan(1, detection())
        f = self.finding()
        self.assertEqual(f.sla_started_at, date(2026, 9, 1))
        self.assertEqual(f.due_date, date(2026, 9, 8))
        self.assertFalse(f.due_date_manual)

    def test_still_open_keeps_its_clock(self):
        self.scan(1, detection())
        self.scan(8, detection())
        self.assertEqual(self.finding().due_date, date(2026, 9, 8))

    def test_reopened_finding_restarts_the_clock(self):
        self.scan(1, detection(), detection(host="other.example.test"))
        self.scan(8, detection(host="other.example.test"), detection(host="web01.example.test", qid="200", severity="low", qualys_severity=1))
        self.assertEqual(self.finding().status, Status.RESOLVED)
        self.scan(15, detection())
        f = self.finding()
        self.assertEqual(f.status, Status.NEEDS_REVIEW)
        self.assertEqual(f.due_date, date(2026, 9, 22))

    def test_due_date_set_by_hand_is_kept(self):
        self.scan(1, detection())
        VulnerabilityFinding.objects.update(due_date=date(2026, 12, 31), due_date_manual=True)
        self.scan(8, detection(severity="low", qualys_severity=1))
        self.assertEqual(self.finding().due_date, date(2026, 12, 31))

    def test_severity_change_moves_the_due_date_on_every_host(self):
        self.scan(1, detection(), detection(host="other.example.test"))
        # A later report covering one host only reports the QID as high.
        self.scan(2, detection(severity="high", qualys_severity=4))
        self.assertEqual(self.finding().due_date, date(2026, 10, 1))
        self.assertEqual(self.finding("other.example.test").due_date, date(2026, 10, 1))

    def test_policy_change_is_reapplied_to_open_findings(self):
        self.scan(1, detection())
        SLAPolicy.objects.filter(severity="critical").update(target_days=3)
        self.assertEqual(sla.recompute(), 1)
        self.assertEqual(self.finding().due_date, date(2026, 9, 4))

    def test_resolved_findings_are_left_alone(self):
        self.scan(1, detection(), detection(host="other.example.test"))
        self.scan(8, detection(host="other.example.test"), detection(qid="200", severity="low", qualys_severity=1))
        self.assertEqual(self.finding().status, Status.RESOLVED)
        SLAPolicy.objects.filter(severity="critical").update(target_days=3)
        sla.recompute()
        self.assertEqual(self.finding().due_date, date(2026, 9, 8))

    def test_severity_without_policy_has_no_due_date(self):
        SLAPolicy.objects.filter(severity="critical").delete()
        self.scan(1, detection())
        self.assertIsNone(self.finding().due_date)

    def test_overdue_shows_on_the_dashboard(self):
        from accounts.models import User

        self.scan(1, detection())
        VulnerabilityFinding.objects.update(due_date=timezone.localdate() - timedelta(days=1))
        User.objects.create_user("ro", "ro@example.com", "correct-horse-battery", role=User.Role.READONLY)
        self.client.post("/account/login/", {"username": "ro", "password": "correct-horse-battery"})
        self.assertEqual(self.client.get("/").context["overdue"], 1)


class SecretKeyTests(TestCase):
    @override_settings(DEBUG=False, SECRET_KEY="insecure-dev-key-change-me")
    def test_placeholder_key_is_refused(self):
        from django.core.exceptions import ImproperlyConfigured

        with self.assertRaises(ImproperlyConfigured):
            require_real_secret_key()

    @override_settings(DEBUG=False, SECRET_KEY="short")
    def test_short_key_is_refused(self):
        from django.core.exceptions import ImproperlyConfigured

        with self.assertRaises(ImproperlyConfigured):
            require_real_secret_key()

    @override_settings(DEBUG=False, SECRET_KEY="x7" * 32)
    def test_real_key_passes(self):
        require_real_secret_key()

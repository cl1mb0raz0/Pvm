import io
import json
from datetime import timedelta
from decimal import Decimal
from unittest import mock

from django.core.management import call_command
from django.test import TestCase, override_settings
from django.utils import timezone

from . import epss, priority
from .models import (
    Cve,
    Host,
    KevEntry,
    PatchCheck,
    Perimeter,
    VulnerabilityDefinition,
    VulnerabilityFinding,
)
from .tests_imports import ImportTestMixin

Status = VulnerabilityFinding.Status


def api_response(*items):
    body = json.dumps({"status": "OK", "data": [{"cve": c, "epss": e, "percentile": p, "date": "2026-09-23"} for c, e, p in items]})
    response = mock.MagicMock()
    response.__enter__.return_value = io.BytesIO(body.encode())
    return response


class EpssTests(TestCase):
    def test_refresh_stores_scores_and_only_its_fields(self):
        scored = Cve.objects.create(cve_id="CVE-2021-44228")
        unscored = Cve.objects.create(cve_id="CVE-2099-0001")
        stale = Cve.objects.get(pk=scored.pk)
        # Another refresh writes Ubuntu data meanwhile: EPSS must not undo it.
        Cve.objects.filter(pk=scored.pk).update(ubuntu_priority="high")
        with mock.patch("core.epss.urllib.request.urlopen", return_value=api_response(("CVE-2021-44228", "0.999990000", "1.000000000"))) as urlopen:
            self.assertEqual(epss.refresh([stale, unscored]), 1)
        self.assertIn("cve=CVE-2021-44228%2CCVE-2099-0001", urlopen.call_args[0][0].full_url)
        scored.refresh_from_db(), unscored.refresh_from_db()
        self.assertEqual(scored.epss_score, Decimal("0.99999"))
        self.assertEqual(str(scored.epss_date), "2026-09-23")
        self.assertEqual(scored.ubuntu_priority, "high")
        self.assertIsNone(unscored.epss_score)
        self.assertIsNotNone(unscored.epss_fetched_at)
        self.assertFalse(epss.never_fetched().exists())

    def test_batches_of_100(self):
        cves = [Cve.objects.create(cve_id=f"CVE-2024-{i:05d}") for i in range(230)]
        with mock.patch("core.epss.fetch", return_value={}) as fetch, mock.patch("core.epss.time.sleep"):
            epss.refresh(cves)
        self.assertEqual([len(c.args[0]) for c in fetch.call_args_list], [100, 100, 30])

    def test_unreachable_api_raises(self):
        import urllib.error

        with mock.patch("core.epss.urllib.request.urlopen", side_effect=urllib.error.URLError("down")), mock.patch("core.epss.time.sleep"):
            with self.assertRaises(epss.EpssError):
                epss.fetch(["CVE-2021-44228"])

    @override_settings(EPSS_ENABLED=False)
    def test_disabled_task_does_nothing(self):
        from .tasks import refresh_epss

        with mock.patch("core.epss.fetch") as fetch:
            self.assertIsNone(refresh_epss.apply().result)
        fetch.assert_not_called()


class PriorityScoreTests(TestCase):
    def setUp(self):
        self.internal = Perimeter.objects.get(slug="internal")
        self.external = Perimeter.objects.get(slug="external")
        self.host = Host.objects.create(hostname="web01.example.test", ip_address="192.0.2.10")
        self.today = timezone.localdate()

    def finding(self, cves=(), severity="critical", perimeter=None, qualys_cvss=None, age_days=0, due_in=30, qid="100"):
        definition = VulnerabilityDefinition.objects.create(
            qid=qid, title="Example", severity=severity, qualys_severity=5, cvss_score=qualys_cvss
        )
        for cve_id, cvss, score in cves:
            definition.cves.add(Cve.objects.create(cve_id=cve_id, cvss_score=cvss, epss_score=score))
        when = timezone.now() - timedelta(days=age_days)
        f = VulnerabilityFinding.objects.create(
            host=self.host, vulnerability_definition=definition, perimeter=perimeter or self.internal,
            first_detected_at=when, last_detected_at=when, due_date=self.today + timedelta(days=due_in),
        )
        priority.recompute()
        f.refresh_from_db()
        return f

    def test_log4shell_internal_is_p1(self):
        KevEntry.objects.create(cve_id="CVE-2021-44228")
        f = self.finding([("CVE-2021-44228", Decimal("10.0"), Decimal("0.99999"))])
        self.assertEqual(f.priority_score, 70)
        self.assertEqual((f.priority_level, f.priority_label), (1, "Fix Now"))
        self.assertEqual([p for _, p in f.priority_factors], [40, 30])

    def test_internet_exposure_and_epss_bands(self):
        f = self.finding([("CVE-2024-0001", Decimal("7.5"), Decimal("0.2"))], perimeter=self.external)
        # 30 (CVSS 7.5) + 20 (EPSS 20%) + 15 (external)
        self.assertEqual(f.priority_score, 65)
        self.assertEqual(f.priority_level, 2)
        self.assertEqual(f.priority_factors[1][0], "EPSS 20.0% (CVE-2024-0001)")

    def test_highest_cvss_and_epss_across_cves(self):
        f = self.finding([("CVE-2024-0001", Decimal("5.0"), Decimal("0.6")), ("CVE-2024-0002", Decimal("9.0"), Decimal("0.001"))])
        self.assertEqual(f.priority_score, 36 + 25)

    def test_fallbacks_without_nvd(self):
        self.assertEqual(self.finding(qualys_cvss=Decimal("6.5")).priority_score, 26)
        self.assertEqual(self.finding(severity="low", qid="101").priority_score, 6)

    def test_age_and_overdue(self):
        self.assertEqual(self.finding(severity="medium", age_days=120).priority_score, 18 + 5)
        self.assertEqual(self.finding(severity="medium", due_in=-1, qid="101").priority_score, 18 + 10)

    def test_fixed_by_installed_version_is_capped(self):
        KevEntry.objects.create(cve_id="CVE-2021-41773")
        f = self.finding([("CVE-2021-41773", Decimal("7.5"), Decimal("0.99"))])
        PatchCheck.objects.create(vulnerability_finding=f, verdict=PatchCheck.Verdict.FIXED, ubuntu_release="focal", checked_at=timezone.now())
        priority.recompute()
        f.refresh_from_db()
        self.assertEqual(f.priority_score, 10)
        self.assertEqual(f.priority_factors[-1][0], "Fixed by Installed Version, To Confirm")

    def test_resolved_findings_are_not_recomputed(self):
        f = self.finding(severity="low")
        VulnerabilityFinding.objects.filter(pk=f.pk).update(status=Status.RESOLVED, priority_score=3)
        priority.recompute()
        f.refresh_from_db()
        self.assertEqual(f.priority_score, 3)

    def test_startup_command_recomputes(self):
        f = self.finding(severity="high")
        VulnerabilityFinding.objects.filter(pk=f.pk).update(priority_score=0, priority_factors=[])
        with override_settings(EPSS_ENABLED=False):
            call_command("priority_refresh", stdout=io.StringIO())
        f.refresh_from_db()
        self.assertEqual(f.priority_score, 28)


class PriorityViewTests(ImportTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        internal = Perimeter.objects.get(slug="internal")
        host = Host.objects.create(hostname="web01.example.test", ip_address="192.0.2.10")
        now = timezone.now()
        KevEntry.objects.create(cve_id="CVE-2021-44228")
        self.defs = {}
        for qid, severity, cve, cvss, score in [
            ("100", "low", None, None, None),
            ("200", "critical", "CVE-2021-44228", Decimal("10.0"), Decimal("0.99")),
            ("300", "high", "CVE-2024-0001", Decimal("7.5"), Decimal("0.02")),
        ]:
            d = VulnerabilityDefinition.objects.create(qid=qid, title=f"Thing {qid}", severity=severity, qualys_severity=3)
            if cve:
                d.cves.add(Cve.objects.create(cve_id=cve, cvss_score=cvss, epss_score=score, epss_percentile=Decimal("0.9")))
            VulnerabilityFinding.objects.create(
                host=host, vulnerability_definition=d, perimeter=internal, first_detected_at=now, last_detected_at=now
            )
        priority.recompute()

    def test_list_is_ordered_by_priority_and_filterable(self):
        page = self.client.get("/vulnerabilities/")
        self.assertEqual([f.vulnerability_definition.qid for f in page.context["page"].object_list], ["200", "300", "100"])
        self.assertContains(page, "EPSS 2.0%")
        self.assertContains(page, "+30  In CISA KEV (CVE-2021-44228)")
        p1 = self.client.get("/vulnerabilities/?priority=1").context["page"].object_list
        self.assertEqual([f.vulnerability_definition.qid for f in p1], ["200"])
        self.assertEqual(self.client.get("/vulnerabilities/?priority=4").context["page"].paginator.count, 1)

    def test_dashboard_top_priorities(self):
        page = self.client.get("/")
        self.assertEqual(page.context["p1_open"], 1)
        self.assertEqual(page.context["top_findings"][0].vulnerability_definition.qid, "200")
        self.assertContains(page, "Top Priorities")

    def test_qid_page_shows_epss(self):
        page = self.client.get("/vulnerabilities/qid/300/")
        self.assertContains(page, "Highest EPSS")
        self.assertContains(page, "Top 10.0%")

    def test_triage_moves_priority(self):
        f = VulnerabilityFinding.objects.get(vulnerability_definition__qid="300")
        before = f.priority_score
        yesterday = (timezone.localdate() - timedelta(days=1)).isoformat()
        self.client.post("/vulnerabilities/triage/", {"finding": [f.pk], "due_mode": "date", "due_date": yesterday})
        f.refresh_from_db()
        self.assertEqual(f.priority_score, before + 10)

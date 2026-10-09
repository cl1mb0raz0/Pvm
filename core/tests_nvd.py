import json
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from unittest import mock

from django.test import TestCase, override_settings
from django.utils import timezone

from . import nvd
from .models import Cve, VulnerabilityDefinition
from .tasks import refresh_nvd

FIXTURES = Path(__file__).parent / "fixtures"


def record(cve_id):
    """A real NVD API 2.0 answer, trimmed, saved in fixtures/."""
    return json.loads((FIXTURES / f"nvd_{cve_id}.json").read_text())["vulnerabilities"][0]["cve"]


class PickMetricTests(TestCase):
    def test_prefers_v31_primary_over_v2(self):
        metric = nvd.pick_metric(record("CVE-2021-44228"))
        self.assertEqual(metric["score"], Decimal("10.0"))
        self.assertEqual(metric["version"], "3.1")
        self.assertEqual(metric["severity"], "CRITICAL")
        self.assertEqual(metric["source"], "NVD")
        self.assertTrue(metric["vector"].startswith("CVSS:3.1/"))

    def test_prefers_nvd_primary_over_cna_secondary(self):
        # CVE-2024-6387 lists the CNA's score first, NVD's second.
        self.assertEqual(nvd.pick_metric(record("CVE-2024-6387"))["source"], "NVD")

    def test_v2_rating_lives_outside_cvss_data(self):
        only_v2 = record("CVE-2021-44228")
        only_v2["metrics"] = {"cvssMetricV2": only_v2["metrics"]["cvssMetricV2"]}
        metric = nvd.pick_metric(only_v2)
        self.assertEqual((metric["score"], metric["version"], metric["severity"]), (Decimal("9.3"), "2.0", "HIGH"))

    def test_ignores_non_cvss_metrics(self):
        self.assertIsNone(nvd.pick_metric({"metrics": {"ssvcV203": [{"source": "x"}]}}))


@override_settings(NVD_ENABLED=True, NVD_API_KEY="")
class RefreshTests(TestCase):
    def fake_fetch(self, cve_id):
        if cve_id == "CVE-2099-0001":
            return None
        if cve_id == "CVE-2000-0000":
            raise nvd.NvdError("NVD answered HTTP 500")
        return record(cve_id)

    def test_refresh_stores_scores_and_outcomes(self):
        for c in ["CVE-2021-44228", "CVE-2024-6387", "CVE-2099-0001", "CVE-2000-0000"]:
            Cve.objects.create(cve_id=c)
        sleeps = []
        with mock.patch("core.nvd.fetch", side_effect=self.fake_fetch):
            counts = nvd.refresh(list(nvd.due_for_refresh()), sleep=sleeps.append)

        self.assertEqual(counts, {"ok": 2, "not_found": 1, "error": 1})
        # Paced for the keyless limit (5 per 30 s): no sleep before the first request.
        self.assertEqual(sleeps, [6.5, 6.5, 6.5])
        log4shell = Cve.objects.get(cve_id="CVE-2021-44228")
        self.assertEqual((log4shell.cvss_score, log4shell.cvss_version), (Decimal("10.0"), "3.1"))
        self.assertEqual(log4shell.nvd_published_at.year, 2021)
        self.assertEqual(Cve.objects.get(cve_id="CVE-2099-0001").nvd_status, Cve.NvdStatus.NOT_FOUND)
        failed = Cve.objects.get(cve_id="CVE-2000-0000")
        self.assertEqual(failed.nvd_status, Cve.NvdStatus.ERROR)
        self.assertIn("500", failed.nvd_error)

    def test_only_due_cves_are_refetched(self):
        fresh = Cve.objects.create(cve_id="CVE-2021-44228", nvd_status=Cve.NvdStatus.OK, nvd_fetched_at=timezone.now())
        old = Cve.objects.create(
            cve_id="CVE-2024-6387", nvd_status=Cve.NvdStatus.OK, nvd_fetched_at=timezone.now() - timedelta(days=30)
        )
        pending = Cve.objects.create(cve_id="CVE-2099-0001")
        self.assertEqual(set(nvd.due_for_refresh()), {old, pending})
        self.assertNotIn(fresh, nvd.due_for_refresh())

    def test_failed_refetch_keeps_the_previous_score(self):
        cve = Cve.objects.create(cve_id="CVE-2000-0000", cvss_score=Decimal("7.5"), nvd_status=Cve.NvdStatus.OK)
        with mock.patch("core.nvd.fetch", side_effect=self.fake_fetch):
            nvd.refresh([cve], sleep=lambda s: None)
        cve.refresh_from_db()
        self.assertEqual(cve.cvss_score, Decimal("7.5"))
        self.assertEqual(cve.nvd_status, Cve.NvdStatus.ERROR)

    def test_task_does_nothing_when_disabled(self):
        Cve.objects.create(cve_id="CVE-2021-44228")
        with override_settings(NVD_ENABLED=False), mock.patch("core.nvd.fetch") as fetch:
            refresh_nvd.apply()
        fetch.assert_not_called()

    def test_task_refreshes_due_cves(self):
        Cve.objects.create(cve_id="CVE-2021-44228")
        with mock.patch("core.nvd.fetch", side_effect=self.fake_fetch), mock.patch("core.tasks._nvd_lock", return_value=None):
            result = refresh_nvd.apply().get()
        self.assertEqual(result["ok"], 1)

    def test_empty_cvss_cell_says_why(self):
        definition = VulnerabilityDefinition.objects.create(qid="2", title="t", severity="high", qualys_severity=4)
        cve = Cve.objects.create(cve_id="CVE-9")
        definition.cves.add(cve)

        def gap():
            return VulnerabilityDefinition.objects.get(pk=definition.pk).nvd_gap

        self.assertEqual(gap()[0], "pending")
        cve.nvd_status = Cve.NvdStatus.ERROR
        cve.nvd_error = "HTTP 503"
        cve.save()
        self.assertEqual(gap()[0], "error")
        self.assertIn("HTTP 503", gap()[1])
        cve.nvd_status = Cve.NvdStatus.NOT_FOUND
        cve.save()
        self.assertEqual(gap()[:2], ("none", "Not in NVD"))
        cve.nvd_status = Cve.NvdStatus.OK
        cve.save()
        self.assertEqual(gap()[1], "NVD Has No CVSS Score for This CVE")
        cve.nvd_status = Cve.NvdStatus.PENDING
        cve.save()
        with override_settings(NVD_ENABLED=False):
            self.assertEqual(gap()[0], "off")

    def test_definition_shows_its_highest_cvss(self):
        definition = VulnerabilityDefinition.objects.create(qid="1", title="t", severity="high", qualys_severity=4)
        definition.cves.add(
            Cve.objects.create(cve_id="CVE-1", cvss_score=Decimal("5.3")),
            Cve.objects.create(cve_id="CVE-2", cvss_score=Decimal("9.8")),
            Cve.objects.create(cve_id="CVE-3"),
        )
        self.assertEqual(definition.nvd_cvss.cve_id, "CVE-2")
        self.assertEqual(definition.qualys_severity_name, "Critical")

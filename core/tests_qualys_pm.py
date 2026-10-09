from unittest import mock

from django.test import TestCase, override_settings
from django.utils import timezone

from accounts.models import User

from . import qualys_pm
from .models import (
    AuditLog,
    Cve,
    DistroPatchVerification,
    Host,
    PatchCheck,
    Perimeter,
    PmSearch,
    VulnerabilityDefinition,
    VulnerabilityFinding,
)
from .tests_imports import PASSWORD, ImportTestMixin

Verdict = PatchCheck.Verdict


def pm_asset(asset_id, name, addresses, missing=(), installed=()):
    return {
        "id": asset_id,
        "name": name,
        "interfaces": [{"address": a} for a in addresses],
        "missingPatches": [{"id": pid} for pid in missing],
        "installedPatches": list(installed),
    }


def pm_patch(patch_id, qids, cve=(), kb="", title=""):
    return {"id": patch_id, "qid": list(qids), "cve": list(cve), "kb": kb, "title": title or patch_id}


class ReadingTests(TestCase):
    def test_windows_detected_on_host(self):
        self.assertTrue(Host(os_version="Microsoft Windows Server 2019 Standard").is_windows)
        self.assertTrue(Host(os_name="Windows 10").is_windows)
        self.assertFalse(Host(os_version="Canonical Ubuntu Jammy Jellyfish").is_windows)
        self.assertFalse(Host().is_windows)

    def test_build_index(self):
        patches = [
            pm_patch("p1", ["100001"], cve=["CVE-2026-0001"], kb="5040942", title="GDR 2056 for SQL Server 2017"),
            pm_patch("p2", ["100001", "100002"], kb="QNPPP8981", title="Notepad++ 8.9.8.1"),
        ]
        catalog, by_qid = qualys_pm.build_index(patches)
        self.assertEqual(set(catalog), {"p1", "p2"})
        self.assertEqual(catalog["p1"]["kb"], "5040942")
        self.assertEqual(by_qid["100001"], {"p1", "p2"})
        self.assertEqual(by_qid["100002"], {"p2"})

    def test_matching(self):
        win = Host(pk=1, hostname="win-analyst-1.corp.test", ip_address="10.0.4.20")
        by_ip_only = Host(pk=2, hostname="10.0.4.21", ip_address="10.0.4.21")
        unknown = Host(pk=3, hostname="gone.corp.test", ip_address="10.0.9.9")
        assets = [
            pm_asset("a1", "win-analyst-1.corp.test", ["10.0.4.20"]),
            pm_asset("a2", "some-other-name", ["10.0.4.21"]),
        ]
        found = {h.pk: (a["id"], how) for h, a, how in qualys_pm.match([win, by_ip_only, unknown], assets)}
        self.assertEqual(found[1], ("a1", "IP and Name"))
        self.assertEqual(found[2], ("a2", "IP Only"))
        self.assertNotIn(3, found)

    def test_matching_by_name_suffix(self):
        # PM sometimes appends " - <tenant>" to the asset name.
        host = Host(pk=1, hostname="t-debug.app.corp", ip_address="10.31.15.11")
        assets = [pm_asset("a1", "t-debug.app.corp - APPX", ["10.31.15.11"])]
        found = qualys_pm.match([host], assets)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0][2], "IP and Name")


@override_settings(QUALYS_GATEWAY_URL="https://gateway.example.test", QUALYS_USERNAME="u", QUALYS_PASSWORD="p")
class FlowTests(ImportTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.host = Host.objects.create(
            hostname="win-a.example.test", ip_address="10.0.4.30", os_version="Microsoft Windows Server 2019 Standard"
        )
        self.perimeter = Perimeter.objects.get(slug="internal")
        self.missing_def = VulnerabilityDefinition.objects.create(
            qid="100001", title="SQL Server Missing Update", severity="critical", qualys_severity=5
        )
        self.missing_def.cves.add(Cve.objects.create(cve_id="CVE-2026-1001"))
        self.fixed_def = VulnerabilityDefinition.objects.create(
            qid="100002", title="SQL Server Old Update", severity="high", qualys_severity=4
        )
        self.unknown_def = VulnerabilityDefinition.objects.create(
            qid="999999", title="Not in Patch Management", severity="medium", qualys_severity=3
        )
        now = timezone.now()
        self.f_missing = VulnerabilityFinding.objects.create(
            host=self.host, vulnerability_definition=self.missing_def, perimeter=self.perimeter,
            first_detected_at=now, last_detected_at=now,
        )
        self.f_fixed = VulnerabilityFinding.objects.create(
            host=self.host, vulnerability_definition=self.fixed_def, perimeter=self.perimeter,
            first_detected_at=now, last_detected_at=now,
        )
        self.f_unknown = VulnerabilityFinding.objects.create(
            host=self.host, vulnerability_definition=self.unknown_def, perimeter=self.perimeter,
            first_detected_at=now, last_detected_at=now,
        )

        client = mock.MagicMock(calls=3)
        client.pm_assets.return_value = [
            pm_asset("a1", "win-a.example.test", ["10.0.4.30"], missing=["p1"], installed=["p2"]),
        ]
        client.pm_patches.return_value = [
            pm_patch("p1", ["100001"], cve=["CVE-2026-1001"], kb="5029375", title="GDR 2052 for SQL Server 2017"),
            pm_patch("p2", ["100002"], kb="5014354", title="GDR 2042 for SQL Server 2017"),
        ]
        patcher = mock.patch("core.qualys_pm.Client", return_value=client)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.client_mock = client

    def post(self, url, data=None):
        with self.captureOnCommitCallbacks(execute=True):
            return self.client.post(url, data or {})

    def search(self):
        self.post("/imports/pm/search/")
        return PmSearch.objects.get()

    def test_search_writes_verdicts_directly(self):
        search = self.search()
        self.assertEqual(search.state, "done")
        self.assertEqual((search.windows_hosts, search.matched, search.findings_checked), (1, 1, 3))
        self.assertEqual((search.missing_count, search.fixed_count, search.unknown_count), (1, 1, 1))

        missing_check = self.f_missing.patch_check
        self.assertEqual(missing_check.verdict, Verdict.VULNERABLE_UPDATE)
        self.assertEqual(missing_check.source, PatchCheck.Source.QUALYS_PM)
        self.assertIn("GDR 2052", missing_check.details[0]["reason"])
        self.assertEqual(missing_check.details[0]["cve"], "CVE-2026-1001")

        fixed_check = self.f_fixed.patch_check
        self.assertEqual(fixed_check.verdict, Verdict.FIXED)

        unknown_check = self.f_unknown.patch_check
        self.assertEqual(unknown_check.verdict, Verdict.UNKNOWN)
        self.assertIn("No Matching Patch", unknown_check.details[0]["reason"])

        self.assertTrue(AuditLog.objects.filter(action="pm.search_started").exists())

    def test_page_shows_the_results(self):
        self.search()
        page = self.client.get("/imports/pm/")
        self.assertContains(page, "win-a.example.test")
        self.assertContains(page, "1 Vulnerable, Patch Missing")

    def test_confirm_workflow_resolves_the_fixed_finding(self):
        self.search()
        self.assertEqual(self.client.post(f"/findings/{self.f_fixed.pk}/confirm-check/").status_code, 302)
        self.f_fixed.refresh_from_db()
        self.assertEqual(self.f_fixed.status, VulnerabilityFinding.Status.RESOLVED)
        v = DistroPatchVerification.objects.get(vulnerability_finding=self.f_fixed)
        self.assertEqual(v.source, PatchCheck.Source.QUALYS_PM)
        self.assertEqual(v.verdict, DistroPatchVerification.Verdict.CONFIRMED_FIXED)
        self.assertEqual(v.reference_url, "https://support.microsoft.com/kb/5014354")

        # A missing-patch verdict can be confirmed too, but stays open, not resolved.
        self.client.post(f"/findings/{self.f_missing.pk}/confirm-check/")
        self.f_missing.refresh_from_db()
        self.assertEqual(self.f_missing.status, VulnerabilityFinding.Status.STILL_OPEN)
        self.assertEqual(
            DistroPatchVerification.objects.get(vulnerability_finding=self.f_missing).verdict,
            DistroPatchVerification.Verdict.CONFIRMED_VULNERABLE,
        )

    def test_a_search_replaces_the_old_one(self):
        self.search()
        self.search()
        self.assertEqual(PmSearch.objects.count(), 1)

    def test_failure_is_shown(self):
        self.client_mock.pm_assets.side_effect = qualys_pm.PmError("Qualys Gateway Unreachable (Is Cato Connected on the VM?)")
        search = self.search()
        self.assertEqual(search.state, "failed")
        self.assertContains(self.client.get("/imports/pm/"), "Is Cato Connected on the VM?")

    def test_readonly_has_no_access(self):
        self.client.post("/account/logout/")
        User.objects.create_user("ro", "ro@example.com", PASSWORD, role=User.Role.READONLY)
        self.client.post("/account/login/", {"username": "ro", "password": PASSWORD})
        self.assertEqual(self.client.get("/imports/pm/").status_code, 403)
        self.assertEqual(self.client.post("/imports/pm/search/").status_code, 403)

    def test_tab_label(self):
        self.assertContains(self.client.get("/imports/"), ">Qualys Pm</a>")

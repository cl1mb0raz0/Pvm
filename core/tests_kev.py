import json
from io import StringIO
from pathlib import Path
from unittest import mock

from django.core.management import call_command
from django.test import TestCase, override_settings

from accounts.models import User

from . import kev
from .models import KevEntry, ScanImport, VulnerabilityFinding
from .tasks import refresh_kev
from .tests_imports import ImportTestMixin

CATALOG = json.loads((Path(__file__).parent / "fixtures" / "kev_catalog.json").read_text())


class CatalogTests(TestCase):
    """On three real entries of the CISA feed."""

    def test_parse(self):
        entries = {e.cve_id: e for e in kev.parse(CATALOG)}
        self.assertEqual(len(entries), 3)
        log4shell = entries["CVE-2021-44228"]
        self.assertEqual((log4shell.vendor, log4shell.product), ("Apache", "Log4j2"))
        self.assertEqual(str(log4shell.date_added), "2021-12-10")
        self.assertTrue(log4shell.ransomware)
        self.assertTrue(log4shell.required_action)

    def test_replace_swaps_the_whole_catalog(self):
        KevEntry.objects.create(cve_id="CVE-2000-0001")
        self.assertEqual(kev.replace_catalog(kev.parse(CATALOG), minimum=1), 3)
        self.assertFalse(KevEntry.objects.filter(cve_id="CVE-2000-0001").exists())

    def test_a_broken_download_never_wipes_the_copy(self):
        KevEntry.objects.create(cve_id="CVE-2021-44228")
        with self.assertRaises(kev.KevError):
            kev.replace_catalog(kev.parse(CATALOG))  # 3 entries < the 100 minimum
        with self.assertRaises(kev.KevError):
            kev.replace_catalog(kev.parse({"vulnerabilities": []}))
        self.assertTrue(KevEntry.objects.filter(cve_id="CVE-2021-44228").exists())

    def test_task_respects_the_setting(self):
        with override_settings(KEV_ENABLED=False), mock.patch("core.kev.fetch") as fetch:
            self.assertIsNone(refresh_kev.apply().get())
        fetch.assert_not_called()
        with override_settings(KEV_ENABLED=True), mock.patch("core.kev.fetch", return_value=CATALOG), \
                mock.patch("core.kev.MIN_ENTRIES", 1):
            self.assertEqual(refresh_kev.apply().get(), 3)


class KevInTheUiTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        call_command("seed_demo", stdout=StringIO())
        kev.replace_catalog([e for e in kev.parse(CATALOG) if e.cve_id == "CVE-2021-44228"], minimum=1)
        User.objects.create_user("ro", "ro@example.com", "correct-horse-battery", role=User.Role.READONLY)

    def setUp(self):
        self.client.post("/account/login/", {"username": "ro", "password": "correct-horse-battery"})

    def test_badge_and_filter_in_the_list(self):
        page = self.client.get("/vulnerabilities/?status=all")
        self.assertContains(page, 'class="badge kev"')
        found = self.client.get("/vulnerabilities/?status=all&kev=yes").context["page"]
        self.assertTrue(found.paginator.count)
        self.assertEqual({f.vulnerability_definition.qid for f in found.object_list}, {"150440"})
        self.assertTrue(all(f.in_kev for f in found.object_list))

    def test_dashboard_counts_open_exploited_findings(self):
        expected = VulnerabilityFinding.objects.filter(vulnerability_definition__qid="150440").exclude(status="resolved").count()
        page = self.client.get("/")
        self.assertEqual(page.context["kev_open"], expected)
        if expected:
            self.assertContains(page, "Exploited in the Wild")

    def test_detail_page_shows_cisa_information(self):
        page = self.client.get("/vulnerabilities/qid/150440/")
        self.assertContains(page, "Exploited in the Wild")
        self.assertContains(page, "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=CVE-2021-44228")
        self.assertContains(page, "Used in Ransomware Campaigns")
        # The second CVE of the QID is not in KEV: no CISA link for it.
        self.assertNotContains(page, "search_api_fulltext=CVE-2021-45046")


class FirstImportFetchesTheCatalogTests(ImportTestMixin, TestCase):
    def test_first_import_triggers_a_refresh(self):
        with override_settings(KEV_ENABLED=True), mock.patch("core.kev.refresh", return_value=1721) as refresh:
            scan_import = self.full_import()
        self.assertEqual(scan_import.status, ScanImport.Status.COMPLETED)
        refresh.assert_called_once()

    def test_later_imports_leave_it_to_the_nightly_refresh(self):
        KevEntry.objects.create(cve_id="CVE-2021-44228")
        with override_settings(KEV_ENABLED=True), mock.patch("core.kev.refresh") as refresh:
            self.full_import()
        refresh.assert_not_called()

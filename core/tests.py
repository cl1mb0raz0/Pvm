from io import StringIO

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase

from accounts.models import User

from .models import Host, VulnerabilityFinding


class PageTests(TestCase):
    """Every screen renders against the demo dataset, full page and htmx partial."""

    @classmethod
    def setUpTestData(cls):
        call_command("seed_demo", stdout=StringIO())
        User.objects.create_user("ro", "ro@example.com", "correct-horse-battery", role=User.Role.READONLY)

    def setUp(self):
        self.client.post("/account/login/", {"username": "ro", "password": "correct-horse-battery"})
        self.web01 = Host.objects.get(hostname="web-01")

    def test_pages_render(self):
        for url in ["/", "/vulnerabilities/", "/hosts/", f"/hosts/{self.web01.pk}/", "/account/"]:
            self.assertEqual(self.client.get(url).status_code, 200, url)

    def test_dashboard_trend_covers_eight_scans(self):
        context = self.client.get("/").context
        self.assertEqual(context["scan_count"], 8)
        self.assertEqual(len(context["trend_rows"]), 8)

    def test_vulnerability_filters(self):
        page = self.client.get("/vulnerabilities/?severity=critical&status=all").context["page"]
        self.assertTrue(page.object_list)
        self.assertEqual({f.vulnerability_definition.severity for f in page.object_list}, {"critical"})

        page = self.client.get("/vulnerabilities/?q=CVE-2024-6387&status=all").context["page"]
        self.assertTrue(page.object_list)
        self.assertEqual({f.vulnerability_definition.qid for f in page.object_list}, {"38909"})

        page = self.client.get("/vulnerabilities/").context["page"]
        self.assertNotIn(VulnerabilityFinding.Status.RESOLVED, {f.status for f in page.object_list})

    def test_htmx_requests_get_partials(self):
        response = self.client.get("/vulnerabilities/?severity=high", HTTP_HX_REQUEST="true")
        self.assertNotContains(response, 'class="sidebar"')

        response = self.client.get(f"/hosts/{self.web01.pk}/?tab=packages", HTTP_HX_REQUEST="true")
        self.assertNotContains(response, 'class="sidebar"')
        self.assertContains(response, "Verified: Patch Backported")

    def test_host_shows_distro_verification(self):
        response = self.client.get(f"/hosts/{self.web01.pk}/")
        self.assertContains(response, "Distro Patch Verification")
        self.assertContains(response, "https://ubuntu.com/security/CVE-2021-41773")

    def test_seed_refuses_non_empty_database(self):
        with self.assertRaises(CommandError):
            call_command("seed_demo")


class VulnerabilityDetailTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        call_command("seed_demo", stdout=StringIO())
        User.objects.create_user("ro", "ro@example.com", "correct-horse-battery", role=User.Role.READONLY)

    def setUp(self):
        self.client.post("/account/login/", {"username": "ro", "password": "correct-horse-battery"})

    def test_rows_link_to_the_detail_page(self):
        self.assertContains(self.client.get("/vulnerabilities/"), "/vulnerabilities/qid/")

    def test_detail_shows_cves_with_public_links_and_hosts(self):
        from .models import VulnerabilityDefinition

        definition = VulnerabilityDefinition.objects.get(qid="150440")  # Log4Shell, two CVEs
        page = self.client.get("/vulnerabilities/qid/150440/")
        self.assertEqual(page.status_code, 200)
        self.assertContains(page, definition.title)
        for cve in ("CVE-2021-44228", "CVE-2021-45046"):
            self.assertContains(page, f"https://nvd.nist.gov/vuln/detail/{cve}")
            self.assertContains(page, f"https://ubuntu.com/security/{cve}")
            self.assertContains(page, f"https://www.cve.org/CVERecord?id={cve}")
        self.assertContains(page, 'rel="noopener noreferrer"')
        self.assertEqual(len(page.context["findings"]), definition.findings.count())

    def test_qid_without_cves(self):
        page = self.client.get("/vulnerabilities/qid/38794/")  # TLS 1.0/1.1, no CVE
        self.assertContains(page, "No CVE for This QID")

    def test_unknown_qid_is_404(self):
        self.assertEqual(self.client.get("/vulnerabilities/qid/999999/").status_code, 404)

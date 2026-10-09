"""The Export page: every filter, three formats (core/export_views.py)."""

import csv
import io

from django.test import TestCase

from .models import ScanImport, Tag, VulnerabilityFinding
from .tests_imports import ImportTestMixin

Status = VulnerabilityFinding.Status


def read_csv(response):
    body = b"".join(response.streaming_content).decode("utf-8")
    return list(csv.reader(io.StringIO(body.lstrip("﻿")), delimiter=";"))


class ExportPageTests(ImportTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.scan = self.full_import()
        self.assertEqual(self.scan.status, ScanImport.Status.COMPLETED, self.scan.error_message)
        self.open_count = VulnerabilityFinding.objects.exclude(status=Status.RESOLVED).count()
        # One finding resolved by hand, to prove "Status: All" is what brings it back.
        self.resolved = VulnerabilityFinding.objects.first()
        VulnerabilityFinding.objects.filter(pk=self.resolved.pk).update(status=Status.RESOLVED)

    def get(self, query):
        return self.client.get("/export/run/?" + query)

    def test_page_offers_the_filters_and_the_formats(self):
        page = self.client.get("/export/")
        for text in ["Export", "All, Resolved Included", "Patch Check", "In CISA KEV", "PDF (to Print or Send)", "Qualys Severity"]:
            self.assertContains(page, text)

    def test_csv_keeps_resolved_out_unless_asked(self):
        rows = read_csv(self.get("dataset=findings&format=csv"))
        self.assertEqual(rows[0][:3], ["Priority", "Priority Score", "Severity"])
        self.assertEqual(len(rows) - 1, self.open_count - 1)
        with_resolved = read_csv(self.get("dataset=findings&format=csv&status=all"))
        self.assertEqual(len(with_resolved) - 1, self.open_count)
        only_resolved = read_csv(self.get("dataset=findings&format=csv&status=resolved"))
        self.assertEqual(len(only_resolved) - 1, 1)

    def test_filters_narrow_the_export(self):
        tag = Tag.objects.create(name="Alpha")
        host = VulnerabilityFinding.objects.first().host
        host.tags.add(tag)
        rows = read_csv(self.get(f"dataset=findings&format=csv&status=all&tag={tag.pk}"))
        self.assertEqual(len(rows) - 1, VulnerabilityFinding.objects.filter(host=host).count())
        critical = read_csv(self.get("dataset=findings&format=csv&status=all&severity=critical"))
        self.assertTrue(all(r[2] == "Critical" for r in critical[1:]))
        self.assertEqual(read_csv(self.get("dataset=findings&format=csv&q=nothing-matches-this"))[1:], [])

    def test_several_severities_at_once(self):
        rows = read_csv(self.get("dataset=findings&format=csv&status=all&severity=critical&severity=high"))
        kinds = {r[2] for r in rows[1:]}
        self.assertEqual(kinds, {"Critical", "High"})
        # Qualys levels tick the same way: 5 and 4 together.
        levels = read_csv(self.get("dataset=findings&format=csv&status=all&qualys=5&qualys=4"))
        self.assertTrue(all(r[3] in ("5 Urgent", "4 Critical") for r in levels[1:]))
        self.assertGreater(len(levels) - 1, 0)
        # One value alone still works, as the Vulnerabilities list sends it.
        one = read_csv(self.get("dataset=findings&format=csv&status=all&severity=critical"))
        self.assertEqual({r[2] for r in one[1:]}, {"Critical"})
        # And the report says both were asked for.
        body = self.get("dataset=findings&format=html&status=all&severity=critical&severity=high").content.decode()
        self.assertIn("<b>Severity:</b> Critical, High", body)

    def test_preview_counts_what_the_export_would_hold(self):
        page = self.client.get("/export/preview/?dataset=findings&status=all")
        self.assertContains(page, "This Export Would Hold")
        self.assertContains(page, "Findings")
        self.assertContains(page, "On 3 Hosts")
        self.assertContains(page, "Resolved")
        narrowed = self.client.get("/export/preview/?dataset=findings&status=all&severity=critical")
        self.assertContains(narrowed, "Severity: Critical")
        empty = self.client.get("/export/preview/?dataset=findings&q=nothing-matches-this")
        self.assertContains(empty, "the Export Would Be Empty")
        hosts = self.client.get("/export/preview/?dataset=hosts")
        self.assertContains(hosts, "Hosts")
        self.assertContains(hosts, "Open Critical")

    def test_the_page_carries_the_preview_and_the_tick_boxes(self):
        page = self.client.get("/export/")
        self.assertContains(page, 'id="preview"')
        self.assertContains(page, "/export/preview/")
        self.assertContains(page, '<input type="checkbox" name="severity" value="critical">')
        self.assertContains(page, '<input type="checkbox" name="qualys" value="5">')

    def test_html_report_carries_the_filters_and_the_counts(self):
        response = self.get("dataset=findings&format=html&severity=critical&status=all&perimeter=internal")
        self.assertEqual(response.status_code, 200)
        self.assertIn("attachment", response["Content-Disposition"])
        self.assertTrue(response["Content-Disposition"].endswith('.html"'))
        body = response.content.decode()
        self.assertIn("Pvm — Vulnerabilities", body)
        self.assertIn("Filters Applied", body)
        self.assertIn("<b>Severity:</b> Critical", body)
        self.assertIn("<b>Perimeter:</b> Internal", body)
        self.assertIn("<b>Status:</b> All, Resolved Included", body)
        self.assertIn("Summary", body)

    def test_html_file_name_says_the_perimeter_and_the_minute(self):
        import re

        def name(query):
            return re.search(r'filename="([^"]+)"', self.get(query)["Content-Disposition"]).group(1)

        pattern = r"pvm_vulnerabilities_{}_\d{{2}}_\d{{2}}_\d{{2}}_\d{{2}}_\d{{2}}\.html"
        self.assertRegex(name("dataset=findings&format=html&perimeter=internal"), pattern.format("internal"))
        self.assertRegex(name("dataset=findings&format=html&perimeter=external"), pattern.format("external"))
        self.assertRegex(name("dataset=findings&format=html"), pattern.format("all"))
        self.assertRegex(name("dataset=findings&format=html&perimeter=nonsense"), pattern.format("all"))
        # Hosts and the other formats keep their own names.
        self.assertRegex(name("dataset=hosts&format=html"), r"pvm-hosts-\d{8}-\d{4}\.html")
        self.assertRegex(name("dataset=findings&format=csv"), r"pvm-vulnerabilities_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}\.csv")

    def test_html_report_links_the_qid_and_title_to_the_vulnerability_page(self):
        body = self.get("dataset=findings&format=html&status=all").content.decode()
        qid = VulnerabilityFinding.objects.first().vulnerability_definition.qid
        self.assertIn(f'<a href="http://testserver/vulnerabilities/qid/{qid}/">{qid}</a>', body)
        self.assertRegex(body, rf'<a href="http://testserver/vulnerabilities/qid/{qid}/">[^<]+</a>')
        # Hosts have no vulnerability page to point at.
        hosts = self.get("dataset=hosts&format=html").content.decode()
        self.assertNotIn("/vulnerabilities/qid/", hosts)

    def test_html_report_filters_itself_and_marks_what_is_settled(self):
        body = self.get("dataset=findings&format=html&status=all").content.decode()
        # Filters that work in the file alone, built from the values it holds.
        self.assertIn('<label>Search<input type="search" id="search"', body)
        for label in ["Priority", "Severity", "Status", "Perimeter"]:
            self.assertIn(f"<label>{label}", body)
        # Nothing in this export has a patch check verdict: no empty menu for it.
        self.assertNotIn("<label>Patch Check", body)
        self.assertIn('data-keys="', body)
        # Each menu says which of the row's keys it matches, so dropping the
        # empty one does not shift the ones after it.
        self.assertIn('<select data-at="2">', body)  # Status
        self.assertIn('<select data-at="4">', body)  # Perimeter, still the fifth key
        self.assertIn(f"{self.open_count} of {self.open_count} Rows", body)
        self.assertIn("Clear", body)
        # Resolved: the row is green and so is the cell that says so.
        self.assertIn('<tr class="settled"', body)
        self.assertIn('<td class="settled">Resolved</td>', body)
        self.assertIn("Green", body)
        # An open finding keeps the plain cell.
        self.assertIn("<td>New</td>", body)

    def test_the_pdf_does_not_print_the_filter_bar(self):
        body = self.get("dataset=findings&format=html").content.decode()
        self.assertIn("@media print { .controls-box { display: none; } }", body)
        self.assertIn('class="box controls-box"', body)

    def test_pdf_is_a_pdf(self):
        response = self.get("dataset=findings&format=pdf&status=all")
        self.assertEqual(response["Content-Type"], "application/pdf")
        self.assertTrue(response.content.startswith(b"%PDF"))
        self.assertGreater(len(response.content), 1000)

    def test_hosts_can_be_exported_too(self):
        rows = read_csv(self.get("dataset=hosts&format=csv"))
        self.assertEqual(rows[0][:4], ["Hostname", "IP Address", "Private IP", "Server"])
        self.assertEqual(len(rows) - 1, self.scan.hosts.count())
        body = self.get("dataset=hosts&format=html").content.decode()
        self.assertIn("Pvm — Hosts", body)

    def test_every_export_is_audited(self):
        from .models import AuditLog

        self.get("dataset=findings&format=pdf")
        self.get("dataset=hosts&format=csv")
        actions = set(AuditLog.objects.values_list("action", flat=True))
        self.assertIn("export.findings", actions)
        self.assertIn("export.hosts", actions)
        self.assertEqual(AuditLog.objects.filter(action="export.findings").first().details["format"], "pdf")

    def test_readonly_can_export(self):
        from accounts.models import User

        from .tests_imports import PASSWORD

        self.client.post("/account/logout/")
        User.objects.create_user("ro", "ro@example.com", PASSWORD, role=User.Role.READONLY)
        self.client.post("/account/login/", {"username": "ro", "password": PASSWORD})
        self.assertEqual(self.client.get("/export/").status_code, 200)
        self.assertEqual(self.get("dataset=findings&format=csv").status_code, 200)

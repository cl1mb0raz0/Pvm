import csv
import io

from django.test import TestCase

from accounts.models import User

from .models import AuditLog, Host, ScanImport, Tag, VulnerabilityFinding
from .tests_imports import PASSWORD, ImportTestMixin


def read_csv(response):
    body = b"".join(response.streaming_content).decode("utf-8")
    assert body.startswith("﻿")
    return list(csv.reader(io.StringIO(body[1:]), delimiter=";"))


class TagTests(ImportTestMixin, TestCase):
    def import_with(self, name="Internal Alpha", **extra):
        self.upload()
        scan_import = ScanImport.objects.latest("pk")
        ScanImport.objects.filter(pk=scan_import.pk).update(name=name)
        scan_import.refresh_from_db()
        self.confirm(scan_import, extra=extra)
        return scan_import

    def test_import_tags_every_host_and_is_suggested_next_time(self):
        scan_import = self.import_with(new_tags="Alpha, alpha ,  Sap")
        self.assertEqual(sorted(Tag.objects.values_list("name", flat=True)), ["Alpha", "Sap"])
        hosts = Host.objects.all()
        self.assertTrue(hosts.exists())
        for host in hosts:
            self.assertEqual(sorted(t.name for t in host.tags.all()), ["Alpha", "Sap"])
        self.assertEqual(AuditLog.objects.get(action="import.started", entity_id=str(scan_import.pk)).details["tags"], ["Alpha", "Sap"])

        # Same name again: its tags are pre-ticked on the column page.
        self.upload()
        second = ScanImport.objects.latest("pk")
        ScanImport.objects.filter(pk=second.pk).update(name="internal alpha")
        page = self.client.get(f"/imports/{second.pk}/columns/")
        self.assertEqual(page.context["selected_tags"], set(Tag.objects.values_list("pk", flat=True)))

    def test_existing_tag_ticked_and_case_insensitive_reuse(self):
        alpha = Tag.objects.create(name="Alpha")
        self.import_with(tag=[alpha.pk], new_tags="ALPHA")
        self.assertEqual(Tag.objects.count(), 1)

    def test_tags_are_never_removed_by_an_import(self):
        self.import_with(new_tags="Alpha")
        self.import_with(name="Internal Other", new_tags="Other")
        host = Host.objects.first()
        self.assertEqual(sorted(t.name for t in host.tags.all()), ["Alpha", "Other"])

    def test_add_tags_later_from_the_import_page(self):
        scan_import = self.import_with()
        self.client.post(f"/imports/{scan_import.pk}/tags/", {"new_tags": "Alpha"})
        self.assertEqual(Host.objects.filter(tags__name="Alpha").count(), scan_import.hosts.count())

    def test_host_page_add_and_remove(self):
        host = Host.objects.create(hostname="appsrv", ip_address="192.0.2.30")
        self.client.post(f"/hosts/{host.pk}/tags/", {"new_tags": "Alpha"})
        alpha = Tag.objects.get(name="Alpha")
        self.assertContains(self.client.get(f"/hosts/{host.pk}/"), 'class="tag">Alpha')
        self.client.post(f"/hosts/{host.pk}/tags/{alpha.pk}/remove/")
        self.assertFalse(host.tags.exists())
        self.assertEqual(
            list(AuditLog.objects.filter(entity_id=str(host.pk), action__startswith="host.").values_list("action", flat=True).order_by("timestamp")),
            ["host.tagged", "host.untagged"],
        )

    def test_filters(self):
        self.import_with(new_tags="Alpha")
        other = Host.objects.create(hostname="untagged.example.test", ip_address="192.0.2.99")
        alpha = Tag.objects.get(name="Alpha")
        hosts = list(self.client.get(f"/hosts/?tag={alpha.pk}").context["hosts"])
        self.assertTrue(hosts and other not in hosts)
        self.assertEqual(list(self.client.get("/hosts/?tag=none").context["hosts"]), [other])
        tagged = self.client.get(f"/vulnerabilities/?tag={alpha.pk}").context["page"].paginator.count
        self.assertEqual(tagged, VulnerabilityFinding.objects.exclude(status="resolved").count())
        self.assertEqual(self.client.get("/vulnerabilities/?tag=none").context["page"].paginator.count, 0)

    def test_os_filter(self):
        ubuntu = Host.objects.create(hostname="web-a.example.test", ip_address="192.0.2.10", os_version="Ubuntu 22.04")
        windows = Host.objects.create(hostname="win-a.example.test", ip_address="192.0.2.11", os_version="Microsoft Windows Server 2019")
        no_os = Host.objects.create(hostname="unknown.example.test", ip_address="192.0.2.12")

        page = self.client.get("/hosts/")
        self.assertEqual(sorted(page.context["os_choices"]), [("Microsoft Windows Server 2019",) * 2, ("Ubuntu 22.04",) * 2])

        hosts = list(self.client.get("/hosts/?os=Ubuntu 22.04").context["hosts"])
        self.assertEqual(hosts, [ubuntu])

        # Several ticks: any of them (widens, does not narrow).
        hosts = self.client.get("/hosts/?os=Ubuntu 22.04&os=Microsoft Windows Server 2019").context["hosts"]
        self.assertEqual(sorted(h.pk for h in hosts), sorted([ubuntu.pk, windows.pk]))
        self.assertNotIn(no_os, hosts)

        response = self.client.get("/hosts/?os=Ubuntu 22.04")
        self.assertContains(response, 'name="os" value="Ubuntu 22.04" checked')
        self.assertTrue(response.context["filtered"])

    def test_readonly_cannot_tag(self):
        host = Host.objects.create(hostname="appsrv", ip_address="192.0.2.30")
        self.client.post("/account/logout/")
        User.objects.create_user("ro", "ro@example.com", PASSWORD, role=User.Role.READONLY)
        self.client.post("/account/login/", {"username": "ro", "password": PASSWORD})
        self.assertEqual(self.client.post(f"/hosts/{host.pk}/tags/", {"new_tags": "Alpha"}).status_code, 403)


class ExportTests(ImportTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.upload()
        scan_import = ScanImport.objects.latest("pk")
        self.confirm(scan_import, extra={"new_tags": "Alpha"})
        self.alpha = Tag.objects.get(name="Alpha")

    def test_vulnerability_export_follows_the_filters(self):
        response = self.client.get(f"/vulnerabilities/export.csv?tag={self.alpha.pk}&severity=critical")
        self.assertEqual(response["Content-Type"], "text/csv; charset=utf-8")
        self.assertIn('attachment; filename="pvm-vulnerabilities_', response["Content-Disposition"])
        rows = read_csv(response)
        self.assertEqual(rows[0][:3], ["Priority", "Priority Score", "Severity"])
        expected = VulnerabilityFinding.objects.exclude(status="resolved").filter(vulnerability_definition__severity="critical").count()
        self.assertEqual(len(rows) - 1, expected)
        self.assertTrue(all(r[2] == "Critical" and r[13] == "Alpha" for r in rows[1:]))
        self.assertTrue(AuditLog.objects.filter(action="export.findings").exists())

    def test_host_export(self):
        rows = read_csv(self.client.get(f"/hosts/export.csv?tag={self.alpha.pk}"))
        self.assertEqual(rows[0][:5], ["Hostname", "IP Address", "Private IP", "Server", "Tags"])
        self.assertEqual(len(rows) - 1, Host.objects.filter(tags=self.alpha).count())

    def test_formula_cells_are_neutralised(self):
        Host.objects.update(hostname="=HYPERLINK(\"http://evil\")")
        rows = read_csv(self.client.get("/hosts/export.csv"))
        self.assertTrue(rows[1][0].startswith("'="))

    def test_readonly_can_export(self):
        self.client.post("/account/logout/")
        User.objects.create_user("ro", "ro@example.com", PASSWORD, role=User.Role.READONLY)
        self.client.post("/account/login/", {"username": "ro", "password": PASSWORD})
        self.assertEqual(self.client.get("/vulnerabilities/export.csv").status_code, 200)

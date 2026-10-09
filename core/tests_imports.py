import csv
import shutil
import tempfile
from datetime import timedelta
from decimal import Decimal
from pathlib import Path

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.utils import timezone
from django_otp.plugins.otp_totp.models import TOTPDevice

from accounts.models import User
from accounts.tests import current_code
from pvm.celery import app as celery_app

from .importers import qualys_csv
from .models import AuditLog, Cve, Host, Perimeter, ScanImport, VulnerabilityDefinition, VulnerabilityFinding

FIXTURE = Path(__file__).parent / "fixtures" / "qualys_scan_report.csv"
PASSWORD = "correct-horse-battery"
Status = VulnerabilityFinding.Status


class ReaderTests(TestCase):
    def test_analyze_skips_preamble_and_counts_virtual_hosts(self):
        info = qualys_csv.analyze(FIXTURE)
        self.assertEqual(info["columns"][:3], ["IP", "DNS", "NetBIOS"])
        self.assertEqual(info["rows"], 9)
        self.assertEqual(info["ip_count"], 2)
        # portal + api share 192.0.2.10; 192.0.2.20 has no DNS name.
        self.assertEqual(info["host_count"], 3)
        self.assertEqual(info["types"], {"Vuln": 7, "Practice": 1, "Ig": 1})

    def test_tab_separated_export_reads_the_same(self):
        folder = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, folder)
        with open(FIXTURE, newline="") as src, open(folder / "report.csv", "w", newline="") as dst:
            csv.writer(dst, delimiter="\t").writerows(csv.reader(src))
        self.assertEqual(qualys_csv.analyze(folder / "report.csv")["rows"], 9)

    def test_suggested_mapping(self):
        mapping = qualys_csv.suggest_mapping(qualys_csv.analyze(FIXTURE)["columns"])
        self.assertEqual(mapping["IP"], "host.ip")
        self.assertEqual(mapping["Results"], "finding.result")
        self.assertEqual(mapping["Impact"], qualys_csv.EXTRA)
        self.assertEqual(qualys_csv.validate_mapping(mapping, list(mapping)), [])

    def test_mapping_without_required_field_is_rejected(self):
        mapping = qualys_csv.suggest_mapping(qualys_csv.analyze(FIXTURE)["columns"])
        mapping["QID"] = qualys_csv.DONT_IMPORT
        self.assertTrue(qualys_csv.validate_mapping(mapping, list(mapping)))

    def test_cvss_parsing(self):
        self.assertEqual(qualys_csv._leading_number("7.5 (AV:N/AC:L)"), "7.5")
        self.assertEqual(qualys_csv._leading_number("n/a"), "")


class ImportTestMixin:
    """Temp storage folders, eager Celery and a verified analyst session."""

    def setUp(self):
        self.imports_root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.imports_root)
        self.backup_root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.backup_root)
        # NVD_ENABLED off: tests never reach the internet (see core.tests_nvd).
        override = override_settings(
            SCAN_IMPORTS_ROOT=self.imports_root,
            BACKUP_ROOT=self.backup_root,
            NVD_ENABLED=False,
            UBUNTU_TRACKER_ENABLED=False,
            KEV_ENABLED=False,
            EPSS_ENABLED=False,
        )
        override.enable()
        self.addCleanup(override.disable)
        celery_app.conf.task_always_eager = True
        self.addCleanup(setattr, celery_app.conf, "task_always_eager", False)

        self.analyst = User.objects.create_user("ana", "ana@example.com", PASSWORD, role=User.Role.ANALYST)
        self._login_verified(self.analyst)

    def _login_verified(self, user):
        device = TOTPDevice.objects.create(user=user, name="test", confirmed=True)
        self.client.post("/account/login/", {"username": user.username, "password": PASSWORD})
        self.client.post("/account/mfa/verify/", {"token": current_code(device)})

    def upload(self, content=None, scan_date=None, name="report.csv"):
        content = FIXTURE.read_bytes() if content is None else content
        return self.client.post(
            "/imports/new/",
            {
                "report": SimpleUploadedFile(name, content, content_type="text/csv"),
                "scan_date": (scan_date or timezone.localdate()).isoformat(),
            },
        )

    def confirm(self, scan_import, overrides=None, perimeter="internal", extra=None):
        columns = scan_import.summary["file"]["columns"]
        mapping = qualys_csv.suggest_mapping(columns)
        mapping.update(overrides or {})
        data = {f"col-{i}": mapping[c] for i, c in enumerate(columns)}
        if perimeter:
            data["perimeter"] = perimeter
        data.update(extra or {})
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(f"/imports/{scan_import.pk}/columns/", data)
        scan_import.refresh_from_db()
        return response

    def full_import(self, content=None, scan_date=None, overrides=None, perimeter="internal"):
        self.upload(content, scan_date)
        scan_import = ScanImport.objects.latest("pk")
        self.confirm(scan_import, overrides, perimeter)
        return scan_import


class ImportFlowTests(ImportTestMixin, TestCase):

    def test_upload_archives_file_and_shows_columns(self):
        response = self.upload()
        scan_import = ScanImport.objects.get()
        self.assertRedirects(response, f"/imports/{scan_import.pk}/columns/")
        self.assertTrue(Path(scan_import.raw_file_path).is_file())
        self.assertTrue(scan_import.raw_file_path.startswith(self.imports_root))

        page = self.client.get(f"/imports/{scan_import.pk}/columns/")
        self.assertContains(page, "Associated Malware")
        self.assertContains(page, "host.ip")

    def test_import_creates_hosts_and_findings(self):
        scan_import = self.full_import(overrides={"Category": qualys_csv.DONT_IMPORT})
        self.assertEqual(scan_import.status, ScanImport.Status.COMPLETED, scan_import.error_message)

        # Two virtual hosts on one IP stay two hosts; the no-DNS host is named by IP.
        self.assertEqual(
            sorted(Host.objects.values_list("hostname", flat=True)),
            ["192.0.2.20", "api.example.test", "portal.example.test"],
        )
        portal = Host.objects.get(hostname="portal.example.test")
        self.assertTrue(portal.os_name.startswith("EulerOS"))
        self.assertIsNone(portal.qualys_host_id)
        self.assertEqual(scan_import.hosts.count(), 3)

        # 9 rows: 1 information-gathered row skipped, 2 rows merged into one finding.
        self.assertEqual(VulnerabilityFinding.objects.count(), 7)
        self.assertEqual(scan_import.summary["skipped"], {"Information Gathered": 1})
        self.assertEqual(scan_import.summary["result"]["findings_new"], 7)

        cert = VulnerabilityFinding.objects.get(host__hostname="api.example.test", vulnerability_definition__qid="38170")
        self.assertEqual(cert.service_port, "465/tcp")
        self.assertIn("Certificate #0", cert.detection_result)
        self.assertIn("Certificate #1", cert.detection_result)
        self.assertEqual(cert.extra_data["SSL"], "over ssl")
        self.assertNotIn("Category", cert.extra_data)

        qualys = dict(VulnerabilityDefinition.objects.values_list("qid", "qualys_severity"))
        self.assertEqual(qualys, {"86729": 2, "38909": 2, "38170": 2, "38739": 3, "150440": 5, "11": 4})
        severities = dict(VulnerabilityDefinition.objects.values_list("qid", "severity"))
        self.assertEqual(severities["150440"], "critical")
        self.assertEqual(severities["11"], "high")
        self.assertEqual(severities["38739"], "medium")
        self.assertEqual(severities["38909"], "low")
        terrapin = VulnerabilityDefinition.objects.get(qid="38739")
        self.assertEqual(sorted(terrapin.cves.values_list("cve_id", flat=True)), ["CVE-2023-48795", "CVE-2023-51385"])

        self.assertTrue(AuditLog.objects.filter(action="import.completed").exists())
        detail = self.client.get(f"/imports/{scan_import.pk}/")
        self.assertContains(detail, "New Findings")

    def test_reimport_resolves_missing_and_reopens_returning(self):
        old = timezone.localdate() - timedelta(days=14)
        mid = timezone.localdate() - timedelta(days=7)
        self.full_import(scan_date=old)

        # A host that is not in the report: its findings must never be touched.
        other = Host.objects.create(hostname="elsewhere", ip_address="198.51.100.5")
        untouched = VulnerabilityFinding.objects.create(
            host=other,
            perimeter=Perimeter.objects.get(slug="internal"),
            vulnerability_definition=VulnerabilityDefinition.objects.get(qid="38909"),
            first_detected_at=timezone.now() - timedelta(days=30),
            last_detected_at=timezone.now() - timedelta(days=30),
        )

        # Second scan: the SSH finding on api.example.test is gone.
        row = '192.0.2.10,api.example.test,,,"host scanned, found vuln",'
        without = FIXTURE.read_text().replace(row + "38909", row + "99999")
        second = self.full_import(content=without.encode(), scan_date=mid)
        ssh_api = VulnerabilityFinding.objects.get(host__hostname="api.example.test", vulnerability_definition__qid="38909")
        self.assertEqual(ssh_api.status, Status.RESOLVED)
        self.assertEqual(second.summary["result"]["findings_resolved"], 1)
        self.assertEqual(
            VulnerabilityFinding.objects.get(host__hostname="portal.example.test", vulnerability_definition__qid="38909").status,
            Status.STILL_OPEN,
        )
        untouched.refresh_from_db()
        self.assertEqual(untouched.status, Status.NEW)

        # Third scan: it is back, so it needs review.
        third = self.full_import(scan_date=timezone.localdate())
        ssh_api.refresh_from_db()
        self.assertEqual(ssh_api.status, Status.NEEDS_REVIEW)
        self.assertIsNone(ssh_api.resolved_at)
        self.assertEqual(third.summary["result"]["findings_reopened"], 1)

    def test_older_report_does_not_resolve_newer_findings(self):
        self.full_import(scan_date=timezone.localdate())
        without = FIXTURE.read_text().replace(",150440,", ",150441,")
        self.full_import(content=without.encode(), scan_date=timezone.localdate() - timedelta(days=30))
        log4j = VulnerabilityFinding.objects.get(vulnerability_definition__qid="150440")
        self.assertNotEqual(log4j.status, Status.RESOLVED)

    def test_missing_required_column_keeps_import_pending(self):
        self.upload()
        scan_import = ScanImport.objects.get()
        response = self.confirm(scan_import, {"QID": qualys_csv.DONT_IMPORT})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "QID")
        self.assertEqual(scan_import.status, ScanImport.Status.PENDING)

    def test_file_without_header_fails_cleanly(self):
        self.upload(content=b"just,some,text\n1,2,3\n")
        scan_import = ScanImport.objects.get()
        self.assertEqual(scan_import.status, ScanImport.Status.FAILED)
        self.assertIn("Header", scan_import.error_message)

    def test_discard_removes_file_and_import(self):
        self.upload()
        scan_import = ScanImport.objects.get()
        path = Path(scan_import.raw_file_path)
        self.client.post(f"/imports/{scan_import.pk}/discard/")
        self.assertFalse(ScanImport.objects.exists())
        self.assertFalse(path.exists())

    def test_stop_ends_a_running_import_and_writes_nothing(self):
        """The task is alive: it sees the flag at its next step and rolls back."""
        from .importers import pipeline
        from .tasks import process_scan_import

        self.upload()
        scan_import = ScanImport.objects.get()
        ScanImport.objects.filter(pk=scan_import.pk).update(status=ScanImport.Status.PARSING)
        # The Stop button, while the worker holds the import.
        response = self.client.post(f"/imports/{scan_import.pk}/stop/")
        self.assertRedirects(response, f"/imports/{scan_import.pk}/")
        scan_import.refresh_from_db()
        self.assertEqual(scan_import.status, ScanImport.Status.FAILED)
        self.assertIn("Stopped by ana", scan_import.error_message)
        self.assertTrue(scan_import.stop_requested)
        self.assertTrue(AuditLog.objects.filter(action="import.stopped").exists())
        # The task then runs (or resumes): it stops without importing anything.
        columns = scan_import.summary["file"]["columns"]
        ScanImport.objects.filter(pk=scan_import.pk).update(
            column_mapping=qualys_csv.suggest_mapping(columns), perimeter=Perimeter.objects.get(slug="internal")
        )
        process_scan_import(scan_import.pk)
        scan_import.refresh_from_db()
        self.assertEqual(scan_import.status, ScanImport.Status.FAILED)
        self.assertEqual(Host.objects.count(), 0)
        self.assertEqual(VulnerabilityFinding.objects.count(), 0)
        self.assertFalse(scan_import.stop_requested)  # cleared once the task has stopped
        self.assertTrue(issubclass(pipeline.Stopped, Exception))

    def test_stop_rolls_back_what_the_pipeline_had_written(self):
        from .importers import pipeline

        scan_import = ScanImport.objects.create(source="manual", perimeter=Perimeter.objects.get(slug="internal"))
        detections = [
            qualys_csv.Detection(
                ip="192.0.2.10", hostname="portal.example.test", qualys_host_id="", os="", qid="1",
                title="t", severity="low", qualys_severity=1
            )
        ]
        with self.assertRaises(pipeline.Stopped):
            pipeline.run(scan_import, detections, {}, should_stop=lambda: True)
        self.assertEqual(Host.objects.count(), 0)
        scan_import.refresh_from_db()
        self.assertNotEqual(scan_import.status, ScanImport.Status.COMPLETED)

    def test_stop_is_refused_for_an_import_that_is_not_running(self):
        scan_import = self.full_import()
        self.assertEqual(self.client.post(f"/imports/{scan_import.pk}/stop/").status_code, 404)
        scan_import.refresh_from_db()
        self.assertEqual(scan_import.status, ScanImport.Status.COMPLETED)

    def test_stop_button_shows_only_while_an_import_runs(self):
        self.upload()
        scan_import = ScanImport.objects.get()
        ScanImport.objects.filter(pk=scan_import.pk).update(status=ScanImport.Status.DOWNLOADING)
        self.assertContains(self.client.get(f"/imports/{scan_import.pk}/"), "Stop Import")
        self.assertContains(self.client.get("/imports/"), f"/imports/{scan_import.pk}/stop/")
        ScanImport.objects.filter(pk=scan_import.pk).update(status=ScanImport.Status.COMPLETED)
        self.assertNotContains(self.client.get("/imports/"), f"/imports/{scan_import.pk}/stop/")

    def test_previous_column_choices_are_remembered(self):
        self.full_import(overrides={"Impact": qualys_csv.DONT_IMPORT})
        self.upload()
        page = self.client.get(f"/imports/{ScanImport.objects.latest('pk').pk}/columns/")
        impact_row = next(r for r in page.context["rows"] if r["name"] == "Impact")
        self.assertEqual(impact_row["value"], qualys_csv.DONT_IMPORT)

    def test_superuser_can_import_whatever_the_role(self):
        self.client.post("/account/logout/")
        root = User.objects.create_superuser("root", "root@example.com", PASSWORD)
        User.objects.filter(pk=root.pk).update(role=User.Role.READONLY)
        self._login_verified(root)
        self.assertEqual(self.client.get("/imports/new/").status_code, 200)
        self.assertContains(self.client.get("/imports/"), "Import Report")

    def test_readonly_cannot_import(self):
        self.client.post("/account/logout/")
        User.objects.create_user("ro", "ro@example.com", PASSWORD, role=User.Role.READONLY)
        self.client.post("/account/login/", {"username": "ro", "password": PASSWORD})
        self.assertEqual(self.client.get("/imports/new/").status_code, 403)
        self.assertEqual(self.client.get("/imports/").status_code, 200)


class PerimeterTests(ImportTestMixin, TestCase):
    def finding(self, perimeter, host="api.example.test", qid="38909"):
        return VulnerabilityFinding.objects.get(
            host__hostname=host, vulnerability_definition__qid=qid, perimeter__slug=perimeter
        )

    def test_perimeter_is_required(self):
        self.upload()
        scan_import = ScanImport.objects.get()
        response = self.confirm(scan_import, perimeter=None)
        self.assertContains(response, "Choose the Perimeter")
        self.assertEqual(scan_import.status, ScanImport.Status.PENDING)

    def test_mapping_page_hints_from_ip_addresses(self):
        self.upload()
        page = self.client.get(f"/imports/{ScanImport.objects.get().pk}/columns/")
        # The fixture only uses documentation (non-public) addresses.
        self.assertContains(page, "Looks Like an <strong>Internal</strong> Scan", html=False)
        self.assertContains(page, 'name="perimeter" value="external"')

    def test_same_detection_from_two_perimeters_is_two_findings(self):
        self.full_import(perimeter="internal")
        self.full_import(perimeter="external")
        self.assertEqual(VulnerabilityFinding.objects.count(), 14)
        self.assertEqual(Host.objects.count(), 3)
        self.assertEqual(self.finding("internal").status, Status.NEW)
        self.assertEqual(self.finding("external").status, Status.NEW)

    def test_external_scan_never_resolves_internal_findings(self):
        self.full_import(perimeter="internal", scan_date=timezone.localdate() - timedelta(days=7))
        # The external scanner does not see SSH on api.example.test.
        row = '192.0.2.10,api.example.test,,,"host scanned, found vuln",'
        without_ssh = FIXTURE.read_text().replace(row + "38909", row + "99999")
        external = self.full_import(content=without_ssh.encode(), perimeter="external")

        self.assertEqual(external.summary["result"]["findings_resolved"], 0)
        self.assertEqual(self.finding("internal").status, Status.NEW)
        self.assertFalse(VulnerabilityFinding.objects.filter(
            host__hostname="api.example.test", vulnerability_definition__qid="38909", perimeter__slug="external"
        ).exists())

        # The next internal scan without it does resolve the internal one.
        self.full_import(content=without_ssh.encode(), perimeter="internal")
        self.assertEqual(self.finding("internal").status, Status.RESOLVED)

    def test_filters_by_perimeter(self):
        self.full_import(perimeter="internal", scan_date=timezone.localdate() - timedelta(days=1))
        row = '192.0.2.10,api.example.test,,,"host scanned, found vuln",'
        self.full_import(content=FIXTURE.read_text().replace(row + "38909", row + "99999").encode(), perimeter="external")

        page = self.client.get("/vulnerabilities/?perimeter=external&status=all").context["page"]
        self.assertEqual({f.perimeter.slug for f in page.object_list}, {"external"})
        self.assertEqual(page.paginator.count, 7)

        dashboard = self.client.get("/?perimeter=external").context
        self.assertEqual(dashboard["perimeter"].slug, "external")
        self.assertEqual(dashboard["scan_count"], 1)
        self.assertEqual(self.client.get("/imports/?perimeter=internal").context["page"].paginator.count, 1)

        hosts = self.client.get("/hosts/?perimeter=external").context["hosts"]
        self.assertEqual(len(hosts), 3)

    def test_all_perimeters_trend_sums_latest_scan_of_each(self):
        self.full_import(perimeter="internal", scan_date=timezone.localdate() - timedelta(days=1))
        self.full_import(perimeter="external")
        context = self.client.get("/").context
        low = next(k for k in context["severity_kpis"] if k["severity"] == "low")
        # Internal scan alone: 4 low findings; then internal + external: 8.
        self.assertEqual(low["series"], [4, 8])


class SeverityColumnsTests(ImportTestMixin, TestCase):
    def test_list_shows_and_filters_qualys_level_and_nvd_cvss(self):
        self.full_import()
        Cve.objects.filter(cve_id="CVE-2021-44228").update(
            cvss_score=Decimal("10.0"), cvss_version="3.1", cvss_severity="CRITICAL", nvd_status="ok"
        )
        page = self.client.get("/vulnerabilities/?status=all")
        self.assertContains(page, 'class="qlevel q5"')
        self.assertContains(page, "10.0")
        self.assertContains(page, "Urgent")

        found = self.client.get("/vulnerabilities/?status=all&qualys=5").context["page"].object_list
        self.assertEqual({f.vulnerability_definition.qid for f in found}, {"150440"})
        found = self.client.get("/vulnerabilities/?status=all&cvss=9").context["page"].object_list
        self.assertEqual({f.vulnerability_definition.qid for f in found}, {"150440"})
        # Terrapin's two CVEs are not scored yet, the rest have no CVE.
        found = self.client.get("/vulnerabilities/?status=all&cvss=none").context["page"]
        self.assertEqual(found.paginator.count, 6)


class ImportNameTests(ImportTestMixin, TestCase):
    def test_name_given_at_upload_shows_in_the_history(self):
        self.client.post(
            "/imports/new/",
            {
                "report": SimpleUploadedFile("report.csv", FIXTURE.read_bytes(), content_type="text/csv"),
                "scan_date": timezone.localdate().isoformat(),
                "name": "  Internal Alpha ",
            },
        )
        scan_import = ScanImport.objects.get()
        self.assertEqual(scan_import.name, "Internal Alpha")
        self.assertEqual(scan_import.label, "Internal Alpha")
        self.confirm(scan_import)

        self.assertContains(self.client.get("/imports/"), "Internal Alpha")
        self.assertContains(self.client.get(f"/imports/{scan_import.pk}/"), "Internal Alpha")
        self.assertContains(self.client.get("/"), "Internal Alpha")
        page = self.client.get(f"/vulnerabilities/?import={scan_import.pk}&status=all")
        self.assertContains(page, "Internal Alpha Only")

    def test_name_is_optional_and_can_be_changed_later(self):
        scan_import = self.full_import()
        self.assertEqual(scan_import.name, "")
        self.assertEqual(scan_import.label, f"Import #{scan_import.pk}")

        self.client.post(f"/imports/{scan_import.pk}/rename/", {"name": "External Weekly"})
        scan_import.refresh_from_db()
        self.assertEqual(scan_import.name, "External Weekly")
        self.assertTrue(AuditLog.objects.filter(action="import.renamed").exists())

    def test_search_by_name_or_file(self):
        first = self.full_import()
        ScanImport.objects.filter(pk=first.pk).update(name="Internal Alpha")
        second = self.full_import()
        ScanImport.objects.filter(pk=second.pk).update(name="External Weekly", original_filename="ext.csv")
        found = [i.pk for i in self.client.get("/imports/?q=alpha").context["page"].object_list]
        self.assertEqual(found, [first.pk])
        found = [i.pk for i in self.client.get("/imports/?q=ext.csv").context["page"].object_list]
        self.assertEqual(found, [second.pk])

    def test_history_sorts_on_any_column(self):
        first = self.full_import()
        ScanImport.objects.filter(pk=first.pk).update(name="Zeta", findings_count=2)
        second = self.full_import()
        ScanImport.objects.filter(pk=second.pk).update(name="Alpha", findings_count=9)

        def order(query):
            return [i.pk for i in self.client.get("/imports/" + query).context["page"].object_list]

        self.assertEqual(order(""), [second.pk, first.pk])  # newest first
        self.assertEqual(order("?sort=name&dir=asc"), [second.pk, first.pk])
        self.assertEqual(order("?sort=name&dir=desc"), [first.pk, second.pk])
        self.assertEqual(order("?sort=findings"), [second.pk, first.pk])
        self.assertEqual(order("?sort=findings&dir=asc"), [first.pk, second.pk])
        self.assertEqual(order("?sort=number&dir=asc"), [first.pk, second.pk])
        self.assertEqual(order("?sort=nope"), order(""))

        page = self.client.get("/imports/?q=a&sort=findings&dir=asc")
        self.assertContains(page, 'aria-sort="ascending"')
        self.assertContains(page, 'name="sort" value="findings"')
        # The header links keep the search and flip only the active column.
        urls = {h["label"]: h["url"] for h in page.context["headers"]}
        self.assertEqual(urls["Findings"], "?q=a&sort=findings&dir=desc")
        self.assertEqual(urls["Name"], "?q=a&sort=name&dir=asc")

    def test_sorting_goes_back_to_the_first_page(self):
        self.full_import()
        headers = self.client.get("/imports/?page=2&sort=name").context["headers"]
        self.assertTrue(all("page=" not in h["url"] for h in headers))

    def test_pre_import_backup_is_listed_with_the_name(self):
        from backups.models import Backup

        scan_import = self.full_import()
        ScanImport.objects.filter(pk=scan_import.pk).update(name="Internal Alpha")
        self.client.post("/account/logout/")
        boss = User.objects.create_user("boss", "boss@example.com", PASSWORD, role=User.Role.SUPER_ADMIN)
        self._login_verified(boss)
        self.assertTrue(Backup.objects.filter(kind="pre_import", scan_import_id=scan_import.pk).exists())
        self.assertContains(self.client.get("/backups/"), "Internal Alpha")

    def test_readonly_cannot_rename(self):
        scan_import = self.full_import()
        self.client.post("/account/logout/")
        User.objects.create_user("ro", "ro@example.com", PASSWORD, role=User.Role.READONLY)
        self.client.post("/account/login/", {"username": "ro", "password": PASSWORD})
        self.assertEqual(self.client.post(f"/imports/{scan_import.pk}/rename/", {"name": "x"}).status_code, 403)

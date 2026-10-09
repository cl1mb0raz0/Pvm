import json
from datetime import datetime, time, timedelta
from datetime import timezone as dt_timezone
from unittest import mock

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone

from accounts.models import User

from . import qualys
from .importers import qualys_csv
from .models import AuditLog, Host, Perimeter, QualysImportRule, ScanImport, Tag, VulnerabilityFinding
from .tasks import run_qualys_rules
from .tests_imports import PASSWORD, ImportTestMixin

LIST_XML = b"""<?xml version="1.0" encoding="UTF-8" ?>
<SCAN_LIST_OUTPUT><RESPONSE><DATETIME>2026-09-25T08:00:00Z</DATETIME><SCAN_LIST>
<SCAN><REF>scan/1001.1</REF><TYPE>Scheduled</TYPE><TITLE><![CDATA[Internal Alpha]]></TITLE><USER_LOGIN>svc</USER_LOGIN>
  <LAUNCH_DATETIME>2026-09-22T08:51:16Z</LAUNCH_DATETIME><DURATION>01:39:27</DURATION><PROCESSED>1</PROCESSED>
  <STATUS><STATE>Finished</STATE></STATUS><TARGET><![CDATA[10.0.4.10-10.0.4.20, 10.0.6.11]]></TARGET>
  <OPTION_PROFILE><TITLE><![CDATA[Initial Options]]></TITLE><DEFAULT_FLAG>0</DEFAULT_FLAG></OPTION_PROFILE></SCAN>
<SCAN><REF>scan/1000.1</REF><TYPE>Scheduled</TYPE><TITLE><![CDATA[Internal Alpha]]></TITLE><USER_LOGIN>svc</USER_LOGIN>
  <LAUNCH_DATETIME>2026-09-15T08:51:16Z</LAUNCH_DATETIME><DURATION>01:30:00</DURATION><PROCESSED>1</PROCESSED>
  <STATUS><STATE>Finished</STATE></STATUS><TARGET><![CDATA[10.0.4.10-10.0.4.20]]></TARGET></SCAN>
<SCAN><REF>scan/2001.1</REF><TYPE>Scheduled</TYPE><TITLE><![CDATA[External Weekly]]></TITLE><USER_LOGIN>svc</USER_LOGIN>
  <LAUNCH_DATETIME>2026-09-21T01:02:16Z</LAUNCH_DATETIME><DURATION>00:51:58</DURATION><PROCESSED>1</PROCESSED>
  <STATUS><STATE>Finished</STATE></STATUS><TARGET><![CDATA[www.example.test, vpn.example.test]]></TARGET>
  <ASSET_GROUP_TITLE_LIST><ASSET_GROUP_TITLE><![CDATA[Public HQ]]></ASSET_GROUP_TITLE></ASSET_GROUP_TITLE_LIST></SCAN>
</SCAN_LIST></RESPONSE></SCAN_LIST_OUTPUT>"""


def scan_results(scanner="QualysScanner01 : 10.0.4.10-10.0.4.20", rows=None):
    header = [
        {"scan_title": "Internal Alpha", "reference": "scan/1001.1", "scanner_appliance": "QualysScanner01 (Scanner 15.3)",
         "active_hosts": "2", "total_hosts": "11", "target_distribution_across_scanner_appliances": scanner},
    ]
    rows = rows if rows is not None else [
        {"ip": "10.0.4.11", "dns": "web-a.example.test", "netbios": "None", "os": "Ubuntu/Linux", "ip_status": "host scanned, found vuln",
         "qid": "38909", "title": "OpenSSH regreSSHion", "type": "Vuln", "severity": "5", "port": "22", "protocol": "tcp",
         "fqdn": "", "ssl": "no", "cve_id": "CVE-2024-6387", "vendor_reference": "None", "bugtraq_id": "None",
         "cvss_base": "7.5 (AV:N/AC:L)", "cvss_temporal": "None", "cvss3_base": "8.1 (AV:N/AC:H)", "cvss3_temporal": "None",
         "threat": "A race condition.", "impact": "Remote code execution.", "solution": "Upgrade OpenSSH.",
         "exploitability": "None", "associated_malware": "None", "results": "SSH-2.0-OpenSSH_9.6p1", "pci_vuln": "yes",
         "instance": "None", "category": "General remote services"},
        {"ip": "10.0.4.12", "dns": "db-a.example.test", "netbios": "DBA", "os": "Windows 2019", "ip_status": "host scanned",
         "qid": "45038", "title": "Host Scan Time", "type": "Ig", "severity": "1", "port": "", "protocol": "",
         "cve_id": "None", "results": "Scan duration: 300 seconds"},
        {"ip": "10.0.4.12", "dns": "db-a.example.test", "netbios": "DBA", "os": "Windows 2019", "ip_status": "host scanned, found vuln",
         "qid": "38173", "title": "SSL Certificate - Signature Verification Failed", "type": "Practice", "severity": "2",
         "port": "443", "protocol": "tcp", "cve_id": "None", "cvss3_base": "None", "cvss_base": "4.3 (AV:N)", "results": "Certificate #0"},
    ]
    data = header + rows
    return header[0], rows, json.dumps(data).encode()


class ClientTests(TestCase):
    def test_perimeter_from_targets(self):
        self.assertEqual(qualys.perimeter_from_targets("10.0.4.10-10.0.4.20, 192.168.1.5"), "internal")
        self.assertEqual(qualys.perimeter_from_targets("www.example.test, vpn.example.test"), "external")
        self.assertEqual(qualys.perimeter_from_targets("10.0.0.1, www.example.test"), "")
        self.assertEqual(qualys.perimeter_from_header({"target_distribution_across_scanner_appliances": "External : 198.51.100.8"}), "external")
        self.assertEqual(qualys.perimeter_from_header({"target_distribution_across_scanner_appliances": "QualysScanner01 : 10.0.0.1"}), "internal")

    @override_settings(QUALYS_API_URL="https://qualysapi.example.test", QUALYS_USERNAME="u", QUALYS_PASSWORD="p")
    def test_list_scans(self):
        with mock.patch("core.qualys._get", return_value=LIST_XML) as get:
            scans = qualys.list_scans(30)
        self.assertEqual(get.call_args[0][1]["state"], "Finished")
        self.assertEqual([s["ref"] for s in scans], ["scan/1001.1", "scan/2001.1", "scan/1000.1"])
        first = scans[0]
        self.assertEqual((first["title"], first["perimeter_guess"], first["target_count"]), ("Internal Alpha", "internal", 2))
        self.assertEqual(first["targets"], "10.0.4.10-10.0.4.20, 10.0.6.11")
        self.assertEqual(scans[1]["asset_groups"], ["Public HQ"])
        self.assertEqual(scans[1]["perimeter_guess"], "external")

    @override_settings(QUALYS_API_URL="https://qualysapi.example.test", QUALYS_USERNAME="u", QUALYS_PASSWORD="p")
    def test_excluded_titles_are_never_listed(self):
        extra = (
            b"<SCAN><REF>scan/3001.1</REF><TYPE>Scheduled</TYPE><TITLE><![CDATA[Connector-CPS-123-Daily]]></TITLE>"
            b"<LAUNCH_DATETIME>2026-09-24T22:15:44Z</LAUNCH_DATETIME><STATUS><STATE>Finished</STATE></STATUS>"
            b"<TARGET>www.example.test</TARGET></SCAN></SCAN_LIST>"
        )
        with mock.patch("core.qualys._get", return_value=LIST_XML.replace(b"</SCAN_LIST>", extra)):
            with override_settings(QUALYS_EXCLUDED_TITLE_PREFIXES=["connector-cps"]):
                self.assertNotIn("scan/3001.1", [s["ref"] for s in qualys.list_scans(30)])
            with override_settings(QUALYS_EXCLUDED_TITLE_PREFIXES=[]):
                self.assertIn("scan/3001.1", [s["ref"] for s in qualys.list_scans(30)])

    def test_matching_targets(self):
        targets = "10.0.4.10-10.0.4.20, 10.0.6.11, 192.168.5.0/24, www.example.test"
        self.assertEqual(qualys.matching_targets(targets, "10.0.4.11"), ["10.0.4.10-10.0.4.20"])
        self.assertEqual(qualys.matching_targets(targets, "10.0.4.20"), ["10.0.4.10-10.0.4.20"])
        self.assertEqual(qualys.matching_targets(targets, "10.0.4.21"), [])
        self.assertEqual(qualys.matching_targets(targets, "10.0.6.11"), ["10.0.6.11"])
        self.assertEqual(qualys.matching_targets(targets, "192.168.5.77"), ["192.168.5.0/24"])
        self.assertEqual(qualys.matching_targets(targets, "10.0.4."), ["10.0.4.10-10.0.4.20"])  # part of an address: text
        self.assertEqual(qualys.matching_targets(targets, "WWW.example"), ["www.example.test"])
        self.assertEqual(qualys.matching_targets("10.0.4.10-20", "10.0.4.15"), ["10.0.4.10-20"])  # Qualys' short range
        self.assertEqual(qualys.matching_targets("", "10.0.4.11"), [])
        self.assertEqual(qualys.matching_targets(targets, "  "), [])

    @override_settings(QUALYS_API_URL="")
    def test_not_configured(self):
        with self.assertRaisesMessage(qualys.QualysError, "Not Configured"):
            qualys.list_scans()

    def test_json_results_read_like_a_csv_export(self):
        _, rows, _ = scan_results()
        path = self._write(qualys.rows_to_csv(rows))
        info = qualys_csv.analyze(path)
        mapping = qualys_csv.suggest_mapping(info["columns"])
        self.assertEqual(mapping["CVSS3.1 Base"], "vuln.cvss")
        self.assertEqual(qualys_csv.validate_mapping(mapping, info["columns"]), [])
        detections, skipped = qualys_csv.read_detections(path, mapping)
        self.assertEqual(skipped["Information Gathered"], 1)
        ssh = next(d for d in detections if d.qid == "38909")
        self.assertEqual((ssh.cvss, ssh.cves, ssh.service_port, ssh.hostname), ("8.1", ["CVE-2024-6387"], "22/tcp", "web-a.example.test"))
        cert = next(d for d in detections if d.qid == "38173")
        # "None" strings are empty; the CVSS 3.1 column is the mapped one, empty here.
        self.assertEqual((cert.cves, cert.cvss), ([], ""))

    def _write(self, text):
        import tempfile
        from pathlib import Path

        folder = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, folder)
        path = Path(folder) / "scan.csv"
        path.write_text(text)
        return path


class ScheduleTests(TestCase):
    def rule(self, **kw):
        return QualysImportRule(scan_title="x", at_time=time(8, 0), **kw)

    @override_settings(SCHEDULE_TIME_ZONE="Europe/Rome")
    def test_weekly(self):
        # Wednesday 2026-09-23 10:00 in Rome (08:00 UTC): next Monday 08:00 Rome = 06:00 UTC.
        after = datetime(2026, 9, 23, 8, 0, tzinfo=dt_timezone.utc)
        nxt = qualys.next_run(self.rule(frequency="weekly", weekday=0), after)
        self.assertEqual(nxt, datetime(2026, 9, 28, 6, 0, tzinfo=dt_timezone.utc))
        # The same day, before the time: today.
        monday_early = datetime(2026, 9, 28, 5, 0, tzinfo=dt_timezone.utc)
        self.assertEqual(qualys.next_run(self.rule(frequency="weekly", weekday=0), monday_early), datetime(2026, 9, 28, 6, 0, tzinfo=dt_timezone.utc))

    @override_settings(SCHEDULE_TIME_ZONE="Europe/Rome")
    def test_monthly_across_the_daylight_saving_change(self):
        after = datetime(2026, 10, 2, 12, 0, tzinfo=dt_timezone.utc)
        nxt = qualys.next_run(self.rule(frequency="monthly", day_of_month=1), after)
        self.assertEqual(nxt, datetime(2026, 11, 1, 7, 0, tzinfo=dt_timezone.utc))  # 08:00 CET


@override_settings(QUALYS_API_URL="https://qualysapi.example.test", QUALYS_USERNAME="u", QUALYS_PASSWORD="p")
class PageTests(ImportTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        cache.clear()
        self.admin = User.objects.create_user("adm", "adm@example.com", PASSWORD, role=User.Role.ADMIN)
        self.client.post("/account/logout/")
        self._login_verified(self.admin)
        for target, kwargs in [("core.qualys._get", {"return_value": LIST_XML}), ("core.qualys.fetch_scan", {"return_value": scan_results()})]:
            patcher = mock.patch(target, **kwargs)
            setattr(self, target.rsplit(".", 1)[1], patcher.start())
            self.addCleanup(patcher.stop)
        self.client.get("/imports/qualys/?refresh=1")  # the page asks Qualys only on request

    def post(self, url, data=None):
        with self.captureOnCommitCallbacks(execute=True):
            return self.client.post(url, data or {})

    def test_list_marks_imported_scans(self):
        page = self.client.get("/imports/qualys/")
        self.assertContains(page, "Internal Alpha")
        self.assertContains(page, "External Weekly")
        self.assertContains(page, "?ref=scan/2001.1")
        self.assertContains(page, "Import Automatically")

    def test_list_sorts_on_any_column(self):
        def order(query):
            return [s["ref"] for s in self.client.get("/imports/qualys/" + query).context["scans"]]

        self.assertEqual(order(""), ["scan/1001.1", "scan/2001.1", "scan/1000.1"])  # newest first
        # Equal titles stay newest first, in both directions.
        self.assertEqual(order("?sort=scan&dir=asc"), ["scan/2001.1", "scan/1001.1", "scan/1000.1"])
        self.assertEqual(order("?sort=scan&dir=desc"), ["scan/1001.1", "scan/1000.1", "scan/2001.1"])
        self.assertEqual(order("?sort=duration&dir=asc"), ["scan/2001.1", "scan/1000.1", "scan/1001.1"])
        self.assertEqual(order("?sort=targets"), ["scan/1001.1", "scan/2001.1", "scan/1000.1"])
        self.assertEqual(order("?sort=nope"), order(""))

        page = self.client.get("/imports/qualys/?q=Alpha&days=90&sort=duration&refresh=1")
        self.assertContains(page, 'aria-sort="descending"')
        self.assertContains(page, 'name="sort" value="duration"')
        # Header links keep the search and the period, flip the active column, never re-ask Qualys.
        urls = {h["label"]: h["url"] for h in page.context["headers"]}
        self.assertEqual(urls["Duration"], "?q=Alpha&days=90&sort=duration&dir=asc")
        self.assertEqual(urls["Scan"], "?q=Alpha&days=90&sort=scan&dir=asc")

    def test_the_page_asks_qualys_only_when_asked(self):
        cache.clear()
        self._get.reset_mock()
        page = self.client.get("/imports/qualys/")
        self.assertContains(page, "Pvm Has Not Asked Qualys Yet")
        self.assertNotContains(page, "scan/1001.1")  # no list at all (the placeholder names a scan)
        self.assertEqual(self._get.call_count, 0)
        # Searching, sorting and changing the period do not ask either.
        self.client.get("/imports/qualys/?q=Alpha&days=90&sort=scan")
        self.assertEqual(self._get.call_count, 0)
        # The button does, once; the list is then kept for the next pages.
        self.assertContains(self.client.get("/imports/qualys/?refresh=1"), "Internal Alpha")
        self.assertEqual(self._get.call_count, 1)
        self.assertContains(self.client.get("/imports/qualys/?q=Alpha"), "Internal Alpha")
        self.assertEqual(self._get.call_count, 1)

    def test_a_failed_refresh_keeps_the_list_already_in_hand(self):
        self._get.side_effect = qualys.QualysError("Qualys Unreachable (Is Cato Connected on the VM?)")
        page = self.client.get("/imports/qualys/?refresh=1")
        self.assertContains(page, "Qualys Could Not Be Reached.")
        self.assertContains(page, "Internal Alpha")

    def test_search_finds_a_scan_by_target_or_asset_group(self):
        def refs(query):
            return [s["ref"] for s in self.client.get("/imports/qualys/?q=" + query).context["scans"]]

        self.assertEqual(refs("Alpha"), ["scan/1001.1", "scan/1000.1"])  # the title, as before
        self.assertEqual(refs("10.0.4.11"), ["scan/1001.1", "scan/1000.1"])  # inside both ranges
        self.assertEqual(refs("10.0.6.11"), ["scan/1001.1"])
        self.assertEqual(refs("vpn.example.test"), ["scan/2001.1"])
        self.assertEqual(refs("Public HQ"), ["scan/2001.1"])  # the asset group
        self.assertEqual(refs("10.0.9.9"), [])
        page = self.client.get("/imports/qualys/?q=10.0.4.11")
        self.assertContains(page, "Target: 10.0.4.10-10.0.4.20")  # why the row answered
        self.assertEqual(self._get.call_count, 1)  # the setUp call, nothing since

    def test_manual_import_end_to_end(self):
        page = self.client.get("/imports/qualys/import/?ref=scan/1001.1")
        self.assertContains(page, 'value="internal" checked')
        response = self.post("/imports/qualys/import/", {"ref": "scan/1001.1", "name": "Internal Alpha", "perimeter": "internal", "new_tags": "Alpha"})
        scan_import = ScanImport.objects.get(qualys_scan_ref="scan/1001.1")
        self.assertRedirects(response, f"/imports/{scan_import.pk}/", fetch_redirect_response=False)
        self.fetch_scan.assert_called_once_with("scan/1001.1")
        self.assertEqual(scan_import.status, ScanImport.Status.COMPLETED, scan_import.error_message)
        self.assertEqual(scan_import.source, ScanImport.Source.QUALYS)
        self.assertEqual(scan_import.scanned_at, datetime(2026, 9, 22, 8, 51, 16, tzinfo=dt_timezone.utc))
        self.assertEqual(VulnerabilityFinding.objects.filter(perimeter__slug="internal").count(), 2)
        self.assertEqual(Host.objects.filter(tags__name="Alpha").count(), 2)
        self.assertEqual(scan_import.summary["qualys"]["detected_perimeter"], "internal")
        self.assertTrue(scan_import.raw_file_path.endswith("qualys_scan.csv"))
        self.assertTrue(AuditLog.objects.filter(action="import.qualys_started").exists())
        # Listed as imported, and never imported twice.
        self.assertContains(self.client.get("/imports/qualys/"), f"Import #{scan_import.pk}")
        self.post("/imports/qualys/import/", {"ref": "scan/1001.1", "perimeter": "internal"})
        self.assertEqual(ScanImport.objects.filter(qualys_scan_ref="scan/1001.1").count(), 1)
        self.assertEqual(self.fetch_scan.call_count, 1)

    def test_wrong_perimeter_is_flagged(self):
        self.fetch_scan.return_value = scan_results(scanner="External : 198.51.100.8")
        self.post("/imports/qualys/import/", {"ref": "scan/1001.1", "perimeter": "internal"})
        scan_import = ScanImport.objects.get(qualys_scan_ref="scan/1001.1")
        self.assertIn("External Scanner", scan_import.summary["qualys"]["perimeter_warning"])
        self.assertContains(self.client.get(f"/imports/{scan_import.pk}/"), "Check the Perimeter.")

    def test_qualys_failure_marks_the_import_failed(self):
        self.fetch_scan.side_effect = qualys.QualysError("Qualys Unreachable (Is Cato Connected on the VM?)")
        self.post("/imports/qualys/import/", {"ref": "scan/1001.1", "perimeter": "internal"})
        scan_import = ScanImport.objects.get(qualys_scan_ref="scan/1001.1")
        self.assertEqual(scan_import.status, ScanImport.Status.FAILED)
        self.assertIn("Cato", scan_import.error_message)

    def test_rule_create_and_run(self):
        self.post("/imports/qualys/rules/new/", {"scan_title": "Internal Alpha", "frequency": "weekly", "weekday": "0", "day_of_month": "1", "at_time": "08:00", "perimeter": "internal", "new_tags": "Alpha"})
        rule = QualysImportRule.objects.get(scan_title="Internal Alpha")
        self.assertTrue(rule.enabled)
        self.assertGreater(rule.next_run_at, timezone.now())
        self.assertEqual([t.name for t in rule.tags.all()], ["Alpha"])
        self.assertContains(self.client.get("/imports/qualys/"), "Every Monday at 08:00")

        # Not due yet: nothing happens.
        self.assertEqual(run_qualys_rules(), 0)
        # Due: the latest run (22 Sep, not the 15 Sep one) is imported, by the rule.
        QualysImportRule.objects.update(next_run_at=timezone.now() - timedelta(minutes=1))
        with self.captureOnCommitCallbacks(execute=True):
            run_qualys_rules()
        scan_import = ScanImport.objects.get(qualys_scan_ref="scan/1001.1")
        self.assertEqual((scan_import.source, scan_import.rule, scan_import.status), (ScanImport.Source.API, rule, ScanImport.Status.COMPLETED))
        self.assertEqual([t.name for t in scan_import.tags.all()], ["Alpha"])
        rule.refresh_from_db()
        self.assertIn(f"Import #{scan_import.pk} Started", rule.last_result)
        self.assertGreater(rule.next_run_at, timezone.now())
        # Next time, nothing new.
        QualysImportRule.objects.update(next_run_at=timezone.now() - timedelta(minutes=1))
        with self.captureOnCommitCallbacks(execute=True):
            run_qualys_rules()
        rule.refresh_from_db()
        self.assertIn("Nothing New", rule.last_result)
        self.assertEqual(ScanImport.objects.count(), 1)

    def test_rule_with_qualys_down_waits_for_next_time(self):
        rule = QualysImportRule.objects.create(scan_title="Internal Alpha", at_time=time(8), perimeter=Perimeter.objects.get(slug="internal"), next_run_at=timezone.now() - timedelta(minutes=1))
        self._get.side_effect = qualys.QualysError("Qualys Unreachable")
        run_qualys_rules()
        rule.refresh_from_db()
        self.assertTrue(rule.last_result.startswith("Failed: Qualys Unreachable"))
        self.assertGreater(rule.next_run_at, timezone.now())
        self.assertFalse(ScanImport.objects.exists())

    def test_pause_resume_delete(self):
        rule = QualysImportRule.objects.create(scan_title="Internal Alpha", at_time=time(8), perimeter=Perimeter.objects.get(slug="internal"), next_run_at=timezone.now() - timedelta(minutes=1))
        self.post(f"/imports/qualys/rules/{rule.pk}/toggle/")
        rule.refresh_from_db()
        self.assertFalse(rule.enabled)
        self.assertEqual(run_qualys_rules(), 0)  # paused rules never run
        self.post(f"/imports/qualys/rules/{rule.pk}/delete/")
        self.assertFalse(QualysImportRule.objects.exists())

    def test_invalid_rule_is_refused(self):
        self.post("/imports/qualys/rules/new/", {"scan_title": "Internal Alpha", "frequency": "monthly", "weekday": "0", "day_of_month": "31", "at_time": "8", "perimeter": "internal"})
        self.assertFalse(QualysImportRule.objects.exists())

    def test_analyst_imports_but_cannot_create_rules(self):
        self.client.post("/account/logout/")
        self._login_verified(User.objects.get(username="ana"))
        self.assertEqual(self.client.get("/imports/qualys/rules/new/?title=Internal+Alpha").status_code, 403)
        self.assertNotContains(self.client.get("/imports/qualys/"), "Import Automatically")
        self.post("/imports/qualys/import/", {"ref": "scan/2001.1", "perimeter": "external"})
        self.assertTrue(ScanImport.objects.filter(qualys_scan_ref="scan/2001.1").exists())

    def test_readonly_has_no_access(self):
        self.client.post("/account/logout/")
        User.objects.create_user("ro", "ro@example.com", PASSWORD, role=User.Role.READONLY)
        self.client.post("/account/login/", {"username": "ro", "password": PASSWORD})
        self.assertEqual(self.client.get("/imports/qualys/").status_code, 403)
        self.assertNotContains(self.client.get("/imports/"), "Qualys Scans")


class NotConfiguredTests(ImportTestMixin, TestCase):
    @override_settings(QUALYS_API_URL="", QUALYS_USERNAME="", QUALYS_PASSWORD="")
    def test_page_explains(self):
        self.assertContains(self.client.get("/imports/qualys/"), "The Qualys API Is Not Configured.")

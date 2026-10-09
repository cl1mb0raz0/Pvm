import re

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase

from accounts.models import User
from backups.models import Backup

from . import network_mapping
from .importers import pipeline
from .importers.qualys_csv import Detection
from .models import AuditLog, Host, LoadBalancer, Perimeter, PrivateIpMapping, ScanImport
from .tests_imports import PASSWORD, ImportTestMixin

CSV = (
    "Public Ip;Dns Hostnamwe;Private Ip\n"  # the header as the user might type it (typo in "Hostname")
    "198.51.100.10;shop.example.test;10.0.5.20\n"
    "198.51.100.10;blog.example.test;10.0.5.21\n"
    "198.51.100.11;;10.0.5.30\n"
    "198.51.100.12;future.example.test;10.0.5.40\n"
    "not-an-ip;x.example.test;10.0.5.50\n"
)
GOOD_CSV = CSV.replace("Dns Hostnamwe", "DNS Hostname")


class ParseTests(TestCase):
    def test_parse_with_any_case_and_separator(self):
        rows, has_hostname = network_mapping.parse(GOOD_CSV.replace(";", ",").encode())
        self.assertTrue(has_hostname)
        self.assertEqual(len(rows), 5)
        self.assertEqual(rows[0], {"line": 2, "public_ip": "198.51.100.10", "hostname": "shop.example.test", "private_ip": "10.0.5.20", "error": ""})
        self.assertEqual(rows[2]["hostname"], "")
        self.assertIn("Invalid Public IP", rows[4]["error"])

    def test_missing_columns(self):
        with self.assertRaisesMessage(network_mapping.MappingError, "Column Not Found: Private IP"):
            network_mapping.parse(b"Public IP,Hostname\n198.51.100.10,a.example.test\n")

    def test_unknown_column_names_are_recognized_from_content(self):
        # "Dns Hostnamwe" is not a known name, but the column holds host names.
        table = network_mapping.parse_table(CSV.encode())
        self.assertTrue(table["has_hostname"])
        self.assertEqual(table["rows"][0]["hostname"], "shop.example.test")
        self.assertIn(("Dns Hostnamwe", "DNS Hostname", True), table["columns"])

    def test_no_header_at_all(self):
        table = network_mapping.parse_table(b"198.51.100.10,shop.example.test,10.0.5.20\n198.51.100.11,,10.0.5.30\n")
        self.assertEqual(len(table["rows"]), 2)
        self.assertEqual(table["rows"][0], {"line": 1, "public_ip": "198.51.100.10", "hostname": "shop.example.test", "private_ip": "10.0.5.20", "error": ""})
        self.assertEqual([role for _, role, _ in table["columns"]], ["Public IP", "DNS Hostname", "Private IP"])

    def test_hostname_column_is_optional(self):
        rows, has_hostname = network_mapping.parse(b"Public IP;Private IP\n198.51.100.11;10.0.5.30\n")
        self.assertFalse(has_hostname)
        self.assertEqual(rows[0]["hostname"], "")


class FlowTests(ImportTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.shop = Host.objects.create(hostname="shop.example.test", ip_address="198.51.100.10")
        self.blog = Host.objects.create(hostname="blog.example.test", ip_address="198.51.100.10", private_ip="10.0.9.9")
        self.other = Host.objects.create(hostname="other.example.test", ip_address="198.51.100.10")
        self.single = Host.objects.create(hostname="api.example.test", ip_address="198.51.100.11")

    def upload(self, text=GOOD_CSV):
        return self.client.post("/imports/mapping/upload/", {"file": SimpleUploadedFile("map.csv", text.encode(), content_type="text/csv")})

    def test_preview_changes_nothing_then_apply(self):
        page = self.upload()
        self.assertContains(page, "Private IP Set")
        self.assertContains(page, "Private IP Changed")
        self.assertContains(page, "No Host Yet (Kept)")
        self.assertContains(page, "Invalid")
        self.assertContains(page, "Apply to 3 Hosts")
        self.shop.refresh_from_db()
        self.assertIsNone(self.shop.private_ip)
        self.assertFalse(PrivateIpMapping.objects.exists())

        payload = re.search(r'name="payload" value="([^"]+)"', page.content.decode()).group(1)
        self.client.post("/imports/mapping/apply/", {"payload": payload, "filename": "map.csv", "mark_balancer": "1", "balancer_name": "A10"})
        for host, expected in ((self.shop, "10.0.5.20"), (self.blog, "10.0.5.21"), (self.single, "10.0.5.30"), (self.other, None)):
            host.refresh_from_db()
            self.assertEqual(host.private_ip, expected, host.hostname)
        self.assertEqual(PrivateIpMapping.objects.count(), 4)  # the invalid row is not kept
        self.assertEqual(set(LoadBalancer.objects.values_list("ip_address", flat=True)), {"198.51.100.10", "198.51.100.11", "198.51.100.12"})
        log = AuditLog.objects.get(action="network.mapping_applied")
        self.assertEqual((log.details["hosts_changed"], log.details["rows"]), (3, 4))

    def test_hosts_that_appear_later_get_their_private_ip(self):
        page = self.upload()
        payload = re.search(r'name="payload" value="([^"]+)"', page.content.decode()).group(1)
        self.client.post("/imports/mapping/apply/", {"payload": payload})
        scan_import = ScanImport.objects.create(source="manual", perimeter=Perimeter.objects.get(slug="external"))
        detection = Detection(ip="198.51.100.12", hostname="future.example.test", qualys_host_id="", os="", qid="1", title="t", severity="low", qualys_severity=1)
        pipeline.run(scan_import, [detection], {})
        self.assertEqual(Host.objects.get(hostname="future.example.test").private_ip, "10.0.5.40")

    def test_analysis_explains_the_columns(self):
        page = self.upload(CSV)
        self.assertContains(page, "Public to Private IP Mapping")
        self.assertContains(page, "Column “Dns Hostnamwe” → DNS Hostname (Recognized from Its Content).")
        self.assertContains(page, "Useful: 3 Hosts Get Their Private IP.")
        page = self.upload("Public IP;Private IP\n198.51.100.11;10.0.5.30\n")
        self.assertContains(page, "No DNS Hostname Column: Rows Match Only Public IPs with a Single Host.")

    def test_nothing_new_the_second_time(self):
        page = self.upload()
        self.client.post("/imports/mapping/apply/", {"payload": re.search(r'name="payload" value="([^"]+)"', page.content.decode()).group(1)})
        self.assertContains(self.upload(), "Nothing New: Every Row Is Already in Pvm.")

    def test_apply_takes_a_backup_first(self):
        page = self.upload()
        payload = re.search(r'name="payload" value="([^"]+)"', page.content.decode()).group(1)
        self.client.post("/imports/mapping/apply/", {"payload": payload, "filename": "map.csv"})
        backup = Backup.objects.get(kind=Backup.Kind.PRE_MAPPING)
        self.assertIn("map.csv", backup.note)

    def test_altered_preview_is_refused(self):
        self.client.post("/imports/mapping/apply/", {"payload": "forged"})
        self.assertFalse(PrivateIpMapping.objects.exists())

    def test_clear(self):
        PrivateIpMapping.objects.create(public_ip="198.51.100.10", hostname="", private_ip="10.0.0.1")
        self.client.post("/imports/mapping/clear/")
        self.assertFalse(PrivateIpMapping.objects.exists())

    def test_readonly_has_no_access(self):
        self.client.post("/account/logout/")
        User.objects.create_user("ro", "ro@example.com", PASSWORD, role=User.Role.READONLY)
        self.client.post("/account/login/", {"username": "ro", "password": PASSWORD})
        self.assertEqual(self.client.get("/imports/mapping/").status_code, 403)
        self.assertEqual(self.upload().status_code, 403)

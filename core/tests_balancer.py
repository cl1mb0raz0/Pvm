import re

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase

from backups.models import Backup

from . import balancer, csam, mapping
from .importers import pipeline
from .importers.qualys_csv import Detection
from .models import AuditLog, BalancerConfig, BalancerRoute, Host, LoadBalancer, Perimeter, PrivateIpMapping, ScanImport
from .tests_imports import ImportTestMixin

# Shaped like a real ACOS 4.1 running configuration (addresses and names invented).
CONFIG = """!Current configuration: 60690 bytes
!Configuration last updated at 14:36:12 CEST Tue Jul 28 2026
!64-bit Advanced Core OS (ACOS) version 4.1.4-GR1-P9, build 69 (Nov-23-2021,01:49)
!
vrrp-a common
  device-id 1
  enable
!
hostname lb-01
!
ldap-server host 192.0.2.50 domain example.lan port 636 ssl timeout 3
!
slb template server-ssl SSL-template-server
  version 33 33
!
slb server 10.20.2.23 10.20.2.23
  port 443 tcp
    template server-ssl SSL-template-server
  port 8582 tcp
!
slb server 10.20.2.24 10.20.2.24
  port 443 tcp
!
slb server AKS 10.30.25.54
  health-check-disable
  port 80 tcp
!
slb server ftp01 10.20.3.10
  port 22 tcp
!
slb server Client-app templ-test2 10.40.3.10
  port 8080 tcp
!
slb service-group web_443 tcp
  method least-connection
  member 10.20.2.23 443
  member 10.20.2.24 443
!
slb service-group AKS_80 tcp
  member AKS 80
!
slb service-group ftp_22 tcp
  member ftp01 22
!
slb service-group app_8080 tcp
  member Client-app templ-test2 8080
!
slb service-group ghost_80 tcp
  member missing-server 80
!
slb virtual-server DNS-GSLB 10.20.250.130
  port 53 dns-udp
    gslb-enable
!
slb virtual-server VIP-BO-01 10.20.250.121
  port 22 tcp
    source-nat pool snat_10.20.250.122
    service-group ftp_22
  port 8443 https
    service-group AKS_80
    template http http_template_8443
!
slb virtual-server VIP-AKS 10.20.250.140
  port 80 http
    service-group AKS_80
    aflex redirect-https
!
 slb template http http_template_8443
  host-switching contains shop.example.test service-group web_443
  host-switching equals api.shop.example.test service-group AKS_80
  host-switching starts-with nobody service-group web_443
!
slb template http unused_template
  host-switching ends-with .intranet.test service-group AKS_80
!
"""


class ParseTests(TestCase):
    def test_recognized_and_read(self):
        parsed = balancer.parse_acos(CONFIG)
        self.assertEqual(parsed["name"], "A10 lb-01")
        self.assertEqual(parsed["product"], "A10 ACOS 4.1.4-GR1-P9")
        self.assertEqual(parsed["counts"]["servers"], 5)
        self.assertEqual(parsed["counts"]["service_groups"], 5)
        self.assertEqual(parsed["counts"]["vips"], 3)
        self.assertEqual(parsed["counts"]["rules"], 4)
        routes = {(r["vip_name"], r["port"], r["pattern"]): r for r in parsed["routes"]}
        self.assertEqual(routes[("VIP-BO-01", "22/tcp", "")]["backend_ips"], ["10.20.3.10"])
        self.assertEqual(routes[("VIP-BO-01", "8443/https", "shop.example.test")]["backend_ips"], ["10.20.2.23", "10.20.2.24"])
        # A rule of a template no VIP uses is kept without a VIP.
        self.assertEqual(routes[("", "", ".intranet.test")]["vip_ip"], None)
        # The DNS VIP has no pool: no route.
        self.assertFalse(any(r["vip_name"] == "DNS-GSLB" for r in parsed["routes"]))
        warnings = " ".join(parsed["warnings"])
        self.assertIn("aFleX", warnings)
        self.assertNotIn("missing-server", warnings)  # the pool nobody uses is not a problem
        self.assertEqual(routes[("VIP-AKS", "80/http", "")]["backend_ips"], ["10.30.25.54"])

    def test_servers_are_kept_by_address(self):
        servers = balancer.parse_acos(CONFIG)["servers"]
        self.assertEqual(servers["10.30.25.54"], "AKS")
        self.assertEqual(servers["10.20.3.10"], "ftp01")
        self.assertEqual(servers["10.40.3.10"], "Client-app templ-test2")
        # A server declared by its address is its own name.
        self.assertEqual(servers["10.20.2.23"], "10.20.2.23")

    def test_server_name_with_spaces(self):
        parsed = balancer.parse_acos(CONFIG + "slb virtual-server VIP-APP 10.20.250.150\n  port 8080 tcp\n    service-group app_8080\n!\n")
        route = next(r for r in parsed["routes"] if r["vip_name"] == "VIP-APP")
        self.assertEqual(route["backend_ips"], ["10.40.3.10"])

    def test_header_only_is_recognized_but_not_importable(self):
        # The first sample the user sent: header, HA and LDAP, no slb sections.
        reading = mapping.analyze(CONFIG[: CONFIG.index("slb template server-ssl")].encode())[0]
        self.assertEqual(reading.kind, "a10")
        self.assertEqual(reading.confidence, 99)
        self.assertFalse(reading.can_import)
        self.assertIn("Export the Whole Running Configuration", reading.problem)

    def test_resolver_prefers_the_most_specific_rule(self):
        resolver = balancer.Resolver(balancer.parse_acos(CONFIG)["routes"])
        exact = resolver.resolve("api.shop.example.test", "198.51.100.20")
        self.assertEqual((exact.how, exact.backends), ("name", ["10.30.25.54"]))
        self.assertEqual(resolver.resolve("shop.example.test", "198.51.100.20").backends, ["10.20.2.23", "10.20.2.24"])
        self.assertEqual(resolver.resolve("wiki.intranet.test", "10.9.9.9").backends, ["10.30.25.54"])
        scanned_on_vip = resolver.resolve("vip-bo-01.example.lan", "10.20.250.121")
        self.assertEqual((scanned_on_vip.how, scanned_on_vip.backends), ("vip", ["10.20.3.10", "10.30.25.54"]))
        via = resolver.resolve("files.example.test", "198.51.100.30", "10.20.250.121")
        self.assertEqual(via.how, "via")
        self.assertIsNone(resolver.resolve("unrelated.example.test", "198.51.100.40"))
        # A server of the pool is not behind itself.
        self.assertIsNone(resolver.resolve("shop.example.test", "10.20.2.23"))


class AnalyzeTests(TestCase):
    def test_qualys_report_is_sent_to_new_import(self):
        with open("core/fixtures/qualys_scan_report.csv", "rb") as f:
            reading = mapping.analyze(f.read())[0]
        self.assertEqual(reading.kind, "qualys_report")
        self.assertFalse(reading.can_import)

    def test_other_tables_are_described(self):
        reading = mapping.analyze(b"Owner;Server;Address\nops;web01.example.test;10.0.0.5\ndev;db01.example.test;10.0.0.6\n")[0]
        self.assertEqual(reading.kind, "table")
        self.assertFalse(reading.can_import)
        self.assertIn("Column “Address”: 2 Private IPs.", reading.reasons)
        self.assertIn("Column “Server”: 2 Host Names.", reading.reasons)

    def test_not_a_table(self):
        reading = mapping.analyze(b"hello\n")[0]
        self.assertEqual(reading.kind, "unknown")


class FlowTests(ImportTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.shop = Host.objects.create(hostname="shop.example.test", ip_address="198.51.100.20")
        self.api = Host.objects.create(hostname="api.shop.example.test", ip_address="198.51.100.20", private_ip="10.0.9.9")
        self.vip = Host.objects.create(hostname="vip-bo-01.example.lan", ip_address="10.20.250.121")
        self.backend = Host.objects.create(hostname="web01.example.lan", ip_address="10.20.2.23")
        self.other = Host.objects.create(hostname="other.example.test", ip_address="198.51.100.40")

    def upload(self, text=CONFIG, name="lb-01.txt"):
        return self.client.post("/imports/mapping/upload/", {"file": SimpleUploadedFile(name, text.encode(), content_type="text/plain")})

    def apply(self, page, **extra):
        payload = re.search(r'name="payload" value="([^"]+)"', page.content.decode()).group(1)
        return self.client.post("/imports/mapping/apply/", {"payload": payload, "filename": "lb-01.txt", **extra})

    def test_preview_then_apply(self):
        page = self.upload()
        self.assertContains(page, "A10 Load Balancer Configuration")
        self.assertContains(page, "99% Certain")
        self.assertContains(page, "A10 Advanced Core OS (ACOS) 4.1.4-GR1-P9")
        self.assertContains(page, "Useful: 3 Hosts Get Their Real Servers as Private IPs, 2 VIPs Marked as Load Balancer.")
        self.assertContains(page, "Name Rule “Contains shop.example.test” → Pool web_443 on VIP-BO-01 (10.20.250.121:8443/https)")
        self.assertContains(page, "Scanned on VIP VIP-BO-01 (10.20.250.121)")
        self.assertContains(page, "Name Rules Match No Pvm Host Yet (Kept)")
        self.assertContains(page, "aFleX")
        self.assertFalse(BalancerConfig.objects.exists())
        self.shop.refresh_from_db()
        self.assertIsNone(self.shop.private_ip)

        self.apply(page)
        self.shop.refresh_from_db()
        self.assertEqual(self.shop.all_private_ips, ["10.20.2.23", "10.20.2.24"])
        self.api.refresh_from_db()
        self.assertEqual(self.api.all_private_ips, ["10.30.25.54"])  # replaced the hand-typed one, as previewed
        self.vip.refresh_from_db()
        self.assertEqual(self.vip.all_private_ips, ["10.20.3.10", "10.30.25.54"])
        self.backend.refresh_from_db()
        self.assertEqual(self.backend.all_private_ips, [])
        self.assertEqual(LoadBalancer.objects.get(ip_address="10.20.250.121").name, "A10 VIP-BO-01")
        config = BalancerConfig.objects.get()
        self.assertEqual((config.name, config.filename), ("A10 lb-01", "lb-01.txt"))
        self.assertTrue(Backup.objects.filter(kind=Backup.Kind.PRE_MAPPING).exists())
        log = AuditLog.objects.get(action="mapping.balancer_applied")
        self.assertEqual((log.details["hosts_changed"], log.details["vips_marked"]), (3, 2))
        self.assertFalse(LoadBalancer.objects.filter(ip_address="10.20.250.130").exists())  # the DNS VIP leads nowhere

        # The same file again: nothing new.
        self.assertContains(self.upload(), "Nothing New: This Configuration Is Already in Pvm.")

    def test_server_names_show_on_the_hosts_list_and_in_the_export(self):
        self.apply(self.upload())
        config = BalancerConfig.objects.get()
        self.assertEqual(config.servers["10.20.3.10"], "ftp01")
        # vip-bo-01 is served by ftp01 and AKS; the list shows the first plus a count.
        page = self.client.get("/hosts/")
        self.assertContains(page, "Server")  # the column header
        self.assertContains(page, 'ftp01 <span class="muted" title="ftp01, AKS">+1</span>')
        self.assertContains(page, ">AKS<")  # api.shop.example.test, one server
        # The Network tab of that host names them too.
        self.assertContains(self.client.get(f"/hosts/{self.vip.pk}/?tab=network"), "ftp01, AKS")
        from .tests_tags import read_csv

        rows = read_csv(self.client.get("/hosts/export.csv"))
        self.assertEqual(rows[0][3], "Server")
        vip = next(r for r in rows if r[0] == "vip-bo-01.example.lan")
        self.assertEqual((vip[2], vip[3]), ("10.20.3.10, 10.30.25.54", "ftp01, AKS"))

    def test_hosts_of_later_scans_get_their_servers(self):
        self.apply(self.upload())
        scan_import = ScanImport.objects.create(source="manual", perimeter=Perimeter.objects.get(slug="external"))
        detection = Detection(ip="198.51.100.20", hostname="new.shop.example.test", qualys_host_id="", os="", qid="1", title="t", severity="low", qualys_severity=1)
        pipeline.run(scan_import, [detection], {})
        self.assertEqual(Host.objects.get(hostname="new.shop.example.test").all_private_ips, ["10.20.2.23", "10.20.2.24"])

    def test_csv_mapping_to_a_vip_leads_to_the_servers(self):
        self.apply(self.upload())
        page = self.upload("Public IP;DNS Hostname;Private IP\n198.51.100.40;other.example.test;10.20.250.121\n", "map.csv")
        self.assertContains(page, "Private IP Is VIP VIP-BO-01 (10.20.250.121)")
        self.apply(page)
        self.other.refresh_from_db()
        self.assertEqual(self.other.all_private_ips, ["10.20.3.10", "10.30.25.54"])
        self.assertEqual(PrivateIpMapping.objects.get().private_ip, "10.20.250.121")

    def test_network_tab_explains(self):
        self.apply(self.upload())
        page = self.client.get(f"/hosts/{self.shop.pk}/?tab=network")
        self.assertContains(page, "Reached Through the Load Balancer")
        self.assertContains(page, "10.20.2.23, 10.20.2.24")
        page = self.client.get(f"/hosts/{self.backend.pk}/?tab=network")
        self.assertContains(page, "Real Server Behind the Load Balancer")
        self.assertContains(page, "Published Externally as")
        self.assertContains(page, "shop.example.test")

    def test_several_private_ips_by_hand(self):
        self.client.post(f"/hosts/{self.other.pk}/network/", {"private_ip": "10.0.0.1, 10.0.0.2 10.0.0.1"})
        self.other.refresh_from_db()
        self.assertEqual(self.other.all_private_ips, ["10.0.0.1", "10.0.0.2"])
        self.assertContains(self.client.get("/hosts/"), "+1")
        self.client.post(f"/hosts/{self.other.pk}/network/", {"private_ip": ""})
        self.other.refresh_from_db()
        self.assertEqual(self.other.all_private_ips, [])
        self.assertFalse(self.other.other_private_ips.exists())

    def test_csam_matches_any_server_of_the_pool(self):
        self.shop.set_private_ips(["10.20.2.23", "10.20.2.24"])
        asset = {"assetId": 7, "address": "10.20.2.24", "assetName": "web02", "networkInterfaceListData": {"networkInterface": [{"addressIpV4": "10.20.2.24"}]}}
        hosts = list(Host.objects.filter(pk=self.shop.pk).prefetch_related("other_private_ips"))
        self.assertEqual([(h.pk, how) for h, _, how in csam.match(hosts, [asset])], [(self.shop.pk, "Private IP")])

    def test_delete_configuration(self):
        self.apply(self.upload())
        config = BalancerConfig.objects.get()
        self.client.post(f"/imports/mapping/balancers/{config.pk}/delete/")
        self.assertFalse(BalancerRoute.objects.exists())
        self.shop.refresh_from_db()
        self.assertEqual(self.shop.private_ip, "10.20.2.23")  # kept

from django.test import TestCase
from django.utils import timezone

from accounts.models import User

from .importers import pipeline
from .importers.qualys_csv import Detection
from .models import Host, LoadBalancer, Perimeter, ScanImport, VulnerabilityDefinition, VulnerabilityFinding
from .views import HOST_COLUMNS
from .tests_imports import ImportTestMixin


class NetworkTabTests(ImportTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.portal = Host.objects.create(hostname="portal.example.test", ip_address="203.0.113.10")
        self.api = Host.objects.create(hostname="api.example.test", ip_address="203.0.113.10")
        self.backend = Host.objects.create(hostname="web-01", ip_address="10.0.20.11")

    def save(self, host, **data):
        return self.client.post(f"/hosts/{host.pk}/network/", data)

    def test_private_ip_and_balancer(self):
        self.save(self.portal, private_ip="10.0.20.11", is_balancer="1", balancer_name="A10")
        self.portal.refresh_from_db()
        self.assertEqual(self.portal.private_ip, "10.0.20.11")
        self.assertEqual(LoadBalancer.objects.get().name, "A10")

        # The balancer is per IP: every host on it shows it in the list.
        hosts = {h.hostname: h for h in self.client.get("/hosts/").context["hosts"]}
        self.assertEqual(hosts["api.example.test"].balancer_name, "A10")
        self.assertIsNone(hosts["web-01"].balancer_name)
        self.assertContains(self.client.get("/hosts/"), "10.0.20.11")

        # Search by private IP.
        found = [h.hostname for h in self.client.get("/hosts/?q=10.0.20.11").context["hosts"]]
        self.assertEqual(sorted(found), ["portal.example.test", "web-01"])

        # Links both ways with the internal scan of that address.
        network = self.client.get(f"/hosts/{self.portal.pk}/?tab=network")
        self.assertEqual(list(network.context["internal_hosts"]), [self.backend])
        backend = self.client.get(f"/hosts/{self.backend.pk}/?tab=network")
        self.assertEqual(list(backend.context["published_as"]), [self.portal])

        # Unticking removes the balancer mark.
        self.save(self.api, private_ip="")
        self.assertFalse(LoadBalancer.objects.exists())

    def test_invalid_ip_is_rejected(self):
        response = self.save(self.portal, private_ip="10.0.20")
        self.portal.refresh_from_db()
        self.assertIsNone(self.portal.private_ip)
        self.assertIn("Not a Valid IP", [str(m) for m in response.wsgi_request._messages][0])

    def test_imports_never_touch_the_private_ip(self):
        self.save(self.portal, private_ip="10.0.20.11")
        scan = ScanImport.objects.create(
            source=ScanImport.Source.MANUAL,
            status=ScanImport.Status.PARSING,
            perimeter=Perimeter.objects.get(slug="external"),
            scanned_at=timezone.now(),
        )
        pipeline.run(scan, [Detection(
            ip="203.0.113.10", hostname="portal.example.test", qualys_host_id="", os="", qid="1",
            title="t", severity="low", qualys_severity=2,
        )], {})
        self.portal.refresh_from_db()
        self.assertEqual(self.portal.private_ip, "10.0.20.11")

    def test_readonly_can_view_not_edit(self):
        self.client.post("/account/logout/")
        User.objects.create_user("ro", "ro@example.com", "correct-horse-battery", role=User.Role.READONLY)
        self.client.post("/account/login/", {"username": "ro", "password": "correct-horse-battery"})
        self.assertEqual(self.client.get(f"/hosts/{self.portal.pk}/?tab=network").status_code, 200)
        self.assertEqual(self.save(self.portal, private_ip="10.0.0.1").status_code, 403)


class HostSortingTests(ImportTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        internal = Perimeter.objects.get(slug="internal")
        critical = VulnerabilityDefinition.objects.create(qid="1", title="c", severity="critical")
        now = timezone.now()
        self.alpha = Host.objects.create(hostname="alpha", ip_address="10.0.0.9", private_ip=None, os_version="Ubuntu 22.04")
        self.bravo = Host.objects.create(hostname="bravo", ip_address="10.0.0.10", private_ip="10.1.0.2", os_name="Linux")
        self.charlie = Host.objects.create(hostname="charlie", ip_address="10.0.0.2", private_ip="10.1.0.1", last_scanned_at=now)
        for host, n in ((self.bravo, 2), (self.charlie, 1)):
            for port in range(n):
                VulnerabilityFinding.objects.create(
                    host=host, vulnerability_definition=critical, service_port=str(port), perimeter=internal,
                    first_detected_at=now, last_detected_at=now,
                )
        LoadBalancer.objects.create(ip_address="10.0.0.10", name="A10")

    def order(self, query=""):
        return [h.hostname for h in self.client.get(f"/hosts/?{query}").context["hosts"]]

    def test_default_is_by_hostname(self):
        self.assertEqual(self.order(), ["alpha", "bravo", "charlie"])

    def test_numbers_start_from_the_highest(self):
        self.assertEqual(self.order("sort=critical"), ["bravo", "charlie", "alpha"])
        self.assertEqual(self.order("sort=critical&dir=asc"), ["alpha", "charlie", "bravo"])

    def test_empty_values_go_last_both_ways(self):
        self.assertEqual(self.order("sort=private_ip&dir=asc"), ["charlie", "bravo", "alpha"])
        self.assertEqual(self.order("sort=private_ip&dir=desc"), ["bravo", "charlie", "alpha"])
        self.assertEqual(self.order("sort=balancer")[0], "bravo")
        self.assertEqual(self.order("sort=last_scanned")[0], "charlie")

    def test_os_column_sorts_on_what_it_shows(self):
        self.assertEqual(self.order("sort=os"), ["bravo", "alpha", "charlie"])

    def test_every_column_sorts(self):
        for key, *_ in HOST_COLUMNS:
            for direction in ("asc", "desc"):
                self.assertEqual(len(self.order(f"sort={key}&dir={direction}")), 3, key)

    def test_headers_toggle_and_keep_filters(self):
        headers = self.client.get("/hosts/?q=a&sort=critical&dir=desc").context["headers"]
        critical = next(h for h in headers if h["label"] == "Critical")
        self.assertTrue(critical["active"])
        self.assertIn("dir=asc", critical["url"])
        self.assertIn("q=a", critical["url"])
        host = next(h for h in headers if h["label"] == "Host")
        self.assertIn("sort=host", host["url"])
        self.assertIn("dir=asc", host["url"])

    def test_unknown_sort_falls_back(self):
        self.assertEqual(self.order("sort=nonsense&dir=sideways"), ["alpha", "bravo", "charlie"])

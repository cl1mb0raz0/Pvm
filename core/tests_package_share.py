from django.test import TestCase
from django.utils import timezone

from accounts.models import User

from .models import AuditLog, Host, HostPrivateIp, InstalledPackage
from .tests_imports import PASSWORD, ImportTestMixin


def site(name, ip, *private):
    host = Host.objects.create(hostname=name, ip_address=ip)
    if private:
        host.set_private_ips(list(private))
    return host


class SharePackageTests(ImportTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.a = site("a.example.test", "203.0.113.1", "10.0.0.5")
        self.b = site("b.example.test", "203.0.113.1", "10.0.0.5")
        self.c = site("c.example.test", "203.0.113.2", "10.0.0.5")
        self.other_server = site("d.example.test", "203.0.113.3", "10.0.0.9")
        self.no_private = site("e.example.test", "203.0.113.4")
        self.tomcat = InstalledPackage.objects.create(
            host=self.a, package_name="tomcat", installed_version="9.0.80",
            source="manual", detected_at=timezone.now(),
        )

    def url(self, host=None, package=None):
        return f"/hosts/{(host or self.a).pk}/packages/{(package or self.tomcat).pk}/share/"

    def test_preview_lists_the_sites_on_the_same_server_and_writes_nothing(self):
        page = self.client.get(self.url())
        self.assertContains(page, "b.example.test")
        self.assertContains(page, "c.example.test")
        self.assertNotContains(page, "d.example.test")  # another server
        self.assertNotContains(page, "e.example.test")  # no private IP
        self.assertContains(page, "2</strong> Sites Found")
        self.assertContains(page, f'value="{self.b.pk}" checked')
        self.assertFalse(InstalledPackage.objects.filter(host=self.b).exists())

    def test_apply_copies_only_the_ticked_sites_as_manual_entries_and_audits_each(self):
        response = self.client.post(self.url(), {"host": [self.b.pk]})
        self.assertRedirects(response, f"/hosts/{self.a.pk}/?tab=packages")
        copy = InstalledPackage.objects.get(host=self.b)
        self.assertEqual((copy.package_name, copy.installed_version, copy.source), ("tomcat", "9.0.80", "manual"))
        self.assertEqual(copy.created_by, self.analyst)
        self.assertFalse(InstalledPackage.objects.filter(host=self.c).exists())
        log = AuditLog.objects.get(action="inventory.package_copied")
        self.assertEqual((log.entity_id, log.details["from_host"]), (str(self.b.pk), "a.example.test"))

    def test_a_host_the_preview_did_not_offer_cannot_be_written(self):
        self.client.post(self.url(), {"host": [self.other_server.pk, self.no_private.pk]})
        self.assertFalse(InstalledPackage.objects.filter(host__in=[self.other_server, self.no_private]).exists())
        self.assertFalse(AuditLog.objects.filter(action="inventory.package_copied").exists())

    def test_another_version_is_shown_and_not_ticked_for_you(self):
        InstalledPackage.objects.create(
            host=self.b, package_name="tomcat", installed_version="9.0.50",
            source="qualys_agent", detected_at=timezone.now(),
        )
        page = self.client.get(self.url())
        self.assertContains(page, "9.0.50")
        self.assertContains(page, "Would Be Replaced")
        self.assertNotContains(page, f'value="{self.b.pk}" checked')
        self.assertContains(page, f'value="{self.c.pk}" checked')
        # Ticking it by hand replaces the version.
        self.client.post(self.url(), {"host": [self.b.pk]})
        self.assertEqual(InstalledPackage.objects.get(host=self.b).installed_version, "9.0.80")

    def test_a_pool_with_several_servers_separates_full_and_partial_matches(self):
        self.a.set_private_ips(["10.0.0.5", "10.0.0.6"])
        self.b.set_private_ips(["10.0.0.5", "10.0.0.6"])  # the same pool
        # c still has only 10.0.0.5: shares some of the servers, not all.
        page = self.client.get(self.url())
        self.assertContains(page, "1 on the Same Server")
        self.assertContains(page, "1 Sharing Only Some of Its Servers")
        self.assertContains(page, f'value="{self.b.pk}" checked')
        self.assertNotContains(page, f'value="{self.c.pk}" checked')
        self.assertContains(page, "Only Some")

    def test_nothing_ticked_is_refused(self):
        response = self.client.post(self.url(), {})
        self.assertRedirects(response, self.url())
        self.assertFalse(InstalledPackage.objects.filter(host=self.b).exists())

    def test_a_host_without_a_private_ip_says_so(self):
        package = InstalledPackage.objects.create(
            host=self.no_private, package_name="tomcat", installed_version="9.0.80",
            source="manual", detected_at=timezone.now(),
        )
        self.assertContains(self.client.get(self.url(self.no_private, package)), "Has No Private IP")

    def test_saving_a_package_can_open_the_review_without_copying(self):
        response = self.client.post(
            f"/hosts/{self.a.pk}/packages/add/",
            {"package_name": "tomcat", "installed_version": "9.0.90", "review_siblings": "1"},
        )
        self.assertRedirects(response, self.url(), fetch_redirect_response=False)
        self.assertFalse(InstalledPackage.objects.filter(host=self.b).exists())

    def test_the_link_shows_on_the_packages_tab_and_read_only_cannot_use_it(self):
        self.assertContains(self.client.get(f"/hosts/{self.a.pk}/?tab=packages"), "Apply to Other Sites")
        reader = User.objects.create_user("rita", "rita@example.com", PASSWORD, role=User.Role.READONLY)
        self.client.logout()
        self._login_verified(reader)
        self.assertEqual(self.client.get(self.url()).status_code, 403)
        self.assertEqual(self.client.post(self.url(), {"host": [self.b.pk]}).status_code, 403)
        self.assertFalse(InstalledPackage.objects.filter(host=self.b).exists())

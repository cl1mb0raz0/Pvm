from unittest import mock

from django.test import TestCase, override_settings
from django.utils import timezone

from accounts.models import User

from . import csam
from .models import AuditLog, CsamProposal, CsamSearch, Host, InstalledPackage, Perimeter, Tag, VulnerabilityDefinition, VulnerabilityFinding
from .tests_imports import PASSWORD, ImportTestMixin

JAMMY = {"fullName": "Canonical Ubuntu Jammy Jellyfish (22.04.5 LTS)", "marketVersion": "Jammy Jellyfish", "version": "22.04 LTS"}


def asset(asset_id, address, name, os_info=None, agent=True, tags=(), extra_ips=()):
    return {
        "assetId": asset_id,
        "hostId": asset_id * 10,
        "address": address,
        "dnsName": name,
        "assetName": name.split(".")[0] if name else "",
        "operatingSystem": os_info or {},
        "inventory": {"source": "QAGENT" if agent else "IP"},
        "agent": {"lastCheckedIn": 1790319613000} if agent else None,
        "tagList": {"tag": [{"tagName": t} for t in tags]},
        "criticality": {"score": 3},
        "networkInterfaceListData": {"networkInterface": [{"addressIpV4": ip, "hostname": ""} for ip in extra_ips]},
    }


SOFTWARE = [
    {"discoveredName": "openssh-server", "discoveredVersion": "1:8.9p1-3ubuntu0.17"},
    {"discoveredName": "libc6:amd64", "discoveredVersion": "2.35-0ubuntu3.8"},
    {"discoveredName": "Some Windows App", "discoveredVersion": "10.0"},  # not a dpkg package
    {"discoveredName": "apache2", "discoveredVersion": "2.4.52-1ubuntu4.12"},
]

WINDOWS = {"fullName": "Microsoft Windows Server 2019 Standard"}

WINDOWS_SOFTWARE = [
    # Free-text name/version, unlike anything valid dpkg format: uppercase,
    # spaces, parentheses.
    {"discoveredName": "Microsoft Visual C++ 2015-2022 Redistributable (x64)", "discoveredVersion": "14.38.33135.0"},
    {"discoveredName": "7-Zip 23.01 (x64)", "discoveredVersion": "23.01.00.0"},
]


class ReadingTests(TestCase):
    def test_ubuntu_release(self):
        self.assertEqual(csam.ubuntu_release(JAMMY), "jammy")
        self.assertEqual(csam.ubuntu_release({"fullName": "Ubuntu Linux", "version": "24.04.1 LTS"}), "noble")
        self.assertEqual(csam.ubuntu_release({"fullName": "The CentOS Project CentOS 7.9 (2009)", "version": "7.9"}), "")

    def test_stale_entries_after_a_release_upgrade_are_ignored(self):
        now, old = "2026-09-25T04:51:49.000Z", "2025-05-30T03:56:14.000Z"
        entries = [
            {"discoveredName": "libc6:amd64", "discoveredVersion": "2.39-0ubuntu8.9", "lastUpdated": now},
            {"discoveredName": "libc6:amd64", "discoveredVersion": "2.31-0ubuntu9.17", "lastUpdated": old},
            {"discoveredName": "python3.8", "discoveredVersion": "3.8.10-0ubuntu1~20.04.18", "lastUpdated": old},
            {"discoveredName": "linux-image-5.4.0-212-generic", "discoveredVersion": "5.4.0-212.232", "lastUpdated": None},
            {"discoveredName": "openssh-server", "discoveredVersion": "1:9.6p1-3ubuntu13.19", "lastUpdated": "2026-09-25T04:50:00.000Z"},
        ]
        self.assertEqual(
            csam.packages_from_software(entries),
            [["libc6", "2.39-0ubuntu8.9"], ["openssh-server", "1:9.6p1-3ubuntu13.19"]],
        )

    def test_entries_without_a_date_are_kept_when_qualys_gives_almost_none(self):
        """Real shape of a Jammy server with the agent: 832 entries, one dated."""
        entries = [{"discoveredName": "openssh-server", "discoveredVersion": "1:8.9p1-3ubuntu0.17", "lastUpdated": None}]
        entries += [
            {"discoveredName": f"libtest{i}", "discoveredVersion": "1.2.3-4ubuntu0.1", "lastUpdated": None}
            for i in range(30)
        ]
        entries.append({"discoveredName": "apache2", "discoveredVersion": "2.4.52-1ubuntu4.12", "lastUpdated": "2026-09-25T04:51:49.000Z"})
        packages = csam.packages_from_software(entries)
        self.assertEqual(len(packages), 32)
        self.assertIn(["openssh-server", "1:8.9p1-3ubuntu0.17"], packages)
        self.assertIn(["apache2", "2.4.52-1ubuntu4.12"], packages)

    def test_packages_from_software(self):
        self.assertEqual(
            csam.packages_from_software(SOFTWARE),
            [["apache2", "2.4.52-1ubuntu4.12"], ["libc6", "2.35-0ubuntu3.8"], ["openssh-server", "1:8.9p1-3ubuntu0.17"]],
        )

    def test_windows_detected(self):
        self.assertTrue(csam.windows_detected(WINDOWS))
        self.assertTrue(csam.windows_detected({"fullName": "Microsoft Windows 10 Enterprise"}))
        self.assertFalse(csam.windows_detected(JAMMY))
        self.assertFalse(csam.windows_detected({}))

    def test_packages_from_software_windows(self):
        # Free-text names/versions are kept as-is: no dpkg format to check,
        # no ":architecture" suffix to strip.
        self.assertEqual(
            csam.packages_from_software(WINDOWS_SOFTWARE, strict=False),
            [["7-Zip 23.01 (x64)", "23.01.00.0"], ["Microsoft Visual C++ 2015-2022 Redistributable (x64)", "14.38.33135.0"]],
        )
        # The same entries are not dpkg packages, so the default (Ubuntu) mode finds none.
        self.assertEqual(csam.packages_from_software(WINDOWS_SOFTWARE), [])

    def test_matching(self):
        web = Host(pk=1, hostname="web-a.example.test", ip_address="10.0.4.11")
        by_ip_only = Host(pk=2, hostname="10.0.4.12", ip_address="10.0.4.12")
        # Two virtual hosts on one load-balancer address, one with its real server's private IP.
        vhost_a = Host(pk=3, hostname="shop.example.test", ip_address="192.0.2.80", private_ip="10.0.5.20")
        vhost_b = Host(pk=4, hostname="blog.example.test", ip_address="192.0.2.80")
        unknown = Host(pk=5, hostname="gone.example.test", ip_address="10.0.9.9")
        assets = [
            asset(101, "10.0.4.11", "web-a.example.test"),
            asset(102, "10.0.4.12", "db-a.example.test"),
            asset(103, "192.0.2.80", "a10-vip.example.test"),
            asset(104, "10.0.5.20", "shop-backend.example.test"),
        ]
        found = {h.pk: (a["assetId"], how) for h, a, how in csam.match([web, by_ip_only, vhost_a, vhost_b, unknown], assets)}
        self.assertEqual(found[1], (101, "IP and Name"))
        self.assertEqual(found[2], (102, "IP Only"))
        self.assertEqual(found[3], (104, "Private IP"))  # the real server, not the load balancer
        self.assertNotIn(4, found)  # a shared address is never enough on its own
        self.assertNotIn(5, found)


@override_settings(QUALYS_GATEWAY_URL="https://gateway.example.test", QUALYS_USERNAME="u", QUALYS_PASSWORD="p")
class FlowTests(ImportTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.web = Host.objects.create(hostname="web-a.example.test", ip_address="10.0.4.11")
        self.win = Host.objects.create(hostname="win-a.example.test", ip_address="10.0.4.12")
        self.web.packages.create(package_name="openssh-server", installed_version="1:8.9p1-3ubuntu0.10", detected_at=timezone.now(), source_package="openssh")
        self.web.packages.create(package_name="telnetd", installed_version="0.17-44", detected_at=timezone.now())
        definition = VulnerabilityDefinition.objects.create(qid="38909", title="OpenSSH", severity="critical", qualys_severity=5)
        self.finding = VulnerabilityFinding.objects.create(
            host=self.web, vulnerability_definition=definition, perimeter=Perimeter.objects.get(slug="internal"),
            first_detected_at=timezone.now(), last_detected_at=timezone.now(),
            related_package=self.web.packages.get(package_name="openssh-server"),
        )
        client = mock.MagicMock(calls=3)
        client.all_assets.return_value = [
            asset(101, "10.0.4.11", "web-a.example.test", JAMMY, tags=["Alpha", "Production"]),
            asset(102, "10.0.4.12", "win-a.example.test", {"fullName": "Microsoft Windows Server 2019"}, agent=False),
            asset(103, "10.0.7.7", "other.example.test", JAMMY),
        ]
        client.software.return_value = {101: SOFTWARE}
        patcher = mock.patch("core.csam.Client", return_value=client)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.client_mock = client

    def post(self, url, data=None):
        with self.captureOnCommitCallbacks(execute=True):
            return self.client.post(url, data or {})

    def search(self):
        self.post("/imports/csam/search/")
        return CsamSearch.objects.get()

    def test_search_proposes_details_for_known_hosts(self):
        search = self.search()
        self.assertEqual((search.state, search.assets_seen, search.hosts_total, search.matched), ("done", 3, 2, 2))
        self.client_mock.software.assert_called_once_with([101])  # Ubuntu with agent only
        web = CsamProposal.objects.get(host=self.web)
        self.assertEqual((web.ubuntu_release, web.matched_by, web.qualys_tags, len(web.packages)), ("jammy", "IP and Name", ["Alpha", "Production"], 3))
        self.assertEqual(CsamProposal.objects.get(host=self.win).packages, [])
        page = self.client.get("/imports/csam/")
        self.assertContains(page, "2 of Your 2 Hosts Found")
        self.assertContains(page, "Ubuntu 22.04 LTS (jammy)")
        self.assertContains(page, "2 New · 1 Changed · 1 Removed")
        self.assertContains(page, "openssh-server 1:8.9p1-3ubuntu0.10 → 1:8.9p1-3ubuntu0.17")

    def test_import_selected(self):
        self.search()
        web = CsamProposal.objects.get(host=self.web)
        with mock.patch("core.csam_views.start_check", return_value=True) as check:
            self.post("/imports/csam/import/", {"proposal": [web.pk], "kind_release": "1", "kind_packages": "1", "kind_os": "1", "kind_tags": "1"})
        self.web.refresh_from_db()
        self.assertEqual(self.web.ubuntu_release, "jammy")
        self.assertEqual(self.web.os_version, JAMMY["fullName"])
        self.assertEqual(self.web.qualys_host_id, "1010")
        self.assertEqual(sorted(t.name for t in self.web.tags.all()), ["Alpha", "Production"])
        packages = {p.package_name: p for p in self.web.packages.all()}
        self.assertEqual(sorted(packages), ["apache2", "libc6", "openssh-server"])  # telnetd removed
        ssh = packages["openssh-server"]
        self.assertEqual((ssh.installed_version, ssh.source, ssh.source_package), ("1:8.9p1-3ubuntu0.17", InstalledPackage.Source.QUALYS_AGENT, ""))
        # Updated in place: the finding still points to the same package row.
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.related_package_id, ssh.pk)
        check.assert_called_once()
        self.assertTrue(AuditLog.objects.filter(action="csam.imported", entity_id=str(self.web.pk)).exists())
        web.refresh_from_db()
        self.assertIsNotNone(web.imported_at)
        # Nothing new any more: the default view hides it.
        self.assertNotContains(self.client.get("/imports/csam/"), 'name="proposal" value="%d"' % web.pk)

    def test_manual_packages_are_kept_unless_confirmed(self):
        self.web.packages.create(
            package_name="my-custom-tool", installed_version="1.0", detected_at=timezone.now(),
            source=InstalledPackage.Source.MANUAL,
        )
        self.search()
        web = CsamProposal.objects.get(host=self.web)

        page = self.client.get("/imports/csam/")
        self.assertContains(page, "1 Manual")
        self.assertContains(page, "Also Remove Manually-Added Packages")

        # Not ticked: the manual package survives; telnetd (not manual) is still removed as before.
        self.post("/imports/csam/import/", {"proposal": [web.pk], "kind_packages": "1"})
        names = set(self.web.packages.values_list("package_name", flat=True))
        self.assertIn("my-custom-tool", names)
        self.assertNotIn("telnetd", names)
        response = self.client.get("/imports/csam/")
        self.assertContains(response, "Kept 1 Manually-Added Package on 1 Host")

        # Ticked: it goes too.
        self.post(
            "/imports/csam/import/",
            {"proposal": [web.pk], "kind_packages": "1", "remove_manual_packages": "1"},
        )
        names = set(self.web.packages.values_list("package_name", flat=True))
        self.assertNotIn("my-custom-tool", names)

    def test_banner_and_badge_say_how_many_hosts_to_import(self):
        from datetime import timedelta

        from django.core.cache import cache

        cache.clear()
        self.assertNotContains(self.client.get("/imports/csam/"), "Review &amp; Import")
        self.search()
        page = self.client.get("/imports/csam/")
        self.assertContains(page, "Import 2 Hosts: Qualys Csam Has Details")
        self.assertContains(page, 'class="nav-badge"')  # on the Imports entry of every page
        self.assertContains(self.client.get("/"), 'class="nav-badge"')
        # The button opens the list with those hosts already ticked.
        ticked = self.client.get("/imports/csam/?select=pending")
        self.assertContains(ticked, "checked aria-label=\"Select web-a.example.test\"")
        # Only what is still to import counts: after the import the host drops out.
        web = CsamProposal.objects.get(host=self.web)
        self.post("/imports/csam/import/", {"proposal": [web.pk], "kind_release": "1", "kind_packages": "1", "kind_os": "1", "kind_tags": "1"})
        self.assertContains(self.client.get("/imports/csam/"), "Import 1 Host: Qualys Csam Has Details")

    def test_nothing_to_import_and_stale_searches_are_said(self):
        from datetime import timedelta

        from django.core.cache import cache

        cache.clear()
        self.search()
        for proposal in CsamProposal.objects.all():
            self.post("/imports/csam/import/", {"proposal": [proposal.pk], "kind_release": "1", "kind_packages": "1", "kind_os": "1", "kind_tags": "1"})
        self.assertContains(self.client.get("/imports/csam/"), "Pvm Is Aligned with the Last Search")
        CsamSearch.objects.update(finished_at=timezone.now() - timedelta(days=9))
        page = self.client.get("/imports/csam/")
        self.assertContains(page, "Nothing to Import from the Last Search, but It Is Old")
        self.assertContains(page, "nav-badge-stale")

    def test_tags_and_imported_hosts_do_not_keep_the_count_up(self):
        from django.core.cache import cache

        cache.clear()
        self.search()
        # Imported without the tags: the host must not stay "to import" for the tags left.
        for proposal in CsamProposal.objects.all():
            self.post("/imports/csam/import/", {"proposal": [proposal.pk], "kind_release": "1", "kind_packages": "1", "kind_os": "1"})
        self.assertContains(self.client.get("/imports/csam/"), "Pvm Is Aligned with the Last Search")

    def test_a_long_operating_system_name_is_not_a_difference_forever(self):
        from core.csam_views import _rows

        long_name = "Linux / " * 40
        self.client_mock.all_assets.return_value[0]["operatingSystem"] = {"fullName": long_name}
        self.search()
        proposal = CsamProposal.objects.get(host=self.web)
        self.post("/imports/csam/import/", {"proposal": [proposal.pk], "kind_os": "1"})
        row = next(r for r in _rows(CsamSearch.objects.get(), True) if r["host"].pk == self.web.pk)
        self.assertFalse(row["diff"]["os"])

    def test_a_kept_manual_package_alone_is_not_something_to_import(self):
        from django.core.cache import cache

        cache.clear()
        self.search()
        web = CsamProposal.objects.get(host=self.web)
        self.web.packages.create(
            package_name="my-custom-tool", installed_version="1.0", detected_at=timezone.now(),
            source=InstalledPackage.Source.MANUAL,
        )
        self.post("/imports/csam/import/", {"proposal": [web.pk], "kind_release": "1", "kind_packages": "1", "kind_os": "1", "kind_tags": "1"})
        self.web.refresh_from_db()
        from core.csam_views import _rows

        row = next(r for r in _rows(CsamSearch.objects.get(), True) if r["host"].pk == self.web.pk)
        self.assertEqual(row["missing_manual"], ["my-custom-tool"])
        self.assertFalse(row["pending"])

    def test_windows_hosts_with_the_agent_get_their_software_as_information_only(self):
        # win-a already exists in setUp, without the agent; give it one here.
        # web-a is left without the agent, to isolate the Windows case fetched.
        self.client_mock.all_assets.return_value = [
            asset(101, "10.0.4.11", "web-a.example.test", JAMMY, agent=False),
            asset(102, "10.0.4.12", "win-a.example.test", WINDOWS, agent=True),
        ]
        self.client_mock.software.return_value = {102: WINDOWS_SOFTWARE}
        search = self.search()
        self.assertEqual(search.matched, 2)
        self.client_mock.software.assert_called_once_with([102])

        proposal = CsamProposal.objects.get(host=self.win)
        self.assertEqual(proposal.ubuntu_release, "")  # Windows, never mistaken for a release
        self.assertEqual(
            sorted(proposal.packages),
            [["7-Zip 23.01 (x64)", "23.01.00.0"], ["Microsoft Visual C++ 2015-2022 Redistributable (x64)", "14.38.33135.0"]],
        )
        page = self.client.get("/imports/csam/")
        self.assertContains(page, "Microsoft Windows Server 2019 Standard")

        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post("/imports/csam/import/", {"proposal": [proposal.pk], "kind_packages": "1"}, follow=True)
        self.assertContains(response, "Details Imported for 1 Host.")
        # No check is queued: the host has no Ubuntu or Rocky release to check against.
        self.assertNotIn("the Patch Check Runs Again", response.content.decode())
        self.win.refresh_from_db()
        self.assertEqual(self.win.ubuntu_release, "")
        names = sorted(p.package_name for p in self.win.packages.all())
        self.assertEqual(names, ["7-Zip 23.01 (x64)", "Microsoft Visual C++ 2015-2022 Redistributable (x64)"])

    def test_only_ticked_kinds_are_imported(self):
        self.search()
        web = CsamProposal.objects.get(host=self.web)
        self.post("/imports/csam/import/", {"proposal": [web.pk], "kind_os": "1"})
        self.web.refresh_from_db()
        self.assertEqual((self.web.ubuntu_release, self.web.os_version), ("", JAMMY["fullName"]))
        self.assertEqual(self.web.packages.get(package_name="openssh-server").installed_version, "1:8.9p1-3ubuntu0.10")
        self.assertFalse(Tag.objects.exists())

    def test_failure_is_shown(self):
        self.client_mock.all_assets.side_effect = csam.CsamError("Qualys Gateway Unreachable (Is Cato Connected on the VM?)")
        search = self.search()
        self.assertEqual(search.state, "failed")
        self.assertContains(self.client.get("/imports/csam/"), "Is Cato Connected on the VM?")

    def test_a_new_search_replaces_the_old_one(self):
        self.search()
        self.search()
        self.assertEqual(CsamSearch.objects.count(), 1)
        self.assertEqual(CsamProposal.objects.count(), 2)

    def test_readonly_has_no_access(self):
        self.client.post("/account/logout/")
        User.objects.create_user("ro", "ro@example.com", PASSWORD, role=User.Role.READONLY)
        self.client.post("/account/login/", {"username": "ro", "password": PASSWORD})
        self.assertEqual(self.client.get("/imports/csam/").status_code, 403)
        self.assertEqual(self.client.post("/imports/csam/search/").status_code, 403)


@override_settings(QUALYS_GATEWAY_URL="https://gateway.example.test", QUALYS_USERNAME="u", QUALYS_PASSWORD="p")
class LookupTests(ImportTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        from django.core.cache import cache

        cache.clear()
        self.web = Host.objects.create(hostname="app-srv-05", ip_address="10.20.4.86")
        client = mock.MagicMock(calls=3)
        client.lookup.return_value = [
            asset(201, "10.20.4.86", "app-srv-05", JAMMY, tags=["Alpha"]),
            asset(202, "10.20.4.89", "app-srv-05-test.example.test", JAMMY),
            asset(203, "10.20.4.90", "<script>x</script>", {"fullName": "Windows"}, agent=False),
        ]
        client.software.return_value = {201: SOFTWARE}
        patcher = mock.patch("core.csam.Client", return_value=client)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.client_mock = client

    def test_live_search_shows_assets_also_outside_pvm(self):
        page = self.client.get("/imports/csam/?q=app-srv-05")
        self.client_mock.lookup.assert_called_once_with("app-srv-05")
        self.client_mock.software.assert_called_once_with([201, 202])
        self.assertContains(page, "In Qualys Csam: “app-srv-05”")
        self.assertContains(page, "Ubuntu 22.04 LTS (jammy)")
        self.assertContains(page, "openssh-server 1:8.9p1-3ubuntu0.17")
        self.assertContains(page, f'href="/hosts/{self.web.pk}/">app-srv-05</a> <span class="muted">(IP and Name)')
        self.assertContains(page, "Not in Pvm")
        self.assertNotContains(page, "<script>x</script>")  # names from Qualys are escaped
        # Cached: a second look does not call Qualys again.
        self.client.get("/imports/csam/?q=app-srv-05")
        self.assertEqual(self.client_mock.lookup.call_count, 1)

    def test_short_query_and_errors(self):
        self.assertContains(self.client.get("/imports/csam/?q=wa"), "Type at Least 3 Characters")
        self.client_mock.lookup.side_effect = csam.CsamError("Qualys Gateway Unreachable (Is Cato Connected on the VM?)")
        self.assertContains(self.client.get("/imports/csam/?q=10.20.4.86"), "Is Cato Connected on the VM?")

    def test_search_filters_the_proposals(self):
        search = CsamSearch.objects.create(state="done", hosts_total=2, matched=2)
        other = Host.objects.create(hostname="web-z.example.test", ip_address="10.0.0.9")
        for h in (self.web, other):
            CsamProposal.objects.create(search=search, host=h, asset_id=h.pk, matched_by="IP and Name", os_full="Windows", inventory_source="IP")
        page = self.client.get("/imports/csam/?q=10.20.4")
        self.assertContains(page, 'aria-label="Select app-srv-05"')
        self.assertNotContains(page, 'aria-label="Select web-z.example.test"')

    def test_tab_label(self):
        self.assertContains(self.client.get("/imports/"), ">Qualys Csam</a>")


@override_settings(QUALYS_GATEWAY_URL="https://gateway.example.test", QUALYS_USERNAME="u", QUALYS_PASSWORD="p")
class SoftwareLookupTests(ImportTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        from django.core.cache import cache

        cache.clear()
        self.web = Host.objects.create(hostname="app-prod-01", ip_address="10.20.4.74")
        client = mock.MagicMock(calls=2)
        client.software_lookup.return_value = (
            [asset(301, "10.20.4.74", "app-prod-01.corp", JAMMY), asset(302, "10.0.9.9", "other-host")],
            False,
        )
        client.software.return_value = {
            301: [
                {"discoveredName": "spring-boot-starter-log4j2", "discoveredVersion": "4j2-2.7.14"},
                {"discoveredName": "some-unrelated-lib", "discoveredVersion": "1.0"},
            ],
            302: [{"discoveredName": "log4j-core", "discoveredVersion": "2.17.1"}],
        }
        patcher = mock.patch("core.csam.Client", return_value=client)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.client_mock = client

    def test_live_search_shows_matching_hosts(self):
        page = self.client.get("/imports/csam/?sw=log4j")
        self.client_mock.software_lookup.assert_called_once_with("log4j")
        self.client_mock.software.assert_called_once_with([301, 302])
        self.assertContains(page, "“log4j” in Qualys Csam")
        self.assertContains(page, "spring-boot-starter-log4j2 4j2-2.7.14")
        self.assertNotContains(page, "some-unrelated-lib")  # matched by Csam's filter, not by name here: left out
        self.assertContains(page, f'href="/hosts/{self.web.pk}/">app-prod-01</a> <span class="muted">(IP and Name)')
        self.assertContains(page, "Not in Pvm")
        # Cached: a second look does not call Qualys again.
        self.client.get("/imports/csam/?sw=log4j")
        self.assertEqual(self.client_mock.software_lookup.call_count, 1)

    def test_short_query_and_errors(self):
        self.assertContains(self.client.get("/imports/csam/?sw=lo"), "Type at Least 3 Characters")
        self.client_mock.software_lookup.side_effect = csam.CsamError("Qualys Gateway Unreachable (Is Cato Connected on the VM?)")
        self.assertContains(self.client.get("/imports/csam/?sw=log4j"), "Is Cato Connected on the VM?")

    def test_truncated_notice(self):
        self.client_mock.software_lookup.return_value = ([asset(301, "10.20.4.74", "app-prod-01.corp", JAMMY)], True)
        page = self.client.get("/imports/csam/?sw=log4j")
        self.assertContains(page, "Narrow the Search for a Full List")

    def test_no_matches(self):
        self.client_mock.software_lookup.return_value = ([], False)
        page = self.client.get("/imports/csam/?sw=nosuchthing")
        self.assertContains(page, "No Asset in Qualys Csam Has Software Matching")

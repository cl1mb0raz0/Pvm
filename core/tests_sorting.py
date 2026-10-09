"""Every list sorts on every column (core/sorting.py and the pages that use it)."""

from django.test import TestCase
from django.utils import timezone

from accounts.models import User
from backups.models import Backup

from .models import Cve, Host, InstalledPackage, ScanImport, VulnerabilityFinding
from .tests_imports import PASSWORD, ImportTestMixin

Status = VulnerabilityFinding.Status


class SortingHelperTests(TestCase):
    def test_empty_values_go_last_in_both_directions(self):
        from .sorting import sort_rows

        rows = [{"n": 2}, {"n": None}, {"n": 1}, {"n": ""}]
        value = lambda r: r["n"]  # noqa: E731
        self.assertEqual([r["n"] for r in sort_rows(rows, value, "asc")][:2], [1, 2])
        self.assertEqual([r["n"] for r in sort_rows(rows, value, "desc")][:2], [2, 1])
        self.assertEqual(len(sort_rows(rows, value, "asc")), 4)

    def test_a_second_table_keeps_its_own_keys(self):
        from django.test import RequestFactory

        from .sorting import sorting

        columns = [("a", "A", "a", "asc", False), ("b", "B", "b", "asc", False)]
        request = RequestFactory().get("/?sort=b&cve_sort=a")
        field, _, key, headers = sorting(request, columns, "a")
        self.assertEqual((field, key), ("b", "b"))
        field, _, key, headers = sorting(request, columns, "b", prefix="cve_")
        self.assertEqual((field, key), ("a", "a"))
        self.assertIn("cve_sort=b", headers[1]["url"])


class ListSortingTests(ImportTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.scan = self.full_import()
        self.host = Host.objects.order_by("hostname").first()

    def order(self, url, key=lambda f: f.pk):
        page = self.client.get(url)
        rows = page.context.get("page")
        rows = rows.object_list if rows is not None else page.context["findings"]
        return [key(r) for r in rows]

    def test_vulnerabilities_list_sorts_on_every_column(self):
        for column in ("priority", "severity", "qualys", "cvss", "qid", "title", "host", "perimeter", "team", "due", "status", "patch"):
            for direction in ("asc", "desc"):
                found = self.order(f"/vulnerabilities/?status=all&sort={column}&dir={direction}")
                self.assertEqual(len(found), VulnerabilityFinding.objects.count(), f"{column} {direction}")
        by_title = self.order("/vulnerabilities/?sort=title&dir=asc", key=lambda f: f.vulnerability_definition.title)
        self.assertEqual(by_title, sorted(by_title))
        by_qid = self.order("/vulnerabilities/?sort=qid&dir=desc", key=lambda f: f.vulnerability_definition.qid)
        self.assertEqual(by_qid, sorted(by_qid, reverse=True))
        page = self.client.get("/vulnerabilities/?sort=title&dir=asc")
        self.assertContains(page, 'aria-sort="ascending"')
        self.assertContains(page, "sort=host")

    def test_the_default_order_is_still_the_priority(self):
        scores = self.order("/vulnerabilities/", key=lambda f: f.priority_score)
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_host_findings_tab_sorts_and_keeps_resolved_last(self):
        finding = self.host.findings.first()
        VulnerabilityFinding.objects.filter(pk=finding.pk).update(status=Status.RESOLVED)
        for column in ("priority", "severity", "qid", "title", "port", "due", "status", "patch"):
            rows = self.order(f"/hosts/{self.host.pk}/?sort={column}")
            self.assertEqual(rows[-1], finding.pk, f"resolved should stay last, sorted by {column}")

    def test_installed_packages_sort(self):
        for name, version in [("zsh", "5.8-1"), ("apache2", "2.4.52-1"), ("bash", "5.1-6")]:
            InstalledPackage.objects.create(
                host=self.host, package_name=name, installed_version=version, detected_at=timezone.now()
            )
        page = self.client.get(f"/hosts/{self.host.pk}/?tab=packages&sort=package&dir=asc")
        names = [p.package_name for p in page.context["packages"]]
        self.assertEqual(names, sorted(names))
        page = self.client.get(f"/hosts/{self.host.pk}/?tab=packages&sort=package&dir=desc")
        self.assertEqual([p.package_name for p in page.context["packages"]], sorted(names, reverse=True))
        self.assertContains(page, "sort=updated")

    def test_the_qid_page_sorts_its_cves_and_its_hosts_apart(self):
        definition = self.host.findings.first().vulnerability_definition
        definition.cves.add(
            Cve.objects.create(cve_id="CVE-2024-0002", cvss_score=9.8),
            Cve.objects.create(cve_id="CVE-2024-0001", cvss_score=4.2),
        )
        page = self.client.get(f"/vulnerabilities/qid/{definition.qid}/?cve_sort=cve&cve_dir=asc&sort=host&dir=desc")
        ids = [c.cve_id for c in page.context["cves"]]
        self.assertEqual(ids, sorted(ids))
        hosts = [f.host.hostname for f in page.context["findings"]]
        self.assertEqual(hosts, sorted(hosts, reverse=True))
        # Sorting the CVEs leaves the hosts table alone, and the scored ones
        # come first with the highest CVSS.
        page = self.client.get(f"/vulnerabilities/qid/{definition.qid}/?cve_sort=cvss&cve_dir=desc")
        scored = [c.cvss_score for c in page.context["cves"] if c.cvss_score is not None]
        self.assertEqual(scored, sorted(scored, reverse=True))
        self.assertEqual(float(scored[0]), 9.8)
        hosts = [f.host.hostname for f in page.context["findings"]]
        self.assertEqual(hosts, sorted(hosts))  # back to its own default

    def test_imports_history_and_hosts_still_sort(self):
        self.assertContains(self.client.get("/imports/?sort=findings"), 'aria-sort=')
        self.assertContains(self.client.get("/hosts/?sort=ip"), 'aria-sort=')


class AdminListSortingTests(ImportTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.client.post("/account/logout/")
        self.admin = User.objects.create_user("adm", "adm@example.com", PASSWORD, role=User.Role.SUPER_ADMIN)
        self._login_verified(self.admin)

    def test_backups_sort(self):
        for size in (300, 100, 200):
            Backup.objects.create(
                kind=Backup.Kind.MANUAL, status=Backup.Status.COMPLETED, size_bytes=size,
                created_by="adm", file_name=f"pvm-{size}.json.gz",
            )
        sizes = [b.size_bytes for b in self.client.get("/backups/?sort=size&dir=desc").context["backups"]]
        self.assertEqual(sizes, [300, 200, 100])
        sizes = [b.size_bytes for b in self.client.get("/backups/?sort=size&dir=asc").context["backups"]]
        self.assertEqual(sizes, [100, 200, 300])
        self.assertContains(self.client.get("/backups/"), "sort=created")

    def test_ssh_access_sorts(self):
        for name in ("beta.example.test", "alpha.example.test"):
            Host.objects.create(hostname=name, ip_address="10.0.0.1", ssh_enabled=True)
        page = self.client.get("/ssh/?sort=host&dir=asc")
        names = [h.hostname for h in page.context["hosts"]]
        self.assertEqual(names, sorted(names))
        self.assertContains(page, "sort=checked")

    def test_mapping_tables_sort_apart(self):
        from .models import BalancerConfig, PrivateIpMapping

        PrivateIpMapping.objects.create(public_ip="198.51.100.20", hostname="b.example.test", private_ip="10.0.0.2")
        PrivateIpMapping.objects.create(public_ip="198.51.100.10", hostname="a.example.test", private_ip="10.0.0.1")
        BalancerConfig.objects.create(name="A10 two", counts={"servers": 2})
        BalancerConfig.objects.create(name="A10 one", counts={"servers": 9})
        page = self.client.get("/imports/mapping/?map_sort=public&map_dir=asc&lb_sort=servers&lb_dir=desc")
        self.assertEqual([m.public_ip for m in page.context["stored"]], ["198.51.100.10", "198.51.100.20"])
        self.assertEqual([c.name for c in page.context["configs"]], ["A10 one", "A10 two"])
        page = self.client.get("/imports/mapping/?map_sort=public&map_dir=desc")
        self.assertEqual([m.public_ip for m in page.context["stored"]], ["198.51.100.20", "198.51.100.10"])

    def test_csam_proposals_sort(self):
        from .models import CsamProposal, CsamSearch

        search = CsamSearch.objects.create(state=CsamSearch.State.DONE, started_at=timezone.now())
        hosts = [Host.objects.create(hostname=n, ip_address=f"10.0.1.{i}") for i, n in enumerate(["b.test", "a.test"], start=1)]
        for i, (host, asset, packages) in enumerate(zip(hosts, ["zeta", "alpha"], [[["a", "1"]], [["a", "1"], ["b", "2"]]])):
            CsamProposal.objects.create(
                search=search, host=host, asset_id=100 + i, asset_name=asset,
                ubuntu_release="jammy", packages=packages, matched_by="IP",
            )
        page = self.client.get("/imports/csam/?all=1&sort=asset&dir=asc")
        self.assertEqual([r["p"].asset_name for r in page.context["rows"]], ["alpha", "zeta"])
        page = self.client.get("/imports/csam/?all=1&sort=packages&dir=desc")
        self.assertEqual([len(r["p"].packages) for r in page.context["rows"]], [2, 1])


class HostRecapTests(ImportTestMixin, TestCase):
    """The band above the Hosts list describes what the filters leave in."""

    def setUp(self):
        super().setUp()
        self.scan = self.full_import()

    def recap(self, query=""):
        return self.client.get("/hosts/" + query).context["recap"]

    def test_counts_what_was_imported(self):
        recap = self.recap()
        self.assertEqual(recap["total"], Host.objects.count())
        self.assertEqual(recap["internal"], Host.objects.count())  # the fixture is one internal scan
        self.assertEqual(recap["external"], 0)
        self.assertEqual(recap["affected"] + recap["clean"], recap["total"])
        self.assertEqual(recap["open_findings"], VulnerabilityFinding.objects.exclude(status=Status.RESOLVED).count())
        self.assertGreaterEqual(recap["worst"], 1)
        self.assertIsNotNone(recap["last_scanned"])

    def test_it_follows_the_filters(self):
        host = Host.objects.order_by("hostname").first()
        page = self.client.get(f"/hosts/?q={host.hostname}")
        self.assertEqual(page.context["recap"]["total"], 1)
        self.assertTrue(page.context["filtered"])
        self.assertEqual(self.recap("?perimeter=external")["total"], 0)
        self.assertFalse(self.client.get("/hosts/").context["filtered"])

    def test_it_is_on_the_page(self):
        page = self.client.get("/hosts/")
        self.assertContains(page, "Everything Imported")
        self.assertContains(page, "With Open Findings")
        self.assertContains(page, "Ubuntu Release Known")
        self.assertContains(page, "Internal ·")


class CsamGapTests(ImportTestMixin, TestCase):
    """Imports > Qualys Csam lists the hosts Pvm has no inventory for, and why."""

    def setUp(self):
        super().setUp()
        self.client.post("/account/logout/")
        self.admin = User.objects.create_user("adm2", "adm2@example.com", PASSWORD, role=User.Role.ADMIN)
        self._login_verified(self.admin)
        from .models import CsamProposal, CsamSearch

        self.search = CsamSearch.objects.create(state=CsamSearch.State.DONE, started_at=timezone.now())
        self.unknown = Host.objects.create(hostname="nowhere.test", ip_address="10.0.2.1")
        self.agentless = Host.objects.create(hostname="noagent.test", ip_address="10.0.2.2")
        self.ready = Host.objects.create(hostname="ready.test", ip_address="10.0.2.3")
        self.done = Host.objects.create(hostname="done.test", ip_address="10.0.2.4", ubuntu_release="jammy")
        CsamProposal.objects.create(search=self.search, host=self.agentless, asset_id=1, asset_name="noagent", matched_by="IP")
        CsamProposal.objects.create(
            search=self.search, host=self.ready, asset_id=2, asset_name="ready",
            matched_by="IP", packages=[["bash", "5.1-6"]], ubuntu_release="jammy",
        )

    def test_it_says_which_hosts_have_nothing_and_why(self):
        page = self.client.get("/imports/csam/")
        rows = {g["host"].hostname: g["why"] for g in page.context["gaps"]}
        self.assertEqual(rows["nowhere.test"], "Not in Qualys Csam")
        self.assertEqual(rows["noagent.test"], "In Csam, No Cloud Agent")
        self.assertEqual(rows["ready.test"], "In Csam with Packages, Not Imported Yet")
        # A host that already has its release is not missing anything.
        self.assertNotIn("done.test", rows)
        counts = page.context["gap_counts"]
        self.assertEqual((counts["to_import"], counts["no_agent"], counts["unknown"]), (1, 1, 1))
        self.assertContains(page, "Hosts Without Inventory")
        self.assertContains(page, "Ready to Import")

    def test_a_host_with_packages_drops_off_the_list(self):
        InstalledPackage.objects.create(
            host=self.unknown, package_name="bash", installed_version="5.1-6", detected_at=timezone.now()
        )
        names = [g["host"].hostname for g in self.client.get("/imports/csam/").context["gaps"]]
        self.assertNotIn("nowhere.test", names)

    def test_the_two_tables_sort_apart(self):
        page = self.client.get("/imports/csam/?gap_sort=host&gap_dir=desc&sort=host&dir=asc")
        names = [g["host"].hostname for g in page.context["gaps"]]
        self.assertEqual(names, sorted(names, reverse=True))
        proposals = [r["host"].hostname for r in page.context["rows"]]
        self.assertEqual(proposals, sorted(proposals))

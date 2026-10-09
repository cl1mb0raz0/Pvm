import json
from pathlib import Path
from unittest import mock

from django.test import TestCase, override_settings
from django.utils import timezone

from accounts.models import User

from . import inventory, patchcheck, ubuntu
from .importers import pipeline
from .importers.qualys_csv import Detection
from .models import (
    Cve,
    DistroPatchVerification,
    Host,
    InstalledPackage,
    PatchCheck,
    Perimeter,
    ScanImport,
    VulnerabilityDefinition,
    VulnerabilityFinding,
)
from .tests_imports import ImportTestMixin

FIXTURES = Path(__file__).parent / "fixtures"
Verdict = PatchCheck.Verdict


def tracker_record(cve_id, throttle=None):
    """A real Ubuntu tracker answer (trimmed to a few packages), or None if not saved = not tracked."""
    path = FIXTURES / f"ubuntu_{cve_id}.json"
    return json.loads(path.read_text()) if path.exists() else None


def tracked_cve(cve_id):
    cve = Cve.objects.create(cve_id=cve_id)
    ubuntu.apply_record(cve, tracker_record(cve_id))
    return cve


def packages(*entries):
    return patchcheck.Inventory(
        InstalledPackage(package_name=n, installed_version=v, source_package=s, detected_at=timezone.now())
        for n, v, s in entries
    )


class InventoryParseTests(TestCase):
    def test_command_output(self):
        text = (
            "VERSION_CODENAME=focal\n"
            "apache2\t2.4.41-4ubuntu3.17\tapache2\t2.4.41-4ubuntu3.17\n"
            "openssh-server\t1:8.2p1-4ubuntu0.11\topenssh\t1:8.2p1-4ubuntu0.11\n"
            "libc6:amd64\t2.31-0ubuntu9.16\tglibc\t2.31-0ubuntu9.16\n"
        )
        release, entries, errors = inventory.parse(text)
        self.assertEqual(release, "focal")
        self.assertEqual(errors, [])
        by_name = {e.name: e for e in entries}
        self.assertEqual(by_name["openssh-server"].source, "openssh")
        self.assertEqual(by_name["libc6"].source, "glibc")

    def test_dpkg_l_and_email_lines(self):
        text = (
            "Desired=Unknown/Install/Remove/Purge/Hold\n"
            "||/ Name  Version  Architecture Description\n"
            "+++-=====-=======-============-===========\n"
            "ii  apache2  2.4.41-4ubuntu3.17  amd64  Apache HTTP Server\n"
            "rc  oldpkg   1.0-1               amd64  removed, config left\n"
            "sudo 1.8.31-1ubuntu1.5\n"
            "this is not a package line\n"
        )
        release, entries, errors = inventory.parse(text)
        self.assertEqual({e.name for e in entries}, {"apache2", "sudo"})
        self.assertEqual(errors, ["this is not a package line"])


class CheckCveTests(TestCase):
    """Verdicts on real tracker records."""

    def test_backported_fix_is_detected(self):
        # The case Qualys gets wrong: Apache/2.4.41 banner, but focal's
        # 2.4.41-4ubuntu3.9 already carries the fix.
        cve = tracked_cve("CVE-2021-44790")
        fixed = patchcheck.check_cve(cve, "focal", packages(("apache2", "2.4.41-4ubuntu3.17", "")))
        self.assertEqual(fixed["verdict"], Verdict.FIXED)
        old = patchcheck.check_cve(cve, "focal", packages(("apache2", "2.4.41-4ubuntu3.8", "")))
        self.assertEqual(old["verdict"], Verdict.VULNERABLE_UPDATE)
        self.assertIn("2.4.41-4ubuntu3.9", old["packages"][0]["why"])

    def test_not_affected_release(self):
        cve = tracked_cve("CVE-2024-6387")
        # Entered by hand as the binary name: matched to the "openssh" source.
        result = patchcheck.check_cve(cve, "focal", packages(("openssh-server", "1:8.2p1-4ubuntu0.5", "")))
        self.assertEqual(result["verdict"], Verdict.NOT_AFFECTED)

    def test_fix_only_in_ubuntu_pro(self):
        cve = tracked_cve("CVE-2023-48795")
        result = patchcheck.check_cve(cve, "bionic", packages(("openssh-server", "1:7.6p1-4ubuntu0.7", "openssh")))
        self.assertEqual(result["verdict"], Verdict.VULNERABLE_PRO)

    def test_no_fix_yet(self):
        cve = tracked_cve("CVE-2023-48795")
        result = patchcheck.check_cve(cve, "noble", packages(("dropbear", "2022.83-1ubuntu1", "")))
        self.assertEqual(result["verdict"], Verdict.VULNERABLE_NO_FIX)

    def test_missing_package_is_listed(self):
        cve = tracked_cve("CVE-2021-44790")
        result = patchcheck.check_cve(cve, "focal", packages(("sudo", "1.8.31-1ubuntu1.5", "")))
        self.assertEqual(result["verdict"], Verdict.UNKNOWN)
        self.assertEqual(result["missing"], ["apache2"])

    def test_untracked_cve(self):
        cve = Cve.objects.create(cve_id="CVE-2099-0001")
        ubuntu.apply_record(cve, None)
        self.assertEqual(patchcheck.check_cve(cve, "focal", packages())["reason"], "Not Tracked by Ubuntu")

    def test_kernel_is_not_guessed(self):
        cve = Cve.objects.create(cve_id="CVE-2024-0001", ubuntu_status="ok", ubuntu_packages={
            "linux": {"jammy": {"status": "released", "fixed": "5.15.0-100.110", "pocket": "security", "note": ""}}
        })
        result = patchcheck.check_cve(cve, "jammy", packages(("linux-image-generic", "5.15.0.100.97", "")))
        self.assertEqual(result["verdict"], Verdict.UNKNOWN)
        self.assertIn("Kernel", result["reason"])

    def test_worst_cve_wins(self):
        self.assertEqual(patchcheck.worst([Verdict.FIXED, Verdict.NOT_AFFECTED]), Verdict.FIXED)
        self.assertEqual(patchcheck.worst([Verdict.FIXED, Verdict.UNKNOWN]), Verdict.UNKNOWN)
        self.assertEqual(patchcheck.worst([Verdict.UNKNOWN, Verdict.VULNERABLE_UPDATE]), Verdict.VULNERABLE_UPDATE)


class HostCheckFlowTests(ImportTestMixin, TestCase):
    """From an empty host to a confirmed verification that survives the next scan."""

    def setUp(self):
        super().setUp()
        self.host = Host.objects.create(hostname="web-01", ip_address="192.0.2.10")
        definition = VulnerabilityDefinition.objects.create(
            qid="150495", title="Apache HTTP Server mod_lua", severity="high", qualys_severity=4
        )
        definition.cves.add(Cve.objects.create(cve_id="CVE-2021-44790"))
        self.internal = Perimeter.objects.get(slug="internal")
        self.finding = VulnerabilityFinding.objects.create(
            host=self.host,
            vulnerability_definition=definition,
            service_port="443/tcp",
            perimeter=self.internal,
            first_detected_at=timezone.now(),
            last_detected_at=timezone.now(),
        )
        tracker = override_settings(UBUNTU_TRACKER_ENABLED=True)
        tracker.enable()
        self.addCleanup(tracker.disable)
        fetch = mock.patch("core.ubuntu.fetch", side_effect=tracker_record)
        self.fetch = fetch.start()
        self.addCleanup(fetch.stop)
        sleep = mock.patch("core.ubuntu.time.sleep")
        sleep.start()
        self.addCleanup(sleep.stop)

    def post(self, url, data=None):
        with self.captureOnCommitCallbacks(execute=True):
            return self.client.post(url, data or {})

    def test_full_flow(self):
        base = f"/hosts/{self.host.pk}"

        # 1. The release is set: the check runs and asks for apache2.
        self.post(f"{base}/release/", {"ubuntu_release": "focal"})
        check = PatchCheck.objects.get(vulnerability_finding=self.finding)
        self.assertEqual(check.verdict, Verdict.UNKNOWN)
        page = self.client.get(f"{base}/?tab=packages")
        self.assertEqual(page.context["missing_packages"], ["apache2"])
        self.assertContains(page, "dpkg-query")

        # 2. The sysadmin's email answer is pasted: the finding is fixed.
        self.post(f"{base}/packages/paste/", {"text": "apache2 2.4.41-4ubuntu3.17"})
        check.refresh_from_db()
        self.assertEqual(check.verdict, Verdict.FIXED)
        self.host.refresh_from_db()
        self.assertEqual(self.host.patch_check_state, "done")
        page = self.client.get(f"{base}/?tab=vulnerabilities")
        self.assertContains(page, "Confirm: Fixed in the Installed Version")

        # 3. An analyst confirms it.
        self.post(f"/findings/{self.finding.pk}/confirm-check/")
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.status, VulnerabilityFinding.Status.RESOLVED)
        verification = DistroPatchVerification.objects.get(vulnerability_finding=self.finding)
        self.assertEqual(verification.verdict, DistroPatchVerification.Verdict.CONFIRMED_FIXED)
        self.assertEqual(verification.package_versions, {"apache2": "2.4.41-4ubuntu3.17"})
        self.assertIn("2.4.41-4ubuntu3.9", verification.note)
        self.assertNotContains(self.client.get(f"{base}/?tab=vulnerabilities"), "Confirm:")

        # 4. Qualys flags it again from the banner: it stays resolved.
        scan = ScanImport.objects.create(
            source=ScanImport.Source.MANUAL, status=ScanImport.Status.PARSING, perimeter=self.internal,
            scanned_at=timezone.now(),
        )
        detection = Detection(
            ip="192.0.2.10", hostname="web-01", qualys_host_id="", os="", qid="150495",
            title="Apache HTTP Server mod_lua", severity="high", qualys_severity=4, service_port="443/tcp",
        )
        counts = pipeline.run(scan, [detection], {})
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.status, VulnerabilityFinding.Status.RESOLVED)
        self.assertEqual((counts["findings_verified"], counts["findings_reopened"]), (1, 0))

        # 5. The package changes: the verification is flagged as outdated.
        self.post(f"{base}/packages/add/", {"package_name": "apache2", "installed_version": "2.4.41-4ubuntu3.8"})
        page = self.client.get(f"{base}/?tab=vulnerabilities")
        self.assertContains(page, "Outdated: Packages Changed")
        self.assertContains(page, "Confirm: Vulnerable, Update Available")

    def test_readonly_cannot_change_inventory(self):
        self.client.post("/account/logout/")
        User.objects.create_user("ro", "ro@example.com", "correct-horse-battery", role=User.Role.READONLY)
        self.client.post("/account/login/", {"username": "ro", "password": "correct-horse-battery"})
        base = f"/hosts/{self.host.pk}"
        self.assertEqual(self.client.post(f"{base}/packages/paste/", {"text": "apache2 1.0"}).status_code, 403)
        self.assertEqual(self.client.post(f"{base}/release/", {"ubuntu_release": "focal"}).status_code, 403)
        self.assertEqual(self.client.get(f"{base}/?tab=packages").status_code, 200)

    def test_invalid_manual_version_is_rejected(self):
        self.post(f"/hosts/{self.host.pk}/packages/add/", {"package_name": "apache2", "installed_version": "latest"})
        self.assertFalse(InstalledPackage.objects.exists())


class NameGuessTests(TestCase):
    def test_longest_source_name_wins(self):
        inv = packages(("libssh2-1", "1.10.0-3", ""), ("libssh-4", "0.9.6-2ubuntu0.22.04.3", ""))
        sources = ["libssh", "libssh2"]
        self.assertEqual([p.package_name for p in inv.find("libssh", sources)], ["libssh-4"])
        self.assertEqual([p.package_name for p in inv.find("libssh2", sources)], ["libssh2-1"])

    def test_known_source_is_used_as_is(self):
        inv = packages(("openssh-server", "1:8.9p1-3ubuntu0.10", "openssh"), ("openssh-sftp-server", "1:8.9p1-3ubuntu0.10", ""))
        self.assertEqual([p.package_name for p in inv.find("openssh")], ["openssh-server"])


class FixedVerdictInOverviewsTests(HostCheckFlowTests):
    """The appsrv case: Qualys reports it, the installed version fixes it; overviews must say so."""

    def test_full_flow(self):  # the parent's flow is not repeated here
        pass

    def test_readonly_cannot_change_inventory(self):
        pass

    def test_invalid_manual_version_is_rejected(self):
        pass

    def check_host(self):
        base = f"/hosts/{self.host.pk}"
        self.post(f"{base}/release/", {"ubuntu_release": "focal"})
        self.post(f"{base}/packages/paste/", {"text": "apache2 2.4.41-4ubuntu3.17"})
        self.assertEqual(PatchCheck.objects.get(vulnerability_finding=self.finding).verdict, Verdict.FIXED)

    def test_verdict_shows_everywhere_before_confirmation(self):
        self.check_host()
        # Vulnerabilities list: still New, but the Patch Check column says Fixed, to confirm.
        page = self.client.get("/vulnerabilities/")
        self.assertContains(page, ">Fixed</span>")
        self.assertContains(page, "To Confirm")
        pending = self.client.get("/vulnerabilities/?patch=fixed_pending").context["page"].object_list
        self.assertEqual([f.pk for f in pending], [self.finding.pk])
        # Hosts list and dashboard count it.
        host = next(h for h in self.client.get("/hosts/").context["hosts"] if h.pk == self.host.pk)
        self.assertEqual(host.open_patched, 1)
        self.assertEqual(self.client.get("/").context["fixed_pending"], 1)
        # The host page offers the one-click confirmation.
        self.assertContains(self.client.get(f"/hosts/{self.host.pk}/?tab=vulnerabilities"), "Confirm All Fixed (1)")

    def test_confirm_all_fixed_resolves_the_host(self):
        self.check_host()
        response = self.post(f"/hosts/{self.host.pk}/confirm-fixed/")
        self.assertEqual(response.status_code, 302)
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.status, VulnerabilityFinding.Status.RESOLVED)
        self.assertTrue(DistroPatchVerification.objects.filter(vulnerability_finding=self.finding, from_patch_check=True).exists())
        self.assertFalse(self.client.get("/vulnerabilities/?patch=fixed_pending").context["page"].object_list)
        self.assertContains(self.client.get("/vulnerabilities/?status=all"), "✓ Confirmed")
        self.assertNotContains(self.client.get(f"/hosts/{self.host.pk}/?tab=vulnerabilities"), "Confirm All Fixed")

    def test_vulnerable_verdicts_are_never_bulk_confirmed(self):
        base = f"/hosts/{self.host.pk}"
        self.post(f"{base}/release/", {"ubuntu_release": "focal"})
        self.post(f"{base}/packages/paste/", {"text": "apache2 2.4.41-4ubuntu3.8"})
        self.post(f"{base}/confirm-fixed/")
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.status, VulnerabilityFinding.Status.NEW)
        self.assertEqual(self.client.get("/vulnerabilities/?patch=vulnerable").context["page"].paginator.count, 1)

    def test_readonly_cannot_confirm_all(self):
        self.check_host()
        self.client.post("/account/logout/")
        User.objects.create_user("ro2", "ro2@example.com", "correct-horse-battery", role=User.Role.READONLY)
        self.client.post("/account/login/", {"username": "ro2", "password": "correct-horse-battery"})
        self.assertEqual(self.client.post(f"/hosts/{self.host.pk}/confirm-fixed/").status_code, 403)

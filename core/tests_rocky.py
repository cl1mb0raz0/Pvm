from unittest import mock

from django.test import TestCase
from django.utils import timezone

from . import patch_views, rocky, rocky_check, rockyversion
from .models import (
    AuditLog,
    Cve,
    DistroPatchVerification,
    Host,
    InstalledPackage,
    PatchCheck,
    Perimeter,
    VulnerabilityDefinition,
    VulnerabilityFinding,
)
from .tests_imports import ImportTestMixin

Verdict = PatchCheck.Verdict

# Trimmed shape of a real errata.rockylinux.org advisory (RLSA-2025:23049,
# checked live 2026-09-29 for CVE-2025-31651, Rocky Linux 9).
ADVISORY = {
    "name": "RLSA-2025:23049",
    "synopsis": "Important: tomcat security update",
    "severity": "SEVERITY_IMPORTANT",
    "affectedProducts": ["Rocky Linux 9"],
    # Real shape, checked live 2026-09-29: rpms[product] is {"nvras": [...]},
    # not a bare list.
    "rpms": {
        "Rocky Linux 9": {
            "nvras": [
                "tomcat-1:9.0.87-2.el9_9.1.noarch.rpm",
                "tomcat-1:9.0.87-2.el9_9.1.src.rpm",
                "tomcat-admin-webapps-1:9.0.87-2.el9_9.1.noarch.rpm",
                "tomcat-lib-1:9.0.87-2.el9_9.1.noarch.rpm",
            ]
        }
    },
}


class RockyVersionTests(TestCase):
    def test_basic_ordering(self):
        self.assertEqual(rockyversion.compare("9.0.87-1.el9", "9.0.87-2.el9"), -1)
        self.assertEqual(rockyversion.compare("9.0.87-2.el9", "9.0.87-2.el9"), 0)
        self.assertEqual(rockyversion.compare("9.0.87-2.el9", "9.0.87-1.el9"), 1)

    def test_epoch_dominates(self):
        self.assertEqual(rockyversion.compare("1.0-1", "1:0.1-1"), -1)
        self.assertEqual(rockyversion.compare("0:1.0-1", "1.0-1"), 0)

    def test_tilde_sorts_before_everything(self):
        self.assertTrue(rockyversion.compare("1.0-0.1.rc1", "1.0-1") < 0)
        self.assertTrue(rockyversion.compare("1.0~rc1-1", "1.0-1") < 0)

    def test_is_valid(self):
        self.assertTrue(rockyversion.is_valid("9.0.87-2.el9_9.1"))
        self.assertFalse(rockyversion.is_valid(""))
        self.assertFalse(rockyversion.is_valid(None))


class RockyTrackerTests(TestCase):
    def test_compact_parses_real_shaped_advisory(self):
        packages = rocky.compact([ADVISORY])
        self.assertEqual(set(packages), {"tomcat", "tomcat-admin-webapps", "tomcat-lib"})
        entry = packages["tomcat"]["9"]
        self.assertEqual(entry["status"], "released")
        self.assertEqual(entry["fixed"], "1:9.0.87-2.el9_9.1")
        self.assertEqual(entry["note"], "RLSA-2025:23049")
        # The source RPM is never installed on a host: left out.
        self.assertNotIn("tomcat.src", packages)

    def test_apply_record_ok_and_not_found(self):
        cve = Cve.objects.create(cve_id="CVE-2025-31651")
        rocky.apply_record(cve, [ADVISORY])
        cve.refresh_from_db()
        self.assertEqual(cve.rocky_status, Cve.NvdStatus.OK)
        self.assertIn("tomcat", cve.rocky_packages)
        self.assertEqual(cve.rocky_priority, "Important")

        other = Cve.objects.create(cve_id="CVE-2099-00001")
        rocky.apply_record(other, [])
        other.refresh_from_db()
        self.assertEqual(other.rocky_status, Cve.NvdStatus.NOT_FOUND)
        self.assertEqual(other.rocky_packages, {})

    def test_fetch_wraps_gateway_errors(self):
        import urllib.error

        with mock.patch("core.rocky.urllib.request.urlopen", side_effect=urllib.error.URLError("boom")):
            with self.assertRaises(rocky.RockyError):
                rocky.fetch("CVE-2025-31651")


class CheckFindingTests(ImportTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.host = Host.objects.create(
            hostname="rocky-a.example.test", ip_address="10.0.9.10", rocky_release="9",
            os_version="Rocky Enterprise Software Foundation Rocky Linux Blue Onyx (9.8)",
        )
        self.definition = VulnerabilityDefinition.objects.create(qid="700001", title="Tomcat", severity="high", qualys_severity=4)
        self.cve = Cve.objects.create(cve_id="CVE-2025-31651")
        rocky.apply_record(self.cve, [ADVISORY])
        self.definition.cves.add(self.cve)
        self.perimeter = Perimeter.objects.get(slug="internal")
        self.finding = VulnerabilityFinding.objects.create(
            host=self.host, vulnerability_definition=self.definition, perimeter=self.perimeter,
            first_detected_at=timezone.now(), last_detected_at=timezone.now(),
        )

    def test_fixed_when_installed_at_or_above(self):
        self.host.packages.create(package_name="tomcat", installed_version="1:9.0.87-2.el9_9.1", detected_at=timezone.now())
        counts = rocky_check.check_host(self.host)
        self.assertEqual(counts, {Verdict.FIXED: 1})
        check = self.finding.patch_check
        self.assertEqual(check.source, PatchCheck.Source.ROCKY_TRACKER)
        self.assertIn("≥ fixed", check.details[0]["packages"][0]["why"])

    def test_vulnerable_when_installed_below(self):
        self.host.packages.create(package_name="tomcat", installed_version="1:9.0.85-1.el9", detected_at=timezone.now())
        counts = rocky_check.check_host(self.host)
        self.assertEqual(counts, {Verdict.VULNERABLE_UPDATE: 1})

    def test_unknown_when_package_missing_from_inventory(self):
        counts = rocky_check.check_host(self.host)
        self.assertEqual(counts, {Verdict.UNKNOWN: 1})
        self.assertIn("tomcat", rocky_check.missing_packages(self.host))

    def test_unknown_when_release_not_covered(self):
        self.host.rocky_release = "8"
        self.host.save(update_fields=["rocky_release"])
        self.host.packages.create(package_name="tomcat", installed_version="1:9.0.85-1.el9", detected_at=timezone.now())
        counts = rocky_check.check_host(self.host)
        self.assertEqual(counts, {Verdict.UNKNOWN: 1})
        self.assertIn("No Fixed Package", self.finding.patch_check.details[0]["reason"])

    def test_check_host_requires_a_release(self):
        self.host.rocky_release = ""
        self.host.save(update_fields=["rocky_release"])
        with self.assertRaises(ValueError):
            rocky_check.check_host(self.host)


class ConfirmWorkflowTests(ImportTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.host = Host.objects.create(hostname="rocky-b.example.test", ip_address="10.0.9.11", rocky_release="9")
        self.host.packages.create(package_name="tomcat", installed_version="1:9.0.87-2.el9_9.1", detected_at=timezone.now())
        definition = VulnerabilityDefinition.objects.create(qid="700002", title="Tomcat", severity="high", qualys_severity=4)
        cve = Cve.objects.create(cve_id="CVE-2025-31651")
        rocky.apply_record(cve, [ADVISORY])
        definition.cves.add(cve)
        self.finding = VulnerabilityFinding.objects.create(
            host=self.host, vulnerability_definition=definition, perimeter=Perimeter.objects.get(slug="internal"),
            first_detected_at=timezone.now(), last_detected_at=timezone.now(),
        )
        rocky_check.check_host(self.host)

    def test_confirm_resolves_and_records_the_advisory_link(self):
        response = self.client.post(f"/findings/{self.finding.pk}/confirm-check/", follow=True)
        self.assertContains(response, "Verification Recorded")
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.status, VulnerabilityFinding.Status.RESOLVED)
        v = DistroPatchVerification.objects.get(vulnerability_finding=self.finding)
        self.assertEqual(v.source, PatchCheck.Source.ROCKY_TRACKER)
        self.assertEqual(v.verdict, DistroPatchVerification.Verdict.CONFIRMED_FIXED)
        self.assertEqual(v.reference_url, "https://errata.rockylinux.org/RLSA-2025:23049")

    def test_set_release_view_uses_the_rocky_field_for_a_rocky_host(self):
        self.host.os_version = "Rocky Enterprise Software Foundation Rocky Linux Blue Onyx (9.8)"
        self.host.rocky_release = ""
        self.host.save(update_fields=["os_version", "rocky_release"])
        response = self.client.post(f"/hosts/{self.host.pk}/release/", {"rocky_release": "9"})
        self.assertEqual(response.status_code, 302)
        self.host.refresh_from_db()
        self.assertEqual(self.host.rocky_release, "9")
        self.assertTrue(AuditLog.objects.filter(entity_id=str(self.host.pk), action="host.release_set").exists())


class HostPropertyTests(TestCase):
    def test_is_rocky(self):
        self.assertTrue(Host(os_version="Rocky Enterprise Software Foundation Rocky Linux Blue Onyx (9.8)").is_rocky)
        self.assertFalse(Host(os_version="Canonical Ubuntu Jammy Jellyfish (22.04.5 LTS)").is_rocky)
        self.assertFalse(Host().is_rocky)

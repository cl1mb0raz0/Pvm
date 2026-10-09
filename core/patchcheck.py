"""
Check findings against the Ubuntu security tracker, using what is known
about the host: its Ubuntu release and its installed packages.

For each CVE of a finding's QID, the tracker (core.ubuntu) says which
source packages are affected and, for the host's release, whether and in
which version each was fixed. The installed version of the matching
package is compared with the fixed one (core.debversion). The finding's
verdict is the worst of its CVEs'. Verdicts are advisory: an analyst
confirms them (see patch_views.confirm_patch_check).

What cannot be checked this way, and is reported as "Cannot verify" with
the reason: software not installed through apt, CVEs Ubuntu does not
track, the kernel (the running kernel matters, not installed packages),
and packages missing from the host's inventory, which are listed so they
can be asked for.
"""

import re

from django.utils import timezone

from . import debversion
from .models import Cve, DistroPatchVerification, PatchCheck, VulnerabilityFinding

Verdict = PatchCheck.Verdict

# Worst first wins when combining packages or CVEs.
RANK = {
    Verdict.NOT_AFFECTED: 0,
    Verdict.FIXED: 1,
    Verdict.UNKNOWN: 2,
    Verdict.VULNERABLE_UPDATE: 3,
    Verdict.VULNERABLE_PRO: 4,
    Verdict.VULNERABLE_NO_FIX: 5,
}
STILL_AFFECTED = {"needed", "needs-triage", "pending", "deferred", "active", "ignored"}
KERNEL = re.compile(r"^linux($|-)")

# Verification verdicts that mean "the distro fixed it, not vulnerable".
NOT_VULNERABLE_VERDICTS = {
    DistroPatchVerification.Verdict.CONFIRMED_FIXED,
    DistroPatchVerification.Verdict.LIKELY_FALSE_POSITIVE,
}


# Check verdicts meaning the installed version is not vulnerable.
NOT_VULNERABLE_CHECKS = [Verdict.FIXED, Verdict.NOT_AFFECTED]

# What confirming a check records as the distro patch verification.
CONFIRMED_AS = {
    Verdict.FIXED: DistroPatchVerification.Verdict.CONFIRMED_FIXED,
    Verdict.NOT_AFFECTED: DistroPatchVerification.Verdict.LIKELY_FALSE_POSITIVE,
    Verdict.VULNERABLE_UPDATE: DistroPatchVerification.Verdict.CONFIRMED_VULNERABLE,
    Verdict.VULNERABLE_PRO: DistroPatchVerification.Verdict.CONFIRMED_VULNERABLE,
    Verdict.VULNERABLE_NO_FIX: DistroPatchVerification.Verdict.CONFIRMED_VULNERABLE,
}


def worst(verdicts, default=Verdict.UNKNOWN):
    return max(verdicts, key=RANK.__getitem__, default=default)


class Inventory:
    """A host's installed packages, looked up by the source package names the tracker uses."""

    def __init__(self, packages):
        self.packages = list(packages)

    def find(self, source, all_sources=()):
        exact = [p for p in self.packages if p.source_package == source]
        if exact:
            return exact
        # Entered by hand without a source name: the binary is often named
        # like the source (apache2), or source + suffix (openssh-server,
        # libwebp7). Only for entries whose source package is unknown, and
        # only if no longer source name in the same CVE fits better
        # (libssh2-1 belongs to libssh2, not libssh).
        return [
            p
            for p in self.packages
            if not p.source_package
            and _guess_matches(source, p.package_name)
            and not any(len(o) > len(source) and _guess_matches(o, p.package_name) for o in all_sources)
        ]


def _guess_matches(source, binary):
    return re.match(rf"^{re.escape(source)}(-.+|\d[\w.+-]*)?$", binary) is not None


def _package_verdict(entry, installed):
    status, fixed = entry["status"], entry["fixed"]
    if status == "released":
        if not debversion.is_valid(fixed):
            return Verdict.UNKNOWN, f"Fixed version given as “{fixed}”, cannot compare"
        if debversion.compare(installed, fixed) >= 0:
            return Verdict.FIXED, f"{installed} ≥ fixed {fixed}"
        if entry["pocket"].startswith("esm"):
            return Verdict.VULNERABLE_PRO, f"{installed} < fixed {fixed}, only in Ubuntu Pro ({entry['pocket']})"
        return Verdict.VULNERABLE_UPDATE, f"{installed} < fixed {fixed}: update to {fixed} or later"
    if status == "not-affected":
        return Verdict.NOT_AFFECTED, entry["note"] or "Ubuntu: not affected"
    if status in STILL_AFFECTED:
        return Verdict.VULNERABLE_NO_FIX, f"Ubuntu status “{status}”" + (f": {entry['note']}" if entry["note"] else "")
    return Verdict.UNKNOWN, f"Unknown Ubuntu status “{status}”"


def check_cve(cve, release, inventory):
    """Verdict and evidence for one CVE on one host."""
    result = {"cve": cve.cve_id, "packages": [], "missing": [], "reason": ""}
    if cve.ubuntu_status != Cve.NvdStatus.OK:
        result["verdict"] = Verdict.UNKNOWN
        result["reason"] = {
            Cve.NvdStatus.NOT_FOUND: "Not Tracked by Ubuntu",
            Cve.NvdStatus.ERROR: f"Ubuntu Tracker Lookup Failed: {cve.ubuntu_error}",
        }.get(cve.ubuntu_status, "Not Fetched from the Ubuntu Tracker Yet")
        return result

    relevant = {
        source: releases[release]
        for source, releases in cve.ubuntu_packages.items()
        if release in releases and releases[release]["status"] != "DNE"
    }
    if not relevant:
        result["verdict"] = Verdict.UNKNOWN
        result["reason"] = f"Ubuntu Lists No Package for {release}"
        return result

    verdicts = []
    for source, entry in sorted(relevant.items()):
        if KERNEL.match(source):
            result["missing"].append(source)
            continue
        installed = inventory.find(source, cve.ubuntu_packages.keys())
        if not installed:
            result["missing"].append(source)
            continue
        for package in installed:
            verdict, why = _package_verdict(entry, package.version_for_tracker)
            verdicts.append(verdict)
            result["packages"].append(
                {
                    "source": source,
                    "package": package.package_name,
                    "installed": package.version_for_tracker,
                    "status": entry["status"],
                    "fixed": entry["fixed"],
                    "pocket": entry["pocket"],
                    "verdict": verdict,
                    "why": why,
                }
            )
    if not verdicts:
        result["verdict"] = Verdict.UNKNOWN
        kernel = [s for s in result["missing"] if KERNEL.match(s)]
        if kernel and len(kernel) == len(result["missing"]):
            result["reason"] = "Kernel Package: Needs the Running Kernel Version, Not Supported Yet"
        else:
            result["reason"] = "None of the Affected Packages Is in This Host's Inventory"
        return result
    result["verdict"] = worst(verdicts)
    return result


def check_finding(finding, inventory):
    """Create or update the finding's PatchCheck; None (and no check) if its QID has no CVE."""
    cves = list(finding.vulnerability_definition.cves.all())
    if not cves:
        PatchCheck.objects.filter(vulnerability_finding=finding).delete()
        return None
    release = finding.host.ubuntu_release
    details = [check_cve(cve, release, inventory) for cve in cves]
    versions = {p["package"]: p["installed"] for d in details for p in d["packages"]}
    check, _ = PatchCheck.objects.update_or_create(
        vulnerability_finding=finding,
        defaults={
            "verdict": worst(d["verdict"] for d in details),
            "ubuntu_release": release,
            "details": details,
            "package_versions": versions,
            "checked_at": timezone.now(),
        },
    )
    return check


def findings_to_check(host):
    """Open findings, plus resolved ones whose verification may need re-checking."""
    return (
        VulnerabilityFinding.objects.filter(host=host)
        .exclude(status=VulnerabilityFinding.Status.RESOLVED, distro_verification__isnull=True)
        .select_related("vulnerability_definition", "host")
        .prefetch_related("vulnerability_definition__cves")
    )


def check_host(host):
    """Re-check every relevant finding of `host`. Returns {verdict: count}."""
    if not host.ubuntu_release:
        raise ValueError("Set the Host's Ubuntu Release First.")
    inventory = Inventory(host.packages.all())
    counts = {}
    for finding in findings_to_check(host):
        check = check_finding(finding, inventory)
        if check:
            counts[check.verdict] = counts.get(check.verdict, 0) + 1
    return counts


def missing_packages(host):
    """Source packages the tracker needs versions for, to verify this host's open findings."""
    missing = set()
    checks = PatchCheck.objects.filter(
        vulnerability_finding__host=host, verdict=Verdict.UNKNOWN
    ).exclude(vulnerability_finding__status=VulnerabilityFinding.Status.RESOLVED)
    for check in checks:
        for detail in check.details:
            if detail["verdict"] == Verdict.UNKNOWN:
                missing.update(s for s in detail["missing"] if not KERNEL.match(s))
    return sorted(missing)


def needs_confirmation(check, verification, verification_outdated):
    """Offer "Confirm" unless the current verdict is already the recorded, up-to-date verification."""
    if check is None or check.verdict not in CONFIRMED_AS:
        return False
    if verification is None or not verification.from_patch_check or verification_outdated:
        return True
    return CONFIRMED_AS[check.verdict] != verification.verdict


def verification_is_current(verification, inventory_versions):
    """False when a package the verification was based on changed version or disappeared."""
    return all(inventory_versions.get(name) == version for name, version in verification.package_versions.items())

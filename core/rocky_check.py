"""
Check findings against Rocky Linux's own errata (core.rocky), using the
host's release and installed packages - the Rocky equivalent of
core.patchcheck (Ubuntu) and core.qualys_pm (Windows). All three write
the same PatchCheck (a `source` tells them apart) and share the "Patch
Check" column/filter and the Confirm workflow (core.patch_views); only
how a verdict is computed differs here.

For each CVE of a finding's QID, Rocky's errata says which RPM packages
were fixed, at which version, for the host's release. The installed
version is compared with core.rockyversion (RPM's own version rules, not
Debian's). The finding's verdict is the worst of its CVEs'. Verdicts are
advisory: an analyst confirms them (core.patch_views.confirm_patch_check).

Unlike Ubuntu's tracker, Rocky's errata only records issued fixes (see
core.rocky's docstring): a package with no matching advisory for the
host's release is reported "cannot verify", never "not affected" - this
module never claims that itself, since it cannot tell "not affected"
apart from "affected, no fix out yet" from this data alone.

What cannot be checked this way, and is reported as "Cannot verify" with
the reason: CVEs Rocky's errata does not track (nothing published for
this release yet), and packages missing from the host's inventory (no
source-package guessing needed here, unlike Ubuntu's dpkg binary/source
split: Rocky's errata already names the installed RPM directly).
"""

from django.utils import timezone

from . import rockyversion
from .models import Cve, PatchCheck, VulnerabilityFinding
from .patchcheck import findings_to_check, worst  # generic: no Ubuntu specifics in either

Verdict = PatchCheck.Verdict


def _package_verdict(entry, installed):
    fixed = entry["fixed"]
    if not rockyversion.is_valid(fixed):
        return Verdict.UNKNOWN, f"Fixed version given as “{fixed}”, cannot compare"
    if rockyversion.compare(installed, fixed) >= 0:
        return Verdict.FIXED, f"{installed} ≥ fixed {fixed}"
    return Verdict.VULNERABLE_UPDATE, f"{installed} < fixed {fixed}: update to {fixed} or later"


def check_cve(cve, release, packages):
    """Verdict and evidence for one CVE on one host. `packages`: {package name: InstalledPackage}."""
    result = {"cve": cve.cve_id, "packages": [], "missing": [], "reason": ""}
    if cve.rocky_status != Cve.NvdStatus.OK:
        result["verdict"] = Verdict.UNKNOWN
        result["reason"] = {
            Cve.NvdStatus.NOT_FOUND: "No Fixed Package Published by Rocky for Any Release Yet",
            Cve.NvdStatus.ERROR: f"Rocky Errata Lookup Failed: {cve.rocky_error}",
        }.get(cve.rocky_status, "Not Fetched from Rocky's Errata Yet")
        return result

    relevant = {name: releases[release] for name, releases in cve.rocky_packages.items() if release in releases}
    if not relevant:
        result["verdict"] = Verdict.UNKNOWN
        result["reason"] = f"Rocky Lists No Fixed Package for Release {release}"
        return result

    verdicts = []
    for name, entry in sorted(relevant.items()):
        package = packages.get(name)
        if not package:
            result["missing"].append(name)
            continue
        verdict, why = _package_verdict(entry, package.version_for_tracker)
        verdicts.append(verdict)
        result["packages"].append(
            {
                "source": name,
                "package": package.package_name,
                "installed": package.version_for_tracker,
                "status": entry["status"],
                "fixed": entry["fixed"],
                "pocket": "",
                "advisory": entry.get("note", ""),
                "verdict": verdict,
                "why": why,
            }
        )
    if not verdicts:
        result["verdict"] = Verdict.UNKNOWN
        result["reason"] = "None of the Fixed Packages Is in This Host's Inventory"
        return result
    result["verdict"] = worst(verdicts)
    return result


def check_finding(finding, packages):
    """Create or update the finding's PatchCheck; None (and no check) if its QID has no CVE."""
    cves = list(finding.vulnerability_definition.cves.all())
    if not cves:
        PatchCheck.objects.filter(vulnerability_finding=finding).delete()
        return None
    release = finding.host.rocky_release
    details = [check_cve(cve, release, packages) for cve in cves]
    versions = {p["package"]: p["installed"] for d in details for p in d["packages"]}
    check, _ = PatchCheck.objects.update_or_create(
        vulnerability_finding=finding,
        defaults={
            "verdict": worst(d["verdict"] for d in details),
            "source": PatchCheck.Source.ROCKY_TRACKER,
            "ubuntu_release": "",
            "details": details,
            "package_versions": versions,
            "checked_at": timezone.now(),
        },
    )
    return check


def check_host(host):
    """Re-check every relevant finding of `host`. Returns {verdict: count}."""
    if not host.rocky_release:
        raise ValueError("Set the Host's Rocky Release First.")
    packages = {p.package_name: p for p in host.packages.all()}
    counts = {}
    for finding in findings_to_check(host):
        check = check_finding(finding, packages)
        if check:
            counts[check.verdict] = counts.get(check.verdict, 0) + 1
    return counts


def missing_packages(host):
    """Fixed packages Rocky lists for this host's open findings that are not in its inventory."""
    missing = set()
    checks = PatchCheck.objects.filter(
        vulnerability_finding__host=host, verdict=Verdict.UNKNOWN, source=PatchCheck.Source.ROCKY_TRACKER
    ).exclude(vulnerability_finding__status=VulnerabilityFinding.Status.RESOLVED)
    for check in checks:
        for detail in check.details:
            if detail["verdict"] == Verdict.UNKNOWN:
                missing.update(detail["missing"])
    return sorted(missing)

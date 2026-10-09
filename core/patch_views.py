"""
Host inventory (Ubuntu/Rocky release, installed packages) and the checks
of its findings against the Ubuntu security tracker or Rocky Linux's own
errata. All changes need an editor (admin/analyst); see core.patchcheck
and core.rocky_check for how verdicts are computed.
"""

from django.contrib import messages
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_POST

from accounts.permissions import editor_required

from . import audit, debversion, inventory, package_share, patchcheck
from .models import DistroPatchVerification, Host, InstalledPackage, PatchCheck, VulnerabilityFinding
from .rocky import ADVISORY_PAGE as ROCKY_ADVISORY_PAGE
from .tasks import check_host_patches
from .ubuntu import TRACKER_PAGE

Verdict = PatchCheck.Verdict
Status = VulnerabilityFinding.Status

CONFIRMED_AS = patchcheck.CONFIRMED_AS


def _host_tab(host, tab):
    return redirect(reverse("core:host_detail", args=[host.pk]) + f"?tab={tab}")


def start_check(host, retry_errors=False):
    """
    Queue a re-check of `host` once the current transaction commits, against
    whichever source applies (Ubuntu tracker or Rocky errata).
    `retry_errors`: ask it again for CVEs it just failed to answer
    ("Check Now"; otherwise they wait UBUNTU_ERROR_RETRY_MINUTES /
    ROCKY_ERROR_RETRY_MINUTES).
    """
    if not host.ubuntu_release and not host.rocky_release:
        return False
    Host.objects.filter(pk=host.pk).update(patch_check_state="running", patch_check_error="", patch_check_done=0, patch_check_total=0)

    def enqueue():
        try:
            check_host_patches.delay(host.pk, retry_errors=retry_errors)
        except Exception as exc:  # broker unreachable
            Host.objects.filter(pk=host.pk).update(
                patch_check_state="failed", patch_check_error=f"Could Not Queue the Check: {exc}"[:255]
            )

    transaction.on_commit(enqueue)
    return True


@editor_required
@require_POST
def set_release(request, pk):
    host = get_object_or_404(Host, pk=pk)
    if host.is_rocky:
        release = request.POST.get("rocky_release", "")
        if release and release not in Host.RockyRelease.values:
            messages.error(request, "Unknown Rocky Linux Release.")
            return _host_tab(host, "packages")
        host.rocky_release = release
        host.save(update_fields=["rocky_release"])
    else:
        release = request.POST.get("ubuntu_release", "")
        if release and release not in Host.UbuntuRelease.values:
            messages.error(request, "Unknown Ubuntu Release.")
            return _host_tab(host, "packages")
        host.ubuntu_release = release
        host.save(update_fields=["ubuntu_release"])
    audit.log(request.user, "host.release_set", host, release=release)
    start_check(host)
    return _host_tab(host, "packages")


@editor_required
@require_POST
def paste_inventory(request, pk):
    host = get_object_or_404(Host, pk=pk)
    release, entries, errors = inventory.parse(request.POST.get("text", ""))
    if release and release in Host.UbuntuRelease.values and release != host.ubuntu_release:
        host.ubuntu_release = release
        host.save(update_fields=["ubuntu_release"])
        messages.info(request, f"Ubuntu Release Set to {host.get_ubuntu_release_display()} from the Pasted Text.")

    created, removed = inventory.store(
        host, entries, request.user, InstalledPackage.Source.PASTED, replace=bool(request.POST.get("replace"))
    )

    if entries:
        audit.log(request.user, "inventory.pasted", host, packages=len(entries), removed=removed)
        messages.success(
            request,
            f"{len(entries)} Package{'s' if len(entries) != 1 else ''} Saved ({created} New, "
            f"{len(entries) - created} Updated{f', {removed} Removed' if removed else ''}).",
        )
        start_check(host)
    if errors:
        shown = "; ".join(errors[:3]) + ("…" if len(errors) > 3 else "")
        messages.warning(request, f"{len(errors)} Line{'s' if len(errors) != 1 else ''} Not Understood: {shown}")
    if not entries and not errors and not release:
        messages.warning(request, "Nothing to Save: The Text Was Empty.")
    return _host_tab(host, "packages")


@editor_required
@require_POST
def add_package(request, pk):
    host = get_object_or_404(Host, pk=pk)
    name = request.POST.get("package_name", "").strip().split(":")[0]
    version = request.POST.get("installed_version", "").strip()
    source = request.POST.get("source_package", "").strip()
    if not inventory.PACKAGE_NAME.match(name) or not debversion.is_valid(version):
        messages.error(request, "Enter a Package Name and a Full Version, e.g. apache2 and 2.4.41-4ubuntu3.17.")
        return _host_tab(host, "packages")
    if source and not inventory.PACKAGE_NAME.match(source):
        messages.error(request, "The Source Package Name Is Not Valid.")
        return _host_tab(host, "packages")
    InstalledPackage.objects.update_or_create(
        host=host,
        package_name=name,
        defaults={
            "installed_version": version,
            "source_package": source,
            "source_version": "",
            "source": InstalledPackage.Source.MANUAL,
            "detected_at": timezone.now(),
            "created_by": request.user,
        },
    )
    audit.log(request.user, "inventory.package_set", host, package=name, version=version)
    messages.success(request, f"{name} {version} Saved.")
    start_check(host)
    if request.POST.get("review_siblings"):
        package = InstalledPackage.objects.get(host=host, package_name=name)
        return redirect("core:host_share_package", pk=host.pk, package_pk=package.pk)
    return _host_tab(host, "packages")


@editor_required
def share_package(request, pk, package_pk):
    """Preview of the sites on the same private server a package could be copied to, then the copy."""
    host = get_object_or_404(Host.objects.prefetch_related("other_private_ips"), pk=pk)
    package = get_object_or_404(InstalledPackage, pk=package_pk, host=host)
    rows = package_share.siblings(host, package)
    if request.method == "POST":
        wanted = {int(i) for i in request.POST.getlist("host") if i.isdigit()}
        targets = [r["host"] for r in rows if r["host"].pk in wanted]  # only hosts the preview offered
        if not targets:
            messages.error(request, "Tick at Least One Site to Apply It To.")
            return redirect("core:host_share_package", pk=host.pk, package_pk=package.pk)
        rechecked = 0
        with transaction.atomic():
            for target in package_share.copy_package(package, targets, request.user, timezone.now()):
                audit.log(
                    request.user, "inventory.package_copied", target,
                    package=package.package_name, version=package.installed_version, from_host=host.hostname,
                )
                rechecked += start_check(target)
        messages.success(
            request,
            f"{package.package_name} {package.installed_version} Applied to {len(targets)} Site{'s' if len(targets) != 1 else ''}"
            f"{f'; the Patch Check Runs Again on {rechecked}' if rechecked else ''}.",
        )
        return _host_tab(host, "packages")
    for row in rows:
        row["checked"] = package_share.preselected(row)
    return render(
        request,
        "core/package_share.html",
        {
            "host": host,
            "package": package,
            "rows": rows,
            "full_count": sum(1 for r in rows if r["full"]),
            "partial_count": sum(1 for r in rows if not r["full"]),
        },
    )


@editor_required
@require_POST
def delete_package(request, pk, package_pk):
    package = get_object_or_404(InstalledPackage, pk=package_pk, host_id=pk)
    audit.log(request.user, "inventory.package_deleted", package.host, package=package.package_name)
    package.delete()
    start_check(package.host)
    return _host_tab(package.host, "packages")


@editor_required
@require_POST
def run_check(request, pk):
    host = get_object_or_404(Host, pk=pk)
    if not start_check(host, retry_errors=True):
        messages.error(request, "Set the Host's Ubuntu Release First (Installed Packages Tab).")
    return _host_tab(host, "vulnerabilities")


@editor_required
@require_POST
def confirm_check(request, finding_pk):
    finding = get_object_or_404(VulnerabilityFinding.objects.select_related("host", "patch_check"), pk=finding_pk)
    check = getattr(finding, "patch_check", None)
    if check is None or check.verdict not in CONFIRMED_AS:
        messages.error(request, "There Is No Conclusive Check to Confirm for This Finding.")
        return _host_tab(finding.host, "vulnerabilities")
    record_confirmation(finding, check, request.user)
    messages.success(request, f"Verification Recorded: {check.get_verdict_display()}.")
    return _host_tab(finding.host, "vulnerabilities")


@editor_required
@require_POST
def confirm_all_fixed(request, pk):
    """Confirm, in one go, every "fixed" / "not affected" verdict of a host still awaiting confirmation."""
    host = get_object_or_404(Host, pk=pk)
    confirmed = 0
    for finding in awaiting_confirmation(host):
        record_confirmation(finding, finding.patch_check, request.user)
        confirmed += 1
    if confirmed:
        messages.success(request, f"{confirmed} Finding{'s' if confirmed != 1 else ''} Confirmed Fixed and Resolved.")
    else:
        messages.info(request, "Nothing to Confirm: No Fixed Verdict Is Awaiting Confirmation.")
    return _host_tab(host, "vulnerabilities")


def awaiting_confirmation(host):
    """The host's findings whose check says not vulnerable and that no current verification records."""
    installed = {p.package_name: p.version_for_tracker for p in host.packages.all()}
    findings = VulnerabilityFinding.objects.filter(
        host=host, patch_check__verdict__in=patchcheck.NOT_VULNERABLE_CHECKS
    ).select_related("patch_check", "distro_verification")
    result = []
    for f in findings:
        verification = getattr(f, "distro_verification", None)
        outdated = bool(
            verification
            and verification.from_patch_check
            and not patchcheck.verification_is_current(verification, installed)
        )
        if patchcheck.needs_confirmation(f.patch_check, verification, outdated):
            result.append(f)
    return result


def _pm_reference_url(check):
    kb = next((d.get("kb") for d in check.details if d.get("kb")), "")
    return f"https://support.microsoft.com/kb/{kb}" if kb and kb[0].isdigit() else ""


def _rocky_reference_url(check):
    advisory = next((p.get("advisory") for d in check.details for p in d["packages"] if p.get("advisory")), "")
    return ROCKY_ADVISORY_PAGE.format(advisory) if advisory else ""


def record_confirmation(finding, check, user):
    """Record the check's verdict as the finding's distro patch verification and update its status."""
    if check.source == PatchCheck.Source.QUALYS_PM:
        lines = [f"Checked Against Qualys Patch Management: {check.get_verdict_display()}."]
        reference_url = _pm_reference_url(check)
    elif check.source == PatchCheck.Source.ROCKY_TRACKER:
        lines = [f"Checked Against {finding.host.get_rocky_release_display()}'s Errata: {check.get_verdict_display()}."]
        reference_url = _rocky_reference_url(check)
    else:
        lines = [f"Checked Against the Ubuntu Security Tracker for {check.ubuntu_release}: {check.get_verdict_display()}."]
        reference_url = TRACKER_PAGE.format(check.details[0]["cve"]) if check.details else ""
    for detail in check.details:
        evidence = "; ".join(f"{p['package']}: {p['why']}" for p in detail["packages"]) or detail["reason"]
        prefix = f"{detail['cve']}: " if detail.get("cve") else ""
        lines.append(f"{prefix}{Verdict(detail['verdict']).label} ({evidence})")
    with transaction.atomic():
        DistroPatchVerification.objects.filter(vulnerability_finding=finding).delete()
        DistroPatchVerification.objects.create(
            vulnerability_finding=finding,
            verified_by=user,
            verdict=CONFIRMED_AS[check.verdict],
            source=check.source,
            note="\n".join(lines),
            reference_url=reference_url,
            from_patch_check=True,
            package_versions=check.package_versions,
        )
        if check.is_not_vulnerable:
            finding.status = Status.RESOLVED
            finding.resolved_at = timezone.now()
        elif finding.status in (Status.NEW, Status.NEEDS_REVIEW, Status.RESOLVED):
            finding.status = Status.STILL_OPEN
            finding.resolved_at = None
        finding.save(update_fields=["status", "resolved_at"])
        audit.log(user, "finding.patch_check_confirmed", finding, verdict=check.verdict)

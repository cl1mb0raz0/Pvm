"""
Imports > Mapping: upload a file, PVM recognizes what it is (core.mapping)
and previews what it would change; applying takes a backup first. Today a
public/private IP mapping (core.network_mapping) or an A10 configuration
(core.balancer).
"""

from django.contrib import messages
from django.core import signing
from django.db.models import F, Max
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from accounts.permissions import editor_required
from backups.models import Backup
from backups.service import create_backup

from . import audit, balancer, mapping, network_mapping
from .models import BalancerConfig, PrivateIpMapping
from .sorting import sort_rows, sorting

SIGNING_SALT = "pvm.mapping"
PREVIEW_MAX_AGE = 3600
MAX_UPLOAD_BYTES = 5 * 1024 * 1024
SHOWN = 300


# The two stored tables of the Mapping page. The balancer one sorts in Python
# (its counts live in a JSON field); each has its own query keys.
CONFIG_COLUMNS = [
    ("balancer", "Balancer", lambda c: c.name.lower(), "asc", False),
    ("software", "Software", lambda c: c.product, "asc", False),
    ("servers", "Servers", lambda c: c.counts.get("servers"), "desc", True),
    ("pools", "Pools", lambda c: c.counts.get("service_groups"), "desc", True),
    ("vips", "VIPs", lambda c: c.counts.get("vips"), "desc", True),
    ("rules", "Name Rules", lambda c: c.counts.get("rules"), "desc", True),
    ("file", "File", lambda c: c.filename, "asc", False),
    ("uploaded", "Uploaded", lambda c: c.uploaded_at, "desc", False),
    ("actions", "", None, "asc", False),
]
MAPPING_COLUMNS = [
    ("public", "Public IP", "public_ip", "asc", False),
    ("hostname", "DNS Hostname", "hostname", "asc", False),
    ("private", "Private IP", "private_ip", "asc", False),
    ("by", "Uploaded By", "uploaded_by__username", "asc", False),
]


@editor_required
def page(request):
    stored = PrivateIpMapping.objects.all()
    field, direction, sort, headers = sorting(request, MAPPING_COLUMNS, "public", prefix="map_")
    column = F(field).asc(nulls_last=True) if direction == "asc" else F(field).desc(nulls_last=True)
    value, lb_direction, lb_sort, lb_headers = sorting(request, CONFIG_COLUMNS, "balancer", prefix="lb_")
    return render(
        request,
        "core/imports/network_mapping.html",
        {
            "stored": stored.order_by(column, "public_ip")[:SHOWN],
            "stored_count": stored.count(),
            "last_upload": stored.aggregate(last=Max("uploaded_at"))["last"],
            "shown": SHOWN,
            "configs": sort_rows(list(BalancerConfig.objects.select_related("uploaded_by")), value, lb_direction),
            "headers": headers,
            "map_sort": sort,
            "map_dir": direction,
            "lb_headers": lb_headers,
            "lb_sort": lb_sort,
            "lb_dir": lb_direction,
        },
    )


@editor_required
@require_POST
def upload(request):
    report = request.FILES.get("file")
    if not report:
        messages.error(request, "Choose a File.")
        return redirect("core:network_mapping")
    if report.size > MAX_UPLOAD_BYTES:
        messages.error(request, "The File Is Larger than 5 MB.")
        return redirect("core:network_mapping")
    readings = mapping.analyze(report.read())
    best, others = readings[0], readings[1:]
    context = {"reading": best, "others": others, "filename": report.name}
    if best.can_import:
        context["payload"] = signing.dumps({"kind": best.kind, "data": best.data}, salt=SIGNING_SALT, compress=True)
        if best.kind == "ip_mapping":
            planned = network_mapping.plan(best.data["rows"])
            context["rows"] = planned
            context["counts"] = {
                status.replace(" ", "_"): sum(1 for r in planned if r["status"] == status)
                for status in ("new", "changed", "same", "no host", "error")
            }
            context["hosts_to_change"] = sum(1 for r in planned for c in r["hosts"] if c["current"] != c["target"])
            context["useful"], context["verdict"] = network_mapping.verdict(planned)
        else:
            context["plan"] = balancer.plan(best.data)
            context["useful"], context["verdict"] = context["plan"]["useful"], context["plan"]["verdict"]
    audit.log(
        request.user, "mapping.analyzed", request.user,
        filename=report.name[:200], kind=best.kind, confidence=best.confidence, can_import=best.can_import,
    )
    return render(request, "core/imports/network_preview.html", context)


@editor_required
@require_POST
def apply(request):
    try:
        payload = signing.loads(request.POST.get("payload", ""), salt=SIGNING_SALT, max_age=PREVIEW_MAX_AGE)
    except signing.BadSignature:
        messages.error(request, "The Preview Expired or Was Altered: Upload the File Again.")
        return redirect("core:network_mapping")
    filename = request.POST.get("filename", "")[:200]

    # Never change hosts without a way back: back up first, and stop if that fails.
    backup = create_backup(Backup.Kind.PRE_MAPPING, request.user, note=f"Automatic, Before Mapping ({filename})")
    if backup.status != Backup.Status.COMPLETED:
        messages.error(request, f"The Backup Before the Mapping Failed, Nothing Was Changed: {backup.error_message}")
        return redirect("core:network_mapping")

    if payload["kind"] == "a10":
        result = balancer.apply(payload["data"], request.user, filename)
        audit.log(
            request.user, "mapping.balancer_applied", result["config"],
            filename=filename, balancer=result["config"].name, routes=result["routes"],
            hosts_changed=result["hosts_changed"], vips_marked=result["vips_marked"], backup=backup.pk,
        )
        messages.success(
            request,
            f"{result['config'].name} Configuration Applied: Real Servers Set on {result['hosts_changed']} "
            f"Host{'s' if result['hosts_changed'] != 1 else ''}, {result['vips_marked']} VIP{'s' if result['vips_marked'] != 1 else ''} "
            "Marked as Load Balancer. Kept for Hosts That Appear Later. Search Qualys Csam Again to Match the Internal Servers.",
        )
        return redirect("core:network_mapping")

    rows = payload["data"]["rows"]
    name = request.POST.get("balancer_name", "").strip() if request.POST.get("mark_balancer") else ""
    changed, stored = network_mapping.apply(rows, request.user, name)
    audit.log(
        request.user, "network.mapping_applied", request.user,
        filename=filename, rows=stored, hosts_changed=changed, balancer=name, backup=backup.pk,
    )
    messages.success(
        request,
        f"Network Mapping Applied: Private IP Set on {changed} Host{'s' if changed != 1 else ''}, {stored} Row{'s' if stored != 1 else ''} Kept "
        "for Hosts That Appear Later. Search Qualys Csam Again to Match the Internal Servers.",
    )
    return redirect("core:network_mapping")


@editor_required
@require_POST
def clear(request):
    count, _ = PrivateIpMapping.objects.all().delete()
    audit.log(request.user, "network.mapping_cleared", request.user, rows=count)
    messages.success(request, "Stored Mapping Cleared. Private IPs Already Set on Hosts Are Kept.")
    return redirect("core:network_mapping")


@editor_required
@require_POST
def delete_config(request, pk):
    config = get_object_or_404(BalancerConfig, pk=pk)
    audit.log(request.user, "mapping.balancer_deleted", config, balancer=config.name)
    config.delete()
    messages.success(request, f"{config.name} Configuration Deleted. Private IPs Already Set on Hosts Are Kept.")
    return redirect("core:network_mapping")

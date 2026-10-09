"""
Imports > Qualys Scans: the finished scans of the Qualys subscription, to
import by hand, or to import automatically with a rule the user creates.
Nothing is imported unless someone picks it (core.qualys).
"""

import re
from datetime import time as dt_time

from django.conf import settings
from django.contrib import messages
from django.core.cache import cache
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from accounts.permissions import can_manage_settings, editor_required, require

from . import audit, qualys, tags
from .models import Perimeter, QualysImportRule, ScanImport, Tag
from .sorting import sorting
from .tasks import start_qualys_import

admin_required = require(can_manage_settings)
CACHE_SECONDS = 3600
DAY_CHOICES = [30, 90]

# Scan list columns: (query key, header, value sorted on, first-click
# direction, numeric). Numbers and dates start from the highest / most recent.
PERIMETER_LABELS = {"external": "External", "internal": "Internal", "": "Mixed"}
SCAN_COLUMNS = [
    ("launched", "Launched", lambda s: s["launched_at"], "desc", False),
    ("scan", "Scan", lambda s: s["title"].lower(), "asc", False),
    ("perimeter", "Perimeter", lambda s: PERIMETER_LABELS.get(s["perimeter_guess"], s["perimeter_guess"]), "asc", False),
    ("type", "Type", lambda s: s["type"].lower() or None, "asc", False),
    ("targets", "Targets", lambda s: s["target_count"], "desc", True),
    ("duration", "Duration", lambda s: _seconds(s["duration"]), "desc", False),
    ("imported", "Imported", lambda s: s["import_pk"], "desc", False),
]


def _seconds(duration):
    """Qualys durations are HH:MM:SS; anything else (e.g. "Pending") sorts last."""
    parts = duration.split(":")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        return None
    hours, minutes, seconds = map(int, parts)
    return hours * 3600 + minutes * 60 + seconds


def _sorted_scans(scans, value, direction):
    """
    Sorted on `value`, empty values last in both directions. The sort is
    stable, so equals keep Qualys' order: newest first.
    """
    known = [s for s in scans if value(s) is not None]
    missing = [s for s in scans if value(s) is None]
    known.sort(key=value, reverse=direction == "desc")
    return known + missing


def _key(days):
    return f"pvm-qualys-scans-2-{days}"


def _cached(days):
    """The scan list kept from the last time Qualys was asked, or None."""
    return cache.get(_key(days))


def _scans(days, refresh=False):
    """
    {"scans": [...], "at": when Qualys answered}. Qualys is asked only when
    nothing is kept or `refresh`: the page itself never asks on its own, so
    opening it costs no API call (the subscription allows 300 an hour).
    """
    entry = None if refresh else _cached(days)
    if entry is None:
        entry = {"scans": qualys.list_scans(days), "at": timezone.now()}
        cache.set(_key(days), entry, CACHE_SECONDS)
    return entry


def _find_scan(ref):
    for days in DAY_CHOICES:
        for scan in _scans(days)["scans"]:
            if scan["ref"] == ref:
                return scan
    return None


def _matches(scan, query):
    """A scan answers a search on its title, its targets or its asset groups."""
    lowered = query.lower()
    if lowered in scan["title"].lower():
        return True
    if any(lowered in group.lower() for group in scan["asset_groups"]):
        return True
    return bool(qualys.matching_targets(scan.get("targets", ""), query))


def _perimeter(slug):
    return Perimeter.objects.filter(slug=slug).first()


@editor_required
def scans(request):
    days = int(request.GET.get("days", DAY_CHOICES[0])) if request.GET.get("days", "").isdigit() else DAY_CHOICES[0]
    days = days if days in DAY_CHOICES else DAY_CHOICES[0]
    q = request.GET.get("q", "").strip()
    context = {
        "days": days,
        "day_choices": DAY_CHOICES,
        "q": q,
        "configured": qualys.configured(),
        "error": "",
        "zone": qualys.schedule_zone().key,
        "excluded_prefixes": settings.QUALYS_EXCLUDED_TITLE_PREFIXES,
    }
    rules = {r.scan_title: r for r in QualysImportRule.objects.select_related("perimeter").prefetch_related("tags")}
    context["rules"] = sorted(rules.values(), key=lambda r: r.scan_title.lower())
    if context["configured"]:
        entry = None
        if request.GET.get("refresh"):
            try:
                entry = _scans(days, refresh=True)
            except qualys.QualysError as exc:
                context["error"] = str(exc)
                entry = _cached(days)  # keep showing the last list Qualys gave
        else:
            entry = _cached(days)  # opening or filtering the page never asks Qualys
        context["listed"] = entry is not None
        listed = entry["scans"] if entry else []
        context["fetched_at"] = entry["at"] if entry else None
        if q:
            listed = [s for s in listed if _matches(s, q)]
        imported = dict(
            ScanImport.objects.filter(qualys_scan_ref__in=[s["ref"] for s in listed]).values_list("qualys_scan_ref", "pk")
        )
        listed = [
            {
                **s,
                "import_pk": imported.get(s["ref"]),
                "rule": rules.get(s["title"]),
                "matched_targets": qualys.matching_targets(s.get("targets", ""), q) if q else [],
            }
            for s in listed
        ]
        value, direction, sort, context["headers"] = sorting(request, SCAN_COLUMNS, "launched")
        context["scans"] = _sorted_scans(listed, value, direction)
        context["sort"], context["dir"] = request.GET.get("sort", ""), direction
    return render(request, "core/imports/qualys_scans.html", context)


@editor_required
def import_scan(request):
    ref = request.GET.get("ref") or request.POST.get("ref", "")
    try:
        scan = _find_scan(ref)
    except qualys.QualysError as exc:
        messages.error(request, str(exc))
        return redirect("core:qualys_scans")
    if scan is None:
        messages.error(request, "That Scan Is Not in the List of Finished Scans; Refresh the List.")
        return redirect("core:qualys_scans")
    existing = ScanImport.objects.filter(qualys_scan_ref=ref).first()
    if existing:
        messages.info(request, "This Scan Is Already Imported.")
        return redirect("core:import_detail", existing.pk)

    error = ""
    if request.method == "POST":
        perimeter = _perimeter(request.POST.get("perimeter", ""))
        if perimeter is None:
            error = "Choose the Perimeter This Scan Was Run From."
        else:
            chosen = tags.from_form(request.POST)
            name = request.POST.get("name", "").strip()[:100] or scan["title"]
            started = start_qualys_import(scan, perimeter, chosen, request.user, ScanImport.Source.QUALYS, name)
            if started is None:
                messages.info(request, "This Scan Is Already Imported.")
                return redirect("core:import_list")
            audit.log(
                request.user, "import.qualys_started", started,
                scan_ref=ref, title=scan["title"], tags=[t.name for t in chosen],
            )
            return redirect("core:import_detail", started.pk)

    # An unsaved import, only to reuse the name-based suggestion.
    suggested = {t.pk for t in tags.suggested_for(ScanImport(name=scan["title"]))}
    return render(
        request,
        "core/imports/qualys_import.html",
        {
            "scan": scan,
            "perimeters": Perimeter.objects.all(),
            "selected_perimeter": request.POST.get("perimeter") or scan["perimeter_guess"],
            "all_tags": Tag.objects.all(),
            "selected_tags": {int(i) for i in request.POST.getlist("tag") if i.isdigit()} or suggested,
            "error": error,
        },
    )


@admin_required
def rule_form(request, pk=None):
    rule = get_object_or_404(QualysImportRule, pk=pk) if pk else None
    title = rule.scan_title if rule else request.GET.get("title") or request.POST.get("scan_title", "")
    if not rule and not title:
        return redirect("core:qualys_scans")
    if not rule and QualysImportRule.objects.filter(scan_title=title).exists():
        return redirect("core:qualys_rule_edit", QualysImportRule.objects.get(scan_title=title).pk)

    errors = []
    if request.method == "POST":
        frequency = request.POST.get("frequency", "")
        weekday = request.POST.get("weekday", "0")
        day_of_month = request.POST.get("day_of_month", "1")
        at = request.POST.get("at_time", "")
        perimeter = _perimeter(request.POST.get("perimeter", ""))
        if frequency not in QualysImportRule.Frequency.values:
            errors.append("Choose Weekly or Monthly.")
        if not weekday.isdigit() or int(weekday) not in QualysImportRule.Weekday.values:
            errors.append("Choose a Day of the Week.")
        if not day_of_month.isdigit() or not 1 <= int(day_of_month) <= 28:
            errors.append("The Day of the Month Must Be Between 1 and 28.")
        match = re.fullmatch(r"([01]?\d|2[0-3]):([0-5]\d)", at)
        if not match:
            errors.append("Enter the Time as HH:MM, e.g. 08:00.")
        if perimeter is None:
            errors.append("Choose the Perimeter.")
        if not errors:
            is_new = rule is None
            rule = rule or QualysImportRule(scan_title=title[:255], created_by=request.user)
            rule.frequency, rule.weekday, rule.day_of_month = frequency, int(weekday), int(day_of_month)
            rule.at_time = dt_time(int(match.group(1)), int(match.group(2)))
            rule.perimeter = perimeter
            rule.enabled = bool(request.POST.get("enabled")) if not is_new else True
            rule.next_run_at = qualys.next_run(rule, timezone.now())
            rule.save()
            chosen = tags.from_form(request.POST)
            rule.tags.set(chosen)
            audit.log(
                request.user, "qualys.rule_created" if is_new else "qualys.rule_changed", rule,
                scan_title=rule.scan_title, schedule=rule.schedule_label, perimeter=perimeter.slug,
                tags=[t.name for t in chosen], enabled=rule.enabled,
            )
            messages.success(request, f"Automatic Import of “{rule.scan_title}” Saved: {rule.schedule_label}.")
            return redirect("core:qualys_scans")

    guess = ""
    if not rule:
        # Only from the list already in hand: this page never asks Qualys either.
        kept = next((entry for entry in (_cached(d) for d in reversed(DAY_CHOICES)) if entry), None)
        guess = next((s["perimeter_guess"] for s in (kept["scans"] if kept else []) if s["title"] == title), "")
    suggested = {t.pk for t in (rule.tags.all() if rule else tags.suggested_for(ScanImport(name=title)))}
    return render(
        request,
        "core/imports/qualys_rule.html",
        {
            "rule": rule,
            "title": title,
            "errors": errors,
            "post": request.POST if request.method == "POST" else None,
            "frequencies": QualysImportRule.Frequency.choices,
            "weekdays": QualysImportRule.Weekday.choices,
            "days_of_month": range(1, 29),
            "perimeters": Perimeter.objects.all(),
            "selected_perimeter": request.POST.get("perimeter") or (rule.perimeter.slug if rule else guess),
            "all_tags": Tag.objects.all(),
            "selected_tags": {int(i) for i in request.POST.getlist("tag") if i.isdigit()} or suggested,
            "zone": qualys.schedule_zone().key,
        },
    )


@admin_required
@require_POST
def rule_toggle(request, pk):
    rule = get_object_or_404(QualysImportRule, pk=pk)
    rule.enabled = not rule.enabled
    if rule.enabled:
        rule.next_run_at = qualys.next_run(rule, timezone.now())
    rule.save(update_fields=["enabled", "next_run_at"])
    audit.log(request.user, "qualys.rule_resumed" if rule.enabled else "qualys.rule_paused", rule, scan_title=rule.scan_title)
    messages.success(request, f"Automatic Import of “{rule.scan_title}” {'Resumed' if rule.enabled else 'Paused'}.")
    return redirect("core:qualys_scans")


@admin_required
@require_POST
def rule_delete(request, pk):
    rule = get_object_or_404(QualysImportRule, pk=pk)
    audit.log(request.user, "qualys.rule_deleted", rule, scan_title=rule.scan_title)
    rule.delete()
    messages.success(request, "Automatic Import Deleted. Imports Already Made Are Kept.")
    return redirect("core:qualys_scans")

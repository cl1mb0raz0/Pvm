import math
from datetime import timedelta
from decimal import Decimal

from django import template

from accounts import permissions
from core.views import DUE_SOON_DAYS

register = template.Library()


@register.filter
def due_class(due_date, today):
    """CSS class for SLA due-date coloring: overdue, due soon, or neutral."""
    if not due_date:
        return ""
    if due_date < today:
        return "due-overdue"
    if due_date <= today + timedelta(days=DUE_SOON_DAYS):
        return "due-soon"
    return ""


@register.simple_tag(takes_context=True)
def nav_current(context, *url_names):
    """aria-current for the sidebar link matching the current view."""
    match = context["request"].resolver_match
    return 'aria-current="page"' if match and match.view_name in url_names else ""


# The Imports section of the sidebar: (label, URL name, who sees it, every
# view that belongs to that entry). The entries show only while a page of
# the section is open.
IMPORTS_MENU = [
    ("History", "core:import_list", None,
     {"core:import_list", "core:import_upload", "core:import_detail", "core:import_mapping"}),
    ("Qualys Scans", "core:qualys_scans", permissions.can_edit,
     {"core:qualys_scans", "core:qualys_import", "core:qualys_rule_new", "core:qualys_rule_edit"}),
    ("Qualys Csam", "core:qualys_csam", permissions.can_edit,
     {"core:qualys_csam", "core:qualys_csam_search", "core:qualys_csam_import"}),
    ("Qualys Pm", "core:qualys_pm", permissions.can_edit,
     {"core:qualys_pm", "core:qualys_pm_search"}),
    ("Mapping", "core:network_mapping", permissions.can_edit,
     {"core:network_mapping", "core:network_mapping_upload", "core:network_mapping_apply",
      "core:network_mapping_clear", "core:balancer_config_delete"}),
    ("Upload", "core:import_backup", permissions.is_super_admin,
     {"core:import_backup", "core:import_backup_upload"}),
]


@register.simple_tag(takes_context=True)
def imports_menu(context):
    """The Imports sidebar entries this user may open, or None outside the
    section. Each is (label, URL name, whether it is the current page)."""
    match = context["request"].resolver_match
    current = match.view_name if match else None
    if not any(current in views for *_, views in IMPORTS_MENU):
        return None
    user = context["request"].user
    return [
        (label, url_name, current in views)
        for label, url_name, allowed, views in IMPORTS_MENU
        if allowed is None or allowed(user)
    ]


@register.simple_tag(takes_context=True)
def csam_todo(context):
    """For the sidebar: {count, stale} of what the last Qualys Csam search
    holds that Pvm does not have yet; None for users who cannot import."""
    if not permissions.can_edit(context["request"].user):
        return None
    from core.csam_views import pending_summary

    return pending_summary()


@register.filter
def can_edit(user):
    return permissions.can_edit(user)


@register.filter
def can_manage_backups(user):
    return permissions.can_manage_backups(user)


@register.filter
def can_manage_settings(user):
    return permissions.can_manage_settings(user)


@register.filter
def is_super_admin(user):
    return permissions.is_super_admin(user)


VERDICT_CLASSES = {
    "fixed": "st-resolved",
    "not_affected": "st-resolved",
    "vulnerable_update": "sev-high",
    "vulnerable_pro": "sev-medium",
    "vulnerable_no_fix": "sev-critical",
    "unknown": "st-still_open",
}


@register.filter
def verdict_class(verdict):
    """Badge color for a patch-check verdict: green not vulnerable, red/orange vulnerable, grey unknown."""
    return VERDICT_CLASSES.get(verdict, "st-still_open")


@register.filter
def verdict_label(verdict):
    from core.models import PatchCheck

    return PatchCheck.Verdict(verdict).label if verdict in PatchCheck.Verdict.values else verdict


VERDICT_SHORT = {
    "fixed": "Fixed",
    "not_affected": "Not Affected",
    "vulnerable_update": "Update Available",
    "vulnerable_pro": "Needs Ubuntu Pro",
    "vulnerable_no_fix": "No Fix Yet",
    "unknown": "Cannot Verify",
}


@register.filter
def verdict_short(verdict):
    """A patch-check verdict short enough for a table cell."""
    return VERDICT_SHORT.get(verdict, verdict)


TRIAGE_FIELDS = {"team": "Team", "due_date": "Due Date", "status": "Status"}


@register.filter
def triage_changes(details):
    """The changes of a triage audit entry as "Status: Still Open → Resolved" lines."""
    from core.models import VulnerabilityFinding

    labels = dict(VulnerabilityFinding.Status.choices)
    empty = {"team": "Unassigned", "due_date": "None", "status": "—"}
    lines = []
    for field, label in TRIAGE_FIELDS.items():
        change = (details or {}).get(field)
        if not change:
            continue
        before, after = (
            labels.get(v, v) if field == "status" and v else (v or empty[field]) for v in (change["from"], change["to"])
        )
        lines.append(f"{label}: {before} → {after}")
    return lines


@register.filter
def signed(points):
    """+30 / −5 (typographic minus), for the priority breakdown."""
    return f"+{points}" if points >= 0 else f"\u2212{-points}"


@register.filter
def pct(value):
    """0.12345 -> "12.3%", truncated so 0.99999 never reads as a certain 100%; tiny values as "<0.1%"."""
    if value is None:
        return ""
    percent = math.floor(Decimal(str(value)) * 1000) / 10
    return "<0.1%" if percent == 0 and value > 0 else f"{percent:.1f}%"


@register.filter
def pct_top(percentile):
    """EPSS percentile 0.987 -> "1.3%": the share of CVEs scored at least as high."""
    if percentile is None:
        return ""
    return pct(max(Decimal(0), 1 - Decimal(str(percentile))) or Decimal("0.0001"))

"""
Triage by hand: assigned team, due date and status of findings.

The only way these three change outside an import (the Django admin shows
them read-only), so every change is written to AuditLog with the value
before and after and the analyst's note: who assigned, rescheduled or
closed what, and when, can always be reconstructed.
"""

from django.utils import timezone

from . import priority, sla
from .models import AuditLog, VulnerabilityFinding

Status = VulnerabilityFinding.Status

NO_CHANGE = object()
FOLLOW_POLICY = "policy"
# Statuses an analyst can set; "New" only comes from an import.
SETTABLE_STATUSES = [Status.STILL_OPEN, Status.NEEDS_REVIEW, Status.RESOLVED]
ACTION = "finding.triaged"


def _show(value):
    if value is None:
        return None
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def _change_team(f, team):
    if f.assigned_team_id == (team.pk if team else None):
        return None
    before, f.assigned_team = f.assigned_team, team
    return ("team", _show(before), _show(team))


def _change_due(f, due, target_days):
    before = f.due_date
    if due == FOLLOW_POLICY:
        f.due_date_manual = False
        sla.apply(f, target_days)
    else:
        f.due_date, f.due_date_manual = due, True
    return ("due_date", _show(before), _show(f.due_date)) if f.due_date != before else None


def _change_status(f, status, now, target_days):
    if f.status == status:
        return None
    before = f.status
    if status == Status.RESOLVED:
        f.resolved_at = now
    elif before == Status.RESOLVED:
        # Reopened by hand: a new remediation clock, as when a scan brings it back.
        f.resolved_at = None
        sla.start_clock(f, now)
        sla.apply(f, target_days)
    f.status = status
    return ("status", before, status)


def update(findings, user, team=NO_CHANGE, due=NO_CHANGE, status=NO_CHANGE, note=""):
    """
    Apply the given changes to `findings` (a queryset); `due` is a date or
    FOLLOW_POLICY, `team` a Team or None (unassigned). Returns how many
    findings actually changed.
    """
    now = timezone.now()
    target_days = sla.targets()
    changed, logs = [], []
    for f in findings.select_related("assigned_team", "vulnerability_definition"):
        changes = [
            c
            for c in (
                _change_team(f, team) if team is not NO_CHANGE else None,
                _change_due(f, due, target_days) if due is not NO_CHANGE else None,
                _change_status(f, status, now, target_days) if status is not NO_CHANGE else None,
            )
            if c
        ]
        if not changes:
            continue
        changed.append(f)
        details = {field: {"from": before, "to": after} for field, before, after in changes}
        if note:
            details["note"] = note
        logs.append(
            AuditLog(
                user=user, action=ACTION, entity_type=f._meta.label, entity_id=str(f.pk), details=details
            )
        )
    VulnerabilityFinding.objects.bulk_update(
        changed,
        ["assigned_team", "due_date", "due_date_manual", "status", "resolved_at", "sla_started_at"],
        batch_size=500,
    )
    AuditLog.objects.bulk_create(logs, batch_size=500)
    priority.recompute(VulnerabilityFinding.objects.filter(pk__in=[f.pk for f in changed]))
    return len(changed)


def history(findings):
    """{finding pk: [AuditLog, newest first]} of triage changes, for display."""
    by_id = {}
    logs = AuditLog.objects.filter(
        action=ACTION, entity_type=VulnerabilityFinding._meta.label, entity_id__in=[str(f.pk) for f in findings]
    ).select_related("user")
    for log in logs:
        by_id.setdefault(int(log.entity_id), []).append(log)
    return by_id

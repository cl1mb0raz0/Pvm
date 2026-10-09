"""
Remediation deadlines from the SLA policy.

A finding's SLA clock starts on the day it is first detected, and again
on the day a resolved finding is detected anew ("needs review"). Its due
date is that day plus the policy's target for its severity. A due date
set by hand (`due_date_manual`) is never overwritten; clearing it hands
the finding back to the policy. The policy is re-applied to open
findings whenever it changes or a QID's severity changes.
"""

from datetime import timedelta

from django.utils import timezone

from .models import SLAPolicy, VulnerabilityFinding


def targets():
    """{severity: target days} from the current policy."""
    return dict(SLAPolicy.objects.values_list("severity", "target_days"))


def start_clock(finding, when):
    finding.sla_started_at = timezone.localdate(when) if timezone.is_aware(when) else when.date()


def policy_due_date(finding, target_days=None):
    target_days = targets() if target_days is None else target_days
    days = target_days.get(finding.vulnerability_definition.severity)
    if days is None or finding.sla_started_at is None:
        return None
    return finding.sla_started_at + timedelta(days=days)


def apply(finding, target_days=None):
    """Set the policy due date unless it was set by hand; True if it changed."""
    if finding.due_date_manual:
        return False
    due = policy_due_date(finding, target_days)
    if due == finding.due_date:
        return False
    finding.due_date = due
    return True


def recompute(findings=None):
    """Re-apply the policy to open findings with a policy due date; returns how many changed."""
    target_days = targets()
    qs = VulnerabilityFinding.objects.all() if findings is None else findings
    qs = (
        qs.exclude(status=VulnerabilityFinding.Status.RESOLVED)
        .filter(due_date_manual=False)
        .select_related("vulnerability_definition")
    )
    changed = [f for f in qs if apply(f, target_days)]
    VulnerabilityFinding.objects.bulk_update(changed, ["due_date"], batch_size=500)
    return len(changed)

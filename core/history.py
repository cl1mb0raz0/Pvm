"""
"As Of <date>": what the vulnerability situation looked like on a past day.

The question a client asks months later ("how were we on 30 June?") has two
possible answers here, and PVM always says which one it gave:

- **From a snapshot** (`Snapshot` + `FindingState`, written after every
  completed import and every night): the state as it really was, statuses,
  severities, priorities, Ubuntu verdicts and triage included. Exact, but it
  can only cover the days since snapshots started being written.
- **Reconstructed from the scans** already imported, for any earlier date.
  `ScanDetectionEvent` records which scan saw which finding, so "was this
  open then" is answered by the scans themselves: a finding was open on day
  X if a scan up to X had seen it and no later scan up to X, looking at that
  host from that perimeter, failed to see it. Which findings were open is
  exact; everything else (severity, CVSS, EPSS, priority, patch check, team,
  due date) is today's value, and every page that shows a reconstruction
  says so.

Both paths give the same shape: a queryset of findings annotated with
`as_of_*` values, which `state()` turns into what a row should display.
"""

from datetime import date, datetime, time

from django.db.models import Exists, F, OuterRef, Q, Subquery
from django.db.models.functions import Coalesce
from django.utils import timezone

from .models import (
    PRIORITY_LEVELS,
    FindingState,
    PatchCheck,
    ScanDetectionEvent,
    ScanImport,
    Snapshot,
    VulnerabilityDefinition,
    VulnerabilityFinding,
)

Status = VulnerabilityFinding.Status
Severity = VulnerabilityDefinition.Severity
# A scan's own date when it has one, else when it was imported: the same
# order Imports > History and the dashboard trend use.
SCAN_DATE = Coalesce("scanned_at", "started_at")

SNAPSHOT = "snapshot"
SCANS = "scans"


def parse(value):
    """The date behind an `as_of` parameter, or None (empty, malformed, future)."""
    text = (value or "").strip()
    if not text:
        return None
    try:
        when = date.fromisoformat(text)
    except ValueError:
        return None
    return None if when >= timezone.localdate() else when


def end_of(day):
    """The last instant of `day`, so "as of the 30th" includes the whole 30th."""
    moment = datetime.combine(day, time.max)
    return timezone.make_aware(moment) if timezone.is_naive(moment) else moment


def scans_up_to(when, perimeter=None):
    """The last completed scan of each perimeter on or before `when`, newest first."""
    scans = (
        ScanImport.objects.filter(status=ScanImport.Status.COMPLETED, perimeter__isnull=False)
        .annotate(when=SCAN_DATE)
        .filter(when__lte=end_of(when))
        .select_related("perimeter")
        .order_by("perimeter_id", "-when", "-pk")
    )
    if perimeter:
        scans = scans.filter(perimeter__slug=perimeter)
    latest = {}
    for scan in scans:
        latest.setdefault(scan.perimeter_id, scan)
    return sorted(latest.values(), key=lambda s: s.when, reverse=True)


def snapshot_at(when):
    """The last snapshot taken on or before `when`, if there is one."""
    return Snapshot.objects.filter(taken_at__lte=end_of(when)).order_by("-taken_at").first()


def as_of(findings, when, status="open"):
    """
    `findings` as they stood on `when`, and how that was answered.

    Returns (findings, source): source is "snapshot" or "scans". `status`
    is the Vulnerabilities status filter: "open" keeps what was open then,
    anything else keeps everything that existed then, whatever its state.
    """
    snapshot = snapshot_at(when)
    if snapshot:
        return _from_snapshot(findings, snapshot, status), SNAPSHOT
    return _from_scans(findings, when, status), SCANS


def _from_snapshot(findings, snapshot, status):
    states = FindingState.objects.filter(snapshot=snapshot, finding=OuterRef("pk"))
    findings = findings.filter(Exists(states)).annotate(
        as_of_moment=Subquery(states.values("snapshot__taken_at")[:1]),
        as_of_status=Subquery(states.values("status")[:1]),
        as_of_severity=Subquery(states.values("severity")[:1]),
        as_of_priority=Subquery(states.values("priority_score")[:1]),
        as_of_patch=Subquery(states.values("patch_verdict")[:1]),
        as_of_team=Subquery(states.values("team")[:1]),
        as_of_due=Subquery(states.values("due_date")[:1]),
    )
    if status == "open":
        findings = findings.exclude(as_of_status=Status.RESOLVED)
    elif status in Status.values:
        findings = findings.filter(as_of_status=status)
    return findings


def _from_scans(findings, when, status):
    """
    Replay of the diffing rules up to `when`.

    A finding was open then if the last scan that saw it is also the last
    scan that looked at its host from its perimeter: a later scan of that
    same host which did not report it is what closed it. A finding resolved
    by hand or by an Ubuntu-check confirm before that day counts as closed
    too, since no scan records those.
    """
    moment = end_of(when)
    last_seen = Subquery(
        ScanDetectionEvent.objects.filter(vulnerability_finding=OuterRef("pk"), detected_at__lte=moment)
        .order_by("-detected_at")
        .values("detected_at")[:1]
    )
    last_scan = Subquery(
        ScanImport.objects.filter(
            status=ScanImport.Status.COMPLETED,
            perimeter=OuterRef("perimeter"),
            hosts__id=OuterRef("host_id"),
        )
        .annotate(when=SCAN_DATE)
        .filter(when__lte=moment)
        .order_by("-when")
        .values("when")[:1]
    )
    findings = findings.annotate(as_of_last_seen=last_seen, as_of_last_scan=last_scan, as_of_moment=last_seen)
    # Nothing was known about it yet: no scan up to that day had seen it.
    findings = findings.filter(as_of_last_seen__isnull=False)
    if status != "open":
        return findings
    return findings.exclude(Q(resolved_at__isnull=False) & Q(resolved_at__lte=moment)).exclude(
        Q(as_of_last_scan__isnull=False) & Q(as_of_last_seen__lt=F("as_of_last_scan"))
    )


class State:
    """
    What a row should show for a finding "as of" a date: the values the
    snapshot holds, or, for a reconstruction, only the status (open then)
    with the scan that says so. Anything left None means "no history for
    this, the page shows today's value and says so".
    """

    def __init__(self, source, status, status_label, note, severity=None, severity_label="",
                 priority_score=None, patch_verdict=None, team=None, due_date=None, resolved=False):
        self.source = source
        self.status = status
        self.status_label = status_label
        self.note = note
        self.severity = severity
        self.severity_label = severity_label
        self.priority_score = priority_score
        self.patch_verdict = patch_verdict
        self.team = team
        self.due_date = due_date
        self.resolved = resolved

    @property
    def priority_level(self):
        if self.priority_score is None:
            return None
        return next(level for level, lowest, _ in PRIORITY_LEVELS if self.priority_score >= lowest)

    @property
    def priority_label(self):
        level = self.priority_level
        return next((label for lv, _, label in PRIORITY_LEVELS if lv == level), "")


STATUS_LABELS = dict(Status.choices)
SEVERITY_LABELS = dict(Severity.choices)
VERDICT_LABELS = dict(PatchCheck.Verdict.choices)


def state(finding):
    """The `State` of an "as of" row, or None when the finding carries no history."""
    if getattr(finding, "as_of_status", None) is not None:
        status = finding.as_of_status
        return State(
            source=SNAPSHOT,
            status=status,
            status_label=STATUS_LABELS.get(status, status),
            note=f"Recorded by the Snapshot of {timezone.localtime(finding.as_of_moment):%Y-%m-%d %H:%M}",
            severity=finding.as_of_severity,
            severity_label=SEVERITY_LABELS.get(finding.as_of_severity, finding.as_of_severity),
            priority_score=finding.as_of_priority,
            patch_verdict=finding.as_of_patch,
            team=finding.as_of_team,
            due_date=finding.as_of_due,
            resolved=status == Status.RESOLVED,
        )
    seen = getattr(finding, "as_of_last_seen", None)
    if seen is None:
        return None
    return State(
        source=SCANS,
        status=Status.STILL_OPEN,
        status_label="Open",
        note=f"Open on That Date: Detected by the Scan of {timezone.localtime(seen):%Y-%m-%d} and Not Closed by a Later One",
    )


def describe(when, source, perimeter=None):
    """One line saying where the "as of" answer comes from, for the banner and the report."""
    if source == SNAPSHOT:
        snapshot = snapshot_at(when)
        return (
            f"From the Snapshot of {timezone.localtime(snapshot.taken_at):%Y-%m-%d %H:%M}"
            f" ({snapshot.get_reason_display()}): Status, Severity, Priority, Team, Due Date and Patch Check"
            " Are the Values of That Day."
        )
    scans = scans_up_to(when, perimeter)
    if not scans:
        return "No Scan Had Run by That Date: Nothing Was Known Yet."
    listed = ", ".join(f"{s.perimeter.name} {s.when:%Y-%m-%d}" for s in scans)
    return (
        f"Reconstructed from the Scans up to That Date ({listed}). Which Findings Were Open Is Exact;"
        " Severity, CVSS, EPSS, Priority, Team, Due Date and Patch Check Are Today's Values."
    )


# --- Writing snapshots ------------------------------------------------


def take(reason, scan_import=None, when=None):
    """
    Record the state of every finding now, so this day can be answered
    exactly later. Cheap enough to run after every import: one row per
    finding (1,000 findings a week is ~50,000 rows a year).
    """
    rows = list(
        VulnerabilityFinding.objects.values_list(
            "pk",
            "status",
            "vulnerability_definition__severity",
            "priority_score",
            "patch_check__verdict",
            "assigned_team__name",
            "due_date",
        )
    )
    counts = {"severities": {}, "statuses": {}}
    for _pk, status, severity, _score, _verdict, _team, _due in rows:
        counts["statuses"][status] = counts["statuses"].get(status, 0) + 1
        counts["severities"][severity] = counts["severities"].get(severity, 0) + 1

    snapshot = Snapshot.objects.create(
        taken_at=when or timezone.now(),
        reason=reason,
        scan_import=scan_import,
        findings_total=len(rows),
        findings_open=sum(1 for r in rows if r[1] != Status.RESOLVED),
        counts=counts,
    )
    FindingState.objects.bulk_create(
        (
            FindingState(
                snapshot=snapshot,
                finding_id=pk,
                status=status,
                severity=severity or "",
                priority_score=score or 0,
                patch_verdict=verdict or "",
                team=team or "",
                due_date=due,
            )
            for pk, status, severity, score, verdict, team, due in rows
        ),
        batch_size=1000,
    )
    return snapshot

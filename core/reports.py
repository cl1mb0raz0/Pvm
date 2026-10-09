"""
What the Export page produces: the same filtered data in three shapes.

The rows are the ones the CSV exports have always written (core/export.py
keeps the CSV details: semicolon, BOM, decimal commas). Here they are also
reused for the HTML report and, through WeasyPrint, for the PDF, so the
three formats can never drift apart.

HTML and PDF are a document rather than a table dump: they carry the
filters that were applied, when they were made and by whom, and counts by
severity, priority and status. The CSV stays the plain table Excel wants.
"""

from django.utils import timezone

from . import export, history
from .models import PRIORITY_LEVELS, VulnerabilityDefinition, VulnerabilityFinding

Severity = VulnerabilityDefinition.Severity
Status = VulnerabilityFinding.Status

FINDING_COLUMNS = [
    "Priority", "Priority Score", "Severity", "Qualys Severity", "CVSS (NVD)", "EPSS (%)", "CVEs", "In CISA KEV", "QID",
    "Title", "Host", "IP Address", "Private IP", "Host Tags", "Perimeter", "Port", "Status", "Team", "Due Date",
    "First Detected", "Last Detected", "Patch Check",
]

HOST_COLUMNS = [
    "Hostname", "IP Address", "Private IP", "Server", "Tags", "OS", "Ubuntu Release", "Environment", "Load Balancer",
    "Open Critical", "Open High", "Open Medium", "Open Low", "Fixed by Installed Version", "Last Scanned",
]

# The columns a page of paper can hold: the CSV keeps them all.
FINDING_PAPER_COLUMNS = ["Priority", "Severity", "CVSS (NVD)", "QID", "Title", "Host", "Perimeter", "Status", "Due Date", "Patch Check"]
HOST_PAPER_COLUMNS = ["Hostname", "IP Address", "Private IP", "Server", "Tags", "OS", "Open Critical", "Open High", "Last Scanned"]


def finding_rows(findings):
    """
    One row per finding. With an "As Of" date the findings carry the state of
    that day (core/history.py): the columns it knows come from there, the
    others stay today's values and the report header says so.
    """
    for f in findings.iterator(chunk_size=500):
        d = f.vulnerability_definition
        cves = list(d.cves.all())
        top_cvss, top_epss = d.nvd_cvss, d.top_epss
        check = getattr(f, "patch_check", None)
        past = history.state(f)
        snapshot = bool(past) and past.source == history.SNAPSHOT
        status = past.status_label if past else f.get_status_display()
        resolved = past.resolved if past else f.status == Status.RESOLVED
        score = past.priority_score if snapshot else f.priority_score
        level = past.priority_level if snapshot else f.priority_level
        label = past.priority_label if snapshot else f.priority_label
        severity = past.severity_label if snapshot else d.get_severity_display()
        team = past.team if snapshot else (f.assigned_team.name if f.assigned_team else "")
        due = past.due_date if snapshot else f.due_date
        verdict = (history.VERDICT_LABELS.get(past.patch_verdict, "") if snapshot
                   else (check.get_verdict_display() if check else ""))
        yield [
            "" if resolved else f"P{level} {label}",
            "" if resolved else score,
            severity, d.get_qualys_severity_display() if d.qualys_severity else "",
            export.decimal(top_cvss.cvss_score, 1) if top_cvss else "",
            export.decimal(top_epss.epss_score * 100, 2) if top_epss else "",
            " ".join(c.cve_id for c in cves), "Yes" if f.in_kev else "No", d.qid, d.title,
            f.host.hostname, f.host.ip_address, ", ".join(f.host.all_private_ips), ", ".join(t.name for t in f.host.tags.all()),
            f.perimeter.name, f.service_port, status, team,
            due.isoformat() if due else "",
            f.first_detected_at.strftime("%Y-%m-%d"), f.last_detected_at.strftime("%Y-%m-%d"),
            verdict,
        ]


def host_rows(hosts):
    for h in hosts:
        yield [
            h.hostname, h.ip_address, ", ".join(h.all_private_ips), ", ".join(getattr(h, "server_names", [])),
            ", ".join(t.name for t in h.tags.all()),
            h.os_version or h.os_name, h.get_ubuntu_release_display() if h.ubuntu_release else "",
            h.get_environment_display(), h.balancer_name or "",
            h.open_critical, h.open_high, h.open_medium, h.open_low, h.open_patched,
            h.last_scanned_at.strftime("%Y-%m-%d %H:%M") if h.last_scanned_at else "",
        ]


# Values that mean "this one is sorted out": shown green in the report, in the
# status column (a finding nobody has to fix any more) and in the patch check
# column (the installed version already carries the fix).
SETTLED = {"Resolved", "Fixed in the Installed Version", "Not Affected", "Confirmed Fixed", "Likely False Positive"}
SEVERITY_CLASS = {"Critical": "sev-critical", "High": "sev-high", "Medium": "sev-medium", "Low": "sev-low"}
# Columns the report's own filters offer, when the export has them.
FINDING_FILTERS = ["Priority", "Severity", "Status", "Patch Check", "Perimeter"]
HOST_FILTERS = ["Tags", "OS"]
NUMERIC = {"Priority Score", "CVSS (NVD)", "EPSS (%)", "Open Critical", "Open High", "Open Medium", "Open Low", "Fixed by Installed Version"}


def decorate(columns, rows, filter_columns, qid_url=""):
    """
    Rows ready for the report template: every cell with the class that colours
    it, every row with the values its filters match on, and the choices each
    filter offers (only the values actually in the export). With `qid_url` (the
    start of a QID page's address) the QID and Title cells link to that page.
    """
    qid_at = columns.index("QID") if qid_url and "QID" in columns else None
    wanted = [c for c in filter_columns if c in columns]
    at = [columns.index(c) for c in wanted]
    choices = [set() for _ in wanted]
    out = []
    for row in rows:
        cells = []
        for column, value in zip(columns, row):
            text = "" if value is None else str(value)
            classes = []
            if column == "Severity":
                classes.append(SEVERITY_CLASS.get(text, ""))
            if text in SETTLED:
                classes.append("settled")
            if column in NUMERIC:
                classes.append("n")
            cell = {"value": value, "cls": " ".join(c for c in classes if c)}
            if qid_at is not None and column in ("QID", "Title") and text:
                cell["href"] = f"{qid_url}{row[qid_at]}/"
            cells.append(cell)
        keys = [str(row[i]) for i in at]
        for i, key in enumerate(keys):
            if key:
                choices[i].add(key)
        out.append({"cells": cells, "keys": keys, "settled": any(str(row[i]) in SETTLED for i in at)})
    # A column the export never fills (no patch check yet, no tag) would be an
    # empty menu: it is left out, keeping "at", its place in every row's keys.
    filters = [
        {"label": label, "values": sorted(values), "at": i}
        for i, (label, values) in enumerate(zip(wanted, choices))
        if values
    ]
    return out, filters


def keep(columns, wanted):
    """The indexes of `wanted` in `columns`, in the order of `wanted`."""
    return [columns.index(name) for name in wanted if name in columns]


def narrow(rows, indexes):
    for row in rows:
        yield [row[i] for i in indexes]


def finding_summary(findings, as_of=None):
    """
    Counts worth reading before the table: by severity, priority band and
    status. With an "As Of" date answered by a snapshot the counts are the
    ones of that day; reconstructed from the scans, every row was open then,
    which is what the status line says.
    """
    if as_of == history.SNAPSHOT:
        rows = list(findings.values_list("as_of_severity", "as_of_status", "as_of_priority").iterator(chunk_size=1000))
    else:
        rows = list(
            findings.values_list("vulnerability_definition__severity", "status", "priority_score").iterator(chunk_size=1000)
        )
    severities = {value: 0 for value, _ in Severity.choices}
    statuses = {value: 0 for value, _ in Status.choices}
    priorities = {level: 0 for level, _, _ in PRIORITY_LEVELS}
    for severity, status, score in rows:
        severities[severity] = severities.get(severity, 0) + 1
        statuses[status] = statuses.get(status, 0) + 1
        if status != Status.RESOLVED:
            for level, lowest, _ in PRIORITY_LEVELS:
                if (score or 0) >= lowest:
                    priorities[level] += 1
                    break
    return {
        "total": len(rows),
        "severities": [(label, severities.get(value, 0)) for value, label in Severity.choices],
        "statuses": (
            [("Open on That Date", len(rows))]
            if as_of == history.SCANS
            else [(label, statuses.get(value, 0)) for value, label in Status.choices]
        ),
        "priorities": [(f"P{level} {label}", priorities.get(level, 0)) for level, _, label in PRIORITY_LEVELS],
    }


def host_summary(hosts):
    hosts = list(hosts)
    return {
        "total": len(hosts),
        "severities": [
            ("Open Critical", sum(h.open_critical for h in hosts)),
            ("Open High", sum(h.open_high for h in hosts)),
            ("Open Medium", sum(h.open_medium for h in hosts)),
            ("Open Low", sum(h.open_low for h in hosts)),
        ],
        "statuses": [
            ("With an Ubuntu Release", sum(1 for h in hosts if h.ubuntu_release)),
            ("Fixed by Installed Version", sum(h.open_patched for h in hosts)),
        ],
        "priorities": [],
    }


def document(title, columns, rows, summary, applied, user, filter_columns=(), note="", qid_url=""):
    """Everything the HTML / PDF report template needs. `note` is a line under
    the title, used by "As Of" to say where the past state comes from."""
    decorated, filters = decorate(columns, rows, filter_columns, qid_url)
    return {
        "title": title,
        "note": note,
        "columns": columns,
        "rows": decorated,
        "filters": filters,
        "summary": summary,
        "applied": applied,
        "made_at": timezone.localtime(),
        "made_by": getattr(user, "username", ""),
    }

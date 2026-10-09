"""
Risk priority of open findings: what to fix first.

A 0-100 score, the sum of a few readable parts, each shown to the user
(`priority_factors`) so the order can always be explained:

- impact: the highest CVSS base score among the QID's CVEs (NVD), else the
  CVSS in the Qualys report, times 4 (max 40); with no CVSS at all, from
  PVM's severity
- exploitation: 30 if a CVE is in the CISA KEV catalog (exploited in the
  wild), else from the highest EPSS (probability of exploitation in the
  next 30 days): 25 from 50%, 20 from 10%, 10 from 1%
- exposure: 15 when the finding's perimeter is internet-facing
- age: 10 when the SLA due date has passed, else 5 when open 90+ days

The Ubuntu check saying the installed version already fixes it (awaiting
confirmation) caps the score at FIXED_CAP. Bands: models.PRIORITY_LEVELS.

Stored on the finding (sortable, filterable) and recomputed after every
import, NVD / EPSS / KEV refresh, host check and triage change, and
nightly (age and due dates move with the calendar). Resolved findings
keep their last score and are not shown by priority.
"""

from collections import defaultdict

from django.utils import timezone

from . import patchcheck
from .models import Cve, KevEntry, VulnerabilityFinding

IMPACT_PER_CVSS_POINT = 4
SEVERITY_IMPACT = {"critical": 36, "high": 28, "medium": 18, "low": 6}
KEV_POINTS = 30
EPSS_BANDS = [(0.5, 25), (0.1, 20), (0.01, 10)]
EXPOSURE_POINTS = 15
OVERDUE_POINTS = 10
OLD_POINTS, OLD_DAYS = 5, 90
FIXED_CAP = 10


def _signals(definition_ids):
    """Per definition: highest CVSS (score, CVE), highest EPSS (score, CVE), KEV CVEs."""
    signals = defaultdict(lambda: {"cvss": None, "epss": None, "kev": []})
    rows = list(
        Cve.objects.filter(vulnerability_definitions__in=definition_ids).values_list(
            "vulnerability_definitions", "cve_id", "cvss_score", "epss_score"
        )
    )
    kev = set(KevEntry.objects.filter(cve_id__in={r[1] for r in rows}).values_list("cve_id", flat=True))
    for definition_id, cve_id, cvss, epss in rows:
        s = signals[definition_id]
        if cvss is not None and (s["cvss"] is None or cvss > s["cvss"][0]):
            s["cvss"] = (cvss, cve_id)
        if epss is not None and (s["epss"] is None or epss > s["epss"][0]):
            s["epss"] = (epss, cve_id)
        if cve_id in kev:
            s["kev"].append(cve_id)
    return signals


def score(finding, signal, today):
    """(score, factors) for one open finding; factors are [label, points] pairs."""
    definition = finding.vulnerability_definition
    factors = []

    if signal["cvss"]:
        cvss, cve_id = signal["cvss"]
        factors.append([f"CVSS {cvss} ({cve_id}, NVD)", round(float(cvss) * IMPACT_PER_CVSS_POINT)])
    elif definition.cvss_score is not None:
        factors.append([f"CVSS {definition.cvss_score} (Qualys)", round(float(definition.cvss_score) * IMPACT_PER_CVSS_POINT)])
    else:
        factors.append([f"Severity {definition.get_severity_display()} (No CVSS)", SEVERITY_IMPACT.get(definition.severity, 0)])

    if signal["kev"]:
        factors.append([f"In CISA KEV ({signal['kev'][0]})", KEV_POINTS])
    elif signal["epss"]:
        epss, cve_id = signal["epss"]
        points = next((p for threshold, p in EPSS_BANDS if epss >= threshold), 0)
        factors.append([f"EPSS {float(epss) * 100:.1f}% ({cve_id})", points])

    if finding.perimeter.internet_facing:
        factors.append([f"Internet-Facing ({finding.perimeter.name})", EXPOSURE_POINTS])

    if finding.due_date and finding.due_date < today:
        factors.append([f"SLA Overdue Since {finding.due_date.isoformat()}", OVERDUE_POINTS])
    else:
        days = (today - timezone.localdate(finding.first_detected_at)).days
        if days >= OLD_DAYS:
            factors.append([f"Open for {days} Days", OLD_POINTS])

    total = min(100, sum(points for _, points in factors))
    check = getattr(finding, "patch_check", None)
    if check and check.verdict in patchcheck.NOT_VULNERABLE_CHECKS and total > FIXED_CAP:
        factors.append(["Fixed by Installed Version, To Confirm", FIXED_CAP - total])
        total = FIXED_CAP
    return total, factors


def recompute(findings=None):
    """Recompute the open ones among `findings` (default: all); returns how many changed."""
    qs = VulnerabilityFinding.objects.all() if findings is None else findings
    open_findings = list(
        qs.exclude(status=VulnerabilityFinding.Status.RESOLVED).select_related(
            "vulnerability_definition", "perimeter", "patch_check"
        )
    )
    signals = _signals({f.vulnerability_definition_id for f in open_findings})
    today = timezone.localdate()
    changed = []
    for f in open_findings:
        total, factors = score(f, signals[f.vulnerability_definition_id], today)
        if (total, factors) != (f.priority_score, f.priority_factors):
            f.priority_score, f.priority_factors = total, factors
            changed.append(f)
    VulnerabilityFinding.objects.bulk_update(changed, ["priority_score", "priority_factors"], batch_size=500)
    return len(changed)

from datetime import timedelta

from django.conf import settings
from django.core.paginator import Paginator
from django.db.models import Case, Count, Exists, F, IntegerField, OuterRef, Q, Subquery, Value, When
from django.db.models.functions import Coalesce, NullIf
from django.shortcuts import get_object_or_404, render
from django.utils import timezone

from accounts.models import Team

from . import audit, balancer, charts, export, history, inventory, network_mapping, patchcheck, reports, rocky_check, ssh, triage
from .sorting import sort_rows, sorting
from .models import (
    Tag,
    PRIORITY_LEVELS,
    Cve,
    DistroPatchVerification,
    Host,
    HostPrivateIp,
    InstalledPackage,
    KevEntry,
    LoadBalancer,
    PatchCheck,
    Perimeter,
    ScanDetectionEvent,
    ScanImport,
    VulnerabilityDefinition,
    VulnerabilityFinding,
)

Severity = VulnerabilityDefinition.Severity
Status = VulnerabilityFinding.Status

SEVERITIES = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
TREND_SCANS = 8
# "Patch Check" filter of the vulnerabilities list, by query value.
PATCH_FILTERS = {
    # Fixed per the installed version but not yet confirmed (confirming resolves the finding).
    "fixed_pending": Q(patch_check__verdict__in=patchcheck.NOT_VULNERABLE_CHECKS) & ~Q(status=Status.RESOLVED),
    "fixed": Q(patch_check__verdict__in=patchcheck.NOT_VULNERABLE_CHECKS),
    "vulnerable": Q(patch_check__verdict__startswith="vulnerable"),
    "unknown": Q(patch_check__verdict=patchcheck.Verdict.UNKNOWN),
    "unchecked": Q(patch_check__isnull=True),
}

PATCH_FILTER_LABELS = [
    ("fixed_pending", "Fixed by Installed Version, Not Confirmed"),
    ("fixed", "Fixed or Not Affected"),
    ("vulnerable", "Vulnerable per Installed Version"),
    ("unknown", "Cannot Verify"),
    ("unchecked", "Not Checked"),
]

# "CVSS (NVD)" filter: minimum base score, by query value.
CVSS_THRESHOLDS = {"9": 9, "7": 7, "4": 4}
# What that dropdown offers, "No Score" included (findings whose QID has no
# scored CVE). Several can be ticked: the filter keeps findings matching any.
CVSS_LABELS = [("9", "9.0 and Above"), ("7", "7.0 and Above"), ("4", "4.0 and Above"), ("none", "No Score")]
CVSS_CHOICES = dict(CVSS_LABELS)
# Priority filter: level -> [lowest score, next level's lowest score).
PRIORITY_RANGES = {
    str(level): (lowest, next((l for lv, l, _ in PRIORITY_LEVELS if lv == level - 1), 101))
    for level, lowest, _ in PRIORITY_LEVELS
}
# What the Priority dropdown offers, as strings, several tickable at once.
PRIORITY_CHOICES = [(str(level), f"P{level} {label}") for level, _, label in PRIORITY_LEVELS]
DUE_SOON_DAYS = 7

# Verdicts that mean "the distro already shipped the fix", shown as the
# "verified: patch backported" badge on a host's installed packages.
BACKPORTED_VERDICTS = [
    DistroPatchVerification.Verdict.CONFIRMED_FIXED,
    DistroPatchVerification.Verdict.LIKELY_FALSE_POSITIVE,
]

SEVERITY_RANK = Case(
    *[When(vulnerability_definition__severity=s, then=Value(i)) for i, s in enumerate(SEVERITIES)],
    output_field=IntegerField(),
)


def _open_findings():
    return VulnerabilityFinding.objects.exclude(status=Status.RESOLVED)


# True when one of the finding's CVEs is in the CISA KEV catalog.
IN_KEV = Exists(
    Cve.objects.filter(
        vulnerability_definitions=OuterRef("vulnerability_definition"),
        cve_id__in=KevEntry.objects.values("cve_id"),
    )
)


def _with_related(findings):
    return (
        findings.select_related(
            "host", "vulnerability_definition", "assigned_team", "perimeter", "patch_check", "distro_verification"
        )
        .prefetch_related("vulnerability_definition__cves", "host__tags", "host__other_private_ips")
        .annotate(in_kev=IN_KEV)
    )


def _is_htmx(request):
    return request.headers.get("HX-Request") == "true"


def _selected_perimeter(request):
    slug = request.GET.get("perimeter", "")
    return Perimeter.objects.filter(slug=slug).first() if slug else None


def dashboard(request):
    today = timezone.localdate()
    perimeter = _selected_perimeter(request)
    open_findings = _open_findings()
    imports = ScanImport.objects.all()
    if perimeter:
        open_findings = open_findings.filter(perimeter=perimeter)
        imports = imports.filter(perimeter=perimeter)

    scans, totals = _trend_points(perimeter)

    trend = []
    for severity in SEVERITIES:
        series = [totals[i].get(severity, 0) for i in range(len(scans))]
        # Change in findings detected, latest scan versus the one before.
        delta = series[-1] - series[-2] if len(series) >= 2 else None
        trend.append(
            {
                "severity": severity,
                "label": severity.label,
                "count": open_findings.filter(vulnerability_definition__severity=severity).count(),
                "delta": delta,
                "delta_abs": abs(delta) if delta is not None else None,
                "chart": charts.line_panel(series, [s.scanned_at or s.started_at for s in scans]),
                "series": series,
            }
        )

    context = {
        "severity_kpis": trend,
        "needs_review": open_findings.filter(status=Status.NEEDS_REVIEW).count(),
        "overdue": open_findings.filter(due_date__lt=today).count(),
        "due_soon": open_findings.filter(due_date__gte=today, due_date__lte=today + timedelta(days=DUE_SOON_DAYS)).count(),
        "scan_count": len(scans),
        # Same numbers as the trend charts, for the "view as table" fallback.
        "trend_rows": [
            {"date": scan.scanned_at or scan.started_at, "values": [k["series"][i] for k in trend]}
            for i, scan in enumerate(scans)
        ],
        "recent_imports": imports.select_related("triggered_by", "perimeter")[:5],
        "perimeters": Perimeter.objects.all(),
        "perimeter": perimeter,
        "kev_open": open_findings.filter(IN_KEV).count(),
        # Qualys still reports them, the installed version already fixes them.
        "fixed_pending": open_findings.filter(patch_check__verdict__in=patchcheck.NOT_VULNERABLE_CHECKS).count(),
        "p1_open": open_findings.filter(priority_score__gte=PRIORITY_RANGES["1"][0]).count(),
        "top_findings": _with_related(open_findings)
        .annotate(severity_rank=SEVERITY_RANK)
        .order_by("-priority_score", "severity_rank", "due_date")[:10],
        "today": today,
    }
    return render(request, "core/dashboard.html", context)


def _trend_points(perimeter):
    """
    The last TREND_SCANS completed scans (of `perimeter`, or of any
    perimeter) and, for each, the findings detected per severity.

    Across all perimeters a single scan only shows one side (an external
    scan knows nothing of internal findings), so each point is the sum of
    the latest scan of every perimeter as of that moment.
    """
    completed = ScanImport.objects.filter(status=ScanImport.Status.COMPLETED, perimeter__isnull=False)
    if perimeter:
        completed = completed.filter(perimeter=perimeter)
    ordered = sorted(completed, key=lambda s: (s.scanned_at or s.started_at, s.pk))

    counts = {}
    rows = (
        ScanDetectionEvent.objects.filter(scan_import__in=completed)
        .values("scan_import", "vulnerability_finding__vulnerability_definition__severity")
        .annotate(n=Count("vulnerability_finding", distinct=True))
    )
    for r in rows:
        counts.setdefault(r["scan_import"], {})[r["vulnerability_finding__vulnerability_definition__severity"]] = r["n"]

    latest, points = {}, []
    for scan in ordered:
        latest[scan.perimeter_id] = counts.get(scan.pk, {})
        points.append((scan, {s: sum(c.get(s, 0) for c in latest.values()) for s in SEVERITIES}))
    points = points[-TREND_SCANS:]
    return [p[0] for p in points], [p[1] for p in points]


def _many(params, key):
    """Every value given for `key`: a plain dict or one value both work."""
    if hasattr(params, "getlist"):
        return [v for v in params.getlist(key) if v]
    value = params.get(key, "")
    return [value] if value else []


def filtered_findings(params):
    """
    The findings matching the Vulnerabilities filters in `params` (a
    QueryDict), and the filters as read. Shared by the list and by triage
    applied to "all findings matching the filters".
    """
    filters = {
        "severity": params.get("severity", ""),
        # The risk filters take several values at once (dropdowns with ticks):
        # Priority, Severity, Qualys, CVSS and Tag. A page sending one value
        # goes through the same code.
        "severities": _many(params, "severity"),
        "qualys_levels": _many(params, "qualys"),
        "priorities": [v for v in _many(params, "priority") if v in PRIORITY_RANGES],
        "cvss_values": [v for v in _many(params, "cvss") if v in CVSS_CHOICES],
        "tags": _many(params, "tag"),
        "status": params.get("status", "open"),
        "team": params.get("team", ""),
        "source": params.get("source", ""),
        "q": params.get("q", "").strip(),
        "import": params.get("import", ""),
        "perimeter": params.get("perimeter", ""),
        "qualys": params.get("qualys", ""),
        "cvss": params.get("cvss", ""),
        "kev": params.get("kev", ""),
        "patch": params.get("patch", ""),
        "host": params.get("host", ""),
        "priority": params.get("priority", ""),
        "tag": params.get("tag", ""),
        # "As Of": the situation on a past day (core/history.py). It replaces
        # the status filter, since the status a finding has today says nothing
        # about the one it had then.
        "as_of": params.get("as_of", ""),
    }
    as_of = history.parse(filters["as_of"])
    filters["as_of_date"] = as_of
    filters["as_of"] = as_of.isoformat() if as_of else ""

    findings = VulnerabilityFinding.objects.all()
    if filters["host"].isdigit():
        findings = findings.filter(host_id=filters["host"])
    # Tags: hosts carrying any of the ticked ones, plus "No Tag" if ticked.
    # Written as subqueries, so several tags never duplicate a finding's row.
    tag_ids = [v for v in filters["tags"] if v.isdigit()]
    tag_query = Q(host__in=Host.objects.filter(tags__in=tag_ids)) if tag_ids else Q()
    if "none" in filters["tags"]:
        tag_query = tag_query | Q(host__in=Host.objects.filter(tags__isnull=True))
    if tag_ids or "none" in filters["tags"]:
        findings = findings.filter(tag_query)
    if as_of:
        findings, filters["as_of_source"] = history.as_of(findings, as_of, filters["status"])
    elif filters["status"] == "open":
        findings = findings.exclude(status=Status.RESOLVED)
    elif filters["status"] in Status.values:
        findings = findings.filter(status=filters["status"])
    # Severity and Qualys severity accept several values (the Export page ticks
    # boxes, e.g. Qualys 4 and 5); the lists send one and land in the same code.
    severities = [v for v in _many(params, "severity") if v in Severity.values]
    if severities:
        findings = findings.filter(vulnerability_definition__severity__in=severities)
    if filters["team"] == "none":
        findings = findings.filter(assigned_team__isnull=True)
    elif filters["team"].isdigit():
        findings = findings.filter(assigned_team_id=filters["team"])
    if filters["source"] in ScanImport.Source.values:
        findings = findings.filter(
            Exists(
                ScanDetectionEvent.objects.filter(
                    vulnerability_finding=OuterRef("pk"), scan_import__source=filters["source"]
                )
            )
        )
    if filters["perimeter"]:
        findings = findings.filter(perimeter__slug=filters["perimeter"])
    levels = [int(v) for v in _many(params, "qualys") if v.isdigit()]
    if levels:
        findings = findings.filter(vulnerability_definition__qualys_severity__in=levels)
    if filters["priorities"]:
        bands = Q()
        for value in filters["priorities"]:
            low, high = PRIORITY_RANGES[value]
            bands |= Q(priority_score__gte=low, priority_score__lt=high)
        findings = findings.filter(bands)
    if filters["patch"] in PATCH_FILTERS:
        findings = findings.filter(PATCH_FILTERS[filters["patch"]])
    if filters["kev"] == "yes":
        findings = findings.filter(IN_KEV)
    if filters["cvss_values"]:
        highest = (
            Cve.objects.filter(vulnerability_definitions=OuterRef("vulnerability_definition"), cvss_score__isnull=False)
            .order_by(F("cvss_score").desc())
            .values("cvss_score")[:1]
        )
        findings = findings.annotate(nvd_cvss_max=Subquery(highest))
        scores = Q()
        for value in filters["cvss_values"]:
            scores |= Q(nvd_cvss_max__isnull=True) if value == "none" else Q(nvd_cvss_max__gte=CVSS_THRESHOLDS[value])
        findings = findings.filter(scores)
    if filters["import"].isdigit():
        findings = findings.filter(
            Exists(
                ScanDetectionEvent.objects.filter(
                    vulnerability_finding=OuterRef("pk"), scan_import_id=filters["import"]
                )
            )
        )
    if filters["q"]:
        q = filters["q"]
        findings = findings.filter(
            Q(host__hostname__icontains=q)
            | Q(host__ip_address__startswith=q)
            | Q(vulnerability_definition__qid=q)
            | Q(vulnerability_definition__cves__cve_id__iexact=q)
            | Q(vulnerability_definition__title__icontains=q)
        ).distinct()
    return findings, filters


# Findings columns: (query key, header, sorted field, first-click direction,
# numeric, tooltip). "priority" is the default: worst first.
FINDING_COLUMNS = [
    ("priority", "Priority", "priority_score", "desc", False,
     "Risk Priority, 0 to 100: CVSS, CISA KEV or EPSS, Internet Exposure and Age. Hover a Value for the Breakdown"),
    ("severity", "Severity", "severity_rank", "asc", False, ""),
    ("qualys", "Qualys", "vulnerability_definition__qualys_severity", "desc", False, "Qualys Severity, 1 to 5"),
    ("cvss", "CVSS / EPSS", "nvd_cvss_max", "desc", False,
     "Highest CVSS Base Score Among the CVEs, from NVD; Highest EPSS from FIRST Below It"),
    ("qid", "CVE / QID", "vulnerability_definition__qid", "asc", False, ""),
    ("title", "Title", "vulnerability_definition__title", "asc", False, ""),
    ("host", "Host", "host__hostname", "asc", False, ""),
    ("perimeter", "Perimeter", "perimeter__name", "asc", False, ""),
    ("team", "Team", "assigned_team__name", "asc", False, ""),
    ("due", "Due", "due_date", "asc", False, ""),
    ("status", "Status", "status", "asc", False, ""),
    ("patch", "Patch Check", "patch_check__verdict", "asc", False,
     "Verdict of the Ubuntu Tracker Check Against the Installed Packages"),
]
# The host page shows the port instead of the host, everything else is the same.
HOST_FINDING_COLUMNS = [
    c if c[0] != "host" else ("port", "Port", "service_port", "asc", False, "") for c in FINDING_COLUMNS
]
# Sorted on nothing the database holds: the highest CVSS of the QID's CVEs.
CVSS_MAX = Subquery(
    Cve.objects.filter(vulnerability_definitions=OuterRef("vulnerability_definition"), cvss_score__isnull=False)
    .order_by(F("cvss_score").desc())
    .values("cvss_score")[:1]
)


# The hosts a QID was found on, in the order the page draws them.
QID_HOST_COLUMNS = [
    ("priority", "Priority", "priority_score", "desc", False),
    ("host", "Host", "host__hostname", "asc", False),
    ("port", "Port", "service_port", "asc", False),
    ("perimeter", "Perimeter", "perimeter__name", "asc", False),
    ("team", "Team", "assigned_team__name", "asc", False),
    ("due", "Due", "due_date", "asc", False),
    ("status", "Status", "status", "asc", False),
    ("patch", "Ubuntu Check", "patch_check__verdict", "asc", False),
    ("last_detected", "Last Detected", "last_detected_at", "desc", False),
]


# "As Of" from a snapshot shows the values of that day, so the columns must
# sort on those and not on what the finding carries today (core/history.py).
AS_OF_SORT = {
    "priority_score": "as_of_priority",
    "severity_rank": "as_of_severity_rank",
    "status": "as_of_status",
    "due_date": "as_of_due",
    "assigned_team__name": "as_of_team",
    "patch_check__verdict": "as_of_patch",
}
AS_OF_SEVERITY_RANK = Case(
    *[When(as_of_severity=s, then=Value(i)) for i, s in enumerate(SEVERITIES)],
    output_field=IntegerField(),
)


def _sorted_findings(request, findings, columns, default="priority", tie=(), swap=None):
    """`findings` in the order the headers ask for, and those headers."""
    field, direction, sort, headers = sorting(request, columns, default)
    swap = swap or {}
    field = swap.get(field, field)
    if field == "nvd_cvss_max":
        findings = findings.annotate(nvd_cvss_max=CVSS_MAX)
    if sort == "priority":
        # The default: worst first, then severity, then the nearest due date.
        score, rank, due = (swap.get(f, f) for f in ("priority_score", "severity_rank", "due_date"))
        order = [f"-{score}", rank, due, "pk"] if direction == "desc" else [score, rank, due, "pk"]
        findings = findings.order_by(*tie, *order)
    else:
        column = F(field).asc(nulls_last=True) if direction == "asc" else F(field).desc(nulls_last=True)
        findings = findings.order_by(*tie, column, "-" + swap.get("priority_score", "priority_score"), "pk")
    return findings, headers, sort, direction


def vulnerability_list(request):
    findings, filters = filtered_findings(request.GET)
    findings = _with_related(findings).annotate(severity_rank=SEVERITY_RANK)
    as_of, swap = filters["as_of_date"], None
    if as_of and filters.get("as_of_source") == history.SNAPSHOT:
        findings, swap = findings.annotate(as_of_severity_rank=AS_OF_SEVERITY_RANK), AS_OF_SORT
    findings, headers, sort, direction = _sorted_findings(request, findings, FINDING_COLUMNS, swap=swap)
    page = Paginator(findings, 50).get_page(request.GET.get("page"))
    if as_of:
        # What each row showed on that day, from the snapshot or from the scans.
        for f in page.object_list:
            f.as_of = history.state(f)

    context = {
        "page": page,
        "filters": filters,
        "query_without_page": _query_without_page(request),
        "severities": Severity.choices,
        "statuses": Status.choices,
        "teams": Team.objects.all(),
        "sources": ScanImport.Source.choices,
        "perimeters": Perimeter.objects.all(),
        "qualys_levels": VulnerabilityDefinition.QualysSeverity.choices,
        "patch_filters": PATCH_FILTER_LABELS,
        "priority_levels": PRIORITY_LEVELS,
        "tags": Tag.objects.all(),
        # The dropdowns that take several ticks (partials/multi_select.html).
        "priority_choices": PRIORITY_CHOICES,
        "cvss_choices": CVSS_LABELS,
        "tag_choices": [("none", "No Tag")] + [(str(t.pk), t.name) for t in Tag.objects.all()],
        "import_filter": ScanImport.objects.filter(pk=filters["import"]).first() if filters["import"].isdigit() else None,
        "today": timezone.localdate(),
        # The "As Of" field asks for a past day: today is the live list.
        "yesterday": timezone.localdate() - timedelta(days=1),
        "triage_statuses": [(s.value, s.label) for s in triage.SETTABLE_STATUSES],
        "headers": headers,
        "sort": sort,
        "dir": direction,
        "as_of": as_of,
        "as_of_note": history.describe(as_of, filters.get("as_of_source"), filters["perimeter"]) if as_of else "",
    }
    template = "core/partials/vulnerability_results.html" if _is_htmx(request) else "core/vulnerability_list.html"
    return render(request, template, context)


# Host list columns: (query key, header, sorted field, first-click direction,
# numeric). Numbers and dates start from the highest / most recent.
HOST_COLUMNS = [
    ("host", "Host", "hostname", "asc", False),
    ("ip", "IP", "ip_address", "asc", False),
    ("balancer", "Balancer", "balancer_name", "asc", False),
    ("private_ip", "Private IP", "private_ip", "asc", False),
    # The name the load balancer knows the real server by (Imports > Mapping):
    # it lives in the balancer configuration, not on the host, so it does not sort.
    ("server", "Server", None, "asc", False),
    ("os", "OS", "os_display", "asc", False),
    ("environment", "Environment", "environment", "asc", False),
    ("critical", "Critical", "open_critical", "desc", True),
    ("high", "High", "open_high", "desc", True),
    ("medium", "Medium", "open_medium", "desc", True),
    ("low", "Low", "open_low", "desc", True),
    ("patched", "Fixed by Installed", "open_patched", "desc", True),
    ("last_scanned", "Last Scanned", "last_scanned_at", "desc", False),
]


# Installed packages of a host.
PACKAGE_COLUMNS = [
    ("package", "Package", "package_name", "asc", False),
    ("version", "Installed Version", "installed_version", "asc", False),
    ("source", "Source Package", "source_package", "asc", False),
    ("updated", "Updated", "updated_at", "desc", False),
    ("how", "How", "source", "asc", False),
    ("verified", "", None, "asc", False),
    ("actions", "", None, "asc", False),
]

# The CVEs of a QID, sorted in Python: `sort_rows` takes these callables.
CVE_COLUMNS = [
    ("cve", "CVE", lambda c: c.cve_id, "asc", False),
    ("cvss", "CVSS", lambda c: c.cvss_score, "desc", False),
    ("epss", "EPSS", lambda c: c.epss_score, "desc", False,
     "EPSS (FIRST): Probability of Exploitation in the Next 30 Days, and Its Percentile Among All CVEs"),
    ("exploited", "Exploited", lambda c: c.kev.date_added if c.kev else None, "desc", False),
    ("vector", "Vector", lambda c: c.cvss_vector, "asc", False),
    ("scored_by", "Scored By", lambda c: c.cvss_source, "asc", False),
    ("published", "Published", lambda c: c.nvd_published_at, "desc", False),
    ("ubuntu", "Ubuntu Priority", lambda c: c.ubuntu_priority, "asc", False),
    ("links", "Learn More", None, "asc", False),
]


def _host_sorting(request):
    """The requested (field, direction) plus the header links, which keep the other filters."""
    field, direction, _, headers = sorting(request, HOST_COLUMNS, "host")
    return field, direction, headers


def vulnerability_detail(request, qid):
    """One QID: what it is, its CVEs with links to the public sources, and every host it was found on."""
    definition = get_object_or_404(VulnerabilityDefinition, qid=qid)
    cves = sorted(definition.cves.all(), key=lambda c: (c.cvss_score is None, -(c.cvss_score or 0), c.cve_id))
    kev_entries = {k.cve_id: k for k in KevEntry.objects.filter(cve_id__in=[c.cve_id for c in cves])}
    for c in cves:
        c.kev = kev_entries.get(c.cve_id)
    # The CVEs sort in Python (KEV and the links are not database columns).
    value, cve_direction, cve_sort, cve_headers = sorting(request, CVE_COLUMNS, "cvss", prefix="cve_")
    cves = sort_rows(cves, value, cve_direction)
    findings = (
        definition.findings.select_related("host", "perimeter", "assigned_team", "patch_check")
        .annotate(
            is_resolved=Case(When(status=Status.RESOLVED, then=Value(1)), default=Value(0), output_field=IntegerField())
        )
    )
    findings, host_headers, host_sort, host_direction = _sorted_findings(
        request, findings, QID_HOST_COLUMNS, default="host", tie=("is_resolved",)
    )
    open_findings = [f for f in findings if f.status != Status.RESOLVED]
    return render(
        request,
        "core/vulnerability_detail.html",
        {
            "definition": definition,
            "cves": cves,
            "top_cve": next((c for c in cves if c.cvss_score is not None), None),
            "top_epss": max((c for c in cves if c.epss_score is not None), key=lambda c: c.epss_score, default=None),
            "kev_cves": [c for c in cves if c.kev],
            "kev_ransomware": any(c.kev.ransomware for c in cves if c.kev),
            "findings": findings,
            "cve_headers": cve_headers,
            "headers": host_headers,
            "sort": host_sort,
            "dir": host_direction,
            "cve_sort": cve_sort,
            "cve_dir": cve_direction,
            "open_count": len(open_findings),
            "host_count": len({f.host_id for f in open_findings}),
            "today": timezone.localdate(),
        },
    )


def _selected_tag(params):
    """The tag filter: a Tag, "none" (hosts without tags) or None (any)."""
    value = params.get("tag", "")
    if value == "none":
        return "none"
    return Tag.objects.filter(pk=value).first() if value.isdigit() else None


def filtered_hosts(request):
    """
    The hosts matching the Hosts filters, with their open-finding counts, and
    the filters as read. Shared by the list and its CSV export.
    """
    q = request.GET.get("q", "").strip()
    perimeter = _selected_perimeter(request)
    tag = _selected_tag(request.GET)
    os_values = _many(request.GET, "os")
    open_filter = ~Q(findings__status=Status.RESOLVED)
    hosts = Host.objects.prefetch_related("tags", "other_private_ips")
    if tag == "none":
        hosts = hosts.filter(tags__isnull=True)
    elif tag:
        hosts = hosts.filter(pk__in=Host.objects.filter(tags=tag).values("pk"))
    if perimeter:
        # Hosts scanned from that perimeter, with only that perimeter's counts.
        open_filter &= Q(findings__perimeter=perimeter)
        scanned_from = Host.objects.filter(Q(scan_imports__perimeter=perimeter) | Q(findings__perimeter=perimeter))
        hosts = hosts.filter(pk__in=scanned_from.values("pk"))
    hosts = hosts.annotate(
        **{
            f"open_{s}": Count("findings", filter=open_filter & Q(findings__vulnerability_definition__severity=s))
            for s in SEVERITIES
        },
        # Open findings the Ubuntu check says the installed version already fixes.
        open_patched=Count(
            "findings", filter=open_filter & Q(findings__patch_check__verdict__in=patchcheck.NOT_VULNERABLE_CHECKS)
        ),
    )
    hosts = hosts.annotate(
        balancer_name=Subquery(LoadBalancer.objects.filter(ip_address=OuterRef("ip_address")).values("name")[:1])
    )
    # What the OS column shows: the release if known, else Qualys' OS string.
    hosts = hosts.annotate(os_display=Coalesce(NullIf("os_version", Value("")), NullIf("os_name", Value(""))))
    if os_values:
        hosts = hosts.filter(os_display__in=os_values)
    if q:
        hosts = hosts.filter(
            Q(hostname__icontains=q)
            | Q(ip_address__startswith=q)
            | Q(private_ip__startswith=q)
            | Exists(HostPrivateIp.objects.filter(host=OuterRef("pk"), ip_address__startswith=q))
        )

    field, direction, headers = _host_sorting(request)
    order = F(field).asc(nulls_last=True) if direction == "asc" else F(field).desc(nulls_last=True)
    hosts = hosts.order_by(order, "hostname", "pk")
    return hosts, {"q": q, "perimeter": perimeter, "tag": tag, "os": os_values, "headers": headers, "direction": direction}


def host_os_choices():
    """Every distinct OS string currently shown on a host (the OS filter's ticks)."""
    return list(
        Host.objects.annotate(os_display=Coalesce(NullIf("os_version", Value("")), NullIf("os_name", Value(""))))
        .exclude(os_display__isnull=True)
        .order_by("os_display")
        .values_list("os_display", "os_display")
        .distinct()
    )


def _with_server_names(hosts):
    """The hosts as a list, each with `server_names`: their private IPs read as server names."""
    names = balancer.server_names()
    hosts = list(hosts)
    if names:
        for host in hosts:
            host.server_names = balancer.names_for(host.all_private_ips, names)
    return hosts


def host_recap(hosts):
    """
    What the Hosts page shows above the list: the shape of what was imported,
    for the hosts the filters leave in. Counted in Python over the rows the
    page already holds, so it costs no extra query per tile.
    """
    total = len(hosts)
    open_counts = [h.open_critical + h.open_high + h.open_medium + h.open_low for h in hosts]
    affected = sum(1 for n in open_counts if n)
    scanned = [h.last_scanned_at for h in hosts if h.last_scanned_at]
    return {
        "total": total,
        "internal": sum(1 for h in hosts if h.seen_internal),
        "external": sum(1 for h in hosts if h.seen_external),
        "both": sum(1 for h in hosts if h.seen_internal and h.seen_external),
        "affected": affected,
        "clean": total - affected,
        "open_findings": sum(open_counts),
        "critical_hosts": sum(1 for h in hosts if h.open_critical),
        "high_hosts": sum(1 for h in hosts if h.open_high),
        "worst": max(open_counts, default=0),
        "with_release": sum(1 for h in hosts if h.ubuntu_release),
        "with_packages": sum(1 for h in hosts if h.has_packages),
        "fixed_pending": sum(h.open_patched for h in hosts),
        "last_scanned": max(scanned, default=None),
        "first_scanned": min(scanned, default=None),
    }


def host_list(request):
    hosts, f = filtered_hosts(request)
    # Where each host was seen from: a host is one asset, scanned from one
    # perimeter or from both.
    # Exists, not Count: another join would multiply the finding counts this
    # queryset already annotates (it turned 859 open findings into 184,665).
    hosts = hosts.annotate(
        seen_internal=Exists(ScanImport.objects.filter(hosts=OuterRef("pk"), perimeter__slug="internal")),
        seen_external=Exists(ScanImport.objects.filter(hosts=OuterRef("pk"), perimeter__slug="external")),
        has_packages=Exists(InstalledPackage.objects.filter(host=OuterRef("pk"))),
    )
    hosts = _with_server_names(hosts)
    return render(
        request,
        "core/host_list.html",
        {
            "hosts": hosts,
            "q": f["q"],
            "perimeters": Perimeter.objects.all(),
            "perimeter": f["perimeter"],
            "tags": Tag.objects.all(),
            "tag": f["tag"],
            "os_choices": host_os_choices(),
            "os_values": f["os"],
            "headers": f["headers"],
            "sort": request.GET.get("sort", ""),
            "dir": f["direction"],
            "export_query": request.GET.urlencode(),
            "recap": host_recap(hosts),
            "filtered": bool(f["q"] or f["perimeter"] or f["tag"] or f["os"]),
        },
    )


HOST_EXPORT_COLUMNS = [
    "Hostname", "IP Address", "Private IP", "Server", "Tags", "OS", "Ubuntu Release", "Environment", "Load Balancer",
    "Open Critical", "Open High", "Open Medium", "Open Low", "Fixed by Installed Version", "Last Scanned",
]


def host_export(request):
    hosts, _ = filtered_hosts(request)
    hosts = _with_server_names(hosts)
    rows = (
        [
            h.hostname, h.ip_address, ", ".join(h.all_private_ips), ", ".join(getattr(h, "server_names", [])),
            ", ".join(t.name for t in h.tags.all()),
            h.os_version or h.os_name, h.get_ubuntu_release_display() if h.ubuntu_release else "",
            h.get_environment_display(), h.balancer_name or "",
            h.open_critical, h.open_high, h.open_medium, h.open_low, h.open_patched,
            h.last_scanned_at.strftime("%Y-%m-%d %H:%M") if h.last_scanned_at else "",
        ]
        for h in hosts
    )
    audit.log(request.user, "export.hosts", request.user, filters=request.GET.dict())
    return export.csv_response("pvm-hosts", HOST_EXPORT_COLUMNS, rows)


FINDING_EXPORT_COLUMNS = [
    "Priority", "Priority Score", "Severity", "Qualys Severity", "CVSS (NVD)", "EPSS (%)", "CVEs", "In CISA KEV", "QID",
    "Title", "Host", "IP Address", "Private IP", "Host Tags", "Perimeter", "Port", "Status", "Team", "Due Date",
    "First Detected", "Last Detected", "Patch Check",
]


def vulnerability_export(request):
    """The list's "Export CSV": the same rows the Export page writes, filters included."""
    findings, _ = filtered_findings(request.GET)
    findings = (
        _with_related(findings)
        .annotate(severity_rank=SEVERITY_RANK)
        .order_by("-priority_score", "severity_rank", "due_date", "pk")
    )
    audit.log(request.user, "export.findings", request.user, filters=request.GET.dict())
    return export.csv_response("pvm-vulnerabilities", FINDING_EXPORT_COLUMNS, reports.finding_rows(findings))


def host_detail(request, pk):
    host = get_object_or_404(Host, pk=pk)
    tab = request.GET.get("tab", "vulnerabilities")
    context = {
        "host": host,
        "tab": tab,
        "today": timezone.localdate(),
        "load_balancer": LoadBalancer.objects.filter(ip_address=host.ip_address).first(),
        "all_tags": Tag.objects.exclude(hosts=host),
    }

    if tab == "network":
        # Informational links between the public side and internal scans.
        private_ips = host.all_private_ips
        context["private_ips"] = private_ips
        # The names the balancer knows those servers by, e.g. 10.0.5.20 -> app-srv-05.
        context["server_names"] = balancer.names_for(private_ips, balancer.server_names())
        context["internal_hosts"] = (
            Host.objects.filter(ip_address__in=private_ips).exclude(pk=host.pk) if private_ips else []
        )
        context["published_as"] = Host.objects.filter(
            Q(private_ip=host.ip_address) | Q(pk__in=HostPrivateIp.objects.filter(ip_address=host.ip_address).values("host"))
        ).exclude(pk=host.pk)
        # What the stored balancer configurations say about this host.
        resolver = balancer.Resolver.stored()
        if resolver:
            via = network_mapping.private_ip_for(host) or host.private_ip
            context["reached_through"] = resolver.resolve(host.hostname, host.ip_address, via)
            context["backend_of"] = resolver.backend_of(host.ip_address)
        context["same_ip_count"] = Host.objects.filter(ip_address=host.ip_address).count()
        partial = "core/partials/host_network.html"
    elif tab == "packages":
        packages = host.packages.select_related("created_by").annotate(
            patch_backported=Exists(
                DistroPatchVerification.objects.filter(
                    vulnerability_finding__related_package=OuterRef("pk"), verdict__in=BACKPORTED_VERDICTS
                )
            )
        )
        field, direction, context["sort"], context["headers"] = sorting(request, PACKAGE_COLUMNS, "package")
        column = F(field).asc(nulls_last=True) if direction == "asc" else F(field).desc(nulls_last=True)
        context["packages"] = packages.order_by(column, "package_name")
        context["dir"] = direction
        context["releases"] = Host.UbuntuRelease.choices
        context["rocky_releases"] = Host.RockyRelease.choices
        if host.rocky_release:
            context["missing_packages"] = rocky_check.missing_packages(host)
        elif host.ubuntu_release:
            context["missing_packages"] = patchcheck.missing_packages(host)
        else:
            context["missing_packages"] = []
        context["inventory_command"] = inventory.COMMAND
        context["last_update"] = host.packages.order_by("-updated_at").select_related("created_by").first()
        address, port, username = ssh.target(host)
        context["ssh_target"] = f"{username}@{address}:{port}"
        context["ssh_not_ready"] = ssh.not_ready_reason(host)
        context["ssh_default_user"] = settings.SSH_DEFAULT_USER
        for field in ("ssh_host_key", "ssh_pending_host_key"):
            key = getattr(host, field)
            context[f"{field}_fingerprint"] = ssh.fingerprint(key) if key else ""
        if host.ssh_pending_host_key:
            context["ssh_host_key_file"] = ssh.host_key_file(host.ssh_pending_host_key)
        partial = "core/partials/host_packages.html"
    else:
        rows = (
            _with_related(host.findings.all())
            .select_related("distro_verification__verified_by", "related_package", "patch_check")
            .annotate(
                severity_rank=SEVERITY_RANK,
                is_resolved=Case(When(status=Status.RESOLVED, then=Value(1)), default=Value(0), output_field=IntegerField()),
            )
        )
        # Resolved findings stay at the bottom whatever the column.
        rows, context["headers"], context["sort"], context["dir"] = _sorted_findings(
            request, rows, HOST_FINDING_COLUMNS, tie=("is_resolved",)
        )
        findings = list(rows)
        # A verification recorded from a check stops describing the host once
        # a package it relied on changes version.
        installed = {p.package_name: p.version_for_tracker for p in host.packages.all()}
        for f in findings:
            verification = getattr(f, "distro_verification", None)
            f.verification_outdated = bool(
                verification
                and verification.from_patch_check
                and not patchcheck.verification_is_current(verification, installed)
            )
            f.can_confirm = patchcheck.needs_confirmation(
                getattr(f, "patch_check", None), verification, f.verification_outdated
            )
        history = triage.history(findings)
        for f in findings:
            f.history = history.get(f.pk, [])
        context["findings"] = findings
        context["teams"] = Team.objects.all()
        context["host_filter"] = f"host={host.pk}&status=open"
        context["triage_statuses"] = [(s.value, s.label) for s in triage.SETTABLE_STATUSES]
        context["package_count"] = len(installed)
        context["fixed_to_confirm"] = sum(
            1 for f in findings if f.can_confirm and f.patch_check.verdict in patchcheck.NOT_VULNERABLE_CHECKS
        )
        if host.is_windows:
            context["pm_last_checked"] = max(
                (f.patch_check.checked_at for f in findings if getattr(f, "patch_check", None) and f.patch_check.source == PatchCheck.Source.QUALYS_PM),
                default=None,
            )
        partial = "core/partials/host_findings.html"

    context["open_count"] = host.findings.exclude(status=Status.RESOLVED).count()
    context.setdefault("package_count", host.packages.count())
    context["check_running"] = host.patch_check_state == "running"
    template = partial if _is_htmx(request) else "core/host_detail.html"
    return render(request, template, context)


def _query_without_page(request):
    params = request.GET.copy()
    params.pop("page", None)
    return params.urlencode()

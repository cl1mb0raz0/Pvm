"""
Export: one page where every filter of the lists can be combined and the
result taken away as CSV, HTML or PDF.

The filters are the ones the Vulnerabilities and Hosts lists already use
(core.views.filtered_findings / filtered_hosts), so what the page shows and
what the file contains can never disagree; "Status: All" is what makes
resolved findings part of an export, which the lists hide by default.

CSV is the plain table for Excel (core/export.py). HTML and PDF are a
document: the filters that were applied, when, by whom, the counts, then
the table. The PDF is the same HTML rendered by WeasyPrint, so the two
always look alike.
"""

from datetime import timedelta

from django.http import HttpResponse
from django.shortcuts import render
from django.urls import reverse
from django.template.loader import render_to_string
from django.utils import timezone

from accounts.models import Team

from . import audit, export, history, reports
from .models import (
    PRIORITY_LEVELS,
    Perimeter,
    ScanImport,
    Tag,
    VulnerabilityDefinition,
    VulnerabilityFinding,
)
from .views import (
    CVSS_LABELS,
    IN_KEV,
    PATCH_FILTER_LABELS,
    PRIORITY_CHOICES,
    SEVERITY_RANK,
    _with_related,
    _with_server_names,
    filtered_findings,
    filtered_hosts,
)

Severity = VulnerabilityDefinition.Severity
Status = VulnerabilityFinding.Status
DATASETS = {"findings": "Vulnerabilities", "hosts": "Hosts"}
FORMATS = {"csv": "CSV (Excel)", "html": "HTML (Web Page)", "pdf": "PDF (to Print or Send)"}

# What the filters say, for the header of the HTML / PDF report. Each entry
# is (query key, label, how to read the value).
STATUS_CHOICES = [("open", "Open (Everything but Resolved)"), ("all", "All, Resolved Included")] + list(Status.choices)


def _labels(choices):
    return {str(value): label for value, label in choices}


def _list(params, key):
    return [v for v in params.getlist(key) if v] if hasattr(params, "getlist") else ([params.get(key)] if params.get(key) else [])


def _applied(params, dataset):
    """[(label, value)] of the filters in use, as a reader of the report should see them."""
    findings = dataset == "findings"
    tag_ids = [v for v in _list(params, "tag") if v.isdigit()]
    tag_names = list(Tag.objects.filter(pk__in=tag_ids).values_list("name", flat=True))
    if "none" in _list(params, "tag"):
        tag_names.append("No Tag")
    team = Team.objects.filter(pk=params.get("team")).first() if (params.get("team") or "").isdigit() else None
    scan = ScanImport.objects.filter(pk=params.get("import")).first() if (params.get("import") or "").isdigit() else None
    perimeter = Perimeter.objects.filter(slug=params.get("perimeter")).first()
    shown = [
        ("Search", params.get("q", "").strip()),
        ("Perimeter", perimeter.name if perimeter else ""),
        ("Tag", ", ".join(tag_names)),
    ]
    if findings:
        as_of = history.parse(params.get("as_of", ""))
        shown += [
            ("As Of", as_of.isoformat() if as_of else ""),
            ("Status", _labels(STATUS_CHOICES).get(params.get("status", "open"), "")),
            ("Severity", ", ".join(_labels(Severity.choices).get(v, v) for v in _list(params, "severity"))),
            ("Qualys Severity", ", ".join(_labels(VulnerabilityDefinition.QualysSeverity.choices).get(v, v) for v in _list(params, "qualys"))),
            ("Priority", ", ".join(dict(PRIORITY_CHOICES).get(v, v) for v in _list(params, "priority"))),
            ("CVSS (NVD)", ", ".join(dict(CVSS_LABELS).get(v, v) for v in _list(params, "cvss"))),
            ("Exploited", "In CISA KEV" if params.get("kev") == "yes" else ""),
            ("Patch Check", _labels(PATCH_FILTER_LABELS).get(params.get("patch", ""), "")),
            ("Team", "Unassigned" if params.get("team") == "none" else (team.name if team else "")),
            ("Source", _labels(ScanImport.Source.choices).get(params.get("source", ""), "")),
            ("Import", scan.label if scan else ""),
        ]
    return [(label, value) for label, value in shown if value]


def _for_export(request):
    """The dataset, the format and the parameters as the queries want them."""
    dataset = request.GET.get("dataset", "findings")
    dataset = dataset if dataset in DATASETS else "findings"
    fmt = request.GET.get("format", "csv")
    fmt = fmt if fmt in FORMATS else "csv"
    params = request.GET.copy()
    # The lists hide resolved findings by default; "all" is how an export asks
    # for everything, and filtered_findings reads that as "no status filter".
    if dataset == "findings" and params.get("status") == "all":
        params["status"] = ""
    return dataset, fmt, params


def _findings(params):
    """The rows an export of Vulnerabilities holds, and the filters as read."""
    findings, filters = filtered_findings(params)
    return (
        _with_related(findings)
        .annotate(severity_rank=SEVERITY_RANK)
        .order_by("-priority_score", "severity_rank", "due_date", "pk")
    ), filters


def page(request):
    """The Export page: choose what, filtered how, in which format."""
    return render(
        request,
        "core/export.html",
        {
            "datasets": DATASETS,
            "formats": FORMATS,
            "dataset": request.GET.get("dataset", "findings"),
            "statuses": STATUS_CHOICES,
            "severities": Severity.choices,
            "qualys_levels": VulnerabilityDefinition.QualysSeverity.choices,
            "priority_levels": PRIORITY_LEVELS,
            "patch_filters": PATCH_FILTER_LABELS,
            # The dropdowns that take several ticks, as on the lists.
            "priority_choices": PRIORITY_CHOICES,
            "cvss_choices": CVSS_LABELS,
            "tag_choices": [("none", "No Tag")] + [(str(t.pk), t.name) for t in Tag.objects.all()],
            "teams": Team.objects.all(),
            "sources": ScanImport.Source.choices,
            "perimeters": Perimeter.objects.all(),
            "tags": Tag.objects.all(),
            "imports": ScanImport.objects.filter(status=ScanImport.Status.COMPLETED)[:50],
            # "As Of" asks for a past day: today is what the lists already show.
            "yesterday": timezone.localdate() - timedelta(days=1),
            "counts": {
                "findings": VulnerabilityFinding.objects.count(),
                "open": VulnerabilityFinding.objects.exclude(status=Status.RESOLVED).count(),
            },
        },
    )


def preview(request):
    """What the export would hold, recomputed as the filters change (HTMX)."""
    dataset, _, params = _for_export(request)
    if dataset == "findings":
        findings, filters = filtered_findings(params)
        as_of, source = filters["as_of_date"], filters.get("as_of_source")
        context = {
            "dataset": dataset,
            "summary": reports.finding_summary(findings, source),
            "hosts": findings.values("host").distinct().count(),
            "kev": findings.filter(IN_KEV).count(),
            "applied": _applied(request.GET, dataset),
            "as_of": as_of,
            "as_of_note": history.describe(as_of, source, params.get("perimeter", "")) if as_of else "",
        }
    else:
        hosts, _filters = filtered_hosts(request)
        context = {
            "dataset": dataset,
            "summary": reports.host_summary(hosts),
            "hosts": None,
            "kev": None,
            "applied": _applied(request.GET, dataset),
        }
    return render(request, "core/partials/export_preview.html", context)


def run(request):
    """Build the export the form asked for."""
    dataset, fmt, params = _for_export(request)
    asked = request.GET  # what the user chose, for the report's header

    note = ""
    if dataset == "findings":
        rows_source, filters = _findings(params)
        as_of, source = filters["as_of_date"], filters.get("as_of_source")
        columns, paper = reports.FINDING_COLUMNS, reports.FINDING_PAPER_COLUMNS
        rows = reports.finding_rows(rows_source)
        summary = reports.finding_summary(rows_source, source) if fmt != "csv" else None
        basename, title, filter_columns = "pvm-vulnerabilities", "Vulnerabilities", reports.FINDING_FILTERS
        if as_of:
            title = f"Vulnerabilities as of {as_of.isoformat()}"
            note = history.describe(as_of, source, params.get("perimeter", ""))
    else:
        hosts, _ = filtered_hosts(request)
        rows_source = _with_server_names(hosts)
        columns, paper = reports.HOST_COLUMNS, reports.HOST_PAPER_COLUMNS
        rows = reports.host_rows(rows_source)
        summary = reports.host_summary(rows_source) if fmt != "csv" else None
        basename, title, filter_columns = "pvm-hosts", "Hosts", reports.HOST_FILTERS

    audit.log(request.user, f"export.{dataset}", request.user, format=fmt, filters=request.GET.dict())
    if fmt == "csv":
        return export.csv_response(basename, columns, rows)

    indexes = reports.keep(columns, paper)
    document = reports.document(
        title, paper, list(reports.narrow(rows, indexes)), summary, _applied(asked, dataset), request.user,
        filter_columns, note,
        qid_url=request.build_absolute_uri(reverse("core:vulnerability_detail", args=["0"]))[:-2] if dataset == "findings" else "",
    )
    html = render_to_string("core/reports/report.html", document, request=request)
    stamp = timezone.localtime().strftime("%Y%m%d-%H%M")
    if fmt == "html":
        response = HttpResponse(html, content_type="text/html; charset=utf-8")
        name = f"{basename}-{stamp}.html"
        if dataset == "findings":
            # pvm_vulnerabilities_<internal|external|all>_dd_mm_yy_hh_mm.html
            perimeter = (
                Perimeter.objects.filter(slug=params.get("perimeter")).values_list("slug", flat=True).first() or "all"
            )
            name = f"pvm_vulnerabilities_{perimeter}_{timezone.localtime():%d_%m_%y_%H_%M}.html"
        response["Content-Disposition"] = f'attachment; filename="{name}"'
        return response

    from weasyprint import HTML  # imported here: only the PDF path needs it

    pdf = HTML(string=html, base_url=request.build_absolute_uri("/")).write_pdf()
    response = HttpResponse(pdf, content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="{basename}-{stamp}.pdf"'
    return response

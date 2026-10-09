"""
Imports > Qualys Pm: Windows findings checked against Qualys Patch
Management (core.qualys_pm). There is no approval step, unlike Qualys
Csam: "Search Qualys Pm" writes the verdicts directly (a PatchCheck per
finding, source=qualys_pm), the same as the Ubuntu tracker's "Check Now".
This page shows the last run and, per Windows host, what it found; a
finding's own verdict and evidence are on the host page, alongside
"Confirm" (shared with the Ubuntu check, see core.patch_views).
"""

from django.contrib import messages
from django.db import transaction
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.views.decorators.http import require_POST

from accounts.permissions import editor_required

from . import audit, csam
from .models import PatchCheck, PmSearch
from .sorting import sort_rows, sorting
from .tasks import search_pm

PM_COLUMNS = [
    ("host", "Windows Host", lambda r: (r["host"].hostname or "").lower(), "asc", False),
    ("checked", "Findings Checked", lambda r: r["total"], "desc", True),
    ("missing", "Vulnerable, Patch Missing", lambda r: r["missing"], "desc", True),
    ("fixed", "Fixed", lambda r: r["fixed"], "desc", True),
    ("unknown", "Cannot Verify", lambda r: r["unknown"], "desc", True),
]


def _rows():
    """Per Windows host with at least one checked finding, the tally of its verdicts."""
    checks = PatchCheck.objects.filter(source=PatchCheck.Source.QUALYS_PM).select_related(
        "vulnerability_finding__host"
    )
    by_host = {}
    for check in checks:
        host = check.vulnerability_finding.host
        row = by_host.setdefault(host.pk, {"host": host, "missing": 0, "fixed": 0, "unknown": 0, "total": 0})
        row["total"] += 1
        if check.verdict == PatchCheck.Verdict.VULNERABLE_UPDATE:
            row["missing"] += 1
        elif check.verdict == PatchCheck.Verdict.FIXED:
            row["fixed"] += 1
        else:
            row["unknown"] += 1
    return list(by_host.values())


@editor_required
def page(request):
    search = PmSearch.objects.select_related("started_by").first()
    value, direction, sort, headers = sorting(request, PM_COLUMNS, "missing")
    context = {
        "headers": headers,
        "sort": sort,
        "dir": direction,
        "rows": sort_rows(_rows(), value, direction),
        "search": search,
        "configured": csam.configured(),
        "running": bool(search and search.state == PmSearch.State.RUNNING),
    }
    if search and search.state == PmSearch.State.DONE:
        context["unmatched"] = search.windows_hosts - search.matched
    if request.headers.get("HX-Request") == "true":
        if not context["running"]:
            # Finished while the page was polling: reload it with the results.
            response = HttpResponse(status=204)
            response["HX-Refresh"] = "true"
            return response
        return render(request, "core/imports/partials/pm_status.html", context)
    return render(request, "core/imports/qualys_pm.html", context)


@editor_required
@require_POST
def start(request):
    if not csam.configured():
        messages.error(request, "Qualys Pm Is Not Configured in .env (Same Credentials as Qualys Csam).")
        return redirect("core:qualys_pm")
    with transaction.atomic():
        PmSearch.objects.all().delete()  # only the latest search is kept
        search = PmSearch.objects.create(started_by=request.user)
        audit.log(request.user, "pm.search_started", search)

        def enqueue():
            try:
                search_pm.delay(search.pk)
            except Exception as exc:  # broker unreachable
                PmSearch.objects.filter(pk=search.pk).update(
                    state=PmSearch.State.FAILED, error=f"Could Not Start the Search: {exc}"
                )

        transaction.on_commit(enqueue)
    return redirect("core:qualys_pm")

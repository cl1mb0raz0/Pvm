from datetime import date

from django.contrib import messages
from django.http import QueryDict
from django.shortcuts import redirect
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_POST

from accounts.models import Team
from accounts.permissions import editor_required

from . import triage
from .models import VulnerabilityFinding
from .views import filtered_findings


def _back(request):
    url = request.POST.get("next", "")
    if url_has_allowed_host_and_scheme(url, allowed_hosts={request.get_host()}, require_https=request.is_secure()):
        return redirect(url)
    return redirect("core:vulnerability_list")


def _parse_changes(post):
    """The requested changes as update() keyword arguments, or an error message."""
    changes = {}
    team = post.get("team", "")
    if team == "none":
        changes["team"] = None
    elif team.isdigit():
        found = Team.objects.filter(pk=team).first()
        if found is None:
            return None, "That Team No Longer Exists."
        changes["team"] = found
    due_mode, due_value = post.get("due_mode", ""), post.get("due_date", "")
    if due_mode == "policy":
        changes["due"] = triage.FOLLOW_POLICY
    elif due_mode == "date" or due_value:
        try:
            changes["due"] = date.fromisoformat(due_value)
        except ValueError:
            return None, "Enter a Valid Due Date."
    status = post.get("status", "")
    if status:
        if status not in triage.SETTABLE_STATUSES:
            return None, "That Status Cannot Be Set by Hand."
        changes["status"] = status
    if not changes:
        return None, "Choose a Team, a Due Date or a Status to Apply."
    return changes, None


@editor_required
@require_POST
def triage_findings(request):
    """
    Apply team / due date / status to the ticked findings, or to every
    finding matching the filters the list was showing ("scope=all").
    """
    changes, error = _parse_changes(request.POST)
    if error:
        messages.error(request, error)
        return _back(request)

    if request.POST.get("scope") == "all":
        findings, _ = filtered_findings(QueryDict(request.POST.get("filters", "")))
        findings = VulnerabilityFinding.objects.filter(pk__in=findings.values("pk"))
    else:
        ids = [i for i in request.POST.getlist("finding") if i.isdigit()]
        if not ids:
            messages.error(request, "Select at Least One Finding.")
            return _back(request)
        findings = VulnerabilityFinding.objects.filter(pk__in=ids)

    note = request.POST.get("note", "").strip()[:500]
    count = triage.update(findings, request.user, note=note, **changes)
    if count:
        messages.success(request, f"{count} Finding{'s' if count != 1 else ''} Updated.")
    else:
        messages.info(request, "Nothing Changed: The Findings Already Had These Values.")
    return _back(request)

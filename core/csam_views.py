"""
Imports > Qualys CSAM: what Qualys' asset inventory knows about PVM's hosts
(core.csam), shown as proposals; only what the user ticks is imported.
"""

from datetime import timedelta

from django.contrib import messages
from django.http import HttpResponse
from django.db import transaction
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from accounts.permissions import editor_required

from . import audit, csam
from .models import CsamProposal, CsamSearch, Host, HostPrivateIp, InstalledPackage
from .patch_views import start_check
from .sorting import sort_rows, sorting
from .tasks import search_csam

PACKAGE_DETAILS_SHOWN = 60
# A finished search older than this is flagged: Csam may know more by now.
STALE_SEARCH_DAYS = 7
OS_MAX = Host._meta.get_field("os_version").max_length
PENDING_CACHE_KEY = "pvm-csam-pending"
PENDING_CACHE_SECONDS = 120


def _package_diff(proposal, current):
    """(new, changed, missing) comparing the agent's list with the host's current packages."""
    found = dict(proposal.packages)
    new = sorted(n for n in found if n not in current)
    changed = sorted((n, current[n], v) for n, v in found.items() if n in current and current[n] != v)
    missing = sorted(n for n in current if n not in found)
    return new, changed, missing


LOOKUP_CACHE_SECONDS = 300


def _lookup(query):
    """Live search in Qualys Csam by name or IP (cached a few minutes), with the PVM hosts each asset matches."""
    from django.core.cache import cache
    from django.db.models import Q

    key = "pvm-csam-lookup-" + query.lower()
    found = cache.get(key)
    if found is None:
        client = csam.Client()
        assets = client.lookup(query)
        agents = [
            a["assetId"] for a in assets
            if (a.get("inventory") or {}).get("source") == "QAGENT"
            and (
                csam.ubuntu_release(a.get("operatingSystem") or {})
                or csam.windows_detected(a.get("operatingSystem") or {})
                or csam.rocky_detected(a.get("operatingSystem") or {})
            )
        ]
        software = client.software(agents[: csam.SOFTWARE_BATCH]) if agents else {}
        found = [(a, software.get(a["assetId"])) for a in assets]
        cache.set(key, found, LOOKUP_CACHE_SECONDS)
    results = []
    for asset, software in found:
        info = csam.describe(asset, software)
        addresses = info["addresses"]
        nearby = list(
            Host.objects.filter(
                Q(ip_address__in=addresses)
                | Q(private_ip__in=addresses)
                | Q(pk__in=HostPrivateIp.objects.filter(ip_address__in=addresses).values("host"))
            ).prefetch_related("other_private_ips")
        )
        info["pvm_hosts"] = [(h, how) for h, _, how in csam.match(nearby, [asset])]
        matched = {h.pk for h, _ in info["pvm_hosts"]}
        info["same_ip_hosts"] = [h for h in nearby if h.pk not in matched]
        results.append(info)
    return results


SOFTWARE_LOOKUP_CACHE_SECONDS = 300


def _software_lookup(query):
    """Live search in Qualys Csam by software name (cached a few minutes), with the PVM hosts each asset matches."""
    from django.core.cache import cache
    from django.db.models import Q

    key = "pvm-csam-software-" + query.lower()
    cached = cache.get(key)
    if cached is None:
        results, truncated, _calls = csam.search_software(query)
        cached = (results, truncated)
        cache.set(key, cached, SOFTWARE_LOOKUP_CACHE_SECONDS)
    results, truncated = cached

    rows, addresses = [], set()
    for asset, matches in results:
        info = csam.describe(asset)
        info["matches"] = matches
        rows.append(info)
        addresses.update(info["addresses"])

    hosts = (
        list(
            Host.objects.filter(
                Q(ip_address__in=addresses)
                | Q(private_ip__in=addresses)
                | Q(pk__in=HostPrivateIp.objects.filter(ip_address__in=addresses).values("host"))
            ).prefetch_related("other_private_ips")
        )
        if addresses
        else []
    )
    asset_by_id = {a["assetId"]: a for a, _ in results}
    matched = {}
    if hosts and asset_by_id:
        for host, asset, how in csam.match(hosts, list(asset_by_id.values())):
            matched.setdefault(asset["assetId"], []).append((host, how))
    for row in rows:
        row["pvm_hosts"] = matched.get(row["asset_id"], [])
    return rows, truncated


def _matches_query(row, query):
    q = query.lower()
    host, p = row["host"], row["p"]
    return (
        q in host.hostname.lower()
        or host.ip_address.startswith(q)
        or (host.private_ip or "").startswith(q)
        or q in (p.asset_name or "").lower()
    )


def _rows(search, only_changes):
    proposals = list(search.proposals.select_related("host", "imported_by").prefetch_related("host__tags"))
    current, manual = {}, {}
    for name, version, source, host_id in (
        Host.objects.filter(pk__in=[p.host_id for p in proposals])
        .values_list("packages__package_name", "packages__installed_version", "packages__source", "pk")
    ):
        if name:
            current.setdefault(host_id, {})[name] = version
            if source == InstalledPackage.Source.MANUAL:
                manual.setdefault(host_id, set()).add(name)
    rows = []
    for p in proposals:
        host = p.host
        new, changed, missing = _package_diff(p, current.get(host.pk, {})) if p.packages else ([], [], [])
        missing_manual = sorted(set(missing) & manual.get(host.pk, set()))
        differences = {
            "release": bool(p.ubuntu_release and p.ubuntu_release != host.ubuntu_release),
            "packages": bool(new or changed or missing),
            # The column is shorter than some Qualys names: compare what would be stored.
            "os": bool(p.os_full and p.os_full[:OS_MAX] != host.os_version),
            "tags": bool(set(p.qualys_tags) - {t.name for t in host.tags.all()}),
        }
        if only_changes and not any(differences.values()):
            continue
        # What is still to import: not imported from this search yet, and a difference that
        # importing with the default ticks would settle. Tags are off by default (the user
        # chooses them), and a manually-added package the agent no longer reports is kept by
        # default, so neither counts on its own; they stay visible in the table.
        pending = not p.imported_at and (
            differences["release"] or differences["os"]
            or bool(new or changed or set(missing) - set(missing_manual))
        )
        rows.append(
            {
                "p": p,
                "host": host,
                "diff": differences,
                "pending": pending,
                "new": new[:PACKAGE_DETAILS_SHOWN],
                "changed": changed[:PACKAGE_DETAILS_SHOWN],
                "missing": missing[:PACKAGE_DETAILS_SHOWN],
                "missing_manual": missing_manual,
                "counts": {"new": len(new), "changed": len(changed), "missing": len(missing)},
                "release_label": dict(Host.UbuntuRelease.choices).get(p.ubuntu_release, ""),
            }
        )
    return rows


def _todo(search, rows=None):
    """
    What the Qualys Csam banner and the sidebar badge say: how many hosts have
    details in the last search that Pvm does not have yet (nothing imported is
    counted again), and whether that search is old enough that Csam may know
    more. Only reads the stored search: it never calls Qualys.
    """
    if not search or search.state != CsamSearch.State.DONE:
        return {"count": 0, "stale": False, "searched_at": None}
    if rows is None:
        rows = _rows(search, True)
    searched_at = search.finished_at
    stale = bool(searched_at and timezone.now() - searched_at > timedelta(days=STALE_SEARCH_DAYS))
    return {"count": sum(1 for r in rows if r["pending"]), "stale": stale, "searched_at": searched_at}


def pending_summary():
    """
    `_todo` of the latest search for the sidebar of every page. Kept two
    minutes per process, under a key that changes with the search and with
    every proposal imported, so an import or a new search shows at once in
    every web worker (a hand edit of a host's packages can lag the two
    minutes). A few cheap queries when the key is warm.
    """
    from django.core.cache import cache

    search = CsamSearch.objects.first()
    if not search or search.state != CsamSearch.State.DONE:
        return _todo(None)
    imported = search.proposals.filter(imported_at__isnull=False).count()
    key = f"{PENDING_CACHE_KEY}-{search.pk}-{search.finished_at.timestamp() if search.finished_at else 0:.0f}-{imported}"
    todo = cache.get(key)
    if todo is None:
        todo = _todo(search)
        cache.set(key, todo, PENDING_CACHE_SECONDS)
    return todo


# Proposal columns: (query key, header, value sorted on, first click, numeric).
# The rows are built in Python, so these are callables (core.sorting.sort_rows).
PROPOSAL_COLUMNS = [
    ("host", "Your Host", lambda r: (r["host"].hostname or "").lower(), "asc", False),
    ("asset", "Qualys Asset", lambda r: (r["p"].asset_name or "").lower(), "asc", False),
    ("agent", "Agent", lambda r: r["p"].agent_checked_in, "desc", False),
    ("release", "Ubuntu Release", lambda r: r["release_label"], "asc", False),
    ("packages", "Installed Packages", lambda r: len(r["p"].packages or []), "desc", False),
    ("os", "Operating System", lambda r: r["p"].os_full, "asc", False),
    ("tags", "Qualys Tags", lambda r: ", ".join(r["p"].qualys_tags), "asc", False),
]


# Hosts with no inventory in Pvm, and why (the "Hosts Without Inventory"
# table): its own query keys, so sorting it leaves the proposals alone.
GAP_COLUMNS = [
    ("host", "Host", lambda r: (r["host"].hostname or "").lower(), "asc", False),
    ("ip", "IP", lambda r: r["host"].ip_address, "asc", False),
    ("private", "Private IP", lambda r: r["private"], "asc", False),
    ("tags", "Tags", lambda r: r["tags"], "asc", False),
    ("why", "Why", lambda r: r["why"], "asc", False),
    ("scanned", "Last Scanned", lambda r: r["host"].last_scanned_at, "desc", False),
]
# Why a host has no packages and no release in Pvm, worst case first.
NOT_IN_CSAM = "Not in Qualys Csam"
NO_AGENT = "In Csam, No Cloud Agent"
NOT_IMPORTED = "In Csam with Packages, Not Imported Yet"


def _gaps(search):
    """
    The hosts Pvm knows nothing about yet: no installed packages and no Ubuntu
    release, with the reason. "Not Imported Yet" is the one to act on; the
    others need the agent installed, or Ssh, or a mail to the sysadmin.
    """
    proposals = {p.host_id: p for p in search.proposals.all()} if search else {}
    hosts = (
        Host.objects.filter(is_active=True, ubuntu_release="")
        .exclude(packages__isnull=False)
        .prefetch_related("tags", "other_private_ips")
        .order_by("hostname")
    )
    rows = []
    for host in hosts:
        proposal = proposals.get(host.pk)
        if proposal is None:
            why = NOT_IN_CSAM
        elif proposal.packages:
            why = NOT_IMPORTED
        else:
            why = NO_AGENT
        rows.append(
            {
                "host": host,
                "why": why,
                "asset": proposal.asset_name if proposal else "",
                "private": ", ".join(host.all_private_ips),
                "tags": ", ".join(t.name for t in host.tags.all()),
            }
        )
    return rows


@editor_required
def page(request):
    search = CsamSearch.objects.select_related("started_by").first()
    query = request.GET.get("q", "").strip()[:100]
    software_query = request.GET.get("sw", "").strip()[:100]
    only_changes = request.GET.get("all") != "1" and not query
    done = bool(search and search.state == CsamSearch.State.DONE)
    rows = _rows(search, only_changes) if done else []
    # The banner counts what is new whatever the filters on screen: reuse the rows when they already are that.
    todo = _todo(search, rows if only_changes else None)
    if query:
        rows = [r for r in rows if _matches_query(r, query)]
    value, direction, sort, headers = sorting(request, PROPOSAL_COLUMNS, "host")
    rows = sort_rows(rows, value, direction)
    gaps = _gaps(search) if done else []
    gap_value, gap_direction, gap_sort, gap_headers = sorting(request, GAP_COLUMNS, "why", prefix="gap_")
    context = {
        "headers": headers,
        "sort": sort,
        "dir": direction,
        "gaps": sort_rows(gaps, gap_value, gap_direction),
        "gap_headers": gap_headers,
        "gap_sort": gap_sort,
        "gap_dir": gap_direction,
        "gap_counts": {
            "total": len(gaps),
            "to_import": sum(1 for g in gaps if g["why"] == NOT_IMPORTED),
            "no_agent": sum(1 for g in gaps if g["why"] == NO_AGENT),
            "unknown": sum(1 for g in gaps if g["why"] == NOT_IN_CSAM),
        },
        "search": search,
        "configured": csam.configured(),
        "running": bool(search and search.state == CsamSearch.State.RUNNING),
        "only_changes": only_changes,
        "rows": rows,
        "todo": todo,
        "preselect_pending": request.GET.get("select") == "pending",
        "manual_at_risk_count": sum(1 for r in rows if r["missing_manual"]),
        "q": query,
        "lookup": [],
        "lookup_error": "",
        "sw": software_query,
        "software_results": [],
        "software_truncated": False,
        "software_error": "",
    }
    if query and csam.configured() and request.headers.get("HX-Request") != "true":
        if len(query) < 3:
            context["lookup_error"] = "Type at Least 3 Characters, or a Whole IP Address."
        else:
            try:
                context["lookup"] = _lookup(query)
            except csam.CsamError as exc:
                context["lookup_error"] = str(exc)
    if software_query and csam.configured() and request.headers.get("HX-Request") != "true":
        if len(software_query) < 3:
            context["software_error"] = "Type at Least 3 Characters."
        else:
            try:
                context["software_results"], context["software_truncated"] = _software_lookup(software_query)
            except csam.CsamError as exc:
                context["software_error"] = str(exc)
    if search and search.state == CsamSearch.State.DONE:
        context["unmatched"] = search.hosts_total - search.matched
        context["imported"] = search.proposals.filter(imported_at__isnull=False).count()
    if request.headers.get("HX-Request") == "true":
        if not context["running"]:
            # Finished while the page was polling: reload it with the results.
            response = HttpResponse(status=204)
            response["HX-Refresh"] = "true"
            return response
        return render(request, "core/imports/partials/csam_status.html", context)
    return render(request, "core/imports/qualys_csam.html", context)


@editor_required
@require_POST
def start(request):
    if CsamSearch.objects.filter(state=CsamSearch.State.RUNNING).exists():
        messages.info(request, "A Search Is Already Running.")
        return redirect("core:qualys_csam")
    if not csam.configured():
        messages.error(request, "Qualys Csam Is Not Configured in .env.")
        return redirect("core:qualys_csam")
    with transaction.atomic():
        CsamSearch.objects.all().delete()  # only the latest search is kept
        search = CsamSearch.objects.create(started_by=request.user)
        audit.log(request.user, "csam.search_started", search)

        def enqueue():
            try:
                search_csam.delay(search.pk)
            except Exception as exc:  # broker unreachable
                CsamSearch.objects.filter(pk=search.pk).update(state=CsamSearch.State.FAILED, error=f"Could Not Start the Search: {exc}")

        transaction.on_commit(enqueue)
    return redirect("core:qualys_csam")


@editor_required
@require_POST
def import_selected(request):
    kinds = [k for k in csam.KINDS if request.POST.get(f"kind_{k}")]
    ids = [i for i in request.POST.getlist("proposal") if i.isdigit()]
    if not kinds or not ids:
        messages.error(request, "Tick at Least One Host and One Kind of Detail to Import.")
        return redirect("core:qualys_csam")
    remove_manual = bool(request.POST.get("remove_manual_packages"))
    imported, rechecked, held_back = 0, 0, []
    for proposal in CsamProposal.objects.filter(pk__in=ids).select_related("host"):
        at_risk = (
            csam.manual_packages_at_risk(proposal.host, proposal.packages)
            if "packages" in kinds and proposal.packages and not remove_manual
            else []
        )
        with transaction.atomic():
            changed = csam.apply(proposal, kinds, request.user, remove_manual=remove_manual)
            proposal.imported_at, proposal.imported_by = timezone.now(), request.user
            proposal.save(update_fields=["imported_at", "imported_by"])
            if changed:
                audit.log(request.user, "csam.imported", proposal.host, asset_id=proposal.asset_id, changed=changed)
                imported += 1
            # New release or packages: check the host's findings again (Ubuntu tracker or Rocky
            # errata; a no-op, start_check returns False, for a host neither applies to).
            if {"Ubuntu Release", "Rocky Release"} & set(changed) or any(c.endswith("Packages") for c in changed):
                rechecked += start_check(Host.objects.get(pk=proposal.host_id))
        if at_risk:
            held_back.append((proposal.host, at_risk))
    messages.success(
        request,
        f"Details Imported for {imported} Host{'s' if imported != 1 else ''}"
        f"{f'; the Patch Check Runs Again on {rechecked}' if rechecked else ''}.",
    )
    if held_back:
        names = ", ".join(f"{h.hostname} ({len(pkgs)})" for h, pkgs in held_back[:5])
        more = f" and {len(held_back) - 5} More" if len(held_back) > 5 else ""
        messages.warning(
            request,
            f"Kept {sum(len(p) for _, p in held_back)} Manually-Added Package"
            f"{'s' if sum(len(p) for _, p in held_back) != 1 else ''} on {len(held_back)} "
            f"Host{'s' if len(held_back) != 1 else ''} That Csam No Longer Reports ({names}{more}). "
            f"Tick \"Also Remove Manually-Added Packages\" and Import Again to Remove Them Too.",
        )
    return redirect("core:qualys_csam")

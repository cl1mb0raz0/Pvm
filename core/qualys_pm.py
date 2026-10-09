"""
Qualys Patch Management (PM): checks PVM's Windows findings against what
Qualys' own PM module already knows about each host's missing and
installed patches, since Windows has no free security tracker like
Ubuntu's.

Nothing is imported into a host's data (unlike Qualys Csam): "Search
Qualys Pm" (Imports > Qualys Pm) reads PVM's Windows hosts, matches them
to Qualys PM assets by IP/name (core.csam-style matching), and writes a
PatchCheck (source=qualys_pm) directly on every relevant finding it can
match by QID, no approval step, exactly like the Ubuntu tracker check
(core.patchcheck): the verdict is advisory, only closing a finding needs
a manual Confirm.

How the correlation works: a PM "patch" (a Windows Update, a vendor
update such as a SQL Server GDR, a third-party app update) carries the
Qualys QID(s) it resolves. A PM "asset" lists, per host, which patch ids
are missing and which are installed. So for a finding's QID: look up the
patches that resolve it, then check whether Qualys PM has them installed
or still missing on that host. No CVE-to-KB mapping is built by PVM: it
is Qualys PM's own reconciliation, already keyed by the same QID PVM
already imports from every scan.

The patch catalog is read once per search and used only for the run
(nothing is kept locally between searches, only the resulting PatchCheck
rows), the same "mirror once, match locally" idea as core.kev but
without the local table: querying Qualys per finding would cost one call
per finding, the catalog fits under a dozen calls at 1,000 rows a page
instead. Checked live: the gateway refuses to page the listing past
roughly its first 10,000 rows ("Only the first 10000 results can be
displayed..."), well short of the full catalog (~43,000 on 2026-09-29);
since it sorts newest published first, a search still sees the newest,
most-likely-to-still-be-missing patches, and a QID whose only patch is
older than that reads as "cannot verify" rather than a guess
(Client.pm_patches stops on that specific error, keeping what it read).
"""

from django.db.models import Q
from django.utils import timezone

from . import csam, patchcheck
from .csam import CsamError as PmError  # noqa: F401 - re-exported: same gateway, same failure modes
from .models import Host, PatchCheck

Verdict = PatchCheck.Verdict

ASSET_PAGE_SIZE = 100
PATCH_PAGE_SIZE = 1000
# Qualys' own wording when a listing is paged past its cap ("Only the
# first 10000 results can be displayed. Refine your search query...").
_PAGING_CAPPED = "Only the first"


class Client(csam.Client):
    """Qualys Patch Management calls, on the same gateway/token as Csam."""

    def pm_assets(self):
        """Every asset PM has scanned, with its missing/installed patch ids."""
        assets, page = [], 1
        while True:
            data = self._call("GET", "/pm/v1/assets", params={"pageSize": ASSET_PAGE_SIZE, "pageNumber": page})
            if not data:
                break
            assets.extend(data)
            if len(data) < ASSET_PAGE_SIZE:
                break
            page += 1
        return assets

    def pm_patches(self):
        """
        The patch catalog: id, the QID(s) it resolves, CVEs, KB, title -
        newest published first (Qualys' own sort). The gateway refuses to
        page a listing past a cap somewhere around its first 10,000 rows
        ("Only the first 10000 results can be displayed..."), well short
        of the ~43,000 total, so a search only ever sees the newest
        patches: the ones most likely to still be missing on a host
        scanned today. A QID whose only patch is older than that reads as
        "cannot verify" rather than a guess.
        """
        patches, page = [], 1
        while True:
            try:
                data = self._call("GET", "/pm/v1/patches", params={"pageSize": PATCH_PAGE_SIZE, "pageNumber": page})
            except PmError as exc:
                if page > 1 and _PAGING_CAPPED in str(exc):
                    break
                raise
            if not data:
                break
            patches.extend(data)
            if len(data) < PATCH_PAGE_SIZE:
                break
            page += 1
        return patches


def windows_hosts():
    """PVM hosts whose recorded OS is some Windows (see Host.is_windows)."""
    return Host.objects.filter(Q(os_version__icontains="windows") | Q(os_name__icontains="windows"))


def build_index(patches):
    """
    (catalog, by_qid): catalog is {patch id: {qids, cve, kb, title}}; by_qid
    is {QID: {patch ids}}, for a finding's QID to look up in O(1).
    """
    catalog, by_qid = {}, {}
    for p in patches:
        pid = p.get("id")
        if not pid:
            continue
        qids = {str(q) for q in (p.get("qid") or [])}
        catalog[pid] = {
            "qids": qids,
            "cve": [c for c in (p.get("cve") or []) if c],
            "kb": str(p.get("kb") or ""),
            "title": p.get("title") or pid,
        }
        for qid in qids:
            by_qid.setdefault(qid, set()).add(pid)
    return catalog, by_qid


def _addresses(asset):
    return {i.get("address") for i in (asset.get("interfaces") or []) if i.get("address")}


def _names(asset):
    # PM asset names sometimes carry a " - <tenant>" suffix.
    name = (asset.get("name") or "").split(" - ")[0].strip().lower().rstrip(".")
    return {name, name.split(".")[0]} if name else set()


def match(hosts, assets):
    """[(host, asset, how)] for the Windows hosts that have a Patch Management asset."""
    by_ip = {}
    for asset in assets:
        for ip in _addresses(asset):
            by_ip.setdefault(ip, []).append(asset)
    hosts_per_ip = {}
    for host in hosts:
        hosts_per_ip.setdefault(host.ip_address, []).append(host)

    matches = []
    for host in hosts:
        name = (host.hostname or "").lower().rstrip(".")
        found = None
        for ip, how in [(p, "Private IP") for p in host.all_private_ips] + [(host.ip_address, "IP")]:
            if not ip:
                continue
            candidates = by_ip.get(ip, [])
            named = [a for a in candidates if name and (name in _names(a) or name.split(".")[0] in _names(a))]
            if len(named) == 1:
                found = (named[0], f"{how} and Name")
            elif how == "IP" and len(candidates) == 1 and len(hosts_per_ip.get(ip, [])) == 1:
                found = (candidates[0], "IP Only")
            elif how == "Private IP" and len(candidates) == 1:
                found = (candidates[0], "Private IP")
            if found:
                break
        if found:
            matches.append((host, found[0], found[1]))
    return matches


def _kb_note(kb):
    if not kb:
        return ""
    return f" (KB{kb})" if kb[0].isdigit() else f" ({kb})"


def check_finding(finding, missing_ids, installed_ids, catalog, by_qid):
    """Create or update the finding's PatchCheck from Qualys Patch Management."""
    qid = finding.vulnerability_definition.qid
    primary_cve = next((c.cve_id for c in finding.vulnerability_definition.cves.all()), "")
    relevant = sorted(by_qid.get(qid, set()) & (missing_ids | installed_ids))
    if not relevant:
        details = [
            {
                "cve": primary_cve,
                "verdict": Verdict.UNKNOWN,
                "packages": [],
                "missing": [],
                "kb": "",
                "reason": "No Matching Patch Found in Qualys Patch Management",
            }
        ]
    else:
        details = []
        for pid in relevant:
            patch = catalog[pid]
            is_missing = pid in missing_ids
            verdict = Verdict.VULNERABLE_UPDATE if is_missing else Verdict.FIXED
            details.append(
                {
                    "cve": patch["cve"][0] if patch["cve"] else primary_cve,
                    "verdict": verdict,
                    "packages": [],
                    "missing": [],
                    "kb": patch["kb"],
                    "reason": f"{'Missing' if is_missing else 'Installed'} in Qualys Patch Management: "
                    f"{patch['title']}{_kb_note(patch['kb'])}",
                }
            )
    check, _ = PatchCheck.objects.update_or_create(
        vulnerability_finding=finding,
        defaults={
            "verdict": patchcheck.worst(d["verdict"] for d in details),
            "source": PatchCheck.Source.QUALYS_PM,
            "ubuntu_release": "",
            "details": details,
            "package_versions": {},
            "checked_at": timezone.now(),
        },
    )
    return check


def check_host(host, missing_ids, installed_ids, catalog, by_qid):
    """Re-check every relevant finding of `host`. Returns {verdict: count}."""
    counts = {}
    for finding in patchcheck.findings_to_check(host):
        check = check_finding(finding, missing_ids, installed_ids, catalog, by_qid)
        counts[check.verdict] = counts.get(check.verdict, 0) + 1
    return counts


def run_search(search):
    """Fill `search` (a PmSearch) by checking every matched Windows host; raises PmError."""
    client = Client()
    hosts = list(windows_hosts().prefetch_related("other_private_ips"))
    assets = client.pm_assets()
    matches = match(hosts, assets)
    patches = client.pm_patches()
    catalog, by_qid = build_index(patches)

    totals = {}
    findings_checked = 0
    for host, asset, _how in matches:
        missing_ids = {p.get("id") for p in (asset.get("missingPatches") or []) if p.get("id")}
        installed_ids = {i for i in (asset.get("installedPatches") or []) if i}
        for verdict, count in check_host(host, missing_ids, installed_ids, catalog, by_qid).items():
            totals[verdict] = totals.get(verdict, 0) + count
            findings_checked += count

    search.windows_hosts = len(hosts)
    search.matched = len(matches)
    search.patches_seen = len(patches)
    search.findings_checked = findings_checked
    search.missing_count = totals.get(Verdict.VULNERABLE_UPDATE, 0)
    search.fixed_count = totals.get(Verdict.FIXED, 0)
    search.unknown_count = totals.get(Verdict.UNKNOWN, 0)
    search.api_calls = client.calls
    search.save()

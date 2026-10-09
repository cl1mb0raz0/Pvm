"""
Qualys CSAM (asset inventory): details about the hosts PVM already has.

Nothing changes on its own. "Search Qualys Csam" (Imports > Qualys Csam)
reads the subscription's assets, matches them to PVM's hosts and stores
what it found as proposals (CsamProposal); the user then picks hosts and
kinds of data to import. The gateway API is used with a short-lived token
from the same Qualys credentials as the VMDR API.

- Listing: every asset with only the fields needed to match and show
  (about 14 calls for 1,300 assets, 100 per page)
- Matching, per PVM host: its scanned IP (or its private IP, the real
  server behind a load balancer) must be one of the asset's addresses,
  and its host name must match one of the asset's names; an IP alone is
  enough only when that IP has one PVM host and one asset (a load
  balancer's address fronts many hosts and never matches by IP alone)
- Packages: for matched Ubuntu, Windows or Rocky Linux assets inventoried
  by the Qualys Cloud Agent only, 10 assets per call. For Ubuntu, the
  agent lists each dpkg package with its name (discoveredName,
  "openssh-server", "libc6:amd64") and full version (discoveredVersion,
  "1:9.6p1-3ubuntu13.19"); for Windows it lists installed software the
  same way, with free-text names and versions (no dpkg format to check
  against); for Rocky it lists each RPM, name and version-release, the
  architecture sometimes baked into the version string
  ("9.0.87-1.el9.noarch") and sometimes not - stripped so it matches the
  same package's fixed version from Rocky's errata (core.rocky). Stale
  entries kept by CSAM (e.g. from before a release upgrade) are left out.
  Windows packages are informational only: PVM has no security tracker
  for Windows, so there is no automatic verdict, only the list on the
  host page (an analyst verifies by hand); Rocky and Ubuntu both get a
  full automatic verdict (core.patchcheck, core.rocky_check)

The subscription allows 300 gateway calls an hour; a search stays far
below that.
"""

import ipaddress
import json
import logging
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta
from datetime import timezone as dt_timezone

from django.conf import settings
from django.db import transaction

from . import debversion, inventory
from .models import CsamProposal, Host, InstalledPackage

logger = logging.getLogger(__name__)

PAGE_SIZE = 100
SOFTWARE_BATCH = 10
# One page of identities; software is fetched only for these, batched.
SOFTWARE_SEARCH_LIMIT = 100
TIMEOUT_SECONDS = 300
LIST_FIELDS = "assetId,hostId,address,dnsName,fqdn,assetName,netbiosName,operatingSystem,agent,tag,criticality,inventory,networkInterface"
# Trailing RPM architecture Qualys sometimes bakes into the version string.
_RPM_ARCH_SUFFIX = re.compile(r"\.(noarch|x86_64|aarch64|i686|i386|s390x|ppc64le)$")


class CsamError(Exception):
    """The gateway could not be reached or refused; the message is shown to the user."""


def configured():
    return bool(settings.QUALYS_GATEWAY_URL and settings.QUALYS_USERNAME and settings.QUALYS_PASSWORD)


class Client:
    def __init__(self):
        if not configured():
            raise CsamError("Qualys Csam Is Not Configured: Set QUALYS_GATEWAY_URL, QUALYS_USERNAME and QUALYS_PASSWORD in .env.")
        self.base = settings.QUALYS_GATEWAY_URL.rstrip("/")
        self.token = self._authenticate()
        self.calls = 1

    def _authenticate(self):
        data = urllib.parse.urlencode(
            {"username": settings.QUALYS_USERNAME, "password": settings.QUALYS_PASSWORD, "token": "true"}
        ).encode()
        request = urllib.request.Request(
            self.base + "/auth", data=data, headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as r:
                return r.read().decode().strip()
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise CsamError("Qualys Refused the Credentials in .env for Csam (Does the User Have Csam / API Access?).") from exc
            raise CsamError(f"Qualys Gateway Answered {exc.code}.") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise CsamError(f"Qualys Gateway Unreachable (Is Cato Connected on the VM?): {exc}") from exc

    def _call(self, method, path, params=None, body=None):
        """
        One gateway call, shared by every API under this base (CSAM's asset
        search and, in core.qualys_pm, Patch Management): retries a 429 after
        its wait header, retries a network error twice, wraps every other
        failure so the page can show why.
        """
        url = self.base + path + (("?" + urllib.parse.urlencode(params)) if params else "")
        data_bytes = json.dumps(body).encode() if body is not None else None
        for attempt in range(3):
            request = urllib.request.Request(
                url, data=data_bytes, method=method,
                headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json", "Accept": "application/json"},
            )
            self.calls += 1
            try:
                with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as r:
                    return json.load(r)
            except urllib.error.HTTPError as exc:
                if exc.code == 429 and attempt < 2:
                    time.sleep(min(int(exc.headers.get("X-RateLimit-ToWait-Sec") or 60), 300))
                    continue
                raise CsamError(f"Qualys Gateway Answered {exc.code}: {exc.read()[:200].decode(errors='replace')}") from exc
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                if attempt < 2:
                    time.sleep(10)
                    continue
                raise CsamError(f"Qualys Gateway Unreachable (Is Cato Connected on the VM?): {exc}") from exc

    def search(self, params, filters=None):
        data = self._call("POST", "/rest/2.0/search/am/asset", params=params, body={"filters": filters} if filters else {})
        if data.get("responseCode") not in (None, "SUCCESS"):
            raise CsamError(f"Qualys Csam: {data.get('responseMessage')}")
        return data

    def all_assets(self):
        """Every asset, with the fields needed to match and show (no software)."""
        assets, last = [], None
        while True:
            params = {"pageSize": PAGE_SIZE, "includeFields": LIST_FIELDS}
            if last:
                params["lastSeenAssetId"] = last
            data = self.search(params)
            page = (data.get("assetListData") or {}).get("asset") or []
            assets.extend(page)
            last = data.get("lastSeenAssetId")
            if not data.get("hasMore") or not page or not last:
                return assets

    def lookup(self, query, limit=20):
        """
        Assets whose name contains `query`, or that have the IP address
        `query` (CSAM matches addresses exactly), whether or not PVM has them.
        """
        query = query.strip()
        if is_ip(query):
            filters = [{"field": "interfaces.address", "operator": "EQUALS", "value": query}]
        else:
            filters = [{"field": "asset.name", "operator": "CONTAINS", "value": query}]
        data = self.search({"pageSize": limit, "includeFields": LIST_FIELDS}, filters)
        return (data.get("assetListData") or {}).get("asset") or []

    def software_lookup(self, query, limit=SOFTWARE_SEARCH_LIMIT):
        """
        Assets (in PVM or not, the whole subscription) whose software list
        has an entry containing `query`, identity fields only (no software:
        that would be every entry of every matching asset, hundreds each).
        Pages up to `limit`; (assets, truncated) - truncated when CSAM had
        more than `limit` to give.
        """
        query = query.strip()
        filters = [{"field": "software.name", "operator": "CONTAINS", "value": query}]
        assets, last = [], None
        while len(assets) < limit:
            params = {"pageSize": min(100, limit - len(assets)), "includeFields": LIST_FIELDS}
            if last:
                params["lastSeenAssetId"] = last
            data = self.search(params, filters)
            page = (data.get("assetListData") or {}).get("asset") or []
            assets.extend(page)
            last = data.get("lastSeenAssetId")
            if not data.get("hasMore") or not page or not last:
                return assets, False
        return assets, True

    def software(self, asset_ids):
        """{asset id: [software entries]} for up to SOFTWARE_BATCH assets."""
        data = self.search(
            {"pageSize": len(asset_ids), "includeFields": "assetId,software"},
            [{"field": "asset.id", "operator": "IN", "value": ",".join(str(i) for i in asset_ids)}],
        )
        return {
            a["assetId"]: ((a.get("softwareListData") or {}).get("software")) or []
            for a in (data.get("assetListData") or {}).get("asset") or []
        }


# --- Reading one asset --------------------------------------------------------


def is_ip(value):
    try:
        ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return True


def describe(asset, software_entries=None):
    """What the page shows about one asset from a live lookup."""
    os_info = asset.get("operatingSystem") or {}
    is_windows = windows_detected(os_info)
    is_rocky = rocky_detected(os_info)
    return {
        "asset_id": asset.get("assetId"),
        "name": asset.get("assetName") or asset.get("dnsName") or "",
        "dns": asset.get("dnsName") or asset.get("fqdn") or "",
        "addresses": sorted(_addresses(asset)),
        "os_full": os_info.get("fullName") or "",
        "ubuntu_release": ubuntu_release(os_info),
        "release_label": dict(Host.UbuntuRelease.choices).get(ubuntu_release(os_info), ""),
        "is_windows": is_windows,
        "is_rocky": is_rocky,
        "has_agent": (asset.get("inventory") or {}).get("source") == "QAGENT",
        "inventory_source": (asset.get("inventory") or {}).get("source") or "",
        "agent_checked_in": _checked_in(asset.get("agent")),
        "tags": sorted({t.get("tagName") for t in ((asset.get("tagList") or {}).get("tag")) or [] if t.get("tagName")}),
        "criticality": (asset.get("criticality") or {}).get("score"),
        "packages": packages_from_software(software_entries, strict=not (is_windows or is_rocky)) if software_entries else [],
    }


def search_software(query):
    """
    [(asset, [(name, version), ...])] for every asset (in PVM or not, the
    whole subscription) with software matching `query`, plus `truncated`
    (Csam had more than SOFTWARE_SEARCH_LIMIT to give) and the call count.

    Two steps on purpose: `software.name CONTAINS` finds the matching
    assets across the whole subscription, but returning "software" in the
    same call would give every entry of every matching asset (hundreds
    each) just to show the handful that matched. So the search asks for
    identity fields only, then reads software for just those assets,
    batched (core.csam.Client.software), and keeps only the entries whose
    name actually contains the query (Csam's own filter is not returned
    in the response, so which entries matched must be re-checked here).
    """
    client = Client()
    assets, truncated = client.software_lookup(query)
    ids = [a["assetId"] for a in assets]
    software = {}
    for start in range(0, len(ids), SOFTWARE_BATCH):
        software.update(client.software(ids[start : start + SOFTWARE_BATCH]))

    needle = query.strip().lower()
    results = []
    for asset in assets:
        entries = software.get(asset["assetId"], [])
        matches = sorted(
            {
                (str(s.get("discoveredName") or "").strip(), str(s.get("discoveredVersion") or "").strip())
                for s in entries
                if needle in str(s.get("discoveredName") or "").lower()
                or needle in str(s.get("productName") or "").lower()
                or needle in str(s.get("fullName") or "").lower()
            }
        )
        results.append((asset, matches))
    return results, truncated, client.calls


def _addresses(asset):
    ips = {asset.get("address")}
    for nic in ((asset.get("networkInterfaceListData") or {}).get("networkInterface")) or []:
        ips.add(nic.get("addressIpV4"))
    return {ip for ip in ips if ip and not ip.startswith("127.")}


def _names(asset):
    names = {asset.get(k) for k in ("dnsName", "fqdn", "assetName", "netbiosName")}
    for nic in ((asset.get("networkInterfaceListData") or {}).get("networkInterface")) or []:
        names.add(nic.get("hostname"))
    names = {n.strip().lower().rstrip(".") for n in names if n and n.strip()}
    return names | {n.split(".")[0] for n in names}


def ubuntu_release(os_info):
    """The Host.UbuntuRelease value for CSAM's operatingSystem, or ""."""
    if "ubuntu" not in str(os_info.get("fullName", "")).lower():
        return ""
    codename = str(os_info.get("marketVersion") or "").split(" ")[0].lower()
    if codename in Host.UbuntuRelease.values:
        return codename
    version = re.match(r"\d+\.\d+", str(os_info.get("version") or ""))
    if version:
        for value, label in Host.UbuntuRelease.choices:
            if f"Ubuntu {version.group(0)} " in label + " ":
                return value
    return ""


def windows_detected(os_info):
    """True when CSAM's operatingSystem is some Windows (server or desktop)."""
    return "windows" in str(os_info.get("fullName", "")).lower()


def rocky_detected(os_info):
    """True when CSAM's operatingSystem is some Rocky Linux."""
    return "rocky linux" in str(os_info.get("fullName", "")).lower()


_ROCKY_RELEASE_RE = re.compile(r"Rocky Linux\D*(\d+)", re.IGNORECASE)


def rocky_release_from_os_full(os_full):
    """Host.RockyRelease value from an OS string ("Rocky Linux Blue Onyx (9.8)" -> "9"), or ""."""
    match = _ROCKY_RELEASE_RE.search(os_full or "")
    if match and match.group(1) in Host.RockyRelease.values:
        return match.group(1)
    return ""


def _checked_in(agent):
    value = (agent or {}).get("lastCheckedIn") or (agent or {}).get("lastActivity")
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value / 1000, tz=dt_timezone.utc)
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")) if value else None
    except ValueError:
        return None


def _updated(entry):
    try:
        return datetime.fromisoformat(str(entry.get("lastUpdated")).replace("Z", "+00:00"))
    except ValueError:
        return None


def packages_from_software(entries, strict=True):
    """
    [[name, version], ...] of the packages reported now: dpkg packages when
    `strict` (the default: Ubuntu), otherwise (Windows, Rocky) whatever
    software/RPMs the agent lists, kept as reported.

    CSAM keeps entries the agent no longer reports: after a release upgrade
    (20.04 -> 24.04) both libc6 2.31 and 2.39 are listed, the old one with an
    older "lastUpdated". Only entries of the latest inventory run (within a
    day of the newest one) count, and for a name listed twice the newest.

    Qualys fills "lastUpdated" on every entry of some assets and on almost
    none of others (measured on a real Jammy server: 1 entry of 832). A
    missing date is not evidence that a package is gone, so the rule above
    applies only when most entries actually carry one; otherwise every entry
    counts and duplicates are resolved by the dates that are there.

    Ubuntu entries are checked against the dpkg name/version format (this is
    also what tells a genuine dpkg package apart from other entries CSAM
    mixes in). Windows program names are free text with no such format to
    check against (e.g. "7-Zip 23.01 (x64)"), and RPM names/versions use a
    different format that mostly fails dpkg's own (checked live: a Rocky
    host's 1,277 entries, dpkg-strict kept 185, e.g. "ca-certificates" with
    version "2025.2.80_v9.0.305-91.el9.noarch" was rejected on its "_"), so
    for `strict=False` only a non-empty name and version, within the column
    length, are kept. Qualys bakes the architecture into an RPM's version
    for some entries and not others ("9.0.87-1.el9.noarch" next to
    "9.0.87-1.el9"); a trailing ".noarch"/".x86_64"/... is stripped so the
    same package always compares the same way against the fixed version
    Rocky's errata gives (core.rocky), which never carries it either.
    """
    dated = [(s, _updated(s)) for s in entries]
    with_date = [when for _, when in dated if when]
    newest = max(with_date, default=None) if len(with_date) * 2 >= len(dated) else None
    found = {}
    for s, when in dated:
        if newest and (when is None or when < newest - timedelta(days=1)):
            continue
        version = str(s.get("discoveredVersion") or "").strip()
        if strict:
            name = str(s.get("discoveredName") or "").split(":")[0].strip()
            if not (inventory.PACKAGE_NAME.match(name) and debversion.is_valid(version)):
                continue
        else:
            version = _RPM_ARCH_SUFFIX.sub("", version)
            name = str(s.get("discoveredName") or "").strip()
            if not name or not version or len(name) > 255 or len(version) > 255:
                continue
        if name not in found or (when and (found[name][1] is None or when > found[name][1])):
            found[name] = (version, when)
    return sorted([name, version] for name, (version, _) in found.items())


# --- Matching and the search itself --------------------------------------------


def match(hosts, assets):
    """[(host, asset, how)] for the PVM hosts that have a Qualys asset."""
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
        # Every private IP first (the real servers of a pool), then the scanned IP.
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


def run_search(search):
    """Fill `search` (a CsamSearch) with proposals; raises CsamError."""
    client = Client()
    assets = client.all_assets()
    hosts = list(Host.objects.prefetch_related("other_private_ips"))
    matches = match(hosts, assets)

    wanted = [
        a["assetId"] for _, a, _ in matches
        if ((a.get("inventory") or {}).get("source") == "QAGENT")
        and (
            ubuntu_release(a.get("operatingSystem") or {})
            or windows_detected(a.get("operatingSystem") or {})
            or rocky_detected(a.get("operatingSystem") or {})
        )
    ]
    software = {}
    for start in range(0, len(wanted), SOFTWARE_BATCH):
        software.update(client.software(wanted[start : start + SOFTWARE_BATCH]))

    proposals = []
    for host, asset, how in matches:
        os_info = asset.get("operatingSystem") or {}
        tags = [t.get("tagName") for t in ((asset.get("tagList") or {}).get("tag")) or [] if t.get("tagName")]
        strict = not (windows_detected(os_info) or rocky_detected(os_info))
        packages = packages_from_software(software.get(asset["assetId"], []), strict=strict)
        proposals.append(
            CsamProposal(
                search=search,
                host=host,
                asset_id=asset["assetId"],
                qualys_host_id=str(asset.get("hostId") or "")[:64],
                asset_name=(asset.get("assetName") or asset.get("dnsName") or "")[:255],
                matched_by=how,
                os_full=str(os_info.get("fullName") or "")[:255],
                ubuntu_release=ubuntu_release(os_info),
                inventory_source=str((asset.get("inventory") or {}).get("source") or "")[:32],
                agent_checked_in=_checked_in(asset.get("agent")),
                qualys_tags=sorted(set(tags)),
                criticality=(asset.get("criticality") or {}).get("score"),
                packages=packages,
            )
        )
    with transaction.atomic():
        CsamProposal.objects.bulk_create(proposals)
    search.assets_seen, search.hosts_total, search.matched, search.api_calls = len(assets), len(hosts), len(proposals), client.calls
    return search


# --- Importing what the user chose ------------------------------------------------

KINDS = ["release", "packages", "os", "tags"]


def apply(proposal, kinds, user, remove_manual=True):
    """Import the chosen kinds of `proposal` into its host; returns what changed (labels)."""
    from . import tags as tag_module

    host = proposal.host
    changed = []
    fields = []
    if proposal.qualys_host_id and not host.qualys_host_id and not Host.objects.filter(qualys_host_id=proposal.qualys_host_id).exists():
        host.qualys_host_id = proposal.qualys_host_id
        fields.append("qualys_host_id")
    if "release" in kinds and proposal.ubuntu_release and proposal.ubuntu_release != host.ubuntu_release:
        host.ubuntu_release = proposal.ubuntu_release
        fields.append("ubuntu_release")
        changed.append("Ubuntu Release")
    if "release" in kinds and not proposal.ubuntu_release:
        rocky = rocky_release_from_os_full(proposal.os_full)
        if rocky and rocky != host.rocky_release:
            host.rocky_release = rocky
            fields.append("rocky_release")
            changed.append("Rocky Release")
    os_full = (proposal.os_full or "")[: Host._meta.get_field("os_version").max_length]
    if "os" in kinds and os_full and os_full != host.os_version:
        host.os_version = os_full
        fields.append("os_version")
        changed.append("Operating System")
    if fields:
        host.save(update_fields=fields)
    if "packages" in kinds and proposal.packages:
        replace_packages(host, proposal.packages, user, remove_manual=remove_manual)
        changed.append(f"{len(proposal.packages)} Packages")
    if "tags" in kinds and proposal.qualys_tags:
        host.tags.add(*tag_module.resolve(proposal.qualys_tags))
        changed.append("Qualys Tags")
    return changed


def manual_packages_at_risk(host, packages):
    """
    Names of the host's manually-added packages (`InstalledPackage.Source.MANUAL`)
    that `packages` (the agent's list) does not report: what `replace_packages`
    would delete, since it treats the agent's list as complete. Used to warn
    before importing, rather than silently losing a manual entry.
    """
    wanted = dict(packages)
    return list(
        host.packages.filter(source=InstalledPackage.Source.MANUAL)
        .exclude(package_name__in=list(wanted))
        .values_list("package_name", flat=True)
    )


def replace_packages(host, packages, user, remove_manual=True):
    """
    The agent's list is complete: packages it lists are created or updated,
    the others removed. Existing rows are updated in place, so findings and
    verifications that point to a package keep pointing to it.

    `remove_manual=False` keeps manually-added packages (`Source.MANUAL`)
    that the agent does not report, instead of deleting them with everything
    else not in the list - used when the caller has not asked to remove
    them (see `manual_packages_at_risk`, checked by the Qualys Csam import
    view before calling this).
    """
    from django.utils import timezone

    now = timezone.now()
    wanted = dict(packages)
    with transaction.atomic():
        existing = {p.package_name: p for p in host.packages.all()}
        changed = []
        for name, package in existing.items():
            version = wanted.get(name)
            if version is not None and (package.installed_version != version or package.source != InstalledPackage.Source.QUALYS_AGENT):
                package.installed_version, package.source, package.detected_at = version[:255], InstalledPackage.Source.QUALYS_AGENT, now
                # The agent gives no source package: a stale one would mislead the check.
                package.source_package = package.source_version = ""
                changed.append(package)
        InstalledPackage.objects.bulk_update(
            changed, ["installed_version", "source", "detected_at", "source_package", "source_version"], batch_size=500
        )
        to_delete = host.packages.exclude(package_name__in=list(wanted))
        if not remove_manual:
            to_delete = to_delete.exclude(source=InstalledPackage.Source.MANUAL)
        to_delete.delete()
        InstalledPackage.objects.bulk_create(
            [
                InstalledPackage(
                    host=host,
                    package_name=name[:255],
                    installed_version=version[:255],
                    source=InstalledPackage.Source.QUALYS_AGENT,
                    detected_at=now,
                    created_by=user,
                )
                for name, version in wanted.items()
                if name not in existing
            ],
            batch_size=500,
        )

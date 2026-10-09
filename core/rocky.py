"""
Per-release fix status of CVEs from Rocky Linux's own errata
(https://errata.rockylinux.org/api/v2/advisories?filters.cve=<CVE>).
Only CVE IDs are sent. The Rocky equivalent of core.ubuntu.

Rocky publishes an RLSA advisory once a fix has shipped, mirroring the
upstream RHSA it rebuilds; there is no separate "affected, not fixed yet"
status the way Ubuntu's tracker has one, since Rocky's own API only
tracks issued errata, not a running vulnerability status. So a package
with no matching advisory for a release reads as "cannot verify" (it
could be unaffected, or affected with no fix out yet - the two cannot be
told apart from this data alone), never as "not affected": core.rocky
never claims that itself. Every advisory found for the CVE lists, per
affected Rocky release, the RPMs (name-[epoch:]version-release.arch.rpm)
that carry the fix; core.rockyversion compares that against what is
installed.
"""

import json
import logging
import re
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import timedelta

from django.conf import settings
from django.db.models import Q
from django.utils import timezone

from .models import Cve

logger = logging.getLogger(__name__)

URL = "https://errata.rockylinux.org/api/v2/advisories?filters.cve={}"
ADVISORY_PAGE = "https://errata.rockylinux.org/{}"
TIMEOUT_SECONDS = 30
RETRIES = 3
MIN_INTERVAL = 0.1
BUSY_PAUSE = 20

ROCKY_FIELDS = ["rocky_fetched_at", "rocky_error", "rocky_status", "rocky_packages", "rocky_priority"]

_PRODUCT_RE = re.compile(r"Rocky Linux (\d+)")
_ARCH_RE = re.compile(r"\.(noarch|x86_64|aarch64|i686|i386|s390x|ppc64le|src)\.rpm$")


class RockyError(Exception):
    pass


class Throttle:
    """Shared by the threads of one refresh: spacing between requests, and a common pause after a 429."""

    def __init__(self):
        self.lock = threading.Lock()
        self.next_at = 0.0

    def wait(self):
        with self.lock:
            now = time.monotonic()
            at = max(now, self.next_at)
            self.next_at = at + MIN_INTERVAL
        if at > now:
            time.sleep(at - now)

    def pause(self, seconds):
        with self.lock:
            self.next_at = max(self.next_at, time.monotonic() + seconds)


def fetch(cve_id, throttle=None):
    """The RLSA advisories that mention `cve_id`, newest first as the API gives them; [] if none."""
    throttle = throttle or Throttle()
    request = urllib.request.Request(URL.format(cve_id), headers={"Accept": "application/json", "User-Agent": "PVM vulnerability management"})
    for attempt in range(RETRIES):
        throttle.wait()
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as r:
                data = json.load(r)
            return data.get("advisories") or []
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return []
            if exc.code == 429 and attempt < RETRIES - 1:
                retry_after = exc.headers.get("Retry-After", "") if exc.headers else ""
                throttle.pause(int(retry_after) if retry_after.isdigit() else BUSY_PAUSE)
                continue
            if exc.code in (500, 502, 503, 504) and attempt < RETRIES - 1:
                time.sleep(1)
                continue
            raise RockyError(f"Rocky Errata Answered HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            if attempt < RETRIES - 1:
                time.sleep(2)
                continue
            raise RockyError(f"Rocky Errata Unreachable: {exc}") from exc
    return []


def _parse_nvra(nvra):
    """(name, "[epoch:]version-release") from an NVRA filename, or None (a source RPM, or unparseable)."""
    match = _ARCH_RE.search(nvra)
    if not match or match.group(1) == "src":
        return None
    parts = nvra[: match.start()].rsplit("-", 2)
    if len(parts) != 3:
        return None
    name, version, release = parts
    return name, f"{version}-{release}"


def compact(advisories):
    """{package name: {release: {status, fixed, note}}} from the RLSA advisories of one CVE."""
    packages = {}
    for advisory in advisories:
        for product, entry in (advisory.get("rpms") or {}).items():
            match = _PRODUCT_RE.search(product)
            if not match:
                continue
            release = match.group(1)
            for nvra in (entry or {}).get("nvras") or []:
                parsed = _parse_nvra(nvra)
                if not parsed:
                    continue
                name, fixed = parsed
                packages.setdefault(name, {})[release] = {
                    "status": "released",
                    "fixed": fixed,
                    "note": advisory.get("name") or "",
                }
    return packages


def apply_record(cve, advisories):
    cve.rocky_fetched_at = timezone.now()
    cve.rocky_error = ""
    if not advisories:
        cve.rocky_status = Cve.NvdStatus.NOT_FOUND
        cve.rocky_packages = {}
        cve.rocky_priority = ""
    else:
        cve.rocky_status = Cve.NvdStatus.OK
        cve.rocky_packages = compact(advisories)
        cve.rocky_priority = (advisories[0].get("severity") or "").removeprefix("SEVERITY_").capitalize()[:16]
    # Only this tracker's own fields: the NVD refresh writes the same rows in
    # parallel and must not be overwritten with stale values (or overwrite us).
    cve.save(update_fields=ROCKY_FIELDS)


def due_for_refresh(cves=None, retry_errors=False):
    """Same rule as core.ubuntu.due_for_refresh, for the Rocky fields."""
    now = timezone.now()
    stale = now - timedelta(hours=settings.ROCKY_REFRESH_HOURS)
    failed_long_ago = now if retry_errors else now - timedelta(minutes=settings.ROCKY_ERROR_RETRY_MINUTES)
    qs = Cve.objects.all() if cves is None else cves
    return qs.filter(
        Q(rocky_status=Cve.NvdStatus.PENDING)
        | Q(rocky_fetched_at__isnull=True)
        | Q(rocky_status=Cve.NvdStatus.ERROR, rocky_fetched_at__lt=failed_long_ago)
        | (~Q(rocky_status=Cve.NvdStatus.ERROR) & Q(rocky_fetched_at__lt=stale))
    )


def refresh(cves, progress=None, workers=None):
    """Fetch the RLSA advisories of `cves`, several at a time (ROCKY_TRACKER_WORKERS threads)."""
    cves = list(cves)
    counts = {"ok": 0, "not_found": 0, "error": 0}
    if not cves:
        return counts
    throttle = Throttle()
    with ThreadPoolExecutor(max_workers=workers or settings.ROCKY_TRACKER_WORKERS) as pool:
        futures = {pool.submit(fetch, cve.cve_id, throttle): cve for cve in cves}
        for done, future in enumerate(as_completed(futures), start=1):
            cve = futures[future]
            try:
                apply_record(cve, future.result())
                counts["ok" if cve.rocky_status == Cve.NvdStatus.OK else "not_found"] += 1
            except RockyError as exc:
                logger.warning("Rocky errata fetch failed for %s: %s", cve.cve_id, exc)
                Cve.objects.filter(pk=cve.pk).update(
                    rocky_status=Cve.NvdStatus.ERROR, rocky_error=str(exc)[:255], rocky_fetched_at=timezone.now()
                )
                counts["error"] += 1
            if progress:
                progress(done, len(cves))
    return counts

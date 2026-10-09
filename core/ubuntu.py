"""
Per-release fix status of CVEs from the Ubuntu security tracker
(https://ubuntu.com/security/cves/<CVE>.json). Only CVE IDs are sent.

Each record lists the affected *source* packages and, for every release
codename, a status: released (with the fixed version, in the "security"
pocket or only in Ubuntu Pro's "esm-*" pockets), not-affected, needed,
needs-triage, pending, deferred, ignored, or DNE (package not in that
release). Stored compactly on Cve.ubuntu_packages for core.patchcheck.
"""

import json
import logging
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

URL = "https://ubuntu.com/security/cves/{}.json"
TRACKER_PAGE = "https://ubuntu.com/security/{}"
# The tracker is slow on records nobody asked for recently (5-15 s, or a
# 504 after ~50 s while it builds them) and fast once built: wait longer
# than its own gateway, then retry at once. Measured on 2026-09-26.
TIMEOUT_SECONDS = 60
RETRIES = 3
# No published limit: a few requests at a time, at most ~10 a second, and
# everyone waits when the tracker answers 429 (Too Many Requests).
MIN_INTERVAL = 0.1
BUSY_PAUSE = 20


UBUNTU_FIELDS = ["ubuntu_fetched_at", "ubuntu_error", "ubuntu_status", "ubuntu_packages", "ubuntu_priority"]


class UbuntuError(Exception):
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
    """The raw tracker record for `cve_id`, or None if Ubuntu does not track it."""
    throttle = throttle or Throttle()
    request = urllib.request.Request(URL.format(cve_id), headers={"User-Agent": "PVM vulnerability management"})
    for attempt in range(RETRIES):
        throttle.wait()
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as r:
                return json.load(r)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            if exc.code == 429 and attempt < RETRIES - 1:
                retry_after = exc.headers.get("Retry-After", "") if exc.headers else ""
                throttle.pause(int(retry_after) if retry_after.isdigit() else BUSY_PAUSE)
                continue
            if exc.code in (500, 502, 503, 504) and attempt < RETRIES - 1:
                time.sleep(1)
                continue
            raise UbuntuError(f"Ubuntu Tracker Answered HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            if attempt < RETRIES - 1:
                time.sleep(2)
                continue
            raise UbuntuError(f"Ubuntu Tracker Unreachable: {exc}") from exc
    return None


def compact(record):
    """{source package: {release: {status, fixed, pocket, note}}} from a tracker record."""
    packages = {}
    for package in record.get("packages") or []:
        releases = {}
        for s in package.get("statuses") or []:
            status = s.get("status") or ""
            description = (s.get("description") or "").strip()
            releases[s.get("release_codename") or ""] = {
                "status": status,
                # For "released" the description is the fixed version.
                "fixed": description if status == "released" else "",
                "pocket": s.get("pocket") or "",
                "note": "" if status == "released" else description,
            }
        packages[package["name"]] = releases
    return packages


def apply_record(cve, record):
    cve.ubuntu_fetched_at = timezone.now()
    cve.ubuntu_error = ""
    if record is None:
        cve.ubuntu_status = Cve.NvdStatus.NOT_FOUND
        cve.ubuntu_packages = {}
    else:
        cve.ubuntu_status = Cve.NvdStatus.OK
        cve.ubuntu_packages = compact(record)
        cve.ubuntu_priority = (record.get("priority") or "")[:16]
    # Only the tracker's own fields: the NVD refresh writes the same rows in
    # parallel and must not be overwritten with stale values (or overwrite us).
    cve.save(update_fields=UBUNTU_FIELDS)


def due_for_refresh(cves=None, retry_errors=False):
    """
    CVEs (all, or among `cves`) never fetched, older than
    UBUNTU_REFRESH_HOURS, or failed more than UBUNTU_ERROR_RETRY_MINUTES ago
    (a failing CVE is not asked again at every automatic check), or failed
    at all with `retry_errors`.
    """
    now = timezone.now()
    stale = now - timedelta(hours=settings.UBUNTU_REFRESH_HOURS)
    failed_long_ago = now if retry_errors else now - timedelta(minutes=settings.UBUNTU_ERROR_RETRY_MINUTES)
    qs = Cve.objects.all() if cves is None else cves
    return qs.filter(
        Q(ubuntu_status=Cve.NvdStatus.PENDING)
        | Q(ubuntu_fetched_at__isnull=True)
        | Q(ubuntu_status=Cve.NvdStatus.ERROR, ubuntu_fetched_at__lt=failed_long_ago)
        | (~Q(ubuntu_status=Cve.NvdStatus.ERROR) & Q(ubuntu_fetched_at__lt=stale))
    )


def refresh(cves, progress=None, workers=None):
    """
    Fetch the tracker records of `cves`, several at a time
    (UBUNTU_TRACKER_WORKERS threads, network only); every database write
    happens here, in the calling thread. `progress(done, total)` is called
    after each CVE.
    """
    cves = list(cves)
    counts = {"ok": 0, "not_found": 0, "error": 0}
    if not cves:
        return counts
    throttle = Throttle()
    with ThreadPoolExecutor(max_workers=workers or settings.UBUNTU_TRACKER_WORKERS) as pool:
        futures = {pool.submit(fetch, cve.cve_id, throttle): cve for cve in cves}
        for done, future in enumerate(as_completed(futures), start=1):
            cve = futures[future]
            try:
                apply_record(cve, future.result())
                counts["ok" if cve.ubuntu_status == Cve.NvdStatus.OK else "not_found"] += 1
            except UbuntuError as exc:
                logger.warning("Ubuntu tracker fetch failed for %s: %s", cve.cve_id, exc)
                Cve.objects.filter(pk=cve.pk).update(
                    ubuntu_status=Cve.NvdStatus.ERROR, ubuntu_error=str(exc)[:255], ubuntu_fetched_at=timezone.now()
                )
                counts["error"] += 1
            if progress:
                progress(done, len(cves))
    return counts

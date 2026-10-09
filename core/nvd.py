"""
CVSS scores from the NVD CVE API 2.0 (https://nvd.nist.gov/developers).

Only CVE IDs are sent to NVD, nothing about hosts. NVD rate-limits to 5
requests per 30 seconds without an API key and 50 with one
(settings.NVD_API_KEY, free on request), so refreshes run in the
background (core.tasks) and pace themselves.

Which score is kept when a CVE has several: CVSS v3.1, then v3.0, then
v4.0, then v2 (v3.x is what NVD itself scores and what most tooling
compares on); within a version, NVD's own "Primary" score before a CNA's
"Secondary" one.
"""

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import timedelta
from datetime import timezone as dt_timezone
from decimal import Decimal

from django.conf import settings
from django.db.models import Q
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from .models import Cve

logger = logging.getLogger(__name__)

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
METRIC_PREFERENCE = ["cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"]
TIMEOUT_SECONDS = 30
RETRIES = 3


NVD_FIELDS = [
    "nvd_fetched_at",
    "nvd_error",
    "nvd_status",
    "nvd_published_at",
    "nvd_last_modified_at",
    "cvss_score",
    "cvss_version",
    "cvss_severity",
    "cvss_vector",
    "cvss_source",
]


class NvdError(Exception):
    pass


def request_interval():
    """Seconds between requests that stay inside NVD's rolling 30 s window."""
    return 0.7 if settings.NVD_API_KEY else 6.5


def fetch(cve_id):
    """Return the raw NVD record for `cve_id`, or None if NVD does not know it."""
    url = f"{API_URL}?{urllib.parse.urlencode({'cveId': cve_id})}"
    headers = {"User-Agent": "PVM vulnerability management"}
    if settings.NVD_API_KEY:
        headers["apiKey"] = settings.NVD_API_KEY
    for attempt in range(RETRIES):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=TIMEOUT_SECONDS) as r:
                data = json.load(r)
            break
        except urllib.error.HTTPError as exc:
            # 403/429/503: rate limited or busy; back off and retry.
            if exc.code in (403, 429, 503) and attempt < RETRIES - 1:
                time.sleep(30)
                continue
            raise NvdError(f"NVD Answered HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            if attempt < RETRIES - 1:
                time.sleep(10)
                continue
            raise NvdError(f"NVD Unreachable: {exc}") from exc
    vulnerabilities = data.get("vulnerabilities") or []
    return vulnerabilities[0]["cve"] if vulnerabilities else None


def pick_metric(record):
    """The CVSS metric to keep for an NVD record, as a dict, or None if it has none."""
    metrics = record.get("metrics") or {}
    for key in METRIC_PREFERENCE:
        entries = [m for m in metrics.get(key) or [] if (m.get("cvssData") or {}).get("baseScore") is not None]
        if not entries:
            continue
        entry = next((m for m in entries if m.get("type") == "Primary"), entries[0])
        data = entry["cvssData"]
        return {
            "score": Decimal(str(data["baseScore"])),
            "version": str(data.get("version", "")),
            # v2 keeps the rating outside cvssData.
            "severity": data.get("baseSeverity") or entry.get("baseSeverity") or "",
            "vector": data.get("vectorString", ""),
            "source": "NVD" if entry.get("source") == "nvd@nist.gov" else entry.get("source", ""),
        }
    return None


def apply_record(cve, record):
    """Update `cve` from an NVD record (None = not found) and save it."""
    cve.nvd_fetched_at = timezone.now()
    cve.nvd_error = ""
    if record is None:
        cve.nvd_status = Cve.NvdStatus.NOT_FOUND
    else:
        cve.nvd_status = Cve.NvdStatus.OK
        cve.nvd_published_at = _aware(record.get("published"))
        cve.nvd_last_modified_at = _aware(record.get("lastModified"))
        metric = pick_metric(record)
        cve.cvss_score = metric["score"] if metric else None
        cve.cvss_version = metric["version"] if metric else ""
        cve.cvss_severity = metric["severity"][:16] if metric else ""
        cve.cvss_vector = metric["vector"][:255] if metric else ""
        cve.cvss_source = metric["source"][:100] if metric else ""
    # Only NVD's own fields: the Ubuntu check writes the same rows in
    # parallel (another worker), and a full save would put back the stale
    # Ubuntu data this object was loaded with.
    cve.save(update_fields=NVD_FIELDS)


def due_for_refresh():
    """CVEs never fetched, failed last time, or not refreshed in NVD_REFRESH_DAYS."""
    stale = timezone.now() - timedelta(days=settings.NVD_REFRESH_DAYS)
    return Cve.objects.filter(
        Q(nvd_status__in=[Cve.NvdStatus.PENDING, Cve.NvdStatus.ERROR]) | Q(nvd_fetched_at__lt=stale)
    ).order_by("nvd_fetched_at", "cve_id")


def refresh(cves, sleep=time.sleep, heartbeat=None):
    """
    Fetch every CVE in `cves` from NVD, pacing requests. Returns counts by
    outcome. `heartbeat`, if given, is called before each request (the task
    uses it to keep its lock alive).
    """
    counts = {"ok": 0, "not_found": 0, "error": 0}
    for i, cve in enumerate(cves):
        if heartbeat:
            heartbeat()
        if i:
            sleep(request_interval())
        try:
            apply_record(cve, fetch(cve.cve_id))
            counts["ok" if cve.nvd_status == Cve.NvdStatus.OK else "not_found"] += 1
        except NvdError as exc:
            logger.warning("NVD fetch failed for %s: %s", cve.cve_id, exc)
            Cve.objects.filter(pk=cve.pk).update(
                nvd_status=Cve.NvdStatus.ERROR, nvd_error=str(exc)[:255], nvd_fetched_at=timezone.now()
            )
            counts["error"] += 1
    return counts


def _aware(value):
    parsed = parse_datetime(value) if value else None
    if parsed and timezone.is_naive(parsed):
        # NVD timestamps are UTC without an offset.
        parsed = timezone.make_aware(parsed, dt_timezone.utc)
    return parsed

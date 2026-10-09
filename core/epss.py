"""
EPSS scores from FIRST (https://www.first.org/epss/).

EPSS is the estimated probability that a CVE sees exploitation activity
in the next 30 days, recomputed daily for every published CVE. PVM asks
FIRST's public API for its own CVEs, 100 per request: only CVE IDs are
sent, as with NVD. Refreshed nightly by Celery beat, for new CVEs after
each import, or with `python manage.py epss_refresh`. Writes only its own
fields of `Cve` (EPSS_FIELDS): NVD and the Ubuntu tracker may be writing
other fields of the same rows at the same time.
"""

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from decimal import Decimal, InvalidOperation

from django.utils import timezone
from django.utils.dateparse import parse_date

from .models import Cve

logger = logging.getLogger(__name__)

API_URL = "https://api.first.org/data/v1/epss"
BATCH = 100
TIMEOUT_SECONDS = 30
RETRIES = 3
PAUSE_SECONDS = 1  # between requests, to stay well inside FIRST's rate limit
EPSS_FIELDS = ["epss_score", "epss_percentile", "epss_date", "epss_fetched_at"]


class EpssError(Exception):
    pass


def fetch(cve_ids):
    """{CVE ID: {"epss", "percentile", "date"}} for up to BATCH IDs; a CVE EPSS does not score is absent."""
    query = urllib.parse.urlencode({"cve": ",".join(cve_ids), "limit": BATCH})
    request = urllib.request.Request(f"{API_URL}?{query}", headers={"User-Agent": "PVM vulnerability management"})
    for attempt in range(RETRIES):
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as r:
                body = json.load(r)
            break
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            if attempt < RETRIES - 1:
                time.sleep(10 * (attempt + 1))
                continue
            raise EpssError(f"EPSS API Unreachable: {exc}") from exc
    return {item.get("cve", "").upper(): item for item in body.get("data") or []}


def _decimal(value):
    try:
        return Decimal(str(value)).quantize(Decimal("0.00001"))
    except (InvalidOperation, TypeError):
        return None


def refresh(cves):
    """Fetch and store EPSS for `cves` (Cve rows); returns how many got a score."""
    cves = list(cves)
    scored = 0
    for start in range(0, len(cves), BATCH):
        batch = cves[start : start + BATCH]
        if start:
            time.sleep(PAUSE_SECONDS)
        found = fetch([c.cve_id for c in batch])
        now = timezone.now()
        for cve in batch:
            item = found.get(cve.cve_id.upper())
            cve.epss_score = _decimal(item.get("epss")) if item else None
            cve.epss_percentile = _decimal(item.get("percentile")) if item else None
            cve.epss_date = parse_date(item.get("date") or "") if item else None
            cve.epss_fetched_at = now
            scored += cve.epss_score is not None
        Cve.objects.bulk_update(batch, EPSS_FIELDS)
    logger.info("EPSS refresh: %s CVEs, %s scored", len(cves), scored)
    return scored


def never_fetched():
    return Cve.objects.filter(epss_fetched_at__isnull=True)

"""
Mirror of the CISA Known Exploited Vulnerabilities (KEV) catalog.

CISA lists the CVEs it has evidence of being exploited in the wild; being
in the catalog is the strongest single signal for what to fix first. The
catalog is one public JSON file (about 2 MB, no API key, nothing is sent
to CISA): it is downloaded whole and replaces the local copy (KevEntry)
in one transaction. Refreshed nightly by Celery beat, after the first
import, or with `python manage.py kev_refresh`.
"""

import json
import logging
import time
import urllib.error
import urllib.request

from django.db import transaction
from django.utils.dateparse import parse_date

from .models import KevEntry

logger = logging.getLogger(__name__)

FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CATALOG_PAGE = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={}"
TIMEOUT_SECONDS = 60
RETRIES = 3
# A real catalog has well over a thousand entries; far fewer means a
# broken download, and must never wipe the local copy.
MIN_ENTRIES = 100


class KevError(Exception):
    pass


def fetch():
    request = urllib.request.Request(FEED_URL, headers={"User-Agent": "PVM vulnerability management"})
    for attempt in range(RETRIES):
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as r:
                return json.load(r)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            if attempt < RETRIES - 1:
                time.sleep(10)
                continue
            raise KevError(f"CISA KEV Catalog Unreachable: {exc}") from exc
    return None


def parse(catalog):
    """KevEntry objects (unsaved) from the CISA JSON."""
    entries = {}
    for item in (catalog or {}).get("vulnerabilities") or []:
        cve_id = (item.get("cveID") or "").strip().upper()
        if not cve_id.startswith("CVE-"):
            continue
        entries[cve_id] = KevEntry(
            cve_id=cve_id[:32],
            vendor=(item.get("vendorProject") or "")[:200],
            product=(item.get("product") or "")[:200],
            name=(item.get("vulnerabilityName") or "")[:500],
            short_description=item.get("shortDescription") or "",
            required_action=item.get("requiredAction") or "",
            date_added=parse_date(item.get("dateAdded") or "") if item.get("dateAdded") else None,
            due_date=parse_date(item.get("dueDate") or "") if item.get("dueDate") else None,
            ransomware=(item.get("knownRansomwareCampaignUse") or "").lower() == "known",
            notes=item.get("notes") or "",
        )
    return list(entries.values())


def replace_catalog(entries, minimum=None):
    """Swap the local copy for `entries`; refuses a suspiciously small catalog."""
    if len(entries) < (MIN_ENTRIES if minimum is None else minimum):
        raise KevError(f"The Downloaded Catalog Has Only {len(entries)} Entries; Kept the Current Copy.")
    with transaction.atomic():
        KevEntry.objects.all().delete()
        KevEntry.objects.bulk_create(entries, batch_size=500)
    return len(entries)


def refresh():
    from . import priority

    count = replace_catalog(parse(fetch()))
    priority.recompute()
    logger.info("CISA KEV catalog refreshed: %s entries", count)
    return count

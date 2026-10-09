"""
Qualys VMDR API (v2): the scans of the subscription and their results.

Nothing is imported on its own: the Imports page lists the finished scans
and the user picks what to import, or creates a rule ("import this scan
every week / month") that core.tasks.run_qualys_rules applies.

A scan's results are fetched as JSON and written as a CSV with Qualys'
own column names, so they go through the same reader, column mapping and
pipeline as a report uploaded by hand (core.importers.qualys_csv). Both
files are archived with the import.

The platform is reached through Cato on the VM.
The subscription allows 300 calls an hour and 2 at a time: a scan list
and one fetch per import stay far below that; a "please wait" answer is
retried after the delay Qualys gives.
"""

import base64
import csv
import io
import ipaddress
import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zoneinfo
from datetime import datetime, timedelta
from datetime import timezone as dt_timezone

from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)

TIMEOUT_SECONDS = 300
RETRIES = 3

# JSON keys of a scan result -> Qualys' CSV column names, in the order of
# a Qualys CSV export. The CVSS 3.1 column comes before the CVSS 2 one so
# the name-based mapping picks the newer score.
COLUMNS = [
    ("ip", "IP"),
    ("dns", "DNS"),
    ("netbios", "NetBIOS"),
    ("os", "OS"),
    ("ip_status", "IP Status"),
    ("qid", "QID"),
    ("title", "Title"),
    ("type", "Type"),
    ("severity", "Severity"),
    ("port", "Port"),
    ("protocol", "Protocol"),
    ("fqdn", "FQDN"),
    ("ssl", "SSL"),
    ("cve_id", "CVE ID"),
    ("vendor_reference", "Vendor Reference"),
    ("bugtraq_id", "Bugtraq ID"),
    ("cvss3_base", "CVSS3.1 Base"),
    ("cvss3_temporal", "CVSS3.1 Temporal"),
    ("cvss_base", "CVSS Base"),
    ("cvss_temporal", "CVSS Temporal"),
    ("threat", "Threat"),
    ("impact", "Impact"),
    ("solution", "Solution"),
    ("exploitability", "Exploitability"),
    ("associated_malware", "Associated Malware"),
    ("results", "Results"),
    ("pci_vuln", "PCI Vuln"),
    ("instance", "Instance"),
    ("category", "Category"),
]


class QualysError(Exception):
    """The API could not be reached or refused; the message is shown to the user."""


def configured():
    return bool(settings.QUALYS_API_URL and settings.QUALYS_USERNAME and settings.QUALYS_PASSWORD)


def _get(path, params):
    if not configured():
        raise QualysError("The Qualys API Is Not Configured: Set QUALYS_API_URL, QUALYS_USERNAME and QUALYS_PASSWORD in .env.")
    url = settings.QUALYS_API_URL.rstrip("/") + path + "?" + urllib.parse.urlencode(params)
    credentials = base64.b64encode(f"{settings.QUALYS_USERNAME}:{settings.QUALYS_PASSWORD}".encode()).decode()
    request = urllib.request.Request(url, headers={"Authorization": f"Basic {credentials}", "X-Requested-With": "PVM"})
    for attempt in range(RETRIES):
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as r:
                return r.read()
        except urllib.error.HTTPError as exc:
            wait = exc.headers.get("X-RateLimit-ToWait-Sec") if exc.headers else None
            if exc.code in (409, 429) and attempt < RETRIES - 1:
                # Rate or concurrency limit: wait as long as Qualys asks (capped).
                time.sleep(min(int(wait or 30), 300))
                continue
            if exc.code == 401:
                raise QualysError("Qualys Refused the Credentials in .env (QUALYS_USERNAME / QUALYS_PASSWORD).") from exc
            raise QualysError(f"Qualys Answered {exc.code}: {_error_text(exc)}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            if attempt < RETRIES - 1:
                time.sleep(10)
                continue
            raise QualysError(f"Qualys Unreachable (Is Cato Connected on the VM?): {exc}") from exc
    raise QualysError("Qualys Kept Asking to Wait; Try Again Later.")


def _error_text(exc):
    try:
        body = exc.read()[:2000]
        return (ET.fromstring(body).findtext(".//TEXT") or body.decode(errors="replace")).strip()[:300]
    except (ET.ParseError, ValueError, AttributeError):
        return ""


def _parse_datetime(value):
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt_timezone.utc)
    except (TypeError, ValueError):
        return None


def perimeter_from_targets(targets):
    """ "internal" if every target is private, "external" if every target is public, else "". """
    kinds = set()
    for part in (targets or "").replace(" ", "").split(","):
        address = part.split("-")[0].split("/")[0]
        try:
            kinds.add("external" if ipaddress.ip_address(address).is_global else "internal")
        except ValueError:
            kinds.add("external")  # a host name: Qualys scans FQDNs from outside
    return kinds.pop() if len(kinds) == 1 else ""


def _address(value):
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def _covers(entry, ip):
    """True if one target entry (an address, a range or a network) contains `ip`."""
    entry = entry.strip()
    try:
        if "/" in entry:
            return ip in ipaddress.ip_network(entry, strict=False)
        if "-" in entry:
            start, _, end = (part.strip() for part in entry.partition("-"))
            if start.count(".") == 3 and "." not in end:
                end = start.rsplit(".", 1)[0] + "." + end  # Qualys' short form, 10.0.4.10-20
            return ipaddress.ip_address(start) <= ip <= ipaddress.ip_address(end)
        return ipaddress.ip_address(entry) == ip
    except (ValueError, TypeError):
        return False


def matching_targets(targets, query):
    """
    The entries of a scan's targets that answer `query`: an address is looked
    up inside ranges and networks too, anything else matches as text.
    """
    query = (query or "").strip()
    if not query:
        return []
    ip = _address(query)
    found = []
    for entry in (part.strip() for part in (targets or "").split(",")):
        if not entry:
            continue
        if _covers(entry, ip) if ip is not None else query.lower() in entry.lower():
            found.append(entry)
    return found


def excluded(title):
    """True for scans of no interest (settings.QUALYS_EXCLUDED_TITLE_PREFIXES)."""
    return title.lower().startswith(tuple(settings.QUALYS_EXCLUDED_TITLE_PREFIXES))


def list_scans(days=None):
    """Finished scans launched in the last `days`, newest first, as dicts; excluded titles left out."""
    days = days or settings.QUALYS_SCAN_LIST_DAYS
    since = (timezone.now() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    body = _get(
        "/api/2.0/fo/scan/",
        {"action": "list", "state": "Finished", "launched_after_datetime": since, "show_ags": "1", "show_op": "1"},
    )
    try:
        root = ET.fromstring(body)
    except ET.ParseError as exc:
        raise QualysError("Unexpected Answer from Qualys (Not XML).") from exc
    error = root.findtext(".//RESPONSE/TEXT")
    if error and not root.findall(".//SCAN"):
        raise QualysError(f"Qualys: {error.strip()}")
    scans = []
    for s in root.findall(".//SCAN"):
        if excluded((s.findtext("TITLE") or "").strip()):
            continue
        targets = (s.findtext("TARGET") or "").strip()
        scans.append(
            {
                "ref": (s.findtext("REF") or "").strip(),
                "targets": targets,
                "title": (s.findtext("TITLE") or "").strip(),
                "type": (s.findtext("TYPE") or "").strip(),
                "launched_at": _parse_datetime(s.findtext("LAUNCH_DATETIME")),
                "duration": (s.findtext("DURATION") or "").strip(),
                "user": (s.findtext("USER_LOGIN") or "").strip(),
                "option_profile": (s.findtext("OPTION_PROFILE/TITLE") or "").strip(),
                "asset_groups": [g.text.strip() for g in s.findall("ASSET_GROUP_TITLE_LIST/ASSET_GROUP_TITLE") if g.text],
                "target_count": len([t for t in targets.split(",") if t.strip()]),
                "perimeter_guess": perimeter_from_targets(targets),
            }
        )
    scans.sort(key=lambda s: s["launched_at"] or datetime.min.replace(tzinfo=dt_timezone.utc), reverse=True)
    return scans


def fetch_scan(ref):
    """(header dict, detection rows, raw body) of one scan's results."""
    body = _get("/api/2.0/fo/scan/", {"action": "fetch", "scan_ref": ref, "output_format": "json_extended", "mode": "extended"})
    try:
        data = json.loads(body)
    except ValueError as exc:
        text = body[:300].decode(errors="replace")
        raise QualysError(f"Unexpected Answer from Qualys for {ref}: {text}") from exc
    header = {k: v for item in data if "qid" not in item for k, v in item.items()}
    rows = [item for item in data if "qid" in item]
    return header, rows, body


def perimeter_from_header(header):
    """What the results say: Qualys' own scanners on the internet are "External"."""
    distribution = str(header.get("target_distribution_across_scanner_appliances") or "")
    if not distribution:
        return ""
    return "external" if distribution.strip().lower().startswith("external") else "internal"


def _cell(value):
    return "" if value is None or str(value) == "None" else str(value)


def rows_to_csv(rows):
    """The detections as a Qualys-style CSV (text), readable by core.importers.qualys_csv."""
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow([name for _, name in COLUMNS])
    for row in rows:
        writer.writerow([_cell(row.get(key)) for key, _ in COLUMNS])
    return out.getvalue()


# --- Rules: when an automatic import is due -------------------------------------


def schedule_zone():
    return zoneinfo.ZoneInfo(settings.SCHEDULE_TIME_ZONE)


def next_run(rule, after):
    """The first moment strictly after `after` when `rule` is due (aware datetime, UTC)."""
    zone = schedule_zone()
    local = after.astimezone(zone)
    candidate_day = local.date()
    for _ in range(400):
        if rule.frequency == rule.Frequency.WEEKLY:
            matches = candidate_day.weekday() == rule.weekday
        else:
            matches = candidate_day.day == rule.day_of_month
        if matches:
            moment = datetime.combine(candidate_day, rule.at_time, tzinfo=zone)
            if moment > local:
                return moment.astimezone(dt_timezone.utc)
        candidate_day += timedelta(days=1)
    raise ValueError("No next run found")

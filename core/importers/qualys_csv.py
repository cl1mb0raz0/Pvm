"""
Reader for Qualys CSV exports (scan report / vulnerability list).

Knows only about the file format: where the header row is, which columns
exist, and how Qualys values translate into PVM values. It never touches
the database; `core.importers.pipeline` does that, so another scanner can
be supported by writing another reader that yields the same `Detection`
records.
"""

import csv
import io
import ipaddress
import re
import sys
from collections import Counter
from dataclasses import dataclass, field

# Qualys "Results" cells can be far larger than csv's 128 KB default.
csv.field_size_limit(min(sys.maxsize, 2**31 - 1))

DONT_IMPORT = ""
EXTRA = "extra"

# PVM fields a column can be imported as: (key, label, required, column
# names recognized automatically, compared case-insensitively).
FIELDS = [
    ("host.ip", "IP Address", True, ["ip", "ip address"]),
    ("host.dns", "Hostname (DNS)", False, ["dns", "dns name", "hostname"]),
    ("host.netbios", "NetBIOS Name", False, ["netbios", "netbios name"]),
    ("host.os", "Operating System", False, ["os", "operating system"]),
    ("host.qualys_id", "Qualys Host ID", False, ["host id", "qualys host id"]),
    ("vuln.qid", "QID", True, ["qid"]),
    ("vuln.title", "Title", True, ["title", "vulnerability title"]),
    ("vuln.severity", "Severity (1-5)", True, ["severity", "severity level"]),
    ("vuln.type", "Detection Type", False, ["type"]),
    ("vuln.cves", "CVE IDs", False, ["cve id", "cve ids", "cve"]),
    ("vuln.cvss", "CVSS Score", False, ["cvss3.1 base", "cvss3 base", "cvss base", "cvss"]),
    ("vuln.threat", "Description (Threat)", False, ["threat"]),
    ("vuln.solution", "Solution", False, ["solution"]),
    ("finding.port", "Port", False, ["port"]),
    ("finding.protocol", "Protocol", False, ["protocol"]),
    ("finding.result", "Detection Result (Evidence)", False, ["results", "result"]),
]
FIELD_LABELS = {key: label for key, label, _, _ in FIELDS}
REQUIRED_FIELDS = [key for key, _, required, _ in FIELDS if required]

# Qualys detection types: "Vuln" (confirmed), "Practice" (potential) and
# "Ig" (information gathered). Information gathered is not a
# vulnerability, so those rows are skipped.
SKIPPED_TYPES = {"ig", "info", "Information Gathered"}

# Qualys severity is 1-5, PVM has four levels.
SEVERITY_MAP = {"5": "critical", "4": "high", "3": "medium", "2": "low", "1": "low"}

SAMPLE_ROWS = 3
SAMPLE_CHARS = 120


class ReportError(Exception):
    """The file is not a Qualys CSV export PVM can read."""


@dataclass
class Detection:
    """One vulnerability detected on one host, as read from the report."""

    ip: str
    hostname: str
    qualys_host_id: str
    os: str
    qid: str
    title: str
    severity: str
    qualys_severity: int
    cves: list = field(default_factory=list)
    cvss: str = ""
    threat: str = ""
    solution: str = ""
    service_port: str = ""
    result: str = ""
    extra: dict = field(default_factory=dict)


def _read_text(path):
    with open(path, "rb") as f:
        raw = f.read()
    for encoding in ("utf-8-sig", "cp1252"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1")


def _rows(path):
    """Return (header, rows): rows is an iterator of lists padded to the header width."""
    text = _read_text(path)
    try:
        dialect = csv.Sniffer().sniff(text[:65536], delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    reader = csv.reader(io.StringIO(text, newline=""), dialect)

    # Qualys reports may start with a few lines of report metadata; the
    # real header is the first row that has both an IP and a QID column.
    for row in reader:
        names = {cell.strip().lower() for cell in row}
        if {"ip", "qid"} <= names:
            header = _unique([cell.strip() for cell in row])
            break
    else:
        raise ReportError("No Header Row with Both an 'IP' and a 'QID' Column Was Found.")

    def body():
        for row in reader:
            if not any(cell.strip() for cell in row):
                continue
            yield (row + [""] * len(header))[: len(header)]

    return header, body()


def suggest_mapping(header):
    """Map each column to the PVM field its name matches, or to extra data."""
    mapping, taken = {}, set()
    for column in header:
        name = column.strip().lower()
        for key, _, _, aliases in FIELDS:
            if key not in taken and name in aliases:
                mapping[column] = key
                taken.add(key)
                break
        else:
            mapping[column] = EXTRA
    return mapping


def analyze(path):
    """Columns, sample values and row counts, shown before the user maps columns."""
    header, rows = _rows(path)
    lowered = {c.lower(): i for i, c in enumerate(header)}
    ip_i, type_i = lowered.get("ip"), lowered.get("type")
    dns_i = lowered.get("dns")

    samples = {c: [] for c in header}
    total, ips, hosts, types = 0, set(), set(), Counter()
    for row in rows:
        total += 1
        if total <= SAMPLE_ROWS:
            for column, value in zip(header, row):
                value = " ".join(value.split())
                if value:
                    samples[column].append(value[:SAMPLE_CHARS] + ("…" if len(value) > SAMPLE_CHARS else ""))
        ips.add(row[ip_i].strip())
        hosts.add((row[ip_i].strip(), row[dns_i].strip() if dns_i is not None else ""))
        if type_i is not None:
            types[row[type_i].strip() or "(empty)"] += 1

    if not total:
        raise ReportError("The File Has a Header Row but No Data Rows.")
    public = sum(1 for ip in ips if _is_ip(ip) and ipaddress.ip_address(ip).is_global)
    return {
        "columns": header,
        "samples": samples,
        "rows": total,
        "ip_count": len(ips),
        # Hint for choosing the perimeter: external scans target public IPs.
        "public_ip_count": public,
        "private_ip_count": len(ips) - public,
        "host_count": len(hosts),
        "types": dict(types.most_common()),
    }


def validate_mapping(mapping, header):
    """Return a list of problems with a column -> field mapping (empty if fine)."""
    errors = []
    used = Counter(v for v in mapping.values() if v not in (DONT_IMPORT, EXTRA))
    for key, count in used.items():
        if key not in FIELD_LABELS:
            errors.append(f"Unknown Field: {key}.")
        elif count > 1:
            errors.append(f"“{FIELD_LABELS[key]}” Is Assigned to More than One Column.")
    for key in REQUIRED_FIELDS:
        if key not in used:
            errors.append(f"A Column Must Be Imported as “{FIELD_LABELS[key]}”.")
    unknown = set(mapping) - set(header)
    if unknown:
        errors.append("The Mapping Names Columns That Are Not in the File.")
    return errors


def read_detections(path, mapping):
    """
    Apply the user's column mapping to every data row. Returns the list of
    `Detection` records and a Counter of skipped rows by reason.
    """
    header, rows = _rows(path)
    index = {column: i for i, column in enumerate(header)}
    by_field = {key: index[column] for column, key in mapping.items() if key not in (DONT_IMPORT, EXTRA)}
    extra_columns = [column for column, key in mapping.items() if key == EXTRA]

    def get(row, key):
        i = by_field.get(key)
        return row[i].strip() if i is not None else ""

    skipped = Counter()
    detections = []
    for row in rows:
        if get(row, "vuln.type").lower() in SKIPPED_TYPES:
            skipped["Information Gathered"] += 1
            continue
        ip, qid, title = get(row, "host.ip"), get(row, "vuln.qid"), get(row, "vuln.title")
        level = get(row, "vuln.severity")[:1]
        severity = SEVERITY_MAP.get(level)
        if not (ip and qid and title and severity):
            skipped["Missing IP, QID, Title or Severity"] += 1
            continue
        if not _is_ip(ip):
            skipped["Invalid IP Address"] += 1
            continue
        port, protocol = get(row, "finding.port"), get(row, "finding.protocol").lower()
        detections.append(
            Detection(
                ip=ip,
                hostname=get(row, "host.dns") or get(row, "host.netbios") or ip,
                qualys_host_id=get(row, "host.qualys_id"),
                os=get(row, "host.os"),
                qid=qid,
                title=title,
                severity=severity,
                qualys_severity=int(level),
                cves=re.findall(r"CVE-\d{4}-\d{4,}", get(row, "vuln.cves"), flags=re.IGNORECASE),
                cvss=_leading_number(get(row, "vuln.cvss")),
                threat=get(row, "vuln.threat"),
                solution=get(row, "vuln.solution"),
                service_port=f"{port}/{protocol}" if port and protocol else port,
                result=get(row, "finding.result"),
                extra={c: row[index[c]].strip() for c in extra_columns if row[index[c]].strip()},
            )
        )
    return detections, skipped


def _leading_number(value):
    """'7.5 (AV:N/AC:L/...)' -> '7.5'; anything unparseable -> ''."""
    match = re.match(r"\s*(\d{1,2}(?:\.\d)?)", value)
    return match.group(1) if match and float(match.group(1)) <= 10 else ""


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _unique(names):
    """Suffix repeated column names ("CVSS", "CVSS (2)") so each can be mapped."""
    seen = Counter()
    result = []
    for name in names:
        seen[name] += 1
        result.append(name if seen[name] == 1 else f"{name} ({seen[name]})")
    return result

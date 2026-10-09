"""
Imports > Mapping: work out what an uploaded file is before anything
happens. Every recognizer looks at the file (names and content, never
anything outside the VM) and says what it thinks the file is, how sure it
is and why, and whether PVM can use it. The view then shows the most
likely reading with a preview of what applying it would change.

Recognized today:

- "a10": an A10 load balancer's running configuration (core/balancer.py)
- "ip_mapping": a table of public IP, DNS host name, private IP
  (core/network_mapping.py), columns found by name or by content
- "qualys_report": a Qualys scan report, which belongs in Imports > New
  Import; recognized so the user is sent there, not refused
- "table": any other table, described column by column, not usable

A new kind of file is one more recognizer in RECOGNIZERS, plus its plan
and apply in the view.
"""

import csv
import io
from dataclasses import dataclass, field

from . import balancer, network_mapping


@dataclass
class Recognition:
    kind: str
    label: str
    confidence: int  # 0-100
    reasons: list = field(default_factory=list)
    can_import: bool = True
    problem: str = ""
    data: dict = field(default_factory=dict)


def _plural(count, word):
    return f"{count} {word}{'s' if count != 1 else ''}"


def recognize_a10(text):
    found, version, blocks = balancer.looks_like_acos(text)
    if not found:
        return None
    parsed = balancer.parse_acos(text)
    c = parsed["counts"]
    reasons = []
    if version:
        reasons.append(f"The Header Names the Software: A10 Advanced Core OS (ACOS) {version}.")
    reasons.append(
        f"Load-Balancing Sections Found: {_plural(c['servers'], 'Server')}, {_plural(c['service_groups'], 'Pool')}, "
        f"{_plural(c['vips'], 'VIP')}, {_plural(c['rules'], 'Name Rule')}."
    )
    reasons.append("Ignored: Everything Else (High Availability, Authentication, SSL Templates, Health Checks...). The File Itself Is Not Kept.")
    recognition = Recognition("a10", "A10 Load Balancer Configuration", 99 if version else 85, reasons, data=parsed)
    if not parsed["routes"]:
        recognition.can_import = False
        recognition.problem = (
            "No VIP Leads to a Server in This File: The Sections “slb server”, “slb service-group” and “slb virtual-server” "
            "Are Missing or Incomplete. Export the Whole Running Configuration."
        )
    return recognition


def recognize_ip_mapping(raw):
    try:
        table = network_mapping.parse_table(raw)
    except network_mapping.MappingError:
        return None
    rows = table["rows"]
    valid = sum(1 for r in rows if not r["error"])
    if not valid:
        return None
    reasons = []
    for name, role, from_content in table["columns"]:
        if role:
            reasons.append(f"Column “{name}” → {role}" + (" (Recognized from Its Content)" if from_content else "") + ".")
    reasons.append(f"{_plural(len(rows), 'Row')}, {valid} Valid.")
    if not table["has_hostname"]:
        reasons.append("No DNS Hostname Column: Rows Match Only Public IPs with a Single Host.")
    by_content = any(from_content for _, role, from_content in table["columns"] if role != "DNS Hostname")
    return Recognition(
        "ip_mapping", "Public to Private IP Mapping", 75 if by_content else 95, reasons,
        data={"rows": rows, "has_hostname": table["has_hostname"]},
    )


def recognize_qualys_report(text):
    reader = csv.reader(io.StringIO(text[:200000], newline=""), _dialect(text))
    for line, row in enumerate(reader):
        if line > 200:
            break
        names = {cell.strip().lower() for cell in row}
        if {"ip", "qid"} <= names:
            return Recognition(
                "qualys_report", "Qualys Scan Report", 95,
                [f"Line {line + 1} Has the Columns of a Qualys Scan Report (IP, QID{', Title' if 'title' in names else ''}...)."],
                can_import=False,
                problem="Scan Reports Are Imported from Imports > History > New Import, Where You Choose Perimeter and Columns.",
            )
    return None


def describe_table(raw):
    """Any other table: what each column seems to hold."""
    try:
        header, body = network_mapping.read_table(raw)
    except network_mapping.MappingError:
        return None
    if len(header) < 2:
        return None
    reasons = []
    for i, name in enumerate(header[:30]):
        c = network_mapping.profile([row[i] if i < len(row) else "" for row in body[:500]])
        parts = [
            _plural(c[k], label) for k, label in (("public", "Public IP"), ("private", "Private IP"), ("hostname", "Host Name")) if c[k]
        ]
        if c["other"]:
            parts.append(f"{c['other']} Other")
        reasons.append(f"Column “{name.strip()[:60]}”: {', '.join(parts) or 'Empty'}.")
    return Recognition(
        "table", "Table Not Recognized", 30, reasons, can_import=False,
        problem=(
            f"A Table of {_plural(len(body), 'Row')} and {_plural(len(header), 'Column')}, but Pvm Does Not Know What to Do with It. "
            "As a Network Mapping It Needs a Public IP and a Private IP Column (and Preferably a DNS Hostname)."
        ),
    )


def _dialect(text):
    try:
        return csv.Sniffer().sniff(text[:8192], delimiters=",;\t")
    except csv.Error:
        return csv.excel


def analyze(raw):
    """Every reading of the file, most likely first; never empty."""
    text = network_mapping._text(raw)
    found = []
    a10 = recognize_a10(text)
    if a10:
        found.append(a10)
    else:
        for recognition in (recognize_qualys_report(text), recognize_ip_mapping(raw)):
            if recognition:
                found.append(recognition)
        if not found:
            table = describe_table(raw)
            if table:
                found.append(table)
    if not found:
        found.append(
            Recognition(
                "unknown", "Not Recognized", 0, ["Neither a Table (CSV or Tab-Separated Text) nor a Known Configuration."],
                can_import=False,
                problem="Pvm Recognizes a Public/Private IP Mapping (CSV) and an A10 Load Balancer Configuration (Text).",
            )
        )
    return sorted(found, key=lambda r: r.confidence, reverse=True)

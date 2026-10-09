"""
Network mapping from a CSV: external sites (public IP, DNS host name) and
the private IP of the internal server behind them (Imports > Mapping, see
core/mapping.py for how a file is recognized).

Columns, recognized by name in any case and order, separator , ; or tab:
"Public IP", "DNS Hostname" (optional per row) and "Private IP". Without
recognizable names the columns are recognized from their content: public
addresses, private addresses, host names. Nothing changes until the user
has seen the preview and applied it. Applying sets the private IP of the
matching hosts (the same as the host's Network tab), stores every row as a
PrivateIpMapping for hosts that appear later, and can mark the public IPs
as a load balancer. If a private IP is a VIP of a stored balancer
configuration (core/balancer.py), the hosts get the real servers behind
it instead. The private IP is what lets Qualys CSAM match an external site
to the internal server that runs it.
"""

import csv
import io
import ipaddress
import re

from django.db import transaction

from . import balancer
from .models import Host, LoadBalancer, PrivateIpMapping

COLUMNS = {
    "public_ip": {"public ip", "public_ip", "publicip", "public address", "ip pubblico", "vip"},
    "hostname": {"dns hostname", "dns_hostname", "hostname", "dns", "dns name", "fqdn", "host name", "dns host name", "name", "site"},
    "private_ip": {"private ip", "private_ip", "privateip", "private address", "ip privato", "internal ip"},
}
MAX_ROWS = 5000


class MappingError(Exception):
    """The file cannot be read as a mapping; the message is shown to the user."""


def _text(raw):
    for encoding in ("utf-8-sig", "cp1252"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1")


def _ip(value):
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _normal(name):
    return " ".join(name.strip().lower().replace("_", " ").split())


def _by_name(header):
    index = {}
    for i, name in enumerate(header):
        name = _normal(name)
        for key, aliases in COLUMNS.items():
            if name in aliases or name.replace(" ", "_") in aliases:
                index.setdefault(key, i)
    return index


HOSTNAME = re.compile(r"^(?=.{1,253}$)[a-z0-9_]([a-z0-9_-]{0,62})(\.[a-z0-9_-]{1,63})*\.?$", re.I)


def profile(values):
    """What a column holds: counts of public / private IPs, host names, empty cells."""
    counts = {"public": 0, "private": 0, "hostname": 0, "empty": 0, "other": 0}
    for value in values:
        value = value.strip()
        ip = balancer.ip_or_none(value) if value else None
        if not value:
            counts["empty"] += 1
        elif ip:
            counts["private" if balancer.is_private(ip) else "public"] += 1
        elif "." in value and HOSTNAME.match(value):
            counts["hostname"] += 1
        else:
            counts["other"] += 1
    return counts


def _by_content(header, body):
    """Columns guessed from what they hold, when their names say nothing."""
    width = max([len(header)] + [len(r) for r in body[:200]])
    columns = [[row[i] if i < len(row) else "" for row in body[:200]] for i in range(width)]
    index = {}
    for i, values in enumerate(columns):
        c = profile(values)
        filled = len(values) - c["empty"]
        if not filled:
            continue
        if c["public"] >= 0.8 * filled and "public_ip" not in index:
            index["public_ip"] = i
        elif c["private"] >= 0.8 * filled and "private_ip" not in index:
            index["private_ip"] = i
        elif c["hostname"] >= 0.8 * filled and "hostname" not in index:
            index["hostname"] = i
    return index


def read_table(raw):
    """(header, data rows) of a delimited text file; raises MappingError when it is not one."""
    text = _text(raw)
    try:
        dialect = csv.Sniffer().sniff(text[:8192], delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    rows = [r for r in csv.reader(io.StringIO(text, newline=""), dialect) if any(c.strip() for c in r)]
    if not rows:
        raise MappingError("The File Is Empty.")
    return rows[0], rows[1:]


def parse_table(raw):
    """
    {"rows", "has_hostname", "columns": [(header, role, from content?)]}:
    the rows as parse() returns them, and how the columns were recognized.
    """
    header, body = read_table(raw)
    index, from_content, first_line = _by_name(header), set(), 2
    if "public_ip" not in index or "private_ip" not in index:
        # The first row may be data (no header at all) or names PVM does not know.
        if sum(1 for c in header if balancer.ip_or_none(c)) >= 2:
            body, header, first_line = [header] + body, [f"Column {i + 1}" for i in range(len(header))], 1
        guessed = _by_content(header, body)
        if "public_ip" in guessed and "private_ip" in guessed:
            if "hostname" in index:
                guessed.setdefault("hostname", index["hostname"])
            from_content = {k for k in guessed if guessed[k] != index.get(k)}
            index = guessed
    if "hostname" not in index:
        guess = _by_content(header, body).get("hostname")
        if guess is not None and guess not in index.values():
            index["hostname"] = guess
            from_content.add("hostname")
    missing = [label for key, label in (("public_ip", "Public IP"), ("private_ip", "Private IP")) if key not in index]
    if missing:
        raise MappingError(f"Column Not Found: {', '.join(missing)}. The First Row Must Name the Columns (Public IP, DNS Hostname, Private IP).")
    if len(body) > MAX_ROWS:
        raise MappingError(f"More than {MAX_ROWS} Rows: Split the File.")

    rows = []
    for line, cells in enumerate(body, start=first_line):
        get = lambda key: cells[index[key]].strip() if key in index and index[key] < len(cells) else ""  # noqa: E731
        public, private = _ip(get("public_ip")), _ip(get("private_ip"))
        hostname = get("hostname").lower().rstrip(".")
        error = ""
        if not public:
            error = f"Invalid Public IP “{get('public_ip')}”."
        elif not private:
            error = f"Invalid Private IP “{get('private_ip')}”."
        rows.append({"line": line, "public_ip": public or get("public_ip"), "hostname": hostname[:255], "private_ip": private or get("private_ip"), "error": error})
    if not rows:
        raise MappingError("The File Has a Header but No Rows.")
    roles = {index[key]: (label, key in from_content) for key, label in (("public_ip", "Public IP"), ("hostname", "DNS Hostname"), ("private_ip", "Private IP")) if key in index}
    return {
        "rows": rows,
        "has_hostname": "hostname" in index,
        "columns": [(name, *roles.get(i, ("", False))) for i, name in enumerate(header)],
    }


def parse(raw):
    """
    ([{"line", "public_ip", "hostname", "private_ip", "error"}], hostname
    column found?) from the CSV bytes.
    """
    table = parse_table(raw)
    return table["rows"], table["has_hostname"]


def hosts_for(public_ip, hostname, hosts_by_ip):
    """PVM hosts a row describes: same public IP and host name; without a name, the only host on that IP."""
    on_ip = hosts_by_ip.get(public_ip, [])
    if hostname:
        short = hostname.split(".")[0]
        return [h for h in on_ip if h.hostname.lower().rstrip(".") in (hostname, short)]
    return on_ip if len(on_ip) == 1 else []


def plan(rows):
    """
    Each row with the hosts it would change and how ("new", "changed",
    "same", "no host", "error"). A private IP that is a VIP of a stored
    balancer configuration leads to the real servers behind it.
    """
    resolver = balancer.Resolver.stored()
    hosts_by_ip = {}
    hosts = Host.objects.filter(ip_address__in={r["public_ip"] for r in rows if not r["error"]}).prefetch_related("other_private_ips")
    for host in hosts:
        hosts_by_ip.setdefault(host.ip_address, []).append(host)
    planned = []
    for row in rows:
        if row["error"]:
            planned.append({**row, "status": "error", "hosts": []})
            continue
        changes = []
        for h in hosts_for(row["public_ip"], row["hostname"], hosts_by_ip):
            found = resolver.resolve(h.hostname, h.ip_address, row["private_ip"]) if resolver else None
            target = found.backends if found and found.how != "name" else [row["private_ip"]]
            changes.append({"host": h, "current": h.all_private_ips, "target": target, "how": found.text if found and found.how != "name" else ""})
        if not changes:
            status = "no host"
        elif all(c["current"] == c["target"] for c in changes):
            status = "same"
        elif any(c["current"] for c in changes):
            status = "changed"
        else:
            status = "new"
        planned.append({**row, "status": status, "hosts": changes})
    return planned


def apply(rows, user, balancer_name=""):
    """Store the valid rows and set the private IPs on their hosts; returns (hosts changed, rows stored)."""
    valid = [r for r in rows if not r["error"]]
    changed = 0
    with transaction.atomic():
        for row in plan(valid):
            PrivateIpMapping.objects.update_or_create(
                public_ip=row["public_ip"], hostname=row["hostname"],
                defaults={"private_ip": row["private_ip"], "uploaded_by": user},
            )
            for change in row["hosts"]:
                if change["current"] != change["target"]:
                    change["host"].set_private_ips(change["target"])
                    changed += 1
        if balancer_name:
            for ip in {r["public_ip"] for r in valid}:
                LoadBalancer.objects.get_or_create(ip_address=ip, defaults={"name": balancer_name[:100]})
    return changed, len(valid)


def verdict(planned):
    """(is it useful, one line saying why) for a planned mapping."""
    hosts = sum(1 for r in planned for c in r["hosts"] if c["current"] != c["target"])
    stored = set(PrivateIpMapping.objects.values_list("public_ip", "hostname", "private_ip"))
    new_rows = sum(1 for r in planned if r["status"] != "error" and (r["public_ip"], r["hostname"], r["private_ip"]) not in stored)
    if hosts:
        return True, f"Useful: {hosts} Host{'s Get Their' if hosts != 1 else ' Gets Its'} Private IP."
    if new_rows:
        return True, f"Nothing Changes on the Hosts Today; {new_rows} New Row{'s Are' if new_rows != 1 else ' Is'} Kept for Hosts of Later Scans."
    return False, "Nothing New: Every Row Is Already in Pvm."


class MappingIndex:
    """The stored mapping, loaded once, for looking up many hosts."""

    def __init__(self):
        self.by_ip = {}
        for mapping in PrivateIpMapping.objects.all():
            self.by_ip.setdefault(mapping.public_ip, []).append(mapping)
        self.hosts_per_ip = {}

    def private_ip_for(self, host, hosts_on_ip=None):
        candidates = self.by_ip.get(host.ip_address, [])
        if not candidates:
            return None
        name = (host.hostname or "").lower().rstrip(".")
        for mapping in candidates:
            if mapping.hostname and mapping.hostname in (name, name.split(".")[0]):
                return mapping.private_ip
        unnamed = [m for m in candidates if not m.hostname]
        if len(unnamed) != 1:
            return None
        if hosts_on_ip is None:
            if host.ip_address not in self.hosts_per_ip:
                self.hosts_per_ip[host.ip_address] = Host.objects.filter(ip_address=host.ip_address).count()
            hosts_on_ip = self.hosts_per_ip[host.ip_address]
        return unnamed[0].private_ip if hosts_on_ip <= 1 else None


def private_ip_for(host):
    """The stored mapping for a host that has no private IP yet (used by imports)."""
    return MappingIndex().private_ip_for(host)

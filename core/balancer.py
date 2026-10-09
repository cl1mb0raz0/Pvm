"""
Load balancer configurations (Imports > Mapping): which real servers are
behind each VIP and each site name.

Today one format, the running configuration of an A10 (ACOS), as saved as
text. Only four kinds of blocks matter, everything else (HA, VRRP,
authentication, SSL templates, health checks...) is ignored:

    slb server <name> <ip>                    a real server
      port 443 tcp
    slb service-group <name> <protocol>       a pool
      member <server> <port>
    slb virtual-server <name> <ip>            a VIP
      port 443 https
        service-group <pool>                  its default pool
        template http <template>              name rules, below
    slb template http <template>
      host-switching contains <pattern> service-group <pool>

They become BalancerRoute rows: a VIP port and its pool, or a name rule
and its pool, each with the pool's server IPs. The file itself is never
kept. A host gets the servers' IPs as its private IPs when (in order):
its name matches a rule, it was scanned on a VIP, or its private IP
(typed, or from a CSV mapping) is a VIP. The VIPs themselves are marked as
load balancers. aFleX scripts are not in the running configuration: sites
routed by aFleX are not seen.
"""

import ipaddress
import re
from dataclasses import dataclass, field

from django.db import transaction

from .models import BalancerConfig, BalancerRoute, Host, HostPrivateIp, LoadBalancer

BRAND = "A10"
SPECIFICITY = {"equals": 4, "starts-with": 3, "ends-with": 3, "contains": 2, "regex-match": 1}
PRIVATE_NETWORKS = [
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "fe80::/10")
]


def ip_or_none(value):
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def is_private(ip):
    """RFC 1918 and friends; documentation ranges count as public (tests use them for external sites)."""
    address = ipaddress.ip_address(ip)
    return any(address in n for n in PRIVATE_NETWORKS if n.version == address.version)


# --- Recognizing and reading an ACOS configuration ----------------------

ACOS_HEADER = re.compile(r"Advanced Core OS \(ACOS\) version (\S+?),")
SLB_BLOCK = re.compile(r"^\s?slb (server|service-group|virtual-server|template http) ", re.M)


def looks_like_acos(text):
    """(is it an A10 configuration, ACOS version or "", number of slb blocks)."""
    version = ACOS_HEADER.search(text[:4000])
    blocks = len(SLB_BLOCK.findall(text))
    return bool(version) or blocks >= 2, version.group(1) if version else "", blocks


def parse_acos(text):
    """
    The routes of an ACOS running configuration, as JSON-friendly dicts:
    {"name", "product", "routes": [...], "counts": {...}, "warnings": [...]}.
    """
    _, version, _ = looks_like_acos(text)
    partition = ""
    hostname = ""
    servers, groups, vips, templates = {}, {}, [], {}
    block = kind = port = None
    warnings = []

    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("!"):
            if not line.startswith(" "):
                block = kind = port = None
            continue
        indent = len(line) - len(line.lstrip(" "))
        tokens = stripped.split()
        # Top level: no indentation (one space tolerated, as pasted text may add it).
        if indent <= 1:
            block = kind = port = None
            if tokens[0] == "active-partition" and len(tokens) > 1:
                partition = "" if tokens[1] == "shared" else tokens[1]
            elif tokens[0] == "hostname" and len(tokens) > 1:
                hostname = tokens[1]
            elif tokens[:2] == ["slb", "server"] and len(tokens) > 3:
                ip = ip_or_none(tokens[-1])
                # The address is the last word; a name with spaces is kept whole.
                name = " ".join(tokens[2:-1]) if ip else tokens[2]
                block, kind = {"name": name, "ip": ip, "ports": []}, "server"
                servers[(partition, name)] = block
            elif tokens[:2] == ["slb", "server"] and len(tokens) == 3:
                ip = ip_or_none(tokens[2])
                block, kind = {"name": tokens[2], "ip": ip, "ports": []}, "server"
                servers[(partition, tokens[2])] = block
            elif tokens[:2] == ["slb", "service-group"] and len(tokens) > 2:
                block, kind = {"name": tokens[2], "members": []}, "group"
                groups[(partition, tokens[2])] = block
            elif tokens[:2] == ["slb", "virtual-server"] and len(tokens) > 2:
                ip = next((ip_or_none(t) for t in tokens[3:] if ip_or_none(t)), None)
                block, kind = {"name": tokens[2], "ip": ip, "ports": [], "partition": partition}, "vip"
                vips.append(block)
            elif tokens[:3] == ["slb", "template", "http"] and len(tokens) > 3:
                block, kind = {"name": tokens[3], "rules": [], "used": False}, "template"
                templates[(partition, tokens[3])] = block
            continue
        if block is None:
            continue
        if kind == "server" and tokens[0] == "port" and len(tokens) > 2:
            block["ports"].append(f"{tokens[1]}/{tokens[2]}")
        elif kind == "group" and tokens[0] == "member" and len(tokens) > 2:
            # member <server> <port> [options]: the port is the first number, the name may have spaces.
            at = next((i for i in range(2, len(tokens)) if tokens[i].isdigit()), 2)
            block["members"].append((" ".join(tokens[1:at]), tokens[at]))
        elif kind == "vip":
            if tokens[0] == "port" and indent <= 3 and len(tokens) > 1:
                port = {"port": "/".join(tokens[1:3]), "service_group": "", "templates": [], "aflex": False}
                block["ports"].append(port)
            elif port is not None and indent > 3:
                if tokens[0] == "service-group" and len(tokens) > 1:
                    port["service_group"] = tokens[1]
                elif tokens[:2] == ["template", "http"] and len(tokens) > 2:
                    port["templates"].append(tokens[2])
                elif tokens[0] == "aflex":
                    port["aflex"] = True
        elif kind == "template" and tokens[0] == "host-switching" and len(tokens) > 2:
            match = tokens[1]
            if "service-group" not in tokens or match not in SPECIFICITY:
                warnings.append(f"Name Rule Not Understood, Ignored: {stripped}")
                continue
            at = tokens.index("service-group")
            pattern = " ".join(tokens[2:at]).lower()
            if match == "regex-match":
                try:
                    re.compile(pattern)
                except re.error:
                    warnings.append(f"Invalid Regular Expression, Ignored: {pattern}")
                    continue
            if pattern and at + 1 < len(tokens):
                block["rules"].append({"match": match, "pattern": pattern, "service_group": tokens[at + 1]})

    def lookup(table, part, name):
        return table.get((part, name)) or table.get(("", name))

    unresolved = set()

    def pool_ips(part, name):
        group = lookup(groups, part, name)
        if group is None:
            unresolved.add(f"Pool {name}")
            return []
        ips = []
        for member, _ in group["members"]:
            server = lookup(servers, part, member)
            ip = server["ip"] if server else ip_or_none(member)
            if ip:
                ips.append(ip)
            else:
                unresolved.add(f"Server {member}")
        return list(dict.fromkeys(ips))

    def qualified(part, name):
        return f"{part}/{name}" if part else name

    routes = []

    def add(vip, port_name, part, match, pattern, pool):
        ips = pool_ips(part, pool)
        if ips:
            routes.append(
                {
                    "vip_name": qualified(part, vip["name"]) if vip else "",
                    "vip_ip": vip["ip"] if vip else None,
                    "port": port_name,
                    "match": match,
                    "pattern": pattern,
                    "service_group": qualified(part, pool),
                    "backend_ips": ips,
                }
            )

    aflex_ports = 0
    for vip in vips:
        part = vip["partition"]
        for p in vip["ports"]:
            aflex_ports += p["aflex"]
            if p["service_group"]:
                add(vip, p["port"], part, "", "", p["service_group"])
            for name in p["templates"]:
                template = lookup(templates, part, name)
                if template is None:
                    continue
                template["used"] = True
                for rule in template["rules"]:
                    add(vip, p["port"], part, rule["match"], rule["pattern"], rule["service_group"])
    for (part, _), template in templates.items():
        if not template["used"]:
            # A template no VIP uses: its rules still tell where a name goes.
            for rule in template["rules"]:
                add(None, "", part, rule["match"], rule["pattern"], rule["service_group"])

    if aflex_ports:
        warnings.append(
            f"{aflex_ports} VIP Port{'s Use' if aflex_ports != 1 else ' Uses'} aFleX Scripts, Which Are Not in the "
            "Running Configuration: Sites Routed Only by aFleX Are Not Seen."
        )
    if unresolved:
        shown = sorted(unresolved)
        warnings.append(f"Not Found in the File: {', '.join(shown[:10])}{' …' if len(shown) > 10 else ''}")
    # The real servers by address: "10.0.5.20" -> "app-srv-05", the name the
    # balancer knows them by (shown as the Server column of the hosts list).
    by_ip = {}
    for server in servers.values():
        if server["ip"]:
            by_ip.setdefault(server["ip"], server["name"])
    return {
        "name": f"{BRAND} {hostname}" if hostname else BRAND,
        "product": f"{BRAND} ACOS {version}" if version else BRAND,
        "routes": routes,
        "servers": by_ip,
        "counts": {
            "servers": len(servers),
            "service_groups": len(groups),
            "vips": len(vips),
            "vips_with_ip": len({v["ip"] for v in vips if v["ip"]}),
            "rules": sum(len(t["rules"]) for t in templates.values()),
            "routes": len(routes),
        },
        "warnings": warnings,
    }


# --- From a host to its real servers -------------------------------------


def _route_dict(route):
    if isinstance(route, dict):
        return route
    return {
        "vip_name": route.vip_name, "vip_ip": route.vip_ip, "port": route.port, "match": route.match,
        "pattern": route.pattern, "service_group": route.service_group, "backend_ips": route.backend_ips,
    }


@dataclass
class Resolution:
    backends: list
    how: str  # "name", "vip" (scanned on the VIP) or "via" (its private IP is the VIP)
    routes: list = field(default_factory=list)

    @property
    def text(self):
        route = self.routes[0]
        where = f"{route['vip_name']} ({route['vip_ip']}{':' + route['port'] if route['port'] else ''})" if route["vip_ip"] else ""
        pools = ", ".join(dict.fromkeys(r["service_group"] for r in self.routes))
        if self.how == "name":
            label = dict(BalancerRoute.Match.choices).get(route["match"], route["match"])
            return f"Name Rule “{label} {route['pattern']}” → Pool {pools}" + (f" on {where}" if where else "")
        vip = f"{route['vip_name']} ({route['vip_ip']})"
        return f"{'Scanned on VIP' if self.how == 'vip' else 'Private IP Is VIP'} {vip} → Pool {pools}"


class Resolver:
    """Finds the real servers behind a host, from a list of routes (dicts or BalancerRoute rows)."""

    def __init__(self, routes):
        self.routes = [_route_dict(r) for r in routes]
        self.vips = {r["vip_ip"] for r in self.routes if r["vip_ip"]}
        self.named = [r for r in self.routes if r["pattern"]]
        self._regex = {r["pattern"]: re.compile(r["pattern"]) for r in self.named if r["match"] == "regex-match"}

    @classmethod
    def stored(cls):
        return cls(BalancerRoute.objects.all())

    def __bool__(self):
        return bool(self.routes)

    def _matches(self, route, name):
        pattern, match = route["pattern"], route["match"]
        if match == "equals":
            return name == pattern
        if match == "starts-with":
            return name.startswith(pattern)
        if match == "ends-with":
            return name.endswith(pattern)
        if match == "contains":
            return pattern in name
        return bool(self._regex[pattern].search(name))

    def resolve(self, hostname, scanned_ip, via_ip=None):
        """The Resolution for a host, or None when no route leads anywhere else."""
        name = (hostname or "").lower().rstrip(".")
        vips = [ip for ip in dict.fromkeys((scanned_ip, via_ip)) if ip and ip in self.vips]
        how, chosen = "", []
        if name:
            rules = [
                r for r in self.named
                if (not vips or not r["vip_ip"] or r["vip_ip"] in vips) and self._matches(r, name)
            ]
            if rules:
                best = max((SPECIFICITY[r["match"]], len(r["pattern"])) for r in rules)
                how = "name"
                chosen = [r for r in rules if (SPECIFICITY[r["match"]], len(r["pattern"])) == best]
        if not chosen and vips:
            how = "vip" if vips[0] == scanned_ip else "via"
            chosen = [r for r in self.routes if not r["pattern"] and r["vip_ip"] == vips[0]]
        backends = list(dict.fromkeys(ip for r in chosen for ip in r["backend_ips"]))
        # A host that is itself one of the servers is not behind them.
        if not backends or scanned_ip in backends:
            return None
        return Resolution(backends, how, chosen)

    def backend_of(self, ip):
        """The routes that send traffic to `ip`."""
        return [r for r in self.routes if ip in r["backend_ips"]]


# --- Preview and apply ----------------------------------------------------


def _route_key(route):
    r = _route_dict(route)
    return (r["vip_name"], r["vip_ip"] or "", r["port"], r["match"], r["pattern"], r["service_group"], tuple(r["backend_ips"]))


def plan(parsed):
    """What applying `parsed` would change; nothing is written."""
    from . import network_mapping

    resolver = Resolver(parsed["routes"])
    mapping = network_mapping.MappingIndex()
    hosts = []
    used = set()
    for host in Host.objects.prefetch_related("other_private_ips").order_by("hostname", "pk"):
        via = mapping.private_ip_for(host) or host.private_ip
        found = resolver.resolve(host.hostname, host.ip_address, via)
        if found is None:
            continue
        used.update(_route_key(r) for r in found.routes)
        current = host.all_private_ips
        status = "same" if current == found.backends else "changed" if current else "new"
        hosts.append({"host": host, "current": current, "target": found.backends, "how": found.text, "status": status})

    vips = {}
    for r in parsed["routes"]:
        if r["vip_ip"]:
            vips.setdefault(r["vip_ip"], r["vip_name"])
    marked = set(LoadBalancer.objects.filter(ip_address__in=vips).values_list("ip_address", flat=True))
    new_vips = [{"ip": ip, "name": name} for ip, name in sorted(vips.items()) if ip not in marked]
    unused_rules = [r for r in parsed["routes"] if r["pattern"] and _route_key(r) not in used]

    stored = BalancerConfig.objects.filter(name=parsed["name"]).first()
    same_config = stored is not None and sorted(map(_route_key, stored.routes.all())) == sorted(map(_route_key, parsed["routes"]))
    changes = sum(1 for h in hosts if h["status"] != "same")
    counts = {s: sum(1 for h in hosts if h["status"] == s) for s in ("new", "changed", "same")}
    if changes or new_vips:
        parts = []
        if changes:
            parts.append(f"{changes} Host{'s' if changes != 1 else ''} Get Their Real Servers as Private IPs")
        if new_vips:
            parts.append(f"{len(new_vips)} VIP{'s' if len(new_vips) != 1 else ''} Marked as Load Balancer")
        verdict, useful = "Useful: " + ", ".join(parts) + ".", True
    elif not same_config and parsed["routes"]:
        verdict, useful = "Nothing Changes on the Hosts Today, but the Configuration Is Kept for Hosts of Later Scans.", True
    else:
        verdict, useful = "Nothing New: This Configuration Is Already in Pvm.", False
    return {
        "hosts": hosts,
        "counts": counts,
        "changes": changes,
        "new_vips": new_vips,
        "unused_rules": unused_rules,
        "stored": stored,
        "same_config": same_config,
        "verdict": verdict,
        "useful": useful,
    }


def apply(parsed, user, filename=""):
    """Store the configuration (replacing the same balancer's), set the hosts' private IPs, mark the VIPs."""
    with transaction.atomic():
        config, _ = BalancerConfig.objects.update_or_create(
            name=parsed["name"],
            defaults={
                "product": parsed["product"][:100], "filename": filename[:255], "counts": parsed["counts"],
                "servers": parsed.get("servers", {}), "uploaded_by": user,
            },
        )
        config.routes.all().delete()
        BalancerRoute.objects.bulk_create(
            BalancerRoute(
                config=config, vip_name=r["vip_name"][:255], vip_ip=r["vip_ip"], port=r["port"][:32],
                match=r["match"], pattern=r["pattern"][:255], service_group=r["service_group"][:255], backend_ips=r["backend_ips"],
            )
            for r in parsed["routes"]
        )
        result = plan(parsed)
        changed = 0
        for row in result["hosts"]:
            if row["status"] != "same":
                row["host"].set_private_ips(row["target"])
                changed += 1
        for vip in result["new_vips"]:
            LoadBalancer.objects.get_or_create(ip_address=vip["ip"], defaults={"name": f"{BRAND} {vip['name']}"[:100]})
    return {"config": config, "hosts_changed": changed, "vips_marked": len(result["new_vips"]), "routes": len(parsed["routes"])}


def server_names():
    """
    {IP: the name the balancer knows that server by} from every stored
    configuration. A host's private IPs are those addresses, so this is what
    gives the hosts list its Server column (e.g. 10.0.5.20 -> app-srv-05).
    """
    names = {}
    for config in BalancerConfig.objects.all():
        for ip, name in (config.servers or {}).items():
            names.setdefault(ip, name)
    return names


def names_for(ips, names):
    """The server names of `ips`, in order, without repeats and without gaps."""
    return list(dict.fromkeys(names[ip] for ip in ips if names.get(ip)))


def private_ips_for_new_host(host, via_ip, resolver):
    """For an import: the private IPs of a host that has none yet, given the CSV mapping's IP (or None)."""
    found = resolver.resolve(host.hostname, host.ip_address, via_ip) if resolver else None
    return found.backends if found else ([via_ip] if via_ip else [])


def save_other_private_ips(host, ips):
    """After the host is saved with ips[0] as its private IP: the rest, as HostPrivateIp rows."""
    HostPrivateIp.objects.filter(host=host).delete()
    HostPrivateIp.objects.bulk_create(
        HostPrivateIp(host=host, ip_address=ip, position=i) for i, ip in enumerate(ips[1:], start=1)
    )

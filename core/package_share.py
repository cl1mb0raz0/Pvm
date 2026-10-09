"""
Copying one installed package of a host to the other sites on the same
private server (Installed Packages tab, "Apply to Other Sites").

Many sites are separate `Host` rows (same IP, different names) behind one
real server, found by its private IP(s): a version learnt for one site
(e.g. Tomcat, from a colleague) holds for the others, but Pvm keeps packages
per host. Nothing is linked: the package is *copied*, as a manual entry, only
to the hosts the user ticks on a preview page, one audit row each.
"""

from django.db.models import Q

from .models import Host, HostPrivateIp, InstalledPackage

# Status of a candidate host for the package being copied.
NEW = "new"
SAME = "same"
DIFFERENT = "different"


def siblings(host, package):
    """
    The other active hosts on the same server(s) as `host`, each as a dict:
    host, `full` (shares every private IP of `host`: the same pool; False
    when only some), `status` (NEW, SAME or DIFFERENT for `package`), the
    version it has now and where that came from. Sorted: full matches first,
    then by name. Empty when `host` has no private IP.
    """
    mine = set(host.all_private_ips)
    if not mine:
        return []
    candidates = (
        Host.objects.filter(is_active=True)
        .exclude(pk=host.pk)
        .filter(Q(private_ip__in=mine) | Q(pk__in=HostPrivateIp.objects.filter(ip_address__in=mine).values("host")))
        .prefetch_related("other_private_ips", "tags")
    )
    existing = {
        p.host_id: p
        for p in InstalledPackage.objects.filter(host__in=candidates, package_name=package.package_name)
    }
    rows = []
    for other in candidates:
        current = existing.get(other.pk)
        if current is None:
            status = NEW
        elif current.installed_version == package.installed_version:
            status = SAME
        else:
            status = DIFFERENT
        rows.append(
            {
                "host": other,
                "full": mine <= set(other.all_private_ips),
                "private_ips": other.all_private_ips,
                "status": status,
                "current": current,
            }
        )
    rows.sort(key=lambda r: (not r["full"], r["host"].hostname.lower()))
    return rows


def preselected(row):
    """Ticked by default: the same pool, and a host that does not have the package yet.
    A host with another version (maybe read from its own agent) and a host that only
    shares some of the servers are shown, never ticked for you."""
    return row["full"] and row["status"] == NEW


def copy_package(package, targets, user, now):
    """Write `package` on each host of `targets` as a manual entry; returns those that changed."""
    changed = []
    for target in targets:
        _, created = InstalledPackage.objects.update_or_create(
            host=target,
            package_name=package.package_name,
            defaults={
                "installed_version": package.installed_version,
                "source_package": package.source_package,
                "source_version": "",
                "source": InstalledPackage.Source.MANUAL,
                "detected_at": now,
                "created_by": user,
            },
        )
        changed.append(target)
    return changed

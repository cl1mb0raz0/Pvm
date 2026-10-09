"""
Parse installed-package lists pasted into a host's page.

Accepted, one package per line, in any mix:

- the output of the command PVM suggests to the sysadmin
  (dpkg-query: package, version, source package, source version, tab-separated)
- `dpkg -l` output (only installed "ii"/"hi" lines are kept)
- plain "package version" lines, as someone might type them in an email

A VERSION_CODENAME=... line (from /etc/os-release) sets the host's release.
"""

import re
from dataclasses import dataclass

from . import debversion

# Read-only, no root needed. Shown on the host page to send to the sysadmin.
COMMAND = (
    "grep VERSION_CODENAME /etc/os-release; "
    "dpkg-query -W -f='${binary:Package}\\t${Version}\\t${source:Package}\\t${source:Version}\\n'"
)

PACKAGE_NAME = re.compile(r"^[a-z0-9][a-z0-9+.-]+$")
CODENAME = re.compile(r"^(?:VERSION_CODENAME|UBUNTU_CODENAME)=\"?([a-z]+)\"?$")


@dataclass
class Entry:
    name: str
    version: str
    source: str = ""
    source_version: str = ""


def parse(text):
    """Return (release or "", [Entry], [unreadable lines])."""
    release, entries, errors = "", {}, []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = CODENAME.match(line)
        if match:
            release = match.group(1)
            continue
        cols = [c.strip() for c in line.split("\t")] if "\t" in line else line.split()
        # dpkg -l: status flags first; skip its header and non-installed rows.
        if cols and re.fullmatch(r"[a-z]{2,3}", cols[0]) and len(cols) >= 3 and not debversion.is_valid(cols[1]):
            if cols[0] not in ("ii", "hi"):
                continue
            cols = cols[1:]
        if line.startswith(("Desired=", "|", "+++-", "||/")):
            continue
        if len(cols) < 2:
            errors.append(line)
            continue
        # Multiarch names carry the architecture: libc6:amd64.
        name = cols[0].split(":")[0]
        version = cols[1]
        source = cols[2].split(" ")[0] if len(cols) > 2 and cols[2] else ""
        source_version = cols[3] if len(cols) > 3 and debversion.is_valid(cols[3]) else ""
        if not PACKAGE_NAME.match(name) or not debversion.is_valid(version):
            errors.append(line)
            continue
        entries[name] = Entry(name, version, source if PACKAGE_NAME.match(source) else "", source_version)
    return release, list(entries.values()), errors


def store(host, entries, user, source, replace=False):
    """
    Save `entries` as `host`'s installed packages; with `replace`, packages
    not in `entries` are removed (a complete list). Returns (created, removed).
    """
    from django.utils import timezone

    from .models import InstalledPackage

    now, created = timezone.now(), 0
    for e in entries:
        _, is_new = InstalledPackage.objects.update_or_create(
            host=host,
            package_name=e.name,
            defaults={
                "installed_version": e.version,
                "source_package": e.source,
                "source_version": e.source_version,
                "source": source,
                "detected_at": now,
                "created_by": user,
            },
        )
        created += is_new
    removed = 0
    if replace and entries:
        removed, _ = host.packages.exclude(package_name__in=[e.name for e in entries]).delete()
    return created, removed

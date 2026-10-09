"""
Debian/Ubuntu package version comparison, same result as
`dpkg --compare-versions` (a port of dpkg's verrevcmp).

A version is [epoch:]upstream[-revision]. "~" sorts before everything,
even the end of the string, so 1.0~rc1 < 1.0; letters sort before other
symbols; digit runs compare numerically.
"""

import functools
import re

VALID = re.compile(r"^(\d+:)?[0-9][A-Za-z0-9.+~:-]*$")


def is_valid(version):
    return bool(VALID.match(version or ""))


def _split(version):
    epoch, _, rest = version.partition(":") if ":" in version else ("0", "", version)
    upstream, _, revision = rest.rpartition("-") if "-" in rest else (rest, "", "")
    return int(epoch or 0), upstream, revision


def _order(char):
    if char == "~":
        return -1
    if char.isdigit():
        return 0
    if char.isascii() and char.isalpha():
        return ord(char)
    return ord(char) + 256


def _verrevcmp(a, b):
    i = j = 0
    while i < len(a) or j < len(b):
        # Non-digit prefix, compared character by character.
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i]) if i < len(a) else 0
            bc = _order(b[j]) if j < len(b) else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        # Digit run, compared numerically.
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        first_diff = 0
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def compare(a, b):
    """Negative if a < b, 0 if equal, positive if a > b."""
    ea, ua, ra = _split(a.strip())
    eb, ub, rb = _split(b.strip())
    if ea != eb:
        return ea - eb
    return _verrevcmp(ua, ub) or _verrevcmp(ra, rb)


sort_key = functools.cmp_to_key(compare)

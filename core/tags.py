"""
Tags: labels for areas or groups of assets (e.g. "Alpha"), not exclusive.

An import's tags are given to every host in its report when it is
applied (and added to later, from the import page); on a host they can
be added or removed by hand. Tags are never removed by an import. Names
are matched without regard to case: "alpha" reuses an existing "Alpha".
"""

from .models import Host, Tag

MAX_LENGTH = Tag._meta.get_field("name").max_length


def parse(text):
    """Comma-separated names, stripped, without duplicates (ignoring case)."""
    names, seen = [], set()
    for raw in (text or "").split(","):
        name = " ".join(raw.split())[:MAX_LENGTH]
        if name and name.lower() not in seen:
            seen.add(name.lower())
            names.append(name)
    return names


def resolve(names):
    """Tag rows for `names`, created when new."""
    tags = []
    for name in names:
        tag = Tag.objects.filter(name__iexact=name).first() or Tag.objects.create(name=name)
        tags.append(tag)
    return tags


def from_form(post):
    """Tags chosen on a form: ticked existing ones ("tag" ids) plus typed new names ("new_tags")."""
    ids = [i for i in post.getlist("tag") if i.isdigit()]
    return list(Tag.objects.filter(pk__in=ids)) + resolve(parse(post.get("new_tags", "")))


def apply(tags, hosts):
    """Give every tag in `tags` to every host in `hosts` (existing pairs are kept)."""
    through = Host.tags.through
    through.objects.bulk_create(
        [through(host_id=h.pk, tag_id=t.pk) for h in hosts for t in tags], ignore_conflicts=True
    )


def suggested_for(scan_import):
    """Tags of the last import with the same name: "Internal Alpha" suggests what it had last time."""
    from .models import ScanImport

    if not scan_import.name:
        return []
    previous = (
        ScanImport.objects.filter(name__iexact=scan_import.name, status=ScanImport.Status.COMPLETED)
        .exclude(pk=scan_import.pk)
        .order_by("-completed_at")
        .first()
    )
    return list(previous.tags.all()) if previous else []

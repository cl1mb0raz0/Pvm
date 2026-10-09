"""
Sortable table headers shared by every list: the requested column and
direction from the query string, and the header links that keep the other
filters. `core/templates/core/partials/sortable_headers.html` draws them.

Lists read from the database pass the field to order_by; lists built in
Python (rows from an API, values computed per row) use `sort_rows`, which
keeps empty values last in both directions.
"""

TITLE = "title"  # what a header's tooltip key is called in a column tuple


def sorting(request, columns, default, prefix=""):
    """
    `columns`: (query key, header, sorted field, first-click direction,
    numeric) and, optionally, a sixth item: the header's tooltip.
    `field` is a model field for a queryset, a callable for `sort_rows`, or
    None for a column that is shown but cannot be sorted on. `prefix` gives a
    second table on the same page its own query keys, so sorting one does not
    reset the other.
    Returns (field, direction, key, headers).
    """
    sort_key, dir_key = f"{prefix}sort", f"{prefix}dir"
    # A column with no field (None) is shown but cannot be sorted on: its
    # value is not in the database (e.g. the Server column of the hosts list).
    columns = [tuple(c) + ("",) * (6 - len(c)) for c in columns]
    fields = {key: (field, first) for key, _, field, first, _, _ in columns if field}
    sort = request.GET.get(sort_key, default)
    if sort not in fields:
        sort = default
    direction = request.GET.get(dir_key)
    if direction not in ("asc", "desc"):
        direction = fields[sort][1]

    headers = []
    for key, label, field, first, numeric, title in columns:
        if not field:
            headers.append({"label": label, "url": "", "active": False, "dir": "", "numeric": numeric, "title": title})
            continue
        params = request.GET.copy()
        params.pop("refresh", None)
        params.pop("page", None)  # a new order starts from the first page
        params[sort_key] = key
        active = key == sort
        # Clicking the active column flips it; another column starts from its default.
        params[dir_key] = ("desc" if direction == "asc" else "asc") if active else first
        headers.append(
            {
                "label": label,
                "url": "?" + params.urlencode(),
                "active": active,
                "dir": direction if active else "",
                "numeric": numeric,
                "title": title,
            }
        )
    return fields[sort][0], direction, sort, headers


def sort_rows(rows, value, direction):
    """
    Rows sorted on `value(row)`, empty values last whichever way it goes.
    Stable, so rows the column cannot tell apart keep the order they had.
    """
    known = [r for r in rows if value(r) not in (None, "")]
    missing = [r for r in rows if value(r) in (None, "")]
    known.sort(key=value, reverse=direction == "desc")
    return known + missing

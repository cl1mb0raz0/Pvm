"""
CSV exports of the Hosts and Vulnerabilities lists, with their filters.

Semicolon-separated with a UTF-8 byte order mark and decimal commas:
that is what Excel in an Italian locale opens directly into columns and
numbers (LibreOffice asks and detects it). Streamed, so a large export does not build up in memory.
Cells that a spreadsheet would run as a formula (text starting with =,
+, -, @, tab or carriage return: hostnames, titles and scanner text are
not ours to trust) are prefixed with an apostrophe.
"""

import csv
from decimal import ROUND_DOWN, Decimal

from django.http import StreamingHttpResponse
from django.utils import timezone

FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def _safe(value):
    if isinstance(value, str) and value.startswith(FORMULA_START):
        return "'" + value
    return value


def decimal(value, places):
    """A number with a decimal comma, as Excel in an Italian locale reads it: 9.8 -> "9,8". Truncated, not rounded."""
    exact = Decimal(str(value)).quantize(Decimal(1).scaleb(-places), rounding=ROUND_DOWN)
    return str(exact).replace(".", ",")


class _Echo:
    def write(self, value):
        return value


def csv_response(basename, header, rows):
    writer = csv.writer(_Echo(), delimiter=";")

    def stream():
        yield "﻿" + writer.writerow(header)
        for row in rows:
            yield writer.writerow([_safe(v) for v in row])

    response = StreamingHttpResponse(stream(), content_type="text/csv; charset=utf-8")
    stamp = timezone.localtime().strftime("%Y-%m-%d_%H-%M")
    response["Content-Disposition"] = f'attachment; filename="{basename}_{stamp}.csv"'
    return response

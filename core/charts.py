"""
Server-side geometry for the dashboard's small trend charts.

Charts are plain inline SVG rendered by the template, so the dashboard
needs no JavaScript charting library. Each panel shows one severity, with
its own y-scale starting at zero; the panel title names the series, so no
legend is needed.
"""

WIDTH = 240
HEIGHT = 110
PAD_TOP = 8
PAD_BOTTOM = 4
PAD_X = 6


def line_panel(values, dates):
    if not values:
        return None

    top = _nice_max(max(values))
    plot_h = HEIGHT - PAD_TOP - PAD_BOTTOM
    step = (WIDTH - 2 * PAD_X) / max(len(values) - 1, 1)

    points = []
    for i, (value, date) in enumerate(zip(values, dates)):
        x = PAD_X + i * step if len(values) > 1 else WIDTH / 2
        y = PAD_TOP + plot_h * (1 - value / top)
        points.append({"x": round(x, 1), "y": round(y, 1), "value": value, "date": date})

    # Hover columns: each point owns the full-height band around it, so
    # the tooltip target is much larger than the dot itself.
    hit_width = step if len(values) > 1 else WIDTH
    for p in points:
        p["hit_x"] = round(p["x"] - hit_width / 2, 1)

    line = " ".join(f"{'M' if i == 0 else 'L'}{p['x']},{p['y']}" for i, p in enumerate(points))
    baseline = HEIGHT - PAD_BOTTOM
    area = f"{line} L{points[-1]['x']},{baseline} L{points[0]['x']},{baseline} Z"

    return {
        "width": WIDTH,
        "height": HEIGHT,
        "baseline": baseline,
        "top_y": PAD_TOP,
        "top_value": top,
        "line": line,
        "area": area,
        "points": points,
        "last": points[-1],
        "hit_width": round(hit_width, 1),
    }


def _nice_max(value):
    """Round the axis top up to a clean number (1, 2, 5, 10, 20, 50, ...)."""
    if value <= 0:
        return 1
    magnitude = 1
    while magnitude * 10 <= value:
        magnitude *= 10
    for factor in (1, 2, 5, 10):
        if value <= factor * magnitude:
            return factor * magnitude
    return 10 * magnitude

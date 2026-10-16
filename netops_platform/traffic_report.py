"""Standalone HTML rendering for collected traffic series.

The page is written as one self-contained file with inline SVG charts and no
external assets, so it can be opened from disk, mailed, or published as-is.
Charts are drawn server-side rather than by script because a report that only
renders when JavaScript runs is not a report.
"""

from __future__ import annotations

import html
import time
from typing import Any, List, Mapping, Optional, Sequence, Tuple

from netops_platform.traffic import humanize_bps

# Teal reads as received and rust as transmitted throughout; the pair stays
# distinguishable on either ground and neither is the semantic status colour.
STYLE = """
:root {
  --bg: #f2f5f6; --surface: #ffffff; --surface-2: #f7f9fa;
  --ink: #101a1f; --ink-2: #46595f; --ink-3: #6d8189;
  --line: #dae3e6; --line-2: #eaf0f2;
  --rx: #0d7482; --rx-fill: rgba(13,116,130,0.14);
  --tx: #a8501a; --tx-fill: rgba(168,80,26,0.13);
  --ok: #2b7a51; --warn: #a1741a; --crit: #a63229;
  --chip-ok: rgba(43,122,81,0.12); --chip-warn: rgba(161,116,26,0.14); --chip-crit: rgba(166,50,41,0.12);
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #0d1316; --surface: #141d21; --surface-2: #182328;
    --ink: #e7eef0; --ink-2: #a6b8bf; --ink-3: #7d9199;
    --line: #24333a; --line-2: #1d2a30;
    --rx: #45c2d1; --rx-fill: rgba(69,194,209,0.16);
    --tx: #e08e52; --tx-fill: rgba(224,142,82,0.15);
    --ok: #56c48c; --warn: #dfb14a; --crit: #e2685f;
    --chip-ok: rgba(86,196,140,0.15); --chip-warn: rgba(223,177,74,0.15); --chip-crit: rgba(226,104,95,0.15);
  }
}
:root[data-theme="dark"] {
  --bg: #0d1316; --surface: #141d21; --surface-2: #182328;
  --ink: #e7eef0; --ink-2: #a6b8bf; --ink-3: #7d9199;
  --line: #24333a; --line-2: #1d2a30;
  --rx: #45c2d1; --rx-fill: rgba(69,194,209,0.16);
  --tx: #e08e52; --tx-fill: rgba(224,142,82,0.15);
  --ok: #56c48c; --warn: #dfb14a; --crit: #e2685f;
  --chip-ok: rgba(86,196,140,0.15); --chip-warn: rgba(223,177,74,0.15); --chip-crit: rgba(226,104,95,0.15);
}

* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--ink);
  font-family: ui-sans-serif, system-ui, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  font-size: 15px; line-height: 1.55; -webkit-font-smoothing: antialiased;
}
.wrap { max-width: 1080px; margin: 0 auto; padding: 40px 24px 72px; display: flex; flex-direction: column; gap: 28px; }

header { display: flex; flex-direction: column; gap: 6px; border-bottom: 1px solid var(--line); padding-bottom: 22px; }
.eyebrow {
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  font-size: 11px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--ink-3);
}
h1 { margin: 0; font-size: 27px; font-weight: 640; letter-spacing: -0.015em; text-wrap: balance; }
.lede { margin: 0; color: var(--ink-2); max-width: 62ch; }

.facts { display: flex; flex-wrap: wrap; gap: 28px; margin-top: 10px; }
.fact { display: flex; flex-direction: column; gap: 1px; }
.fact dt { font-size: 11px; letter-spacing: 0.09em; text-transform: uppercase; color: var(--ink-3); }
.fact dd {
  margin: 0; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 15px; font-variant-numeric: tabular-nums; color: var(--ink);
}

.cards { display: flex; flex-direction: column; gap: 18px; }
.card {
  background: var(--surface); border: 1px solid var(--line); border-radius: 10px;
  padding: 20px 22px 14px; display: flex; flex-direction: column; gap: 14px;
}
.card-head { display: flex; flex-wrap: wrap; align-items: baseline; gap: 10px 14px; }
.card-title { font-size: 17px; font-weight: 620; letter-spacing: -0.01em; }
.card-sub {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px; color: var(--ink-3);
}
.chip {
  margin-left: auto; font-size: 11.5px; font-weight: 600; letter-spacing: 0.04em;
  text-transform: uppercase; padding: 3px 9px; border-radius: 999px; white-space: nowrap;
}
.chip.ok { color: var(--ok); background: var(--chip-ok); }
.chip.warn { color: var(--warn); background: var(--chip-warn); }
.chip.crit { color: var(--crit); background: var(--chip-crit); }

.readings { display: flex; flex-wrap: wrap; gap: 8px 26px; }
.reading { display: flex; flex-direction: column; gap: 0; min-width: 108px; }
.reading .label {
  font-size: 10.5px; letter-spacing: 0.09em; text-transform: uppercase; color: var(--ink-3);
  display: flex; align-items: center; gap: 6px;
}
.reading .value {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 18px; font-variant-numeric: tabular-nums; letter-spacing: -0.02em;
}
.swatch { width: 9px; height: 9px; border-radius: 2px; display: inline-block; }
.swatch.rx { background: var(--rx); }
.swatch.tx { background: var(--tx); }
.swatch.loss { background: var(--crit); }

.chart-scroll { overflow-x: auto; margin: 0 -4px; }
svg.chart { display: block; width: 100%; min-width: 420px; height: auto; }
.grid { stroke: var(--line-2); stroke-width: 1; }
.axis-label {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 10px; fill: var(--ink-3);
}
.series-rx { fill: none; stroke: var(--rx); stroke-width: 1.8; stroke-linejoin: round; stroke-linecap: round; }
.series-tx { fill: none; stroke: var(--tx); stroke-width: 1.8; stroke-linejoin: round; stroke-linecap: round; }
.area-rx { fill: var(--rx-fill); stroke: none; }
.area-tx { fill: var(--tx-fill); stroke: none; }
.tip-rx { fill: var(--rx); }
.tip-tx { fill: var(--tx); }
.loss-bar { fill: var(--crit); }
.empty { color: var(--ink-3); font-size: 13.5px; padding: 8px 0 14px; }

footer {
  border-top: 1px solid var(--line); padding-top: 18px; color: var(--ink-3); font-size: 12.5px;
  display: flex; flex-wrap: wrap; gap: 6px 18px;
}
footer code {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  background: var(--surface-2); border: 1px solid var(--line); border-radius: 4px; padding: 1px 5px;
}
@media (max-width: 600px) {
  .wrap { padding: 28px 16px 56px; }
  h1 { font-size: 23px; }
}
"""

CHART_WIDTH = 1000
CHART_HEIGHT = 190
PAD_LEFT = 64
PAD_RIGHT = 14
PAD_TOP = 14
PAD_BOTTOM = 26


def _esc(value: Any) -> str:
    return html.escape(str(value or ""), quote=True)


def _nice_ceiling(value: float) -> float:
    """Round a maximum up to a value an operator would draw an axis at."""
    if value <= 0:
        return 1.0
    magnitude = 10 ** (len(str(int(value))) - 1)
    for step in (1, 1.5, 2, 2.5, 3, 4, 5, 7.5, 10):
        if value <= step * magnitude:
            return step * magnitude
    return 10 * magnitude


def _points(
    rows: Sequence[Mapping[str, Any]],
    start: int,
    end: int,
    ceiling: float,
) -> List[Optional[Tuple[float, float]]]:
    span = max(1, end - start)
    plotted: List[Optional[Tuple[float, float]]] = []
    previous_ts: Optional[int] = None
    for row in rows:
        observed = int(row["observed_at"])
        # A gap far wider than the sampling cadence is missing data, not a line
        # from one reading to the next, so the series is broken there.
        if previous_ts is not None and observed - previous_ts > max(300, span // 12):
            plotted.append(None)
        previous_ts = observed
        x = PAD_LEFT + (observed - start) / span * (CHART_WIDTH - PAD_LEFT - PAD_RIGHT)
        y = CHART_HEIGHT - PAD_BOTTOM - (float(row["value"]) / ceiling) * (CHART_HEIGHT - PAD_TOP - PAD_BOTTOM)
        plotted.append((x, y))
    return plotted


def _path(plotted: Sequence[Optional[Tuple[float, float]]]) -> str:
    parts: List[str] = []
    pen_down = False
    for point in plotted:
        if point is None:
            pen_down = False
            continue
        command = "L" if pen_down else "M"
        parts.append(f"{command}{point[0]:.1f},{point[1]:.1f}")
        pen_down = True
    return " ".join(parts)


def _area(plotted: Sequence[Optional[Tuple[float, float]]]) -> str:
    floor = CHART_HEIGHT - PAD_BOTTOM
    segments: List[str] = []
    run: List[Tuple[float, float]] = []
    for point in list(plotted) + [None]:
        if point is None:
            if len(run) > 1:
                body = " ".join(f"L{x:.1f},{y:.1f}" for x, y in run[1:])
                segments.append(f"M{run[0][0]:.1f},{floor:.1f} L{run[0][0]:.1f},{run[0][1]:.1f} {body} "
                                f"L{run[-1][0]:.1f},{floor:.1f} Z")
            run = []
            continue
        run.append(point)
    return " ".join(segments)


def _clock(timestamp: int) -> str:
    return time.strftime("%H:%M", time.localtime(timestamp))


def _chart(
    series: Sequence[Tuple[str, Sequence[Mapping[str, Any]]]],
    start: int,
    end: int,
    unit_format,
    title: str,
    loss: Sequence[Mapping[str, Any]] = (),
) -> str:
    values = [float(row["value"]) for _, rows in series for row in rows]
    if not values:
        return f'<p class="empty">No samples in this window yet.</p>'
    ceiling = _nice_ceiling(max(values))
    lines: List[str] = [
        f'<svg class="chart" viewBox="0 0 {CHART_WIDTH} {CHART_HEIGHT}" role="img" '
        f'preserveAspectRatio="none" aria-label="{_esc(title)}">'
    ]
    for fraction in (0, 0.25, 0.5, 0.75, 1.0):
        y = CHART_HEIGHT - PAD_BOTTOM - fraction * (CHART_HEIGHT - PAD_TOP - PAD_BOTTOM)
        lines.append(f'<line class="grid" x1="{PAD_LEFT}" y1="{y:.1f}" x2="{CHART_WIDTH - PAD_RIGHT}" y2="{y:.1f}"/>')
        if fraction in (0.5, 1.0):
            lines.append(f'<text class="axis-label" x="{PAD_LEFT - 8}" y="{y + 3.5:.1f}" '
                         f'text-anchor="end">{_esc(unit_format(ceiling * fraction))}</text>')
    for index, label in ((0, _clock(start)), (1, _clock(end))):
        x = PAD_LEFT if index == 0 else CHART_WIDTH - PAD_RIGHT
        anchor = "start" if index == 0 else "end"
        lines.append(f'<text class="axis-label" x="{x}" y="{CHART_HEIGHT - 8}" '
                     f'text-anchor="{anchor}">{_esc(label)}</text>')

    for kind, rows in series:
        if not rows:
            continue
        plotted = _points(rows, start, end, ceiling)
        area = _area(plotted)
        if area:
            lines.append(f'<path class="area-{kind}" d="{area}"/>')
        path = _path(plotted)
        if path:
            lines.append(f'<path class="series-{kind}" d="{path}"/>')
        last = [point for point in plotted if point is not None]
        if last:
            lines.append(f'<circle class="tip-{kind}" cx="{last[-1][0]:.1f}" cy="{last[-1][1]:.1f}" r="3"/>')

    # Loss is drawn as bars from the floor rather than as another line, because
    # a dropped packet is an event and a latency reading is a level.
    span = max(1, end - start)
    floor = CHART_HEIGHT - PAD_BOTTOM
    for row in loss:
        share = float(row["value"]) / 100.0
        if share <= 0:
            continue
        x = PAD_LEFT + (int(row["observed_at"]) - start) / span * (CHART_WIDTH - PAD_LEFT - PAD_RIGHT)
        height = max(3.0, share * (CHART_HEIGHT - PAD_TOP - PAD_BOTTOM))
        lines.append(f'<rect class="loss-bar" x="{x - 1.5:.1f}" y="{floor - height:.1f}" '
                     f'width="3" height="{height:.1f}" rx="1"/>')
    lines.append("</svg>")
    return '<div class="chart-scroll">' + "".join(lines) + "</div>"


def _status(watch: Mapping[str, Any], readings: Mapping[str, Mapping[str, Any]]) -> Tuple[str, str]:
    if watch["kind"] == "icmp":
        latest = readings.get("packet_loss_pct", {}).get("latest")
        peak = readings.get("packet_loss_pct", {}).get("peak")
        if latest is None:
            return "warn", "no data"
        if latest >= 100:
            return "crit", "unreachable"
        if peak and peak >= 100:
            return "warn", "went unreachable"
        if peak:
            return "warn", f"peak {peak:.0f}% loss"
        return "ok", "reachable"
    peak_util = max(
        (readings.get(name, {}).get("peak") or 0.0)
        for name in ("in_utilization_pct", "out_utilization_pct")
    )
    if not readings.get("in_bps", {}).get("samples") and not readings.get("out_bps", {}).get("samples"):
        return "warn", "no data"
    if peak_util >= 80:
        return "crit", f"peak {peak_util:.0f}% of link"
    if peak_util >= 50:
        return "warn", f"peak {peak_util:.0f}% of link"
    return "ok", f"peak {peak_util:.1f}% of link"


def render_report(payload: Mapping[str, Any]) -> str:
    """Render one collected window as a self-contained HTML page."""
    window = int(payload.get("window_seconds") or 3600)
    end = int(payload.get("generated_at") or time.time())
    start = end - window
    cards = list(payload.get("cards") or [])
    collectors = sorted({c for card in cards for c in card.get("collectors", [])})

    worst = "ok"
    rendered: List[str] = []
    for card in cards:
        watch = card["watch"]
        readings = card["readings"]
        series = card["series"]
        level, note = _status(watch, readings)
        worst = level if (level == "crit" or (level == "warn" and worst == "ok")) else worst
        title = (f"{watch.get('device_name') or watch.get('device_ip')} "
                 f"{watch.get('interface_name') or ''}").strip() or str(watch.get("target") or "")
        if watch["kind"] == "icmp":
            subtitle = f"ICMP · {watch.get('target')}"
            body = [
                _reading("round trip", readings.get("rtt_ms"), lambda v: f"{v:.1f} ms", "rx"),
                _reading("jitter", readings.get("jitter_ms"), lambda v: f"{v:.1f} ms", ""),
                _reading("peak loss", readings.get("packet_loss_pct"), lambda v: f"{v:.0f}%", "loss", key="peak"),
            ]
            chart = _chart([("rx", series.get("rtt_ms", []))], start, end,
                           lambda v: f"{v:.0f} ms", f"round trip time to {watch.get('target')}",
                           loss=series.get("packet_loss_pct", []))
        else:
            speed = card.get("speed_bps") or 0
            subtitle = (f"{watch.get('device_ip')} · ifIndex {watch.get('ifindex') or '?'}"
                        + (f" · {humanize_bps(speed)} link" if speed else ""))
            body = [
                _reading("in now", readings.get("in_bps"), humanize_bps, "rx"),
                _reading("in peak", readings.get("in_bps"), humanize_bps, "", key="peak"),
                _reading("out now", readings.get("out_bps"), humanize_bps, "tx"),
                _reading("out peak", readings.get("out_bps"), humanize_bps, "", key="peak"),
            ]
            chart = _chart(
                [("rx", series.get("in_bps", [])), ("tx", series.get("out_bps", []))],
                start, end, humanize_bps, f"throughput on {title}",
            )
        rendered.append(
            '<article class="card">'
            '<div class="card-head">'
            f'<span class="card-title">{_esc(title)}</span>'
            f'<span class="card-sub">{_esc(subtitle)}</span>'
            f'<span class="chip {level}">{_esc(note)}</span>'
            "</div>"
            f'<div class="readings">{"".join(body)}</div>'
            f"{chart}"
            "</article>"
        )

    if not rendered:
        rendered.append('<article class="card"><p class="empty">'
                        "Nothing is being monitored yet. Add a target with "
                        "<code>netrune traffic watch &lt;device&gt; &lt;interface&gt;</code>."
                        "</p></article>")

    facts = [
        ("window", _window_label(window)),
        ("targets", str(len(cards))),
        ("collector", ", ".join(collectors) or str(payload.get("collector") or "local")),
        ("generated", time.strftime("%Y-%m-%d %H:%M", time.localtime(end))),
    ]
    fact_html = "".join(
        f'<div class="fact"><dt>{_esc(label)}</dt><dd>{_esc(value)}</dd></div>' for label, value in facts
    )
    headline = {
        "ok": "All monitored targets are within normal range.",
        "warn": "One or more targets need a look.",
        "crit": "A monitored target is saturated or unreachable.",
    }[worst]

    return (
        f"<title>Traffic Watch</title>\n<style>{STYLE}</style>\n"
        '<div class="wrap">'
        "<header>"
        '<span class="eyebrow">Netrune · interface telemetry</span>'
        "<h1>Traffic Watch</h1>"
        f'<p class="lede">{_esc(headline)} Only the targets on the watchlist are polled; '
        "each series below is drawn from counter deltas taken by the collector named here.</p>"
        f'<dl class="facts">{fact_html}</dl>'
        "</header>"
        f'<section class="cards">{"".join(rendered)}</section>'
        "<footer>"
        "<span>Regenerate with <code>netrune traffic report</code></span>"
        "<span>Collect continuously with <code>netrune traffic daemon</code></span>"
        "</footer>"
        "</div>"
    )


def _reading(label: str, summary: Optional[Mapping[str, Any]], render, swatch: str, key: str = "latest") -> str:
    value = (summary or {}).get(key)
    shown = render(float(value)) if value is not None else "—"
    mark = f'<span class="swatch {swatch}"></span>' if swatch else ""
    return (f'<div class="reading"><span class="label">{mark}{_esc(label)}</span>'
            f'<span class="value">{_esc(shown)}</span></div>')


def _window_label(seconds: int) -> str:
    if seconds % 86400 == 0 and seconds >= 86400:
        return f"last {seconds // 86400}d"
    if seconds % 3600 == 0 and seconds >= 3600:
        return f"last {seconds // 3600}h"
    return f"last {max(1, seconds // 60)}m"

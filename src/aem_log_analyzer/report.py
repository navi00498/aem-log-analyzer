"""Render an analysis report as text, JSON or a self-contained HTML page."""

from __future__ import annotations

import json
from html import escape
from typing import Any, Dict, List, Optional, Sequence

SEVERITY_LABEL = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}


def render(report: Dict[str, Any], fmt: str) -> str:
    if fmt == "json":
        return json.dumps(report, indent=2) + "\n"
    if fmt == "html":
        return render_html(report)
    return render_text(report)


def _fmt_ms(value: Optional[int]) -> str:
    return "-" if value is None else f"{value:,} ms"


def _truncate(text: str, width: int) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= width else text[: width - 1] + "…"


def _table(headers: Sequence[str], rows: List[Sequence[Any]], widths: Sequence[int]) -> List[str]:
    def line(cells):
        return "  ".join(_truncate(str(c), w).ljust(w) for c, w in zip(cells, widths)).rstrip()

    out = [line(headers), line(["-" * w for w in widths])]
    out.extend(line(row) for row in rows)
    return out


# ---------------------------------------------------------------------------- text


def render_text(report: Dict[str, Any]) -> str:
    lines: List[str] = [f"AEM Log Analyzer {report['tool']['version']}", "=" * 60]
    for source in report["sources"]:
        lines.append(f"  {source['type']:<8} {source['path']}")

    err = report["error_log"]
    req = report["request_log"]
    if err:
        levels = ", ".join(f"{k} {v:,}" for k, v in err["levels"].items())
        lines += [
            "",
            f"error.log   {err['entries']:,} entries ({err['start']} → {err['end']})",
            f"            {levels}",
        ]
    if req:
        lat = req["latency_ms"]
        lines += [
            "",
            f"request.log {req['requests']:,} requests ({req['start']} → {req['end']})",
            f"            p50 {_fmt_ms(lat['p50'])} | p90 {_fmt_ms(lat['p90'])} | p99 {_fmt_ms(lat['p99'])}"
            f" | max {_fmt_ms(lat['max'])}",
            f"            5xx {req['errors_5xx']:,} ({req['error_rate_5xx']:.2%}) | "
            f"slow (≥{req['slow_threshold_ms']} ms) {req['slow_requests']:,}",
        ]

    lines += ["", f"FINDINGS ({len(report['findings'])})", "-" * 60]
    if not report["findings"]:
        lines.append("No known issues detected.")
    for finding in report["findings"]:
        lines.append(f"[{SEVERITY_LABEL[finding['severity']]:<8}] {finding['title']} ({finding['count']:,}x)")
        for example in finding["examples"][:3]:
            lines.append(f"           • {_truncate(example, 110)}")
        lines.append(f"           → {finding['hint']}")
        lines.append("")

    if err and err["top_errors"]:
        lines += ["TOP ERRORS AND WARNINGS", "-" * 60]
        rows = [
            [
                e["count"],
                e["level"],
                e["logger"].rsplit(".", 1)[-1],
                e["root_cause"] or e["exception"] or "",
                e["message"],
            ]
            for e in err["top_errors"]
        ]
        lines += _table(["Count", "Level", "Logger", "Exception", "Message"], rows, [6, 5, 28, 28, 50])
        lines.append("")

    if req and req["slowest_paths"]:
        lines += ["SLOWEST PATHS (by p90)", "-" * 60]
        rows = [[p["p90_ms"], p["avg_ms"], p["count"], p["errors_5xx"], p["path"]] for p in req["slowest_paths"]]
        lines += _table(["p90 ms", "avg ms", "Count", "5xx", "Path"], rows, [7, 7, 6, 4, 70])
        lines.append("")

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------- html

_CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#1d2433;--muted:#5d6b82;--line:#e3e7ee;--accent:#eb1000;
--critical:#b00020;--high:#e4572e;--medium:#f0a202;--low:#4a90d9}
*{box-sizing:border-box}body{margin:0;font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
background:var(--bg);color:var(--ink)}header{background:#1d2433;color:#fff;padding:24px 32px}
header h1{margin:0;font-size:22px}header p{margin:4px 0 0;color:#c4cbd8}main{padding:24px 32px;max-width:1300px}
section{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:20px;margin-bottom:20px}
h2{margin:0 0 12px;font-size:17px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.card b{display:block;font-size:22px}.card span{color:var(--muted);font-size:12px;text-transform:uppercase}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);
vertical-align:top}th{color:var(--muted);font-size:12px;text-transform:uppercase}td.num{text-align:right;
font-variant-numeric:tabular-nums}code{font:12px/1.4 ui-monospace,Menlo,monospace;word-break:break-all}
.sev{display:inline-block;padding:2px 8px;border-radius:999px;color:#fff;font-size:11px;font-weight:700}
.critical{background:var(--critical)}.high{background:var(--high)}.medium{background:var(--medium)}.low{background:var(--low)}
.hint{color:var(--muted);margin-top:4px}ul.ex{margin:6px 0 0;padding-left:18px}
.chart{display:flex;align-items:flex-end;gap:3px;height:140px;border-bottom:1px solid var(--line);padding-top:8px}
.bar{flex:1;background:var(--accent);border-radius:3px 3px 0 0;min-height:1px;position:relative}
.bar:hover{opacity:.75}.axis{display:flex;justify-content:space-between;color:var(--muted);font-size:11px;margin-top:4px}
footer{color:var(--muted);padding:0 32px 32px;font-size:12px}
"""


def _cell(value: Any, cls: str = "") -> str:
    attr = f' class="{cls}"' if cls else ""
    return f"<td{attr}>{escape('' if value is None else str(value))}</td>"


def _html_table(headers: Sequence[str], rows: List[str]) -> str:
    head = "".join(f"<th>{escape(h)}</th>" for h in headers)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(rows)}</tbody></table>"


def _chart(points: List[List[Any]], label: str) -> str:
    if not points:
        return "<p>No data.</p>"
    peak = max(count for _, count in points) or 1
    bars = "".join(
        f'<div class="bar" style="height:{max(1, round(count / peak * 100))}%" '
        f'title="{escape(str(hour))}: {count:,} {label}"></div>'
        for hour, count in points
    )
    return (
        f'<div class="chart">{bars}</div>'
        f'<div class="axis"><span>{escape(str(points[0][0]))}</span><span>peak {peak:,}/hour</span>'
        f"<span>{escape(str(points[-1][0]))}</span></div>"
    )


def render_html(report: Dict[str, Any]) -> str:
    err = report["error_log"]
    req = report["request_log"]
    sources = ", ".join(f"{s['path']} ({s['type']})" for s in report["sources"])

    cards = []
    if err:
        cards += [
            (f"{err['entries']:,}", "log entries"),
            (f"{err['levels'].get('ERROR', 0):,}", "errors"),
            (f"{err['levels'].get('WARN', 0):,}", "warnings"),
        ]
    if req:
        lat = req["latency_ms"]
        cards += [
            (f"{req['requests']:,}", "requests"),
            (_fmt_ms(lat["p50"]), "p50 latency"),
            (_fmt_ms(lat["p99"]), "p99 latency"),
            (f"{req['error_rate_5xx']:.2%}", "5xx rate"),
        ]
    counts = {}
    for finding in report["findings"]:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    cards.insert(0, (str(len(report["findings"])), "findings"))
    card_html = "".join(f'<div class="card"><b>{escape(v)}</b><span>{escape(k)}</span></div>' for v, k in cards)

    parts = [f'<section><div class="cards">{card_html}</div></section>']

    rows = []
    for f in report["findings"]:
        examples = "".join(f"<li><code>{escape(e)}</code></li>" for e in f["examples"][:5])
        rows.append(
            f'<tr><td><span class="sev {f["severity"]}">{SEVERITY_LABEL[f["severity"]]}</span></td>'
            f'<td class="num">{f["count"]:,}</td><td><b>{escape(f["title"])}</b>'
            f'<div class="hint">{escape(f["detail"])}</div>'
            f'{f"<ul class=ex>{examples}</ul>" if examples else ""}'
            f'<div class="hint">→ {escape(f["hint"])}</div></td></tr>'
        )
    parts.append(
        "<section><h2>Findings</h2>"
        + (_html_table(["Severity", "Count", "Issue and recommendation"], rows) if rows else "<p>No known issues.</p>")
        + "</section>"
    )

    if err:
        parts.append(f"<section><h2>Errors per hour</h2>{_chart(err['errors_by_hour'], 'errors')}</section>")
        rows = [
            "<tr>"
            + _cell(f"{e['count']:,}", "num")
            + _cell(e["level"])
            + f"<td><code>{escape(e['logger'])}</code></td>"
            + f"<td>{escape(e['message'][:300])}"
            + (f"<div class=hint>{escape(e['root_cause'] or e['exception'])}</div>" if e["exception"] else "")
            + "</td>"
            + _cell(e["first_seen"])
            + _cell(e["last_seen"])
            + "</tr>"
            for e in err["top_errors"]
        ]
        parts.append(
            "<section><h2>Top errors and warnings</h2>"
            + _html_table(["Count", "Level", "Logger", "Message / root cause", "First seen", "Last seen"], rows)
            + "</section>"
        )
        if err["traversal_queries"]:
            rows = [
                f'<tr>{_cell(f"{count:,}", "num")}<td><code>{escape(query)}</code></td></tr>'
                for query, count in err["traversal_queries"]
            ]
            parts.append(
                "<section><h2>Queries that need an index</h2>"
                + _html_table(["Count", "Query (literals replaced with ?)"], rows)
                + "</section>"
            )

    if req:
        parts.append(f"<section><h2>Requests per hour</h2>{_chart(req['requests_by_hour'], 'requests')}</section>")
        rows = [
            "<tr>"
            + _cell(f"{p['p90_ms']:,}", "num")
            + _cell(f"{p['avg_ms']:,}", "num")
            + _cell(f"{p['max_ms']:,}", "num")
            + _cell(f"{p['count']:,}", "num")
            + _cell(p["errors_5xx"], "num")
            + f"<td><code>{escape(p['path'])}</code></td></tr>"
            for p in req["slowest_paths"]
        ]
        parts.append(
            "<section><h2>Slowest paths</h2>"
            + _html_table(["p90 ms", "Avg ms", "Max ms", "Count", "5xx", "Path"], rows)
            + "</section>"
        )
        rows = [
            "<tr>"
            + _cell(f"{r['duration_ms']:,}", "num")
            + _cell(r["status"])
            + _cell(r["time"])
            + f"<td><code>{escape(r['method'])} {escape(r['url'])}</code></td></tr>"
            for r in req["slowest_requests"]
        ]
        parts.append(
            "<section><h2>Slowest requests</h2>"
            + _html_table(["ms", "Status", "Time", "Request"], rows)
            + "</section>"
        )
        codes = " · ".join(f"<b>{escape(code)}</b> {count:,}" for code, count in req["status_codes"].items())
        parts.append(f"<section><h2>Status codes</h2><p>{codes}</p></section>")

    return (
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        '<meta name=viewport content="width=device-width,initial-scale=1">'
        f"<title>AEM Log Analysis</title><style>{_CSS}</style></head><body>"
        f"<header><h1>AEM Log Analysis</h1><p>{escape(sources)}</p></header>"
        f"<main>{''.join(parts)}</main>"
        f"<footer>Generated {escape(report['generated_at'])} by aem-log-analyzer {escape(report['tool']['version'])}"
        "</footer></body></html>\n"
    )

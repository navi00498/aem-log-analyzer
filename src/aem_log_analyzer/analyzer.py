"""Aggregate parsed log records into statistics and prioritized findings."""

from __future__ import annotations

import heapq
import itertools
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from . import __version__
from .parsers import LogEntry, Request
from .rules import SEVERITY_ORDER, Rule, match_rule

_NORMALIZERS = (
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), "<uuid>"),
    (re.compile(r"(?<![\w.:/])/[\w\-.:~%@]+(?:/[\w\-.:~%@]*)+"), "<path>"),
    (re.compile(r"\b(?:0x)?[0-9a-f]{8,}\b", re.I), "<hex>"),
    (re.compile(r"'[^'\n]{0,200}'"), "'*'"),
    (re.compile(r'"[^"\n]{0,200}"'), '"*"'),
    (re.compile(r"\b\d+(?:\.\d+)*\b"), "<n>"),
    (re.compile(r"\s+"), " "),
)
_QUERY_LITERALS = (
    (re.compile(r"'[^']*'"), "'?'"),
    (re.compile(r"\b\d+\b"), "?"),
)
_EXCEPTION = re.compile(
    r"^\s*(?P<cause>Caused by: )?(?P<cls>(?:[A-Za-z_$][\w$]*\.)+[A-Z][\w$]*(?:Exception|Error|Throwable))\b"
)
_ID_SEGMENT = re.compile(r"^(?:\d+|[0-9a-f]{8}-[0-9a-f-]{27}|[0-9a-f]{16,})$", re.I)

NOISY_THRESHOLD = 100


def normalize_message(text: str, limit: int = 240) -> str:
    """Replace volatile tokens (ids, paths, numbers, literals) so similar messages group together."""
    for pattern, replacement in _NORMALIZERS:
        text = pattern.sub(replacement, text)
    return text.strip()[:limit]


def normalize_query(query: str) -> str:
    for pattern, replacement in _QUERY_LITERALS:
        query = pattern.sub(replacement, query)
    return query.strip()


def normalize_url(url: str) -> str:
    path = url.split("?", 1)[0].split("#", 1)[0]
    return "/".join("{id}" if _ID_SEGMENT.match(seg) else seg for seg in path.split("/")) or "/"


def exception_chain(entry: LogEntry) -> List[str]:
    """Return the top-level exception followed by each ``Caused by`` class."""
    chain: List[str] = []
    for line in entry.stack:
        match = _EXCEPTION.match(line)
        if match and (match["cause"] or not chain):
            chain.append(match["cls"])
    return chain


def percentile(sorted_values: List[int], pct: float) -> Optional[int]:
    if not sorted_values:
        return None
    rank = max(1, math.ceil(pct / 100 * len(sorted_values)))
    return sorted_values[rank - 1]


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat(sep=" ", timespec="seconds") if value else None


def _hour(value: datetime) -> datetime:
    return value.replace(minute=0, second=0, microsecond=0)


@dataclass
class ErrorGroup:
    level: str
    logger: str
    message: str
    first_seen: datetime
    last_seen: datetime
    line_no: int
    exception: Optional[str] = None
    root_cause: Optional[str] = None
    count: int = 0


@dataclass
class RuleHit:
    rule: Rule
    first_seen: datetime
    last_seen: datetime
    count: int = 0
    details: Counter = field(default_factory=Counter)
    samples: List[str] = field(default_factory=list)


class ErrorLogStats:
    def __init__(self) -> None:
        self.total = 0
        self.levels: Counter = Counter()
        self.start: Optional[datetime] = None
        self.end: Optional[datetime] = None
        self.errors_by_hour: Counter = Counter()
        self.loggers: Counter = Counter()
        self.groups: Dict[str, ErrorGroup] = {}
        self.rule_hits: Dict[str, RuleHit] = {}

    def add(self, entry: LogEntry) -> None:
        self.total += 1
        self.levels[entry.level] += 1
        ts = entry.timestamp
        self.start = ts if self.start is None or ts < self.start else self.start
        self.end = ts if self.end is None or ts > self.end else self.end

        if entry.level not in ("ERROR", "WARN") and "OutOfMemoryError" not in entry.message:
            return

        text = entry.text()
        rule = match_rule(entry.level, text)
        detail = self._record_rule(rule, entry, text) if rule is not None else None

        if entry.level == "ERROR":
            self.errors_by_hour[_hour(ts)] += 1
        self.loggers[entry.logger] += 1

        if detail is not None:
            # Group by what the rule extracted (query, failing class, host) rather than raw text.
            key = f"{entry.level}|{entry.logger}|rule:{rule.id}|{detail}"
        else:
            key = f"{entry.level}|{entry.logger}|{normalize_message(entry.message)}"
        group = self.groups.get(key)
        if group is None:
            chain = exception_chain(entry)
            group = ErrorGroup(
                level=entry.level,
                logger=entry.logger,
                message=entry.message.strip()[:500],
                first_seen=ts,
                last_seen=ts,
                line_no=entry.line_no,
                exception=chain[0] if chain else None,
                root_cause=chain[-1] if len(chain) > 1 else None,
            )
            self.groups[key] = group
        group.count += 1
        group.first_seen = min(group.first_seen, ts)
        group.last_seen = max(group.last_seen, ts)

    def _record_rule(self, rule: Rule, entry: LogEntry, text: str) -> Optional[str]:
        hit = self.rule_hits.get(rule.id)
        if hit is None:
            hit = RuleHit(rule=rule, first_seen=entry.timestamp, last_seen=entry.timestamp)
            self.rule_hits[rule.id] = hit
        hit.count += 1
        hit.first_seen = min(hit.first_seen, entry.timestamp)
        hit.last_seen = max(hit.last_seen, entry.timestamp)
        if len(hit.samples) < 3:
            hit.samples.append(f"line {entry.line_no}: {entry.message.strip()[:300]}")
        if rule.extract is not None:
            match = rule.extract.search(text)
            if match:
                detail = normalize_query(match[1])[:300]
                hit.details[detail] += 1
                return detail
        return None

    def to_dict(self, top: int) -> Dict[str, Any]:
        groups = sorted(self.groups.values(), key=lambda g: (-g.count, g.first_seen))
        traversal = self.rule_hits.get("oak-traversal")
        return {
            "entries": self.total,
            "levels": dict(self.levels.most_common()),
            "start": _iso(self.start),
            "end": _iso(self.end),
            "errors_by_hour": [[_iso(hour), count] for hour, count in sorted(self.errors_by_hour.items())],
            "top_loggers": [list(item) for item in self.loggers.most_common(top)],
            "top_errors": [
                {
                    "count": g.count,
                    "level": g.level,
                    "logger": g.logger,
                    "message": g.message,
                    "exception": g.exception,
                    "root_cause": g.root_cause,
                    "first_seen": _iso(g.first_seen),
                    "last_seen": _iso(g.last_seen),
                    "first_line": g.line_no,
                }
                for g in groups[:top]
            ],
            "traversal_queries": [list(item) for item in traversal.details.most_common(top)] if traversal else [],
        }


@dataclass
class PathStats:
    durations: List[int] = field(default_factory=list)
    errors_5xx: int = 0


class RequestLogStats:
    def __init__(self, slow_ms: int = 1000, top: int = 10) -> None:
        self.slow_ms = slow_ms
        self.top = top
        self.total = 0
        self.incomplete: List[Request] = []
        self.statuses: Counter = Counter()
        self.durations: List[int] = []
        self.paths: Dict[str, PathStats] = {}
        self.requests_by_hour: Counter = Counter()
        self.start: Optional[datetime] = None
        self.end: Optional[datetime] = None
        self._slowest: List[Any] = []
        self._seq = itertools.count()

    def add(self, request: Request) -> None:
        self.total += 1
        ts = request.start
        self.start = ts if self.start is None or ts < self.start else self.start
        self.end = ts if self.end is None or ts > self.end else self.end
        self.requests_by_hour[_hour(ts)] += 1

        if not request.completed:
            self.incomplete.append(request)
            return

        duration = request.duration_ms or 0
        self.statuses[request.status] += 1
        self.durations.append(duration)
        path = self.paths.setdefault(normalize_url(request.url), PathStats())
        path.durations.append(duration)
        if request.status >= 500:
            path.errors_5xx += 1

        item = (duration, next(self._seq), request)
        if len(self._slowest) < self.top:
            heapq.heappush(self._slowest, item)
        else:
            heapq.heappushpop(self._slowest, item)

    @property
    def completed(self) -> int:
        return len(self.durations)

    @property
    def errors_5xx(self) -> int:
        return sum(count for status, count in self.statuses.items() if status >= 500)

    @property
    def slow_count(self) -> int:
        return sum(1 for d in self.durations if d >= self.slow_ms)

    def to_dict(self) -> Dict[str, Any]:
        ordered = sorted(self.durations)
        classes: Counter = Counter()
        for status, count in self.statuses.items():
            classes[f"{status // 100}xx"] += count
        path_rows = []
        for name, stats in self.paths.items():
            values = sorted(stats.durations)
            path_rows.append(
                {
                    "path": name,
                    "count": len(values),
                    "avg_ms": round(sum(values) / len(values)),
                    "p90_ms": percentile(values, 90),
                    "max_ms": values[-1],
                    "errors_5xx": stats.errors_5xx,
                }
            )
        path_rows.sort(key=lambda row: (-row["p90_ms"], -row["count"]))
        return {
            "requests": self.total,
            "completed": self.completed,
            "incomplete": len(self.incomplete),
            "incomplete_samples": [
                {"time": _iso(r.start), "method": r.method, "url": r.url} for r in self.incomplete[: self.top]
            ],
            "start": _iso(self.start),
            "end": _iso(self.end),
            "status_classes": dict(sorted(classes.items())),
            "status_codes": {str(k): v for k, v in sorted(self.statuses.items())},
            "latency_ms": {
                "avg": round(sum(ordered) / len(ordered)) if ordered else None,
                "p50": percentile(ordered, 50),
                "p90": percentile(ordered, 90),
                "p95": percentile(ordered, 95),
                "p99": percentile(ordered, 99),
                "max": ordered[-1] if ordered else None,
            },
            "slow_threshold_ms": self.slow_ms,
            "slow_requests": self.slow_count,
            "errors_5xx": self.errors_5xx,
            "error_rate_5xx": round(self.errors_5xx / self.completed, 4) if self.completed else 0.0,
            "requests_by_hour": [[_iso(h), c] for h, c in sorted(self.requests_by_hour.items())],
            "slowest_requests": [
                {
                    "duration_ms": duration,
                    "time": _iso(req.start),
                    "method": req.method,
                    "url": req.url,
                    "status": req.status,
                }
                for duration, _, req in sorted(self._slowest, key=lambda item: (-item[0], item[1]))
            ],
            "slowest_paths": path_rows[: self.top],
        }


def _finding(severity, title, count, hint, detail="", examples=None, rule=None) -> Dict[str, Any]:
    return {
        "severity": severity,
        "title": title,
        "count": count,
        "detail": detail,
        "hint": hint,
        "examples": examples or [],
        "rule": rule,
    }


def build_findings(errors: Optional[ErrorLogStats], requests: Optional[RequestLogStats]) -> List[Dict]:
    findings: List[Dict[str, Any]] = []
    if errors is not None:
        for hit in errors.rule_hits.values():
            examples = [f"{count}x {detail}" for detail, count in hit.details.most_common(5)] or hit.samples
            findings.append(
                _finding(
                    hit.rule.severity,
                    hit.rule.title,
                    hit.count,
                    hit.rule.hint,
                    detail=f"First seen {_iso(hit.first_seen)}, last seen {_iso(hit.last_seen)}",
                    examples=examples,
                    rule=hit.rule.id,
                )
            )
        noisy = [g for g in errors.groups.values() if g.level == "ERROR" and g.count >= NOISY_THRESHOLD]
        for group in sorted(noisy, key=lambda g: -g.count)[:3]:
            findings.append(
                _finding(
                    "low",
                    f"Noisy repeated error from {group.logger}",
                    group.count,
                    "High-volume repeated errors hide real problems and add disk I/O. Fix the cause or "
                    "lower the log level for this logger.",
                    detail=group.message[:200],
                    rule="noisy-logger",
                )
            )

    if requests is not None and requests.completed:
        rate = requests.errors_5xx / requests.completed
        if requests.errors_5xx:
            worst = sorted(
                ((name, s.errors_5xx) for name, s in requests.paths.items() if s.errors_5xx),
                key=lambda item: -item[1],
            )[:5]
            findings.append(
                _finding(
                    "high" if rate >= 0.01 else "medium",
                    f"HTTP 5xx responses ({rate:.2%} of requests)",
                    requests.errors_5xx,
                    "Correlate the timestamps with error.log entries (uncaught exceptions, timeouts) to "
                    "find the failing component or dependency.",
                    examples=[f"{count}x {name}" for name, count in worst],
                    rule="http-5xx",
                )
            )
        slow = requests.slow_count
        if slow:
            share = slow / requests.completed
            worst_paths = sorted(
                requests.paths.items(), key=lambda item: -sum(d >= requests.slow_ms for d in item[1].durations)
            )[:5]
            findings.append(
                _finding(
                    "high" if share >= 0.05 else "medium",
                    f"Slow requests over {requests.slow_ms} ms ({share:.2%} of requests)",
                    slow,
                    "Check Dispatcher/CDN cache-ability for these paths, slow queries (see Oak traversal "
                    "findings) and downstream calls. Take thread dumps while requests are slow.",
                    examples=[
                        f"{sum(d >= requests.slow_ms for d in s.durations)}x {name}"
                        for name, s in worst_paths
                        if any(d >= requests.slow_ms for d in s.durations)
                    ],
                    rule="slow-requests",
                )
            )
    if requests is not None and requests.incomplete:
        findings.append(
            _finding(
                "low",
                "Requests without a logged response",
                len(requests.incomplete),
                "These may have been in flight when the log rotated, or stuck. If they cluster in time, "
                "take a series of thread dumps to look for blocked request threads.",
                examples=[f"{r.start:%H:%M:%S} {r.method} {r.url}" for r in requests.incomplete[:5]],
                rule="incomplete-requests",
            )
        )

    findings.sort(key=lambda f: (-SEVERITY_ORDER[f["severity"]], -f["count"]))
    return findings


def build_report(
    sources: List[Dict[str, str]],
    errors: Optional[ErrorLogStats],
    requests: Optional[RequestLogStats],
    top: int = 10,
) -> Dict[str, Any]:
    return {
        "tool": {"name": "aem-log-analyzer", "version": __version__},
        "generated_at": datetime.now().isoformat(sep=" ", timespec="seconds"),
        "sources": sources,
        "findings": build_findings(errors, requests),
        "error_log": errors.to_dict(top) if errors is not None else None,
        "request_log": requests.to_dict() if requests is not None else None,
    }

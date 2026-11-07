"""Streaming parsers for AEM ``error.log`` and ``request.log`` files.

Supported formats:

* AEM 6.x / AMS error.log::

    06.11.2026 10:15:32.123 *ERROR* [qtp123-45] com.example.Logger Message

* AEM as a Cloud Service error.log (pod name before the level)::

    06.11.2026 10:15:32.123 [cm-p1-e2-aem-author-abc] *ERROR* [qtp123-45] com.example.Logger Message

* request.log (optionally with a trailing ``[pod]`` on AEMaaCS)::

    06/Nov/2026:10:15:32 +0000 [42] -> GET /content/site/en.html HTTP/1.1
    06/Nov/2026:10:15:32 +0000 [42] <- 200 text/html 123ms
"""

from __future__ import annotations

import gzip
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, TextIO, Tuple, Union

MAX_STACK_LINES = 200

ERROR_HEADER = re.compile(
    r"^(?P<ts>\d{2}\.\d{2}\.\d{4} \d{2}:\d{2}:\d{2}\.\d{3})"
    r"(?: \[(?P<pod>[^\]\s]+)\])?"
    r" \*(?P<level>[A-Z]+)\* (?P<rest>.*)$"
)
REQUEST_LINE = re.compile(
    r"^(?P<ts>\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}) \[(?P<id>\d+)\] "
    r"(?P<dir>->|<-) (?P<body>.*?)(?: \[(?P<pod>[^\]\s]+)\])?\s*$"
)
REQUEST_START = re.compile(r"^(?P<method>[A-Z]+) (?P<url>\S+)(?: (?P<protocol>\S+))?$")
REQUEST_END = re.compile(r"^(?P<status>\d{3}) (?:(?P<ctype>.*?) )?(?P<ms>\d+)ms$")

_MONTHS = {
    name: index
    for index, name in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1
    )
}

PathLike = Union[str, Path]


@dataclass
class LogEntry:
    """One logical error.log entry, including any stack-trace continuation lines."""

    timestamp: datetime
    level: str
    thread: str
    logger: str
    message: str
    pod: Optional[str] = None
    line_no: int = 0
    stack: List[str] = field(default_factory=list)

    def text(self, max_stack: int = 30) -> str:
        return "\n".join([self.message, *self.stack[:max_stack]])


@dataclass
class Request:
    """A request.log request, paired with its response when one was logged."""

    request_id: int
    method: str
    url: str
    protocol: Optional[str]
    start: datetime
    pod: Optional[str] = None
    status: Optional[int] = None
    content_type: Optional[str] = None
    duration_ms: Optional[int] = None

    @property
    def completed(self) -> bool:
        return self.status is not None


def open_log(path: PathLike) -> TextIO:
    """Open a plain or gzip-compressed log file as text."""
    p = Path(path)
    if p.suffix == ".gz":
        return gzip.open(p, "rt", encoding="utf-8", errors="replace")
    return open(p, encoding="utf-8", errors="replace")


def detect_log_type(path: PathLike, max_lines: int = 200) -> Optional[str]:
    """Return ``"error"``, ``"request"`` or ``None`` by sniffing the first lines."""
    with open_log(path) as fh:
        for index, raw in enumerate(fh):
            if index >= max_lines:
                break
            line = raw.rstrip("\r\n")
            if ERROR_HEADER.match(line):
                return "error"
            if REQUEST_LINE.match(line):
                return "request"
    return None


def _split_thread(rest: str) -> Tuple[str, str]:
    """Split ``[thread] logger message`` where the thread may contain nested brackets."""
    if not rest.startswith("["):
        return "", rest
    depth = 0
    for index, char in enumerate(rest):
        if char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0:
                return rest[1:index], rest[index + 1 :].lstrip()
    return "", rest


def parse_error_log(lines: Iterable[str]) -> Iterator[LogEntry]:
    """Yield :class:`LogEntry` objects, attaching stack-trace lines to their entry."""
    current: Optional[LogEntry] = None
    for line_no, raw in enumerate(lines, 1):
        line = raw.rstrip("\r\n")
        match = ERROR_HEADER.match(line)
        if match:
            if current is not None:
                yield current
            thread, remainder = _split_thread(match["rest"])
            logger, _, message = remainder.partition(" ")
            current = LogEntry(
                timestamp=datetime.strptime(match["ts"], "%d.%m.%Y %H:%M:%S.%f"),
                level=match["level"],
                thread=thread,
                logger=logger,
                message=message,
                pod=match["pod"],
                line_no=line_no,
            )
        elif current is not None and line.strip() and len(current.stack) < MAX_STACK_LINES:
            current.stack.append(line)
    if current is not None:
        yield current


def _parse_request_ts(value: str) -> datetime:
    month = _MONTHS.get(value[3:6].title())
    if month is None:
        raise ValueError(f"unknown month in timestamp: {value}")
    return datetime.strptime(f"{value[:3]}{month:02d}{value[6:]}", "%d/%m/%Y:%H:%M:%S %z")


def parse_request_log(lines: Iterable[str]) -> Iterator[Request]:
    """Yield requests as their responses arrive, then any requests that never completed."""
    pending: Dict[Tuple[Optional[str], int], Request] = {}
    for raw in lines:
        match = REQUEST_LINE.match(raw.rstrip("\r\n"))
        if not match:
            continue
        key = (match["pod"], int(match["id"]))
        try:
            timestamp = _parse_request_ts(match["ts"])
        except ValueError:
            continue
        if match["dir"] == "->":
            start = REQUEST_START.match(match["body"])
            if not start:
                continue
            if key in pending:
                # Request ids restart after an instance restart; flush the stale one.
                yield pending.pop(key)
            pending[key] = Request(
                request_id=key[1],
                method=start["method"],
                url=start["url"],
                protocol=start["protocol"],
                start=timestamp,
                pod=match["pod"],
            )
        else:
            end = REQUEST_END.match(match["body"])
            request = pending.pop(key, None)
            if end is None or request is None:
                continue
            ctype = end["ctype"]
            request.status = int(end["status"])
            request.content_type = None if ctype in (None, "", "-") else ctype
            request.duration_ms = int(end["ms"])
            yield request
    yield from pending.values()

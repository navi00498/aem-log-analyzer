"""Command-line interface for aem-log-analyzer."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from . import __version__
from .analyzer import ErrorLogStats, RequestLogStats, build_report
from .parsers import detect_log_type, open_log, parse_error_log, parse_request_log
from .report import render
from .rules import SEVERITIES, SEVERITY_ORDER

FORMAT_BY_SUFFIX = {".html": "html", ".htm": "html", ".json": "json"}


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid int value: {value!r}") from None
    if number < 1:
        raise argparse.ArgumentTypeError(f"must be 1 or greater, got {number}")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aem-log-analyzer",
        description="Triage AEM error.log and request.log files: group errors, detect known issues "
        "and find slow or failing requests.",
    )
    parser.add_argument("files", nargs="+", help="error.log / request.log files (plain or .gz)")
    parser.add_argument(
        "-f", "--format", choices=("text", "json", "html"),
        help="output format (default: inferred from --output extension, otherwise text)",
    )
    parser.add_argument("-o", "--output", help="write the report to this file instead of stdout")
    parser.add_argument(
        "-t", "--type", choices=("auto", "error", "request"), default="auto",
        help="log type for all files (default: auto-detect per file)",
    )
    parser.add_argument("--slow-ms", type=_positive_int, default=1000, help="slow request threshold (default: 1000)")
    parser.add_argument("--top", type=_positive_int, default=10, help="rows per table (default: 10)")
    parser.add_argument(
        "--fail-on", choices=SEVERITIES,
        help="exit with status 1 if any finding has this severity or higher (useful in CI pipelines)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    errors: Optional[ErrorLogStats] = None
    requests: Optional[RequestLogStats] = None
    sources: List[Dict[str, str]] = []

    if args.output:
        out_dir = Path(args.output).parent
        if not out_dir.is_dir():
            parser.error(f"output directory does not exist: {out_dir}")

    for name in args.files:
        path = Path(name)
        if path.is_dir():
            parser.error(f"{name} is a directory; pass the log files inside it (e.g. {name}/error.log*)")
        if not path.is_file():
            parser.error(f"file not found: {name}")
        kind = detect_log_type(path) if args.type == "auto" else args.type
        if kind is None:
            print(f"warning: unrecognized log format, skipping {name} (use --type)", file=sys.stderr)
            continue
        parsed = 0
        with open_log(path) as fh:
            if kind == "error":
                errors = errors if errors is not None else ErrorLogStats()
                for entry in parse_error_log(fh):
                    errors.add(entry)
                    parsed += 1
            else:
                requests = requests if requests is not None else RequestLogStats(args.slow_ms, args.top)
                for request in parse_request_log(fh):
                    requests.add(request)
                    parsed += 1
        if parsed == 0:
            print(f"warning: no {kind}.log entries found in {name}, skipping", file=sys.stderr)
            continue
        sources.append({"path": str(path), "type": kind})

    if not sources:
        print("error: no recognizable AEM log files were given", file=sys.stderr)
        return 2

    report = build_report(sources, errors, requests, top=args.top)
    fmt = args.format
    if fmt is None:
        fmt = FORMAT_BY_SUFFIX.get(Path(args.output).suffix.lower(), "text") if args.output else "text"
    output = render(report, fmt)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"{fmt} report written to {args.output} ({len(report['findings'])} findings)", file=sys.stderr)
    else:
        sys.stdout.write(output)

    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f["severity"]] >= threshold for f in report["findings"]):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

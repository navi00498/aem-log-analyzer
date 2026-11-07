import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from aem_log_analyzer.cli import main

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
LOGS = [str(SAMPLES / "error.log"), str(SAMPLES / "request.log")]


def run(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(args))
    return code, out.getvalue(), err.getvalue()


class CliTest(unittest.TestCase):
    def test_text_report_on_samples(self):
        code, out, _ = run(*LOGS)
        self.assertEqual(code, 0)
        self.assertIn("JVM OutOfMemoryError", out)
        self.assertIn("/content/mysite/us/en/search.html", out)

    def test_json_report_detects_planted_issues(self):
        code, out, _ = run(*LOGS, "--format", "json")
        self.assertEqual(code, 0)
        report = json.loads(out)
        rules = {f["rule"] for f in report["findings"]}
        self.assertTrue({
            "jvm-oom", "oak-traversal", "oak-query-limit", "sling-uncaught", "replication",
            "service-user-mapping", "unclosed-resolver", "downstream-timeout", "osgi-component",
            "oak-commit-conflict", "oak-async-index", "noisy-logger", "http-5xx", "slow-requests",
            "incomplete-requests",
        } <= rules)
        self.assertEqual(report["findings"][0]["severity"], "critical")
        self.assertEqual(report["request_log"]["incomplete"], 3)

    def test_html_output_inferred_from_extension(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp, "report.html")
            code, _, err = run(*LOGS, "-o", str(target))
            self.assertEqual(code, 0)
            self.assertIn("html report written", err)
            html = target.read_text(encoding="utf-8")
            self.assertTrue(html.startswith("<!doctype html>"))
            self.assertIn("Queries that need an index", html)
            self.assertNotIn("<script", html)

    def test_fail_on_threshold(self):
        self.assertEqual(run(*LOGS, "--fail-on", "critical")[0], 1)
        self.assertEqual(run(LOGS[1], "--fail-on", "critical")[0], 0)

    def test_unrecognized_file_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            junk = Path(tmp, "junk.txt")
            junk.write_text("not a log\n", encoding="utf-8")
            code, _, err = run(str(junk))
            self.assertEqual(code, 2)
            self.assertIn("unrecognized log format", err)

    def test_missing_file_exits_with_usage_error(self):
        with self.assertRaises(SystemExit) as ctx:
            run("does-not-exist.log")
        self.assertEqual(ctx.exception.code, 2)


if __name__ == "__main__":
    unittest.main()

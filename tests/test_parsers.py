import gzip
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from aem_log_analyzer.parsers import detect_log_type, open_log, parse_error_log, parse_request_log

ERROR_LOG = """\
06.11.2026 10:15:32.123 *INFO* [main] org.apache.sling.Startup Started
06.11.2026 10:15:33.456 *ERROR* [0:0:0:0:0:0:0:1 [1730888133456] GET /content/site/en.html HTTP/1.1] \
org.apache.sling.engine.impl.SlingRequestProcessorImpl service: Uncaught SlingException
org.apache.sling.api.SlingException: boom
\tat com.example.Model.init(Model.java:10)
Caused by: java.lang.NullPointerException: null
\tat com.example.Model.getName(Model.java:20)

06.11.2026 10:15:34.000 [cm-p123-e456-aem-author-7f9c-abcde] *WARN* [qtp1-2] com.example.Svc Slow call
"""

REQUEST_LOG = """\
06/Nov/2026:10:15:32 +0000 [1] -> GET /content/site/en.html HTTP/1.1
06/Nov/2026:10:15:32 +0000 [2] -> POST /bin/form HTTP/1.1 [cm-p1-e2-aem-publish-abc]
06/Nov/2026:10:15:33 +0000 [1] <- 200 text/html 812ms
06/Nov/2026:10:15:33 +0000 [2] <- 302 - 15ms [cm-p1-e2-aem-publish-abc]
06/Nov/2026:10:15:34 +0000 [3] -> GET /content/site/slow.html HTTP/1.1
"""


class ErrorLogParserTest(unittest.TestCase):
    def setUp(self):
        self.entries = list(parse_error_log(ERROR_LOG.splitlines(True)))

    def test_parses_all_entries(self):
        self.assertEqual([e.level for e in self.entries], ["INFO", "ERROR", "WARN"])

    def test_nested_brackets_in_thread_name(self):
        entry = self.entries[1]
        self.assertEqual(entry.thread, "0:0:0:0:0:0:0:1 [1730888133456] GET /content/site/en.html HTTP/1.1")
        self.assertEqual(entry.logger, "org.apache.sling.engine.impl.SlingRequestProcessorImpl")
        self.assertEqual(entry.message, "service: Uncaught SlingException")

    def test_stack_trace_attached_and_blank_lines_skipped(self):
        stack = self.entries[1].stack
        self.assertEqual(len(stack), 4)
        self.assertTrue(stack[2].startswith("Caused by: java.lang.NullPointerException"))

    def test_cloud_service_pod_name(self):
        entry = self.entries[2]
        self.assertEqual(entry.pod, "cm-p123-e456-aem-author-7f9c-abcde")
        self.assertEqual(entry.timestamp, datetime(2026, 11, 6, 10, 15, 34))
        self.assertEqual(entry.line_no, 8)


class RequestLogParserTest(unittest.TestCase):
    def setUp(self):
        self.requests = list(parse_request_log(REQUEST_LOG.splitlines(True)))

    def test_pairs_requests_and_responses(self):
        by_id = {r.request_id: r for r in self.requests}
        self.assertEqual(by_id[1].status, 200)
        self.assertEqual(by_id[1].duration_ms, 812)
        self.assertEqual(by_id[1].content_type, "text/html")
        self.assertEqual(by_id[2].method, "POST")
        self.assertEqual(by_id[2].pod, "cm-p1-e2-aem-publish-abc")
        self.assertIsNone(by_id[2].content_type)

    def test_unfinished_requests_are_reported(self):
        unfinished = [r for r in self.requests if not r.completed]
        self.assertEqual([r.url for r in unfinished], ["/content/site/slow.html"])

    def test_restarted_request_id_flushes_previous(self):
        lines = [
            "06/Nov/2026:10:00:00 +0000 [1] -> GET /a HTTP/1.1",
            "06/Nov/2026:10:05:00 +0000 [1] -> GET /b HTTP/1.1",
            "06/Nov/2026:10:05:01 +0000 [1] <- 200 text/html 5ms",
        ]
        requests = list(parse_request_log(lines))
        self.assertEqual([(r.url, r.status) for r in requests], [("/a", None), ("/b", 200)])


class FileHandlingTest(unittest.TestCase):
    def test_detects_types_and_reads_gzip(self):
        with tempfile.TemporaryDirectory() as tmp:
            error = Path(tmp, "error.log.gz")
            with gzip.open(error, "wt", encoding="utf-8") as fh:
                fh.write(ERROR_LOG)
            request = Path(tmp, "request.log")
            request.write_text(REQUEST_LOG, encoding="utf-8")
            other = Path(tmp, "notes.txt")
            other.write_text("hello\n", encoding="utf-8")

            self.assertEqual(detect_log_type(error), "error")
            self.assertEqual(detect_log_type(request), "request")
            self.assertIsNone(detect_log_type(other))
            with open_log(error) as fh:
                self.assertEqual(len(list(parse_error_log(fh))), 3)


if __name__ == "__main__":
    unittest.main()

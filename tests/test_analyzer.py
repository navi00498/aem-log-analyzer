import unittest
from datetime import datetime, timezone

from aem_log_analyzer.analyzer import (
    ErrorLogStats,
    RequestLogStats,
    build_findings,
    exception_chain,
    normalize_message,
    normalize_url,
    percentile,
)
from aem_log_analyzer.parsers import LogEntry, Request
from aem_log_analyzer.rules import match_rule


def entry(level, logger, message, stack=(), minute=0):
    return LogEntry(datetime(2026, 11, 6, 10, minute), level, "t", logger, message, stack=list(stack))


def request(rid, url, status, ms):
    return Request(rid, "GET", url, "HTTP/1.1", datetime(2026, 11, 6, 10, tzinfo=timezone.utc),
                   status=status, duration_ms=ms)


class NormalizationTest(unittest.TestCase):
    def test_similar_messages_share_a_signature(self):
        a = normalize_message("Failed to load /content/site/en/page-1 after 300 ms (id 3f2a9c1d-0b1e-4c2f-9a7d-1234567890ab)")
        b = normalize_message("Failed to load /content/other/fr after 12 ms (id 00000000-1111-2222-3333-444444444444)")
        self.assertEqual(a, b)

    def test_normalize_url(self):
        self.assertEqual(normalize_url("/api/orders/12345/items?x=1"), "/api/orders/{id}/items")
        self.assertEqual(normalize_url("/content/site/en.html#top"), "/content/site/en.html")

    def test_percentile_nearest_rank(self):
        values = list(range(1, 101))
        self.assertEqual(percentile(values, 50), 50)
        self.assertEqual(percentile(values, 99), 99)
        self.assertEqual(percentile(values, 100), 100)
        self.assertIsNone(percentile([], 50))

    def test_exception_chain(self):
        e = entry("ERROR", "x", "boom", [
            "org.apache.sling.api.SlingException: wrapped",
            "\tat com.example.A.b(A.java:1)",
            "Caused by: java.lang.IllegalStateException: inner",
            "Caused by: java.lang.NullPointerException",
        ])
        self.assertEqual(exception_chain(e), [
            "org.apache.sling.api.SlingException",
            "java.lang.IllegalStateException",
            "java.lang.NullPointerException",
        ])


class RuleTest(unittest.TestCase):
    def test_rule_matching(self):
        cases = {
            "jvm-oom": ("ERROR", "Uncaught Throwable\njava.lang.OutOfMemoryError: Java heap space"),
            "oak-traversal": ("WARN", "Traversed 10000 nodes with filter Filter(query=SELECT * FROM [nt:base])"),
            "service-user-mapping": ("ERROR", "LoginException: Cannot derive user name for bundle x [1] and sub service y"),
            "sling-uncaught": ("ERROR", "service: Uncaught SlingException"),
            "downstream-timeout": ("ERROR", "java.net.SocketTimeoutException: Read timed out"),
        }
        for rule_id, (level, text) in cases.items():
            with self.subTest(rule_id):
                self.assertEqual(match_rule(level, text).id, rule_id)

    def test_info_entries_only_match_level_agnostic_rules(self):
        self.assertIsNone(match_rule("INFO", "Traversed 10000 nodes"))
        self.assertEqual(match_rule("INFO", "java.lang.OutOfMemoryError").id, "jvm-oom")


class ErrorStatsTest(unittest.TestCase):
    def test_traversal_queries_group_by_normalized_query(self):
        stats = ErrorLogStats()
        for author in ("alice", "bob", "carol"):
            stats.add(entry("WARN", "org.apache.jackrabbit.oak.plugins.index.Cursors$TraversingCursor",
                            f"Traversed 10000 nodes with filter Filter(query=SELECT * FROM [cq:Page] "
                            f"WHERE [author] = '{author}', path=/content//*)"))
        stats.add(entry("INFO", "x", "ignored"))
        report = stats.to_dict(top=10)
        self.assertEqual(report["entries"], 4)
        self.assertEqual(len(report["top_errors"]), 1)
        self.assertEqual(report["top_errors"][0]["count"], 3)
        self.assertEqual(report["traversal_queries"], [["SELECT * FROM [cq:Page] WHERE [author] = '?'", 3]])

    def test_noisy_logger_finding(self):
        stats = ErrorLogStats()
        for n in range(120):
            stats.add(entry("ERROR", "com.example.Noisy", f"Missing key {n}"))
        findings = build_findings(stats, None)
        self.assertEqual([f["rule"] for f in findings], ["noisy-logger"])
        self.assertEqual(findings[0]["count"], 120)


class RequestStatsTest(unittest.TestCase):
    def test_latency_and_findings(self):
        stats = RequestLogStats(slow_ms=1000, top=3)
        for i in range(95):
            stats.add(request(i, "/content/fast.html", 200, 50))
        for i in range(95, 100):
            stats.add(request(i, "/content/slow.html", 500, 5000))
        data = stats.to_dict()
        self.assertEqual(data["latency_ms"]["p50"], 50)
        self.assertEqual(data["latency_ms"]["max"], 5000)
        self.assertEqual(data["errors_5xx"], 5)
        self.assertEqual(data["slowest_paths"][0]["path"], "/content/slow.html")
        self.assertEqual(len(data["slowest_requests"]), 3)

        findings = {f["rule"]: f for f in build_findings(None, stats)}
        self.assertEqual(findings["http-5xx"]["severity"], "high")
        self.assertEqual(findings["slow-requests"]["severity"], "high")
        self.assertEqual(findings["slow-requests"]["count"], 5)


if __name__ == "__main__":
    unittest.main()

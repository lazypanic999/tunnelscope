"""Evidence and budget checks for adaptive size search."""

import unittest
from unittest.mock import patch

import tunnelscope
from tunnelscope_search import assess_search
from tunnelscope_view import render_report_html


def row(size, **counts):
    return {"payload_bytes": size, "status_counts": {
        name: counts.get(name, 0)
        for name in ("acknowledged", "packet_too_large", "timeout", "socket_error")
    }}


class SearchTests(unittest.TestCase):
    def test_adjacent_explicit_bounds(self):
        rows = [row(1200, acknowledged=2), row(1300, packet_too_large=2)]
        next_size, summary = assess_search(1200, 1300, rows, 12)
        self.assertEqual(next_size, 1250)
        rows.append(row(1250, acknowledged=2))
        next_size, summary = assess_search(1200, 1300, rows, 12)
        self.assertEqual(next_size, 1275)
        rows.extend([row(1275, packet_too_large=2), row(1249, packet_too_large=2)])
        # A later result below an acknowledged size is contradictory evidence.
        next_size, summary = assess_search(1200, 1300, rows, 12)
        self.assertIsNone(next_size)
        self.assertEqual(summary["assessment"], "inconclusive")

    def test_timeout_and_mixed_results_stop_search(self):
        for uncertain in (row(1300, timeout=2), row(1300, acknowledged=1, timeout=1)):
            next_size, summary = assess_search(1200, 1300, [row(1200, acknowledged=2), uncertain], 12)
            self.assertIsNone(next_size)
            self.assertEqual(summary["assessment"], "inconclusive")
            self.assertEqual(summary["ambiguous_payload_sizes"], [1300])
            self.assertIsNone(summary["observed_interval_payload_bytes"])

    def test_budget_and_terminal_interval(self):
        rows = [row(1200, acknowledged=1), row(1300, packet_too_large=1)]
        self.assertEqual(assess_search(1200, 1300, rows, 2)[1]["assessment"], "budget_limited_interval")
        next_size, summary = assess_search(1252, 1253,
                                           [row(1252, acknowledged=1), row(1253, packet_too_large=1)], 12)
        self.assertIsNone(next_size)
        self.assertEqual(summary["assessment"], "adjacent_observed_bounds")
        self.assertEqual(summary["observed_interval_payload_bytes"], [1252, 1253])

    def test_missing_bracket_and_all_timeout(self):
        for rows in (
            [row(1200, acknowledged=1), row(1300, acknowledged=1)],
            [row(1200, packet_too_large=1), row(1300, packet_too_large=1)],
        ):
            self.assertEqual(assess_search(1200, 1300, rows, 12)[1]["assessment"], "no_explicit_bracket")
        summary = assess_search(1200, 1300,
                                [row(1200, timeout=1), row(1300, timeout=1)], 12)[1]
        self.assertEqual(summary["assessment"], "inconclusive")

    def test_invalid_budget_rejected_before_socket(self):
        with patch.object(tunnelscope.sys, "platform", "linux"):
            with self.assertRaisesRegex(ValueError, "budget exceeds"):
                tunnelscope.probe("127.0.0.1", 9471, None, 10, 5, True,
                                  search_bounds=(1200, 1300), max_sizes=16)

    def test_search_summary_is_visible_and_html_escaped(self):
        report = {"schema_version": 1, "kind": "probe", "results": [],
                  "summary": {"by_payload_size": [], "search": {
                      "assessment": "<script>alert(1)</script>",
                      "observed_interval_payload_bytes": [1252, 1253],
                      "largest_acknowledged_payload_bytes": 1252,
                      "smallest_packet_too_large_payload_bytes": 1253,
                      "tested_payload_sizes": [1252, 1253], "max_tested_sizes": 12,
                  }}}
        self.assertIn("1252..1253 UDP payload bytes", tunnelscope.format_report(report))
        html = render_report_html(report)
        self.assertIn("Size search evidence", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertNotIn("<script>alert(1)</script>", html)


if __name__ == "__main__":
    unittest.main()

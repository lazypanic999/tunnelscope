"""Checks for the HTML report table layout."""

import json
from pathlib import Path
import re
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tunnelscope_core.view import render_report_html

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "asymmetric-return-v07.json"


def header_cells(html):
    head = re.search(r"<thead><tr>(.*?)</tr></thead>", html, re.S).group(1)
    return re.findall(r"<th scope='col'>(.*?)</th>", head)


class ReportTableTests(unittest.TestCase):
    def setUp(self):
        self.correlation = json.loads(EXAMPLE.read_text(encoding="utf-8"))["correlation"]
        self.html = render_report_html(self.correlation)

    def test_every_example_row_has_one_cell_per_header(self):
        from tunnelscope_core.tables import report_table
        for path in sorted(EXAMPLE.parent.glob("*.json")):
            with self.subTest(example=path.name):
                report = json.loads(path.read_text(encoding="utf-8"))
                try:
                    _, headers, rows, _ = report_table(report)
                except ValueError:
                    continue  # not a table-backed report
                self.assertTrue(all(len(row) == len(headers) for row in rows),
                                f"{path.name}: {len(headers)} headers, row widths {sorted({len(r) for r in rows})}")

    def test_theme_supports_light_and_dark_and_colours_known_statuses_only(self):
        self.assertIn("color-scheme: light dark", self.html)
        self.assertIn("@media (prefers-color-scheme: dark)", self.html)
        self.assertIn("@media print", self.html)
        # Status colours are applied by script from exact cell text; the markup stays plain.
        self.assertIn("'receiver_reply_send_failed'", self.html)
        self.assertNotIn("class='s-", self.html)
        self.assertIn("<td>receiver_reply_send_failed</td>", self.html)

    def test_evidence_columns_come_before_identifiers_and_times(self):
        headers = header_cells(self.html)
        self.assertEqual(headers[:5], ["Bytes", "Sender status", "Receiver saw", "Evidence case", "Return evidence"])
        self.assertLess(headers.index("Return evidence"), headers.index("Probe ID"))
        self.assertEqual(headers[-3:], ["Send attempted (UTC)", "Receiver received (UTC)",
                                        "Sender ACK received (UTC)"])

    def test_long_values_are_shortened_but_kept_in_full(self):
        row = self.correlation["results"][0]
        probe_id, sent = row["probe_id"], row["send_attempted_at_utc"]
        self.assertIn(f"<td title='{probe_id}'>{probe_id[:8]}…</td>", self.html)
        time_of_day = sent.split("T")[1][:12]
        self.assertIn(f"<td title='{sent}'>{time_of_day}</td>", self.html)
        # The filter searches data-search, which holds the full values.
        self.assertRegex(self.html, rf"<tr data-search='[^']*{probe_id}[^']*{re.escape(sent)}")
        self.assertIn("row.dataset.search", self.html)
        # Values without a short form render unchanged.
        self.assertIn("<td>receiver_observed_sized_reply_missing</td>", self.html)

    def test_timestamp_cells_normalize_offsets_and_keep_full_search_values(self):
        for original, expected in (
                ("2026-11-08T03:04:05+03:00", "00:04:05"),
                ("2026-11-08T23:45:00-04:30", "04:15:00"),
                ("2026-11-08T00:01:02.1Z", "00:01:02.100"),
                ("2026-11-08T00:01:02.123456Z", "00:01:02.123")):
            with self.subTest(timestamp=original):
                self.correlation["results"][0]["send_attempted_at_utc"] = original
                html = render_report_html(self.correlation)
                self.assertTrue(f"<td title='{original}'>{expected}</td>" in html,
                                f"Expected UTC cell {expected} for {original}")
                self.assertRegex(html, rf"<tr data-search='[^']*{re.escape(original)}")

    def test_invalid_timestamp_is_displayed_in_full(self):
        original = "2026-99-08T03:04:05+03:00"
        self.correlation["results"][0]["send_attempted_at_utc"] = original
        self.assertTrue(f"<td>{original}</td>" in render_report_html(self.correlation))

    def test_shortened_values_are_escaped(self):
        report = json.loads(json.dumps(self.correlation))
        report["results"][0]["direction"] = "<b>x</b>"
        html = render_report_html(report)
        self.assertNotIn("<b>x</b>", html.split("<details>")[0])
        self.assertIn("&lt;b&gt;x&lt;/b&gt;", html)

    def test_non_utf8_os_names_stay_representable_in_html(self):
        report = json.loads(json.dumps(self.correlation))
        report["results"][0]["direction"] = "tunnel-\udcff"
        html = render_report_html(report)
        html.encode("utf-8")
        self.assertTrue("tunnel-\\udcff" in html)

    def test_lab_cases_show_both_feedback_conditions(self):
        report = json.loads((EXAMPLE.parent / "ipv6-routed-feedback.json").read_text(encoding="utf-8"))
        html = render_report_html(report)
        self.assertEqual(header_cells(html), ["Case", "Bytes", "Status", "Receiver saw"])
        self.assertEqual(html.count("<td>blocked</td>"), 4)
        self.assertEqual(html.count("<td>visible</td>"), 4)
        self.assertEqual(html.count("<td>timeout</td>"), 2)
        report["cases"]["visible"] = []
        with self.assertRaisesRegex(ValueError, "invalid case results"):
            render_report_html(report)

    def test_receiver_capture_card(self):
        receiver = json.loads((EXAMPLE.parent / "receiver-v06.json").read_text(encoding="utf-8"))
        html = render_report_html(receiver)
        self.assertIn("<h2>Receiver capture</h2>", html)
        self.assertIn("<strong>Exit reason:</strong> idle_timeout", html)
        self.assertIn("<strong>Listening on:</strong> 198.51.100.2:9471", html)
        self.assertIn("<strong>Sized replies:</strong> off", html)
        self.assertNotIn("Reply fragmentation", html)
        receiver["receiver"] = {"bind_ipv6": "fd00::2", "port": 9471, "sized_reply": True,
                                "reply_fragmentation": "disabled: Linux IPV6_DONTFRAG"}
        html = render_report_html(receiver)
        self.assertIn("<strong>Listening on:</strong> [fd00::2]:9471", html)
        self.assertIn("<strong>Reply fragmentation:</strong> disabled: Linux IPV6_DONTFRAG", html)
        receiver["receiver"] = {"bind_ipv4": "<b>x</b>", "port": True}
        html = render_report_html(receiver)
        self.assertIn("<strong>Listening on:</strong> —", html)
        self.assertNotIn("<b>x</b>", html.split("<details>")[0])

    def test_diagnosis_join_without_sized_replies_keeps_alignment(self):
        from tunnelscope_core.view import _table_data
        result = dict(self.correlation["results"][0])
        result.pop("return_evidence")
        correlation = {"results": [result]}
        diagnosis = {"kind": "diagnosis", "receiver_evidence": {"correlations": {
            "df": correlation, "fragmentation_permitted": correlation, "size_search": correlation}}}
        headers, rows = _table_data(diagnosis)
        self.assertNotIn("Return evidence", headers)
        self.assertEqual(len(headers), len(rows[0]))
        self.assertEqual(rows[0][headers.index("Evidence case")], result["evidence_case"])
        self.assertEqual(rows[0][headers.index("Probe ID")], result["probe_id"])


if __name__ == "__main__":
    unittest.main()

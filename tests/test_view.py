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

    def test_shortened_values_are_escaped(self):
        report = json.loads(json.dumps(self.correlation))
        report["results"][0]["direction"] = "<b>x</b>"
        html = render_report_html(report)
        self.assertNotIn("<b>x</b>", html.split("<details>")[0])
        self.assertIn("&lt;b&gt;x&lt;/b&gt;", html)

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

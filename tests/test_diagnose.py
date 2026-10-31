"""Focused checks for the bounded diagnosis workflow."""

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import tunnelscope
from tunnelscope_core.diagnose import build_diagnosis, diagnose
from tunnelscope_core.view import render_report_html


class DiagnoseTests(unittest.TestCase):
    def test_budget_rejected_before_network_runs(self):
        with patch("tunnelscope_core.diagnose.compare_fragmentation") as compare, patch("tunnelscope_core.diagnose.require_df_support"), patch("tunnelscope_core.diagnose.require_icmp_support"):
            with self.assertRaisesRegex(ValueError, "budget"):
                diagnose("192.0.2.2", 9471, 1200, 1400, count=10, timeout=5, max_sizes=16)
            compare.assert_not_called()

    def test_windows_rejected_before_network_runs(self):
        with patch("tunnelscope_core.network.sys.platform", "win32"), patch("tunnelscope_core.diagnose.compare_fragmentation") as compare:
            with self.assertRaisesRegex(ValueError, "requires Linux"):
                diagnose("127.0.0.1", 9471, 1200, 1400)
            compare.assert_not_called()

    def test_report_contains_three_distinct_runs_and_escapes_html(self):
        target = {"ipv4": "192.0.2.2", "port": 9471}
        source = {"ipv4": "192.0.2.1", "interface": "ts-a"}
        def run(status, size):
            return {"kind": "probe", "target": target, "source": source,
                    "settings": {"count": 1, "timeout_seconds": 1},
                    "summary": {"icmp_feedback": {"size_feedback_events": 0}},
                    "results": [{"payload_bytes": size, "status": status}]}
        df = run("acknowledged", 1200)
        permitted = run("acknowledged", 1200)
        comparison = {"schema_version": 1, "kind": "fragmentation_comparison", "target": target,
                      "settings": {"payload_sizes": [1200], "count_per_mode": 1},
                      "source_check": "matched", "runs": {"df": df, "fragmentation_permitted": permitted},
                      "comparison": {"by_payload_size": [{"payload_bytes": 1200,
                                   "df": {"assessment": "delivery_observed"},
                                   "fragmentation_permitted": {"assessment": "delivery_observed"}}]}}
        search = run("packet_too_large", 1201)
        search["summary"]["search"] = {"assessment": "adjacent_observed_bounds",
                                         "observed_interval_payload_bytes": [1200, 1201]}
        report = build_diagnosis(comparison, search)
        self.assertEqual(report["summary"]["attempts"], 3)
        self.assertEqual(report["settings"]["count_per_size_per_run"], 1)
        self.assertEqual(report["consistency"]["search_target_check"], "matched")
        self.assertIn("single sender direction", tunnelscope.format_report(report))
        report["target"]["hostname"] = "<script>alert(1)</script>"
        html = render_report_html(report)
        self.assertIn("Size search evidence", html)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertEqual(json.loads(json.dumps(report))["kind"], "diagnosis")

    def test_existing_output_is_rejected_before_probe(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "diagnosis.json"
            output.write_text("keep", encoding="utf-8")
            argv = ["tunnelscope.py", "diagnose", "192.0.2.2", "--min", "1200",
                    "--max", "1400", "--output", str(output)]
            with patch.object(sys, "argv", argv), patch.object(tunnelscope, "diagnose") as run:
                with self.assertRaises(SystemExit) as stopped:
                    tunnelscope.main()
                self.assertEqual(stopped.exception.code, 1)
                run.assert_not_called()
            self.assertEqual(output.read_text(encoding="utf-8"), "keep")


if __name__ == "__main__":
    unittest.main()

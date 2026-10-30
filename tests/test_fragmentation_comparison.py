"""Repeated observations and conservative fragmentation comparison."""

import json
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

import tunnelscope
from tunnelscope_core.fragmentation import compare_fragmentation_reports
from tunnelscope_core.reports import no_ack_measurement
from tunnelscope_view import render_report_html


def report(df, statuses):
    results = [{"payload_bytes": 1400, "status": status} for status in statuses]
    return {
        "schema_version": 1, "kind": "probe", "source": {"ipv4": "192.0.2.1", "interface": "ts-a"},
        "target": {"host": "192.0.2.2", "ipv4": "192.0.2.2", "port": 9471},
        "settings": {"payload_sizes": [1400], "count": len(statuses),
                     "timeout_seconds": 1, "dont_fragment": df},
        "fragmentation_mode": "df" if df else "permitted",
        "summary": {"by_payload_size": tunnelscope.summarize_results([1400], results)},
        "results": results,
    }


class FragmentationComparisonTests(unittest.TestCase):
    def test_no_ack_rate_and_wilson_interval_are_separate_from_errors(self):
        counts = {"acknowledged": 3, "timeout": 7, "packet_too_large": 2, "socket_error": 1}
        measurement = no_ack_measurement(counts)
        self.assertEqual(measurement["sent_attempts"], 10)
        self.assertEqual(measurement["no_ack_count"], 7)
        self.assertEqual(measurement["no_ack_rate"], 0.7)
        self.assertEqual(measurement["no_ack_wilson_95"], [0.3968, 0.8922])
        self.assertEqual(no_ack_measurement({"packet_too_large": 3})["no_ack_rate"], None)
        rows = tunnelscope.summarize_results([1400], [{"payload_bytes": 1400, "status": s}
                                                        for s in ["acknowledged"] * 3 + ["timeout"] * 7])
        self.assertEqual(rows[0]["assessment"], "mixed_observations")
        self.assertEqual(rows[0]["no_ack_measurement"]["no_ack_rate"], 0.7)
        probe = report(True, ["acknowledged"] * 3 + ["timeout"] * 7)
        self.assertIn("7/10 (70%; 95% 40%-89%)", tunnelscope.format_report(probe))
        html = render_report_html(probe)
        self.assertIn("Repeated measurements", html)
        self.assertIn("7/10 (70%; 95% 40%-89%)", html)

    def test_comparison_preserves_both_runs_and_renders(self):
        df = report(True, ["packet_too_large"] * 3)
        allowed = report(False, ["acknowledged"] * 3)
        comparison = compare_fragmentation_reports(df, allowed)
        row = comparison["comparison"]["by_payload_size"][0]
        self.assertTrue(row["outcomes_differ"])
        self.assertEqual(row["df"]["assessment"], "kernel_rejected_df_payload")
        self.assertEqual(row["fragmentation_permitted"]["assessment"], "delivery_observed")
        self.assertIsNone(row["df"]["no_ack_measurement"]["no_ack_rate"])
        self.assertEqual(comparison["source_check"], "matched")
        self.assertIn("fragmentation was permitted", tunnelscope.format_report(comparison))
        html = render_report_html(comparison)
        self.assertIn("Fragmentation modes", html)
        self.assertIn("kernel_rejected_df_payload", html)
        self.assertIn("Raw JSON evidence", html)
        self.assertEqual(json.loads(json.dumps(comparison))["schema_version"], 1)

    def test_changed_source_snapshot_is_flagged(self):
        df, allowed = report(True, ["timeout"]), report(False, ["acknowledged"])
        allowed["source"]["interface"] = "unexpected"
        comparison = compare_fragmentation_reports(df, allowed)
        self.assertEqual(comparison["source_check"], "changed")
        df["source"] = None
        self.assertEqual(compare_fragmentation_reports(df, allowed)["source_check"], "unavailable")

    def test_incompatible_runs_rejected(self):
        df, allowed = report(True, ["timeout"]), report(False, ["acknowledged"])
        allowed["target"]["port"] = 9472
        with self.assertRaisesRegex(ValueError, "different targets"):
            compare_fragmentation_reports(df, allowed)
        allowed = report(False, ["acknowledged"])
        allowed["fragmentation_mode"] = "os_default"
        with self.assertRaisesRegex(ValueError, "explicitly permit"):
            compare_fragmentation_reports(df, allowed)

    def test_linux_socket_options_and_budget(self):
        sock = Mock()
        sock.family = socket.AF_INET
        tunnelscope.configure_fragmentation(sock, False, True)
        sock.setsockopt.assert_called_once_with(socket.IPPROTO_IP, tunnelscope.IP_MTU_DISCOVER,
                                                 tunnelscope.IP_PMTUDISC_DONT)
        sock = Mock()
        sock.family = socket.AF_INET6
        tunnelscope.configure_fragmentation(sock, False, True)
        sock.setsockopt.assert_called_once_with(socket.IPPROTO_IPV6, tunnelscope.IPV6_DONTFRAG, 0)
        with patch.object(tunnelscope.sys, "platform", "linux"):
            with self.assertRaisesRegex(ValueError, "budget exceeds"):
                tunnelscope.compare_fragmentation("127.0.0.1", 9471, list(range(64, 80)), 10, 1)
        with patch.object(tunnelscope.sys, "platform", "win32"):
            with self.assertRaisesRegex(ValueError, "requires Linux"):
                tunnelscope.compare_fragmentation("127.0.0.1", 9471, [64], 1, 1)

    def test_cli_help_exposes_comparison(self):
        process = subprocess.run([sys.executable, str(Path(tunnelscope.__file__)),
                                  "compare-fragmentation", "--help"],
                                 capture_output=True, text=True, timeout=5)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertIn("--count", process.stdout)
        self.assertIn("--sweep", process.stdout)


if __name__ == "__main__":
    unittest.main()

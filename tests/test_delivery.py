import base64
import json
import re
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import tunnelscope
import tunnelscope_view


class DeliveryTests(unittest.TestCase):
    def test_cli_reports_version(self):
        result = subprocess.run(
            [sys.executable, str(Path(tunnelscope.__file__)), "--version"],
            capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "TunnelScope 0.4.0")

    @unittest.skipUnless(socket.has_ipv6, "IPv6 unavailable")
    def test_ipv6_receiver_probe_and_correlation(self):
        with tempfile.TemporaryDirectory() as directory:
            receiver_path = Path(directory) / "receiver.json"
            process = subprocess.Popen(
                [sys.executable, str(Path(tunnelscope.__file__)), "receive", "--bind", "::1",
                 "--port", "0", "--max-packets", "2", "--idle-timeout", "3",
                 "--output", str(receiver_path)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            try:
                port = int(process.stdout.readline().strip().rsplit(":", 1)[1])
                report = tunnelscope.probe("::1", port, [64, 1200], 1, 1)
                self.assertEqual([row["status"] for row in report["results"]], ["acknowledged"] * 2)
                self.assertEqual(report["source"]["ipv6"], "::1")
                self.assertEqual(report["target"]["ipv6"], "::1")
                self.assertEqual(process.wait(timeout=4), 0)
                receiver = json.loads(receiver_path.read_text(encoding="utf-8"))
                self.assertEqual(receiver["receiver"]["bind_ipv6"], "::1")
                self.assertEqual([row["source_ipv6"] for row in receiver["observations"]], ["::1"] * 2)
                correlation = tunnelscope.correlate_reports(report, receiver)
                self.assertEqual(correlation["summary"]["receiver_observed"], 2)
                self.assertTrue(correlation["pairing"]["endpoint_checks"]["target_ipv6_matches_receiver_bind"])
                combined = tunnelscope.combine_reports(report, report)
                self.assertEqual(combined["endpoint_check"], "reversed_ipv6_match")
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                process.stdout.close()
                process.stderr.close()

    def test_real_receiver_acknowledges_requested_sizes(self):
        process = subprocess.Popen(
            [sys.executable, str(Path(tunnelscope.__file__)), "receive", "--port", "0", "--max-packets", "3", "--idle-timeout", "3"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        try:
            port = int(process.stdout.readline().strip().rsplit(":", 1)[1])
            report = tunnelscope.probe("127.0.0.1", port, [32, 1400, 8192], 1, 1)
            self.assertEqual([r["status"] for r in report["results"]], ["acknowledged"] * 3)
            self.assertEqual([r["payload_bytes"] for r in report["results"]], [32, 1400, 8192])
            self.assertEqual(report["source"]["ipv4"], "127.0.0.1")
            self.assertEqual([row["assessment"] for row in report["summary"]["by_payload_size"]], ["delivery_observed"] * 3)
            self.assertEqual(report["evidence"]["hypotheses"], [])
            self.assertIn("controlled_fragmentation_behavior", report["evidence"]["missing_evidence"])
            self.assertEqual(json.loads(json.dumps(report))["schema_version"], 1)
            self.assertEqual(process.wait(timeout=4), 0)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            process.stdout.close()
            process.stderr.close()

    def test_unrelated_ack_is_not_counted_as_delivery(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
            server.bind(("127.0.0.1", 0))
            server.settimeout(3)
            def wrong_reply():
                _, peer = server.recvfrom(8192)
                server.sendto(tunnelscope.HEADER.pack(tunnelscope.ACK, b"x" * 16, 64), peer)
            worker = threading.Thread(target=wrong_reply)
            worker.start()
            try:
                report = tunnelscope.probe("127.0.0.1", server.getsockname()[1], [64], 1, 1)
                self.assertEqual(report["results"][0]["status"], "timeout")
                self.assertEqual(report["summary"]["by_payload_size"][0]["assessment"], "inconclusive")
            finally:
                worker.join(timeout=4)

    def test_probe_cli_rejects_excessive_payload(self):
        result = subprocess.run([sys.executable, str(Path(tunnelscope.__file__)), "probe", "127.0.0.1", "--sizes", "99999"], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertIn("32..8192", result.stderr)

    def test_sweep_cli_expands_bounded_inclusive_sizes(self):
        process = subprocess.Popen(
            [sys.executable, str(Path(tunnelscope.__file__)), "receive", "--port", "0",
             "--max-packets", "3", "--idle-timeout", "3"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        try:
            port = int(process.stdout.readline().strip().rsplit(":", 1)[1])
            result = subprocess.run(
                [sys.executable, str(Path(tunnelscope.__file__)), "probe", "127.0.0.1",
                 "--port", str(port), "--sweep", "64:1400:700", "--count", "1"],
                capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["settings"]["payload_sizes"], [64, 764, 1400])
            self.assertEqual([row["status"] for row in report["results"]], ["acknowledged"] * 3)
            self.assertEqual(process.wait(timeout=4), 0)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            process.stdout.close()
            process.stderr.close()

        for spec in ("1400:64:100", "64:1400:1", "64:1400:0", "bad"):
            invalid = subprocess.run(
                [sys.executable, str(Path(tunnelscope.__file__)), "probe", "127.0.0.1",
                 "--sweep", spec], capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(invalid.returncode, 2, spec)
        exclusive = subprocess.run(
            [sys.executable, str(Path(tunnelscope.__file__)), "probe", "127.0.0.1",
             "--sizes", "64,1400", "--sweep", "64:1400:700"],
            capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(exclusive.returncode, 2)

    def test_html_view_is_searchable_and_escapes_report_content(self):
        report = {"schema_version": 1, "kind": "probe", "results": [
            {"payload_bytes": 64, "attempt": 1, "status": "acknowledged", "rtt_ms": 1.25},
            {"payload_bytes": 1400, "attempt": 1, "status": "socket_error",
             "error": "<script>alert(1)</script>"},
        ]}
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "report.json"
            output_path = Path(directory) / "report.html"
            input_path.write_text(json.dumps(report), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(Path(tunnelscope.__file__)), "html", str(input_path),
                 "--output", str(output_path)], capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            html = output_path.read_text(encoding="utf-8")
        self.assertIn("Filter rows", html)
        self.assertIn("Showing 2 of 2 rows", html)
        self.assertIn("No matching rows.", html)
        self.assertIn("Raw JSON evidence", html)
        self.assertIn("1400", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertNotIn("https://", html)
        logo = re.search(r"url\('data:image/png;base64,([^']+)'\)", html)
        self.assertIsNotNone(logo)
        self.assertEqual(base64.b64decode(logo.group(1)),
                         (Path(tunnelscope_view.__file__).parent / "tunnelscope_assets" /
                          "tunnelscope-logo-blue.png").read_bytes())
        self.assertIn("Receiver saw", tunnelscope_view.render_report_html({
            "schema_version": 1, "kind": "probe_receiver_correlation", "results": []}))

    def test_report_commands_do_not_overwrite_input(self):
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "probe.json"
            original = json.dumps({"schema_version": 1, "kind": "probe", "results": []})
            report_path.write_text(original, encoding="utf-8")
            for command in (
                ["html", str(report_path)],
                ["combine", str(report_path), str(report_path)],
                ["correlate", str(report_path), str(report_path)],
            ):
                with self.subTest(command=command[0]):
                    result = subprocess.run(
                        [sys.executable, str(Path(tunnelscope.__file__)), *command,
                         "--output", str(report_path)],
                        capture_output=True, text=True, timeout=5,
                    )
                    self.assertEqual(result.returncode, 1)
                    self.assertIn("--output must differ", result.stderr)
                    self.assertEqual(report_path.read_text(encoding="utf-8"), original)

    def test_summary_keeps_mixed_outcomes_and_repeated_sizes(self):
        results = [
            {"payload_bytes": 64, "status": "acknowledged"},
            {"payload_bytes": 64, "status": "timeout"},
            {"payload_bytes": 1400, "status": "packet_too_large"},
            {"payload_bytes": 1400, "status": "socket_error"},
        ]
        summary = tunnelscope.summarize_results([64, 1400, 64], results)
        self.assertEqual([row["payload_bytes"] for row in summary], [64, 1400])
        self.assertEqual([row["assessment"] for row in summary], ["mixed_observations"] * 2)
        self.assertEqual(summary[0]["status_counts"], {
            "acknowledged": 1, "packet_too_large": 0, "timeout": 1, "socket_error": 0,
        })

    def test_evidence_does_not_infer_boundary_from_mixed_sizes(self):
        rows = tunnelscope.summarize_results([64, 1400], [
            {"payload_bytes": 64, "status": "timeout"},
            {"payload_bytes": 1400, "status": "acknowledged"},
        ])
        evidence = tunnelscope.explain_evidence(rows, True)
        self.assertEqual(evidence["hypotheses"], [])
        self.assertIn({"payload_bytes": 64, "status": "timeout", "attempts": 1}, evidence["observations"])
        self.assertIn("icmp_feedback_observation", evidence["missing_evidence"])

    def test_combine_preserves_both_directions_and_unmatched_sizes(self):
        forward = {
            "schema_version": 1, "source": {"ipv4": "192.0.2.1"},
            "target": {"ipv4": "192.0.2.2"}, "results": [],
            "summary": {"by_payload_size": [
                {"payload_bytes": 64, "assessment": "delivery_observed"},
                {"payload_bytes": 1400, "assessment": "inconclusive"},
            ]},
        }
        reverse = {
            "schema_version": 1, "source": {"ipv4": "192.0.2.2"},
            "target": {"ipv4": "192.0.2.1"}, "results": [],
            "summary": {"by_payload_size": [
                {"payload_bytes": 64, "assessment": "delivery_observed"},
            ]},
        }
        with tempfile.TemporaryDirectory() as directory:
            first, second, output = (Path(directory) / name for name in ("a.json", "b.json", "combined.json"))
            first.write_text(json.dumps(forward), encoding="utf-8")
            second.write_text(json.dumps(reverse), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(Path(tunnelscope.__file__)), "combine", str(first), str(second), "--output", str(output)],
                capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            combined = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(combined["endpoint_check"], "reversed_ipv4_match")
        self.assertEqual([row["direction"] for row in combined["directions"]], ["a-to-b", "b-to-a"])
        self.assertEqual(combined["comparison"]["by_payload_size"], [
            {"payload_bytes": 64, "a_to_b": "delivery_observed", "b_to_a": "delivery_observed"},
            {"payload_bytes": 1400, "a_to_b": "inconclusive", "b_to_a": None},
        ])
        rendered = tunnelscope.format_report(combined)
        self.assertIn("1400", rendered)
        self.assertIn("inconclusive", rendered)
        self.assertIn("A to B", rendered)

    def test_combine_rejects_non_probe_input(self):
        with self.assertRaisesRegex(ValueError, "schema_version 1 probe report"):
            tunnelscope.combine_reports({}, {})

    def test_receiver_report_correlates_with_probe_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            receiver_path = directory / "receiver.json"
            probe_path = directory / "probe.json"
            correlation_path = directory / "correlation.json"
            process = subprocess.Popen(
                [sys.executable, str(Path(tunnelscope.__file__)), "receive", "--port", "0",
                 "--max-packets", "2", "--output", str(receiver_path)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            try:
                port = int(process.stdout.readline().strip().rsplit(":", 1)[1])
                sent = subprocess.run(
                    [sys.executable, str(Path(tunnelscope.__file__)), "probe", "127.0.0.1",
                     "--port", str(port), "--sizes", "64,1400", "--count", "1",
                     "--output", str(probe_path)],
                    capture_output=True, text=True, timeout=5,
                )
                self.assertEqual(sent.returncode, 0, sent.stderr)
                self.assertEqual(process.wait(timeout=4), 0)
                correlated = subprocess.run(
                    [sys.executable, str(Path(tunnelscope.__file__)), "correlate", str(probe_path),
                     str(receiver_path), "--output", str(correlation_path)],
                    capture_output=True, text=True, timeout=5,
                )
                self.assertEqual(correlated.returncode, 0, correlated.stderr)
                receiver = json.loads(receiver_path.read_text(encoding="utf-8"))
                probe = json.loads(probe_path.read_text(encoding="utf-8"))
                correlation = json.loads(correlation_path.read_text(encoding="utf-8"))
                self.assertEqual([row["probe_id"] for row in probe["results"]],
                                 [row["probe_id"] for row in receiver["observations"]])
                self.assertEqual({row["run_id"] for row in receiver["observations"]}, {probe["run_id"]})
                self.assertEqual(correlation["pairing"]["run_id_check"], "matched")
                self.assertTrue(correlation["pairing"]["endpoint_checks"]["target_port_matches_receiver"])
                self.assertTrue(correlation["pairing"]["endpoint_checks"]["target_ipv4_matches_receiver_bind"])
                self.assertLessEqual(probe["started_at_utc"], probe["finished_at_utc"])
                self.assertLessEqual(receiver["started_at_utc"], receiver["finished_at_utc"])
                self.assertEqual(correlation["summary"], {
                    "sent_probes": 2, "receiver_observed": 2,
                    "timed_out_but_receiver_observed": 0,
                    "unmatched_receiver_observations": 0,
                })
                self.assertEqual([row["ack_send_status"] for row in correlation["results"]], ["sent"] * 2)
                shown = subprocess.run(
                    [sys.executable, str(Path(tunnelscope.__file__)), "show", str(correlation_path)],
                    capture_output=True, text=True, timeout=5,
                )
                self.assertEqual(shown.returncode, 0, shown.stderr)
                self.assertIn("2/2 observed at receiver", shown.stdout)
                self.assertIn("Receiver saw", shown.stdout)
                receiver_shown = subprocess.run(
                    [sys.executable, str(Path(tunnelscope.__file__)), "show", str(receiver_path)],
                    capture_output=True, text=True, timeout=5,
                )
                self.assertEqual(receiver_shown.returncode, 0, receiver_shown.stderr)
                self.assertIn("Receiver observations: 2 probes", receiver_shown.stdout)
                self.assertIn(probe["run_id"], receiver_shown.stdout)
                self.assertIn("ACK sent", receiver_shown.stdout)
                self.assertIn("64", tunnelscope.format_report(probe))
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                process.stdout.close()
                process.stderr.close()

    def test_correlation_marks_receiver_observed_timeout_without_claiming_cause(self):
        probe = {"schema_version": 1, "results": [
            {"probe_id": "ab" * 16, "payload_bytes": 1400, "status": "timeout"},
        ]}
        receiver = {"schema_version": 1, "kind": "receiver_observations", "observations": [
            {"probe_id": "ab" * 16, "payload_bytes": 1400, "ack_send_status": "sent"},
        ]}
        result = tunnelscope.correlate_reports(probe, receiver)
        self.assertEqual(result["summary"]["timed_out_but_receiver_observed"], 1)
        self.assertTrue(result["results"][0]["receiver_observed"])
        self.assertNotIn("cause", result["results"][0])
        receiver["observations"][0]["payload_bytes"] = 64
        with self.assertRaisesRegex(ValueError, "different payload sizes"):
            tunnelscope.correlate_reports(probe, receiver)

    def test_correlation_rejects_receiver_report_from_different_run(self):
        probe = {"schema_version": 1, "run_id": "11" * 8, "results": [
            {"probe_id": "ab" * 16, "payload_bytes": 64, "status": "timeout"},
        ]}
        receiver = {"schema_version": 1, "kind": "receiver_observations", "observations": [
            {"probe_id": "cd" * 16, "run_id": "22" * 8, "payload_bytes": 64},
        ]}
        with self.assertRaisesRegex(ValueError, "different run"):
            tunnelscope.correlate_reports(probe, receiver)
        receiver["observations"] = []
        result = tunnelscope.correlate_reports(probe, receiver)
        self.assertEqual(result["pairing"]["run_id_check"], "unverified_no_receiver_observations")

    def test_correlation_flags_receiver_capture_with_other_runs(self):
        probe = {"schema_version": 1, "run_id": "11" * 8, "results": [
            {"probe_id": "ab" * 16, "payload_bytes": 64, "status": "acknowledged"},
        ]}
        receiver = {"schema_version": 1, "kind": "receiver_observations", "observations": [
            {"probe_id": "ab" * 16, "run_id": "11" * 8, "payload_bytes": 64},
            {"probe_id": "cd" * 16, "run_id": "22" * 8, "payload_bytes": 1400},
        ]}
        result = tunnelscope.correlate_reports(probe, receiver)
        self.assertEqual(result["pairing"]["run_id_check"], "matched_with_other_runs")
        self.assertEqual(result["summary"]["unmatched_receiver_observations"], 1)
        shown = tunnelscope.format_report(result)
        self.assertIn("1 unmatched receiver observations", shown)
        self.assertIn("matched_with_other_runs", shown)

        receiver["observations"][0]["run_id"] = "22" * 8
        receiver["observations"].append({"probe_id": "ef" * 16, "run_id": "11" * 8,
                                          "payload_bytes": 64})
        with self.assertRaisesRegex(ValueError, "matching probe ID has a different run ID"):
            tunnelscope.correlate_reports(probe, receiver)

    def test_receiver_view_separates_runs_and_ack_send_errors(self):
        report = {"schema_version": 1, "kind": "receiver_observations", "exit_reason": "idle_timeout",
                  "observations": [
                      {"run_id": "11" * 8, "payload_bytes": 64, "ack_send_status": "sent"},
                      {"run_id": "11" * 8, "payload_bytes": 64, "ack_send_status": "socket_error"},
                      {"run_id": "22" * 8, "payload_bytes": 1400, "ack_send_status": "sent"},
                  ]}
        rendered = tunnelscope.format_report(report)
        self.assertIn("Receiver observations: 3 probes; exit: idle_timeout", rendered)
        self.assertIn("1111111111111111  64     2     1         1", rendered)
        self.assertIn("2222222222222222  1400   1     1         0", rendered)
        self.assertIn("not that it arrived", rendered)
        report["observations"] = []
        self.assertIn("Receiver observations: 0 probes", tunnelscope.format_report(report))


if __name__ == "__main__":
    unittest.main()

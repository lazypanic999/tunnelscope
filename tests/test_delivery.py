import json
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import tunnelscope


class DeliveryTests(unittest.TestCase):
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

    def test_combine_rejects_non_probe_input(self):
        with self.assertRaisesRegex(ValueError, "schema_version 1 probe report"):
            tunnelscope.combine_reports({}, {})


if __name__ == "__main__":
    unittest.main()

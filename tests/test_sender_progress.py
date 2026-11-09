"""Sender commands print one progress line per attempt on stderr."""

import json
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tunnelscope_core import network
from tunnelscope_core.network import attempt_line


class AttemptLineTests(unittest.TestCase):
    def test_each_status_reads_plainly(self):
        base = {"payload_bytes": 1400, "attempt": 2}
        cases = [
            ({"status": "acknowledged", "rtt_ms": 0.42}, "acknowledged in 0.42 ms"),
            ({"status": "acknowledged", "rtt_ms": 1.0, "return_status": "small_ack_only"},
             "acknowledged in 1.0 ms, small ACK only"),
            ({"status": "acknowledged", "rtt_ms": 1.0, "return_status": "sized_reply_received"},
             "acknowledged in 1.0 ms, sized reply received"),
            ({"status": "timeout", "return_status": "no_reply"}, "timeout"),
            ({"status": "packet_too_large", "kernel_reported_mtu_bytes": 1280},
             "packet_too_large (kernel MTU 1280)"),
            ({"status": "packet_too_large"}, "packet_too_large"),
            ({"status": "socket_error", "errno": 111}, "socket_error (errno 111)"),
        ]
        for extra, outcome in cases:
            with self.subTest(outcome=outcome):
                line = attempt_line({**base, **extra}, 3, "DF")
                self.assertEqual(line, f" 1400 bytes  attempt 2/3  DF          {outcome}")

    def test_probe_reports_mode_for_each_attempt(self):
        lines = []
        with patch.object(network.time, "sleep"):
            # A just-closed loopback port: nothing listens, so each attempt ends quickly.
            network.probe("127.0.0.1", self.closed_port(), [64, 128], 1, 1, progress=lines.append)
        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[0].startswith("   64 bytes  attempt 1/1  OS default"))
        self.assertTrue(lines[1].startswith("  128 bytes  attempt 1/1  OS default"))

    @staticmethod
    def closed_port():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]


@unittest.skipUnless(sys.platform.startswith("linux") or sys.platform == "win32",
                     "loopback receiver checks run on Linux and Windows")
class SenderProgressCliTests(unittest.TestCase):
    def run_pair(self, *probe_args):
        receiver = subprocess.Popen(
            [sys.executable, str(ROOT / "tunnelscope.py"), "receive", "--port", "0", "--max-packets", "2",
             "--idle-timeout", "5", "--quiet"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            port = receiver.stdout.readline().strip().rsplit(":", 1)[1]
            result = subprocess.run(
                [sys.executable, str(ROOT / "tunnelscope.py"), "probe", "127.0.0.1", "--port", port,
                 "--sizes", "64,200", "--count", "1", *probe_args],
                capture_output=True, text=True, timeout=30)
            leftover, _ = receiver.communicate(timeout=10)
        finally:
            if receiver.poll() is None:
                receiver.kill()
                receiver.communicate()
        return result, leftover

    def test_progress_on_stderr_and_json_on_stdout(self):
        result, receiver_out = self.run_pair()
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual([row["status"] for row in report["results"]], ["acknowledged"] * 2)
        lines = result.stderr.splitlines()
        self.assertEqual(len(lines), 2)
        self.assertIn("   64 bytes  attempt 1/1  OS default  acknowledged in", lines[0])
        self.assertEqual(receiver_out, "")  # --quiet receiver: no per-probe lines

    def test_quiet_probe_prints_nothing_on_stderr(self):
        result, _ = self.run_pair("--quiet")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")
        json.loads(result.stdout)


if __name__ == "__main__":
    unittest.main()

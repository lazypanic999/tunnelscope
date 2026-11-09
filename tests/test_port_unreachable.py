"""A probe to a port with no receiver says so instead of a bare socket_error."""

import json
from pathlib import Path
import socket
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tunnelscope_core.reports import format_report, refused_attempts, summarize_results


def probe_report(rows):
    return {"schema_version": 1, "kind": "probe", "results": rows,
            "summary": {"by_payload_size": summarize_results([64], rows)}}


def failed(errno):
    return {"payload_bytes": 64, "attempt": 1, "probe_id": "0" * 32,
            "status": "socket_error", "error": "test", "errno": errno}


class PortUnreachableTests(unittest.TestCase):
    def test_refused_errnos_from_each_platform_are_counted(self):
        for errno in (111, 61, 10054, 10061):
            with self.subTest(errno=errno):
                text = format_report(probe_report([failed(errno)]))
                self.assertIn("Port unreachable: 1 attempt got a connection-refused error.", text)
                self.assertIn("a firewall can also answer with port unreachable", text)

    def test_other_errors_and_timeouts_get_no_port_hint(self):
        timeout = {"payload_bytes": 64, "attempt": 2, "probe_id": "1" * 32, "status": "timeout"}
        for rows in ([failed(101)], [timeout], [failed(None)], []):
            with self.subTest(rows=rows):
                self.assertEqual(refused_attempts(rows), 0)
                if rows:
                    self.assertNotIn("Port unreachable", format_report(probe_report(rows)))

    def test_count_ignores_malformed_rows(self):
        self.assertEqual(refused_attempts(None), 0)
        self.assertEqual(refused_attempts(["x", failed(111), {"status": "socket_error", "errno": "111"}]), 1)
        self.assertIn("2 attempts", format_report(probe_report([failed(111), failed(111)])))

    @unittest.skipUnless(sys.platform.startswith("linux") or sys.platform == "win32",
                         "loopback port unreachable is checked on Linux and Windows")
    def test_cli_probe_to_closed_port_notes_it_on_stderr_and_keeps_json_stdout(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        result = subprocess.run(
            [sys.executable, str(ROOT / "tunnelscope.py"), "probe", "127.0.0.1", "--port", str(port),
             "--sizes", "64", "--count", "1", "--timeout", "1"],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["results"][0]["status"], "socket_error")
        self.assertIn("Note: 1 attempt got port unreachable", result.stderr)


if __name__ == "__main__":
    unittest.main()

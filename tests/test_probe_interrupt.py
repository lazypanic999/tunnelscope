"""Ctrl+C during a plain probe keeps the attempts that finished."""

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import tunnelscope
from tunnelscope_core import network
from tunnelscope_core.reports import correlate_reports, format_report


def closed_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def stop_after(calls):
    seen = []

    def progress(line):
        seen.append(line)
        if len(seen) == calls:
            raise KeyboardInterrupt
    return progress


class ProbeInterruptTests(unittest.TestCase):
    def interrupted_report(self, calls=3, sizes=(64, 128, 256), count=2):
        with patch.object(network.time, "sleep"), self.assertRaises(network.ProbeInterrupted) as caught:
            network.probe("127.0.0.1", closed_port(), list(sizes), count, 1, progress=stop_after(calls))
        return caught.exception

    def test_partial_report_keeps_finished_attempts_only(self):
        stopped = self.interrupted_report()
        self.assertIsInstance(stopped, KeyboardInterrupt)
        report = stopped.report
        self.assertEqual(report["exit_reason"], "interrupted")
        self.assertEqual(len(report["results"]), 3)
        self.assertEqual([row["payload_bytes"] for row in report["summary"]["by_payload_size"]], [64, 128])
        self.assertEqual(report["settings"]["payload_sizes"], [64, 128, 256])

    def test_summary_text_says_how_much_was_recorded(self):
        text = format_report(self.interrupted_report().report)
        self.assertIn("Interrupted: 3 of 6 attempts were recorded before Ctrl+C", text)

    def test_html_view_has_an_interrupted_run_card(self):
        from tunnelscope_core.view import render_report_html
        html = render_report_html(self.interrupted_report().report)
        self.assertIn("<h2>Interrupted run</h2>", html)
        self.assertIn("<strong>Attempts recorded:</strong> 3 of 6 planned", html)

    def test_complete_run_has_no_exit_reason(self):
        with patch.object(network.time, "sleep"):
            report = network.probe("127.0.0.1", closed_port(), [64], 1, 1)
        self.assertNotIn("exit_reason", report)
        self.assertNotIn("Interrupted", format_report(report))

    def test_partial_report_still_correlates(self):
        report = self.interrupted_report(calls=1).report
        receiver = {"schema_version": 1, "kind": "receiver_observations", "observations": []}
        joined = correlate_reports(report, receiver)
        self.assertEqual(joined["summary"]["sent_probes"], 1)

    @unittest.skipUnless(sys.platform.startswith("linux"), "size search needs Linux DF mode")
    def test_search_interrupt_stays_a_plain_keyboard_interrupt(self):
        with patch.object(network.time, "sleep"), self.assertRaises(KeyboardInterrupt) as caught:
            network.probe("127.0.0.1", closed_port(), None, 1, 1, True, search_bounds=(64, 1400),
                          max_sizes=4, progress=stop_after(1))
        self.assertNotIsInstance(caught.exception, network.ProbeInterrupted)


@unittest.skipUnless(sys.platform == "win32", "Windows-only: Ctrl+C does not wake a socket wait there")
class WindowsProbeWaitTests(unittest.TestCase):
    def test_interrupt_does_not_wait_for_the_reply_deadline(self):
        import _thread
        import threading
        import time
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as silent:
            silent.bind(("127.0.0.1", 0))
            timer = threading.Timer(0.5, _thread.interrupt_main)
            started = time.monotonic()
            timer.start()
            try:
                with self.assertRaises(KeyboardInterrupt):
                    network.probe("127.0.0.1", silent.getsockname()[1], [64], 1, 5)
            finally:
                timer.cancel()
            self.assertLess(time.monotonic() - started, 3)

    def test_sliced_wait_still_times_out_at_the_deadline(self):
        import time
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as silent:
            silent.bind(("127.0.0.1", 0))
            started = time.monotonic()
            report = network.probe("127.0.0.1", silent.getsockname()[1], [64], 1, 1)
            elapsed = time.monotonic() - started
        self.assertEqual(report["results"][0]["status"], "timeout")
        self.assertGreaterEqual(elapsed, 0.95)
        self.assertLess(elapsed, 2)


class ProbeInterruptCliTests(unittest.TestCase):
    def run_cli(self, *extra):
        partial = {"schema_version": 1, "kind": "probe", "exit_reason": "interrupted",
                   "results": [{"payload_bytes": 64}, {"payload_bytes": 64}]}
        stdout, stderr = StringIO(), StringIO()
        with patch.object(tunnelscope, "probe", side_effect=network.ProbeInterrupted(partial)), \
                patch.object(sys, "argv", ["tunnelscope", "probe", "127.0.0.1", "--quiet", *extra]), \
                redirect_stdout(stdout), redirect_stderr(stderr), self.assertRaises(SystemExit) as caught:
            tunnelscope.main()
        return caught.exception.code, stdout.getvalue(), stderr.getvalue()

    def test_cli_saves_partial_report_and_exits_130(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "probe.json"
            code, stdout, stderr = self.run_cli("--output", str(output))
            saved = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(code, 130)
        self.assertEqual(saved["exit_reason"], "interrupted")
        self.assertEqual(json.loads(stdout), saved)
        self.assertEqual(stderr.strip(), f"Stopped after 2 attempts; saved {output}.")

    def test_cli_without_output_prints_json_then_stops(self):
        code, stdout, stderr = self.run_cli()
        self.assertEqual(code, 130)
        self.assertEqual(json.loads(stdout)["exit_reason"], "interrupted")
        self.assertEqual(stderr.strip(), "Stopped after 2 attempts.")


if __name__ == "__main__":
    unittest.main()

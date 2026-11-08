"""Exercise the documented collection and sharing commands with real CLI processes.

Loopback verifies file/workflow compatibility, not independent field evidence.
"""

import json
from contextlib import contextmanager
import os
from pathlib import Path
import queue
import signal
import subprocess
import sys
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
CLI = [sys.executable, str(ROOT / "tunnelscope.py")]
ENV = {**os.environ, "PYTHONIOENCODING": "utf-8"}


class FieldReportWorkflowTests(unittest.TestCase):
    def run_cli(self, directory, *args):
        result = subprocess.run([*CLI, *args], cwd=directory, env=ENV,
                                capture_output=True, encoding="utf-8", timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    @contextmanager
    def receiver(self, root, attempts):
        process = subprocess.Popen(
            [*CLI, "receive", "--port", "0", "--sized-reply", "--max-packets", str(attempts),
             "--idle-timeout", "5", "--output", "receiver.json"],
            cwd=root, env=ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8",
        )
        ready = queue.Queue()
        reader = threading.Thread(target=lambda: ready.put(process.stdout.readline()), daemon=True)
        reader.start()
        try:
            listening = ready.get(timeout=5)
            self.assertTrue(listening.startswith("Listening on 127.0.0.1:"), listening)
            yield listening.strip().rsplit(":", 1)[1], process
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=3)
            reader.join(timeout=3)
            process.stdout.close()
            process.stderr.close()

    def workflow(self, mode):
        attempts = 6 if mode == "diagnose" else 2
        sender_name = "diagnosis.json" if mode == "diagnose" else "probe.json"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.receiver(root, attempts) as (port, receiver):
                options = (["--min", "1200", "--max", "1201", "--max-sizes", "2"]
                           if mode == "diagnose" else ["--sizes", "64,1200"])
                self.run_cli(root, mode, "127.0.0.1", "--port", port, *options,
                             "--count", "1", "--sized-reply", "--output", sender_name)
                self.assertEqual(receiver.wait(timeout=6), 0, "receiver did not save a complete capture")

            self.run_cli(root, "correlate", sender_name, "receiver.json",
                         "--output", "correlation.json", "--html", "correlation.html")
            names = (sender_name, "receiver.json", "correlation.json")
            originals = {name: (root / name).read_bytes() for name in names}
            shared = root / "shared"
            shared.mkdir()
            self.run_cli(root, "sanitize", *names, "--output-dir", "shared", "--html")
            for name in names:
                clean = json.loads((shared / name).read_text(encoding="utf-8"))
                self.assertIn("sanitization", clean)
                self.assertTrue((shared / Path(name).with_suffix(".html")).is_file())
                self.assertEqual((root / name).read_bytes(), originals[name])

            joined = json.loads((shared / "correlation.json").read_text(encoding="utf-8"))
            summary = joined["receiver_evidence"]["summary"] if mode == "diagnose" else joined["summary"]
            self.assertEqual(summary["receiver_observed"], attempts)
            self.assertEqual(summary["sent_probes"], attempts)
            correlations = (joined["receiver_evidence"]["correlations"].values()
                            if mode == "diagnose" else (joined,))
            for correlation in correlations:
                self.assertEqual(correlation["summary"]["timed_out_but_receiver_observed"], 0)
            sender = json.loads((shared / sender_name).read_text(encoding="utf-8"))
            self.assertTrue(sender["started_at_utc"].startswith("2000-"))
            shown = self.run_cli(root, "show", "shared/correlation.json")
            self.assertIn("Sanitized report", shown)
            self.assertIn("Receiver observed: 6/6" if mode == "diagnose" else "Correlation: 2/2", shown)
            html = (shared / "correlation.html").read_text(encoding="utf-8")
            self.assertTrue("Sanitized report" in html and "sized_reply_returned" in html)
            markdown = self.run_cli(root, "show", "shared/correlation.json", "--format", "markdown")
            self.assertTrue(markdown.startswith("# TunnelScope - "))
            self.assertIn("Sanitization record present", markdown)

            # Sanitized source files must still pair with the same outcomes.
            self.run_cli(shared, "correlate", sender_name, "receiver.json", "--output", "rejoined.json")
            rejoined = json.loads((shared / "rejoined.json").read_text(encoding="utf-8"))
            key = "receiver_evidence" if mode == "diagnose" else "results"
            self.assertEqual(rejoined[key], joined[key])

    @unittest.skipUnless(sys.platform.startswith("linux") or sys.platform == "win32",
                         "same-sized receiver requires Linux or Windows")
    def test_probe_collection_join_sanitize_and_display(self):
        self.workflow("probe")

    @unittest.skipUnless(sys.platform.startswith("linux"), "diagnose requires Linux")
    def test_diagnose_collection_join_sanitize_and_display(self):
        self.workflow("diagnose")

    @unittest.skipUnless(sys.platform.startswith("linux"), "POSIX receiver interrupt")
    def test_interrupt_saves_receiver_capture_before_exit_130(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.receiver(root, 100) as (port, receiver):
                self.run_cli(root, "probe", "127.0.0.1", "--port", port, "--sizes", "64",
                             "--count", "1", "--sized-reply", "--output", "probe.json")
                receiver.send_signal(signal.SIGINT)
                self.assertEqual(receiver.wait(timeout=5), 130)
            report = json.loads((root / "receiver.json").read_text(encoding="utf-8"))
            self.assertEqual(report["exit_reason"], "interrupted")
            self.assertEqual(len(report["observations"]), 1)
            self.assertEqual(report["observations"][0]["ack_send_status"], "sent")


if __name__ == "__main__":
    unittest.main()

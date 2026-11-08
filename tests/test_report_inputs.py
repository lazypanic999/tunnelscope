"""Offline commands accept shell exports and reject malformed input cleanly."""

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import tunnelscope
from tunnelscope_core.view import render_report_html
from tunnelscope_core.reports import correlate_reports, format_report


class ReportInputTests(unittest.TestCase):
    def invoke(self, *arguments, error=False):
        output, errors = StringIO(), StringIO()
        with patch.object(sys, "argv", ["tunnelscope", *map(str, arguments)]), \
                redirect_stdout(output), redirect_stderr(errors):
            if error:
                with self.assertRaises(SystemExit) as stopped:
                    tunnelscope.main()
                self.assertEqual(stopped.exception.code, 1)
            else:
                tunnelscope.main()
        self.assertNotIn("Traceback", errors.getvalue())
        return errors.getvalue() if error else output.getvalue()

    def test_bom_encodings_work_for_display_join_combine_and_sanitize(self):
        original = json.loads((ROOT / "examples/openvpn-routed-v09.json").read_text(encoding="utf-8"))
        case = original["cases"]["visible"]
        for encoding in ("utf-8", "utf-8-sig", "utf-16", "utf-32"):
            with self.subTest(encoding=encoding), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                sender, receiver = root / "sender.json", root / "receiver.json"
                sender.write_bytes(json.dumps(case["probe"]).encode(encoding))
                receiver.write_bytes(json.dumps(case["receiver"]).encode(encoding))
                self.assertIn("Probe results", self.invoke("show", sender))
                self.assertIn("## Observations", self.invoke("show", sender, "--format", "markdown"))
                self.invoke("html", sender, "--output", root / "report.html")
                joined = json.loads(self.invoke("correlate", sender, receiver))
                self.assertEqual(joined["results"], case["correlation"]["results"])
                self.assertEqual(json.loads(self.invoke("combine", sender, sender))["kind"],
                                 "bidirectional_comparison")
                shared = root / "shared"
                shared.mkdir()
                self.invoke("sanitize", sender, receiver, "--output-dir", shared)
                self.assertIn("sanitization", json.loads((shared / "sender.json").read_text(encoding="utf-8")))

    def test_invalid_json_and_nonobjects_fail_with_input_path(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "broken.json"
            for content in (b"[", b"[]", b"null", b"42", b"\xffinvalid"):
                with self.subTest(content=content):
                    source.write_bytes(content)
                    message = self.invoke("show", source, error=True)
                    self.assertIn(str(source), message)
                    self.assertTrue(message.startswith("Error:"))

    def test_invalid_report_kind_fails_cleanly_in_offline_views(self):
        for kind in ([], {}):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / "bad-kind.json"
                source.write_text(json.dumps({
                    "schema_version": 1, "kind": kind, "input_versions": {},
                    "results": [], "summary": {"by_payload_size": []},
                }), encoding="utf-8")
                original = source.read_bytes()
                for arguments in (("show", source),
                                  ("show", source, "--format", "markdown"),
                                  ("html", source, "--output", root / "report.html")):
                    with self.subTest(arguments=arguments):
                        result = subprocess.run(
                            [sys.executable, str(ROOT / "tunnelscope.py"), *map(str, arguments)],
                            capture_output=True, text=True, timeout=10,
                        )
                        self.assertEqual(result.returncode, 1, result.stderr)
                        self.assertTrue(result.stderr.startswith("Error:"), result.stderr)
                        self.assertNotIn("Traceback", result.stderr)
                        self.assertEqual(result.stdout, "")
                        self.assertEqual(source.read_bytes(), original)
                        self.assertEqual(sorted(path.name for path in root.iterdir()), [source.name])

    def test_correlate_rejects_declared_nonprobe_sender_kinds(self):
        fixture = json.loads((ROOT / "examples/windows-wsl2-receiver-v09.json").read_text(encoding="utf-8"))
        sender = fixture["cases"]["sized_reply"]["probe"]
        receiver = fixture["shared_receiver_capture"]
        before = json.dumps(fixture, sort_keys=True)
        with self.assertRaisesRegex(ValueError, "probe report"):
            correlate_reports(fixture["cases"]["sized_reply"]["correlation"], receiver)
        for kind in ("probe_receiver_correlation", "receiver_observations", "diagnosis",
                     "", None, [], {}, 0, False):
            with self.subTest(kind=kind):
                with self.assertRaisesRegex(ValueError, "probe report"):
                    correlate_reports({**sender, "kind": kind}, receiver)
        self.assertEqual(json.dumps(fixture, sort_keys=True), before)

    def test_correlate_preserves_probe_and_legacy_sender_inputs(self):
        fixture = json.loads((ROOT / "examples/windows-wsl2-receiver-v09.json").read_text(encoding="utf-8"))
        sender = fixture["cases"]["sized_reply"]["probe"]
        receiver = fixture["shared_receiver_capture"]
        expected = correlate_reports(sender, receiver)
        self.assertEqual(expected["results"], fixture["cases"]["sized_reply"]["correlation"]["results"])
        legacy = {key: value for key, value in sender.items() if key != "kind"}
        self.assertEqual(correlate_reports(legacy, receiver), expected)

    def test_correlate_wrong_sender_kind_fails_before_writing_outputs(self):
        fixture = json.loads((ROOT / "examples/windows-wsl2-receiver-v09.json").read_text(encoding="utf-8"))
        wrong_sender = fixture["cases"]["sized_reply"]["correlation"]
        for kind in (wrong_sender["kind"], None, [], {}, "", 0, False):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                sender, receiver = root / "sender.json", root / "receiver.json"
                sender.write_text(json.dumps({**wrong_sender, "kind": kind}), encoding="utf-8")
                receiver.write_text(json.dumps(fixture["shared_receiver_capture"]), encoding="utf-8")
                originals = {path: path.read_bytes() for path in (sender, receiver)}
                result = subprocess.run(
                    [sys.executable, str(ROOT / "tunnelscope.py"), "correlate",
                     str(sender), str(receiver), "--output", str(root / "joined.json"),
                     "--html", str(root / "joined.html")],
                    capture_output=True, text=True, timeout=10,
                )
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertTrue(result.stderr.startswith("Error:"), result.stderr)
                self.assertIn("probe report", result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertEqual(set(root.iterdir()), set(originals))
                for path, original in originals.items():
                    self.assertEqual(path.read_bytes(), original)

    def test_invalid_diagnosis_containers_raise_value_error(self):
        report = json.loads((ROOT / "examples/diagnosis-v06.json").read_text(encoding="utf-8"))
        for key in ("summary", "consistency"):
            for value in (None, [], 1, "bad"):
                for renderer in (format_report, render_report_html):
                    with self.subTest(key=key, value=value, renderer=renderer.__name__):
                        with self.assertRaisesRegex(ValueError, "diagnosis"):
                            renderer({**report, key: value})


if __name__ == "__main__":
    unittest.main()

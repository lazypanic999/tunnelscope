"""Offline commands accept shell exports and reject malformed input cleanly."""

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import tunnelscope
from tunnelscope_core.view import render_report_html
from tunnelscope_core.reports import format_report


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

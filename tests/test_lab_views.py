"""Every checked-in lab should be readable with the default show command."""

import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tunnelscope_core.reports import format_report
from tunnelscope_core.markdown import render_report_markdown
from tunnelscope_core.view import render_report_html


class LabViewTests(unittest.TestCase):
    def test_every_example_has_a_text_view(self):
        for path in sorted((ROOT / "examples").glob("*.json")):
            with self.subTest(example=path.name):
                report = json.loads(path.read_text(encoding="utf-8"))
                self.assertTrue(format_report(report))

    def test_named_cases_are_visible_through_the_default_cli(self):
        for name in ("ipv6-routed-feedback.json", "openvpn-routed-v09.json"):
            with self.subTest(example=name):
                result = subprocess.run([sys.executable, str(ROOT / "tunnelscope.py"), "show",
                                         str(ROOT / "examples" / name)],
                                        capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                for text in ("Case", "blocked", "visible", "timeout", "inconclusive"):
                    self.assertIn(text, result.stdout)

    def test_empty_and_invalid_lab_groups(self):
        self.assertIn("No observations", format_report({"lab": "empty", "cases": {}}))
        with self.assertRaises(ValueError):
            format_report({"lab": "bad", "cases": {"blocked": []}})

    def test_grouped_sized_replies_keep_joined_return_evidence(self):
        report = json.loads((ROOT / "examples/openvpn-asymmetric-return-v09.json").read_text(encoding="utf-8"))
        from html import unescape
        for renderer in (format_report, render_report_html, render_report_markdown):
            with self.subTest(renderer=renderer.__name__):
                rendered = unescape(renderer(report))
                self.assertTrue("Return evidence" in rendered)
                self.assertTrue("receiver_observed_sized_reply_missing" in rendered)
                self.assertTrue("receiver_reply_send_failed" in rendered)


if __name__ == "__main__":
    unittest.main()

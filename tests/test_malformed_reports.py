"""Malformed report fields give a clear error, not a Python traceback.

The CLI turns ValueError and OSError into "Error: ..." and exit status 1.
Anything else reaches the user as a traceback, so renderers must not raise it
for values a hand-edited or truncated JSON file can contain.
"""

import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tunnelscope_core.markdown import render_report_markdown
from tunnelscope_core.reports import format_report
from tunnelscope_core.view import render_report_html

RENDERERS = (format_report, render_report_html, render_report_markdown)
LAB = json.loads((ROOT / "examples" / "ipv6-routed-feedback.json").read_text(encoding="utf-8"))


def blackhole_lab():
    return json.loads((ROOT / "examples" / "pmtu-blackhole.json").read_text(encoding="utf-8"))


class MalformedReportTests(unittest.TestCase):
    def assert_rendered_or_value_error(self, report):
        for render in RENDERERS:
            with self.subTest(renderer=render.__name__):
                try:
                    render(report)
                except ValueError:
                    pass

    def test_lab_case_with_non_string_probe_ids_does_not_crash(self):
        case = next(iter(LAB["cases"]))
        for section in ("probe", "correlation"):
            for value in ([None], {"a": 1}, 7, None):
                with self.subTest(section=section, value=value):
                    report = copy.deepcopy(LAB)
                    report["cases"][case][section]["results"][0]["probe_id"] = value
                    self.assert_rendered_or_value_error(report)

    def test_unmatched_probe_id_type_leaves_the_receiver_column_empty(self):
        case = next(iter(LAB["cases"]))
        report = copy.deepcopy(LAB)
        report["cases"][case]["probe"]["results"][0]["probe_id"] = ["not", "an", "id"]
        text = format_report(report)
        self.assertIn("Receiver saw", text)

    def test_non_integer_status_counts_are_rejected_clearly(self):
        base = blackhole_lab()
        for value in ("x", 1.5, None, True, -1, [1]):
            with self.subTest(value=value):
                report = copy.deepcopy(base)
                report["probe"]["summary"]["by_payload_size"][0]["status_counts"]["acknowledged"] = value
                with self.assertRaisesRegex(ValueError, "invalid probe status counts"):
                    format_report(report)


if __name__ == "__main__":
    unittest.main()

"""Producer claims survive offline joins without relabeling old evidence."""

import copy
from html import unescape
import json
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import tunnelscope
from tunnelscope_core._version import VERSION, declared_version
from tunnelscope_core.diagnose import build_diagnosis, correlate_diagnosis
from tunnelscope_core.fragmentation import compare_fragmentation_reports
from tunnelscope_core.markdown import render_report_markdown
from tunnelscope_core.reports import combine_reports, correlate_reports, version_details
from tunnelscope_core.sanitize import sanitize_reports
from tunnelscope_core.view import render_report_html


class VersionTests(unittest.TestCase):
    def setUp(self):
        self.diagnosis = json.loads((ROOT / "examples/diagnosis-v06.json").read_text(encoding="utf-8"))
        self.receiver = json.loads((ROOT / "examples/receiver-v06.json").read_text(encoding="utf-8"))
        self.probe = self.diagnosis["runs"]["fragmentation_comparison"]["runs"]["df"]

    def test_runtime_distribution_and_compatibility_versions_agree(self):
        project = (ROOT / "pyproject.toml").read_text(encoding="utf-8").split("[project]", 1)[1]
        self.assertEqual(re.search(r'^version = "([^"]+)"', project, re.M)[1], VERSION)
        self.assertEqual(tunnelscope.VERSION, VERSION)
        for invalid in (None, {}, {"tunnelscope_version": 7}, {"tunnelscope_version": ""}):
            self.assertIsNone(declared_version(invalid))

    def test_mixed_correlation_records_claims_and_keeps_inputs_unchanged(self):
        self.probe["tunnelscope_version"] = "0.8.2"
        originals = copy.deepcopy((self.probe, self.receiver))
        joined = correlate_reports(self.probe, self.receiver)
        self.assertEqual(joined["tunnelscope_version"], VERSION)
        self.assertEqual(joined["input_versions"], {"probe": "0.8.2", "receiver": None})
        self.assertIn(("Receiver input version", "unknown (not recorded)"), version_details(joined))
        self.assertEqual((self.probe, self.receiver), originals)

    def test_comparison_and_diagnosis_capture_immediate_input_versions(self):
        comparison = self.diagnosis["runs"]["fragmentation_comparison"]
        first, second = comparison["runs"]["df"], comparison["runs"]["fragmentation_permitted"]
        first["tunnelscope_version"] = "0.8.1"
        second["tunnelscope_version"] = "0.8.2"
        compared = compare_fragmentation_reports(first, second)
        self.assertEqual(compared["input_versions"], {"df": "0.8.1", "fragmentation_permitted": "0.8.2"})
        paired = combine_reports(first, second)
        self.assertEqual(paired["input_versions"], {"a_to_b": "0.8.1", "b_to_a": "0.8.2"})
        search = self.diagnosis["runs"]["size_search"]
        built = build_diagnosis(compared, search)
        self.assertEqual(built["tunnelscope_version"], VERSION)
        self.assertEqual(built["input_versions"], {"fragmentation_comparison": VERSION, "size_search": None})

    def test_later_receiver_join_preserves_original_diagnosis_producer(self):
        for old in (None, "0.6.0"):
            with self.subTest(old=old):
                original = copy.deepcopy(self.diagnosis)
                if old is not None:
                    original["tunnelscope_version"] = old
                joined = correlate_diagnosis(original, self.receiver)
                self.assertEqual(declared_version(joined), old)
                evidence = joined["receiver_evidence"]
                self.assertEqual(evidence["tunnelscope_version"], VERSION)
                self.assertEqual(evidence["input_versions"], {"diagnosis": old, "receiver": None})
                self.assertNotIn("receiver_evidence", original)
                clean, = sanitize_reports([joined])
                self.assertEqual(clean["receiver_evidence"]["input_versions"], evidence["input_versions"])
                self.assertEqual(declared_version(clean), old)

    def test_untrusted_producer_claim_is_escaped_and_markdown_stays_bounded(self):
        joined = correlate_reports(self.probe, self.receiver)
        hostile = '<img src=x onerror="alert(1)">![x](https://invalid.test)'
        joined["tunnelscope_version"] = hostile
        html = render_report_html(joined)
        self.assertTrue("&lt;img src=x" in html)
        self.assertFalse(hostile in html)
        markdown = render_report_markdown(joined)
        self.assertIn(hostile, unescape(markdown))
        self.assertNotIn("<img", markdown)
        self.assertNotIn("![x]", markdown)
        joined["tunnelscope_version"] = "[" * 100000
        joined["input_versions"] = {"probe": "[" * 100000, "receiver": "[" * 100000}
        markdown = render_report_markdown(joined)
        self.assertLessEqual(len(markdown), 24000)
        markdown.encode("ascii")


if __name__ == "__main__":
    unittest.main()

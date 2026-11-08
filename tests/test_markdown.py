"""Checks for issue-ready Markdown without new network measurements."""

import copy
from html import unescape
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tunnelscope_core.markdown import render_report_markdown
from tunnelscope_core.reports import format_report
from tunnelscope_core.sanitize import sanitize_reports


class MarkdownTests(unittest.TestCase):
    def setUp(self):
        self.report = json.loads((ROOT / "examples/asymmetric-return-v07.json").read_text(encoding="utf-8"))["correlation"]

    def test_all_examples_render_without_modifying_inputs(self):
        for path in sorted((ROOT / "examples").glob("*.json")):
            with self.subTest(example=path.name):
                report = json.loads(path.read_text(encoding="utf-8"))
                original = copy.deepcopy(report)
                markdown = render_report_markdown(report)
                self.assertTrue(markdown.startswith("# TunnelScope - "))
                self.assertIn("## Interpretation limits", markdown)
                self.assertIn("inconclusive", markdown)
                self.assertLessEqual(len(markdown), 24000)
                markdown.encode("ascii")  # safe in redirected Windows consoles, too
                self.assertEqual(report, original)

    def test_joined_evidence_and_ids_remain_visible(self):
        markdown = unescape(render_report_markdown(self.report))
        self.assertIn("receiver_observed_sized_reply_missing", markdown)
        self.assertIn("receiver_reply_send_failed", markdown)
        self.assertIn("Observations (6 of 6 rows)", markdown)
        probe_id = self.report["results"][0]["probe_id"]
        self.assertIn(probe_id[:8] + "...", markdown)
        self.assertNotIn(probe_id, markdown)

    def test_untrusted_fields_cannot_add_rows_links_or_html(self):
        self.report["results"] = self.report["results"][:1]
        value = 'x|![track](https://example.invalid/pixel)\n# title\n```<img src=x> & **bold**'
        self.report["results"][0]["direction"] = value
        markdown = render_report_markdown(self.report)
        self.assertNotIn("![track]", markdown)
        self.assertNotIn("<img", markdown)
        self.assertNotIn("```", markdown)
        self.assertNotIn("https://", markdown)
        self.assertEqual(len([line for line in markdown.splitlines() if line.startswith("# ")]), 1)
        table = [line for line in markdown.splitlines() if line.startswith("| ")]
        self.assertEqual(len(table), 3)
        self.assertEqual(len({line.count("|") for line in table}), 1)
        self.assertIn(value.replace("\n", " [newline] "), unescape(markdown))

    def test_plain_source_stays_readable(self):
        markdown = render_report_markdown(self.report)
        row = self.report["results"][0]
        for value in (row["direction"], "receiver_observed_sized_reply_missing",
                      "Send attempted (UTC)", row["probe_id"][:8] + "..."):
            self.assertIn(value, markdown)
        self.assertIn("2026-11-05T22:51:31.856867+00:00", markdown)
        self.assertIn("| - |", markdown)  # missing values
        self.assertNotIn("&#46;", markdown)
        self.assertNotIn("&#95;", markdown)

    def test_mentions_references_autolinks_and_inline_markup_are_neutralized(self):
        self.report["results"] = self.report["results"][:1]
        cases = {
            "@octocat ping": "@octocat",
            "see #12 here": "#12",
            "and GH-7 or gh-8": "GH-7",
            "ftp://host and https://example.invalid": "://",
            "visit www.example.invalid": "www.example",
            "user@example.invalid": "@example",
            "_emphasis_ and *bold* and ~~strike~~": "_emphasis_",
            "$x^2$ math": "$x^2$",
            "emoji :smile: :+1: :100:": ":smile:",
            "2001:db8:abc:def::1": ":abc:",
            r"a\|b`code`": "`code`",
        }
        for value, forbidden in cases.items():
            with self.subTest(value=value):
                self.report["results"][0]["direction"] = value
                markdown = render_report_markdown(self.report)
                self.assertNotIn(forbidden, markdown)
                self.assertNotRegex(markdown, r"(?<!&#8203;)\$")  # every dollar sign is broken
                shown = unescape(markdown).replace("​", "")
                self.assertIn(value, shown)
                markdown.encode("ascii")
        # Intraword underscores and plain timestamps are left alone.
        self.report["results"][0]["direction"] = "snake_case_name at 22:51:31"
        self.assertIn("snake_case_name at 22:51:31", render_report_markdown(self.report))

    def test_sanitization_state_and_kept_timestamps_are_explicit(self):
        self.assertIn("No sanitization record", render_report_markdown(self.report))
        clean, = sanitize_reports([self.report], keep_timestamps=True)
        markdown = render_report_markdown(clean)
        self.assertIn("Sanitization record present", markdown)
        self.assertIn("Timestamps: kept.", markdown)
        self.assertNotIn("No sanitization record", markdown)

    def test_timestamp_columns_normalize_to_utc(self):
        self.report["results"][0]["send_attempted_at_utc"] = "2026-11-08T03:04:05+03:00"
        markdown = unescape(render_report_markdown(self.report))
        self.assertIn("2026-11-08T00:04:05+00:00", markdown)
        self.assertNotIn("2026-11-08T03:04:05+03:00", markdown)

    def test_row_and_character_limits_are_reported(self):
        self.report["results"] = self.report["results"] * 20
        markdown = render_report_markdown(self.report)
        self.assertIn("Observations (50 of 120 rows)", markdown)
        self.assertIn("Truncated to the first 50 rows", markdown)
        for row in self.report["results"]:
            row["direction"] = "[" * 10000
        markdown = render_report_markdown(self.report)
        self.assertLessEqual(len(markdown), 24000)
        self.assertIn("Truncated", markdown)
        self.assertNotIn("[" * 10000, markdown)
        self.assertEqual(len(self.report["results"]), 120)

    def test_empty_and_invalid_reports(self):
        report = {"schema_version": 1, "kind": "probe", "results": []}
        self.assertIn("No observations in this report", render_report_markdown(report))
        for invalid in ([], {"schema_version": 2}, {"schema_version": 1, "kind": "unknown"},
                        {"lab": "unknown", "probe": {"kind": "unknown"}}):
            with self.subTest(report=invalid), self.assertRaises(ValueError):
                render_report_markdown(invalid)

    def test_cli_defaults_to_text_and_markdown_works_with_ascii_stdout(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "correlation.json"
            path.write_text(json.dumps(self.report), encoding="utf-8")
            command = [sys.executable, str(ROOT / "tunnelscope.py"), "show", str(path)]
            environment = {**os.environ, "PYTHONIOENCODING": "ascii"}
            text = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=5)
            self.assertEqual(text.returncode, 0, text.stderr)
            self.assertEqual(text.stdout, format_report(self.report) + "\n")
            result = subprocess.run([*command, "--format", "markdown"], env=environment,
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, render_report_markdown(self.report))
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), self.report)

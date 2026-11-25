"""The Markdown export names port-unreachable attempts, as the text summary does."""

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tunnelscope_core.markdown import render_report_markdown


def failed(errno):
    return {"payload_bytes": 64, "attempt": 1, "probe_id": "0" * 32,
            "status": "socket_error", "error": "test", "errno": errno}


def probe_report(rows):
    return {"schema_version": 1, "kind": "probe", "results": rows}


def lab_report(rows):
    return {"lab": "closed-port", "probe": probe_report(rows)}


class MarkdownPortUnreachableTests(unittest.TestCase):
    def test_refused_errnos_from_each_platform_are_counted(self):
        for errno in (111, 10054):
            with self.subTest(errno=errno):
                markdown = render_report_markdown(probe_report([failed(errno)]))
                self.assertIn("- Port unreachable attempts: 1", markdown)
                self.assertIn("- Port unreachable attempts: 2", render_report_markdown(
                    probe_report([failed(errno), failed(errno)])))

    def test_lab_report_wrapping_a_probe_is_counted(self):
        markdown = render_report_markdown(lab_report([failed(111)]))
        self.assertIn("- Port unreachable attempts: 1", markdown)

    def test_timeouts_get_no_port_unreachable_line(self):
        timeout = {"payload_bytes": 64, "attempt": 2, "probe_id": "1" * 32, "status": "timeout"}
        markdown = render_report_markdown(probe_report([timeout]))
        self.assertNotIn("Port unreachable attempts", markdown)

    def test_report_is_not_modified(self):
        report = probe_report([failed(111)])
        render_report_markdown(report)
        self.assertEqual(report["results"][0]["errno"], 111)


if __name__ == "__main__":
    unittest.main()

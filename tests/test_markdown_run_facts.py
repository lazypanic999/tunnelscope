"""The Markdown export carries the run facts the HTML cards show."""

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tunnelscope_core.markdown import render_report_markdown


def receiver_report(receiver, exit_reason="idle_timeout"):
    return {"schema_version": 1, "kind": "receiver_observations", "exit_reason": exit_reason,
            "receiver": receiver, "observations": []}


def probe_report(**extra):
    row = {"payload_bytes": 64, "attempt": 1, "probe_id": "0" * 32, "status": "timeout"}
    return {"schema_version": 1, "kind": "probe", "results": [row, dict(row, attempt=2)],
            "settings": {"payload_sizes": [64, 128], "count": 2}, **extra}


class MarkdownReceiverFactsTests(unittest.TestCase):
    def test_exit_reason_and_ipv4_address(self):
        markdown = render_report_markdown(receiver_report({"bind_ipv4": "0.0.0.0", "port": 9471}))
        self.assertIn("- Receiver exit reason: idle_timeout", markdown)
        self.assertIn("- Listening on: 0.0.0.0:9471", markdown)

    def test_ipv6_address_is_bracketed(self):
        markdown = render_report_markdown(receiver_report({"bind_ipv6": "::1", "port": 9471}, "max_packets"))
        self.assertIn("- Receiver exit reason: max_packets", markdown)
        self.assertIn("- Listening on: &#91;::1&#93;:9471", markdown)

    def test_missing_or_malformed_endpoint_has_no_address_line(self):
        for receiver in (None, {}, {"port": 9471}, {"bind_ipv4": "0.0.0.0", "port": True},
                         {"bind_ipv4": 7, "port": 9471}):
            with self.subTest(receiver=receiver):
                markdown = render_report_markdown(receiver_report(receiver))
                self.assertIn("- Receiver exit reason: idle_timeout", markdown)
                self.assertNotIn("Listening on", markdown)

    def test_missing_exit_reason_says_unknown(self):
        report = receiver_report({"bind_ipv4": "0.0.0.0", "port": 9471})
        report.pop("exit_reason")
        self.assertIn("- Receiver exit reason: unknown", render_report_markdown(report))


class MarkdownInterruptedRunTests(unittest.TestCase):
    def test_interrupted_probe_says_how_much_was_recorded(self):
        markdown = render_report_markdown(probe_report(exit_reason="interrupted"))
        self.assertIn("- Interrupted run: 2 of 4 planned attempts recorded before Ctrl+C", markdown)

    def test_unknown_plan_is_shown_as_a_question_mark(self):
        report = probe_report(exit_reason="interrupted")
        report["settings"] = {"payload_sizes": [64], "count": "2"}
        self.assertIn("- Interrupted run: 2 of ? planned", render_report_markdown(report))

    def test_lab_report_wrapping_an_interrupted_probe(self):
        markdown = render_report_markdown({"lab": "partial", "probe": probe_report(exit_reason="interrupted")})
        self.assertIn("- Interrupted run: 2 of 4", markdown)

    def test_complete_probe_has_no_interrupted_line(self):
        self.assertNotIn("Interrupted run", render_report_markdown(probe_report()))


if __name__ == "__main__":
    unittest.main()

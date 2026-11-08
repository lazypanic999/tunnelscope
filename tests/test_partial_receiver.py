"""An interrupted receiver can record arrival before its send outcome exists."""

from contextlib import redirect_stdout
from html import unescape
from io import StringIO
import json
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tunnelscope_core import network
from tunnelscope_core.diagnose import build_diagnosis, correlate_diagnosis
from tunnelscope_core.fragmentation import compare_fragmentation_reports
from tunnelscope_core.markdown import render_report_markdown
from tunnelscope_core.reports import correlate_reports, format_report, summarize_results
from tunnelscope_core.view import render_report_html


def probe_run(index, df=True):
    rows = [{"probe_id": f"{index:032x}", "payload_bytes": 64, "attempt": 1,
             "status": "timeout", "return_status": "no_reply"}]
    return {"schema_version": 1, "kind": "probe", "run_id": f"{index:016x}",
            "target": {"ipv4": "127.0.0.1", "port": 9471},
            "settings": {"payload_sizes": [64], "count": 1, "timeout_seconds": 1,
                         "dont_fragment": df, "sized_reply": True},
            "fragmentation_mode": "df" if df else "permitted", "results": rows,
            "summary": {"by_payload_size": summarize_results([64], rows)}}


def incomplete_observation(probe):
    return {"probe_id": probe["results"][0]["probe_id"], "run_id": probe["run_id"],
            "payload_bytes": 64, "reply_kind": "sized", "reply_bytes": 64}


class PartialReceiverTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith("linux") or sys.platform == "win32",
                         "sized receiver supports Linux and Windows")
    def test_interrupt_during_send_saves_an_unverified_reply(self):
        probe = probe_run(1)
        token, run = bytes.fromhex(probe["results"][0]["probe_id"]), bytes.fromhex(probe["run_id"])
        data = network.HEADER.pack(network.MAGIC, token, 64) + run + network.REPLY_REQUEST
        data += bytes(64 - len(data))
        sock = MagicMock()
        sock.__enter__.return_value = sock
        sock.family = socket.AF_INET
        sock.getsockname.return_value = ("127.0.0.1", 9471)
        sock.recvfrom.return_value = (data, ("127.0.0.1", 12345))
        sock.sendto.side_effect = KeyboardInterrupt
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receiver.json"
            with patch.object(network.socket, "socket", return_value=sock), \
                    patch.object(network, "disable_reply_fragmentation", return_value="test disabled"), \
                    redirect_stdout(StringIO()), self.assertRaises(KeyboardInterrupt):
                network.receive("127.0.0.1", 9471, 1, 1, path, sized_reply=True)
            receiver = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(receiver["exit_reason"], "interrupted")
        self.assertNotIn("ack_send_status", receiver["observations"][0])
        joined = correlate_reports(probe, receiver)
        self.assertEqual(joined["results"][0]["return_evidence"], "receiver_reply_send_unverified")
        self.assertEqual(joined["summary"]["receiver_reply_send_unverified"], 1)
        self.assertEqual(joined["summary"]["sized_reply_missing_after_arrival"], 0)
        self.assertEqual(joined["summary"]["receiver_reply_send_failed"], 0)
        self.assertIn("Receiver reply sends unverified: 1", format_report(joined))
        for renderer in (render_report_html, render_report_markdown):
            self.assertTrue("receiver_reply_send_unverified" in unescape(renderer(joined)))
        self.assertTrue("Unverified receiver reply sends" in render_report_html(joined))
        self.assertIn("Receiver reply sends without recorded outcome", render_report_markdown(joined))

    def test_unknown_send_result_does_not_become_sent_small_or_sized_reply(self):
        probe = probe_run(1)
        for kind in (None, "sized"):
            for status in (None, "pending"):
                with self.subTest(kind=kind, status=status):
                    observation = {**incomplete_observation(probe), "reply_kind": kind, "ack_send_status": status}
                    receiver = {"schema_version": 1, "kind": "receiver_observations", "observations": [observation]}
                    joined = correlate_reports(probe, receiver)
                    self.assertEqual(joined["results"][0]["return_evidence"], "receiver_reply_send_unverified")

    def test_diagnosis_sums_unverified_send_outcomes_across_runs(self):
        df, permitted, search = probe_run(1), probe_run(2, df=False), probe_run(3)
        search["summary"]["search"] = {"assessment": "inconclusive", "observed_interval_payload_bytes": None}
        diagnosis = build_diagnosis(compare_fragmentation_reports(df, permitted), search)
        receiver = {"schema_version": 1, "kind": "receiver_observations", "exit_reason": "interrupted",
                    "observations": [incomplete_observation(run) for run in (df, permitted, search)]}
        joined = correlate_diagnosis(diagnosis, receiver)
        summary = joined["receiver_evidence"]["summary"]
        self.assertEqual(summary["receiver_reply_send_unverified"], 3)
        self.assertEqual(summary["receiver_observed"], 3)
        self.assertEqual(summary["sized_reply_missing_after_arrival"], 0)
        self.assertIn("Receiver reply sends unverified: 3", format_report(joined))


if __name__ == "__main__":
    unittest.main()

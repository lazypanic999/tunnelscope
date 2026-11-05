"""Checks for opt-in same-sized replies (return-path evidence)."""

import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import tunnelscope
from tunnelscope_core.network import (
    ACK, HEADER, MAGIC, REPLY_REQUEST, SIZED_ACK, SIZED_REPLY_MIN_BYTES, probe, receive, sized_reply_for,
)
from tunnelscope_core.reports import correlate_reports, format_report
from tunnelscope_core.view import render_report_html

NETNS = os.environ.get("TUNNELSCOPE_RUN_NETNS_TESTS") == "1" and sys.platform.startswith("linux")


class FakeReceiver:
    """A loopback UDP peer whose reply to each probe is chosen by ``answer(data)``."""

    def __init__(self, answer, packets):
        self.answer, self.packets = answer, packets
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(5)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self):
        for _ in range(self.packets):
            try:
                data, peer = self.sock.recvfrom(8193)
            except OSError:
                return
            reply = self.answer(data)
            if reply is not None:
                self.sock.sendto(reply, peer)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.thread.join(timeout=10)
        self.sock.close()


def small_ack(data):
    _, token, size = HEADER.unpack_from(data)
    return HEADER.pack(ACK, token, size)


def start_receiver(*extra):
    process = subprocess.Popen(
        [sys.executable, str(Path(tunnelscope.__file__)), "receive", "--port", "0", "--idle-timeout", "5", *extra],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    line = process.stdout.readline()
    if not line.startswith("Listening on"):
        process.kill()
        raise AssertionError(process.stderr.read())
    return process, int(line.strip().rsplit(":", 1)[1])


def stop(process):
    if process.poll() is None:
        process.kill()
    process.wait()
    process.stdout.close()
    process.stderr.close()


class SizedReplyProtocolTests(unittest.TestCase):
    def test_reply_mirrors_size_and_requires_the_marker(self):
        token, run_id = bytes(range(16)), b"\x01" * 8
        request = HEADER.pack(MAGIC, token, 1200) + run_id + REPLY_REQUEST
        request += bytes(1200 - len(request))
        reply = sized_reply_for(request)
        self.assertEqual(len(reply), 1200)
        self.assertEqual(reply[:HEADER.size], HEADER.pack(SIZED_ACK, token, 1200))
        self.assertEqual(reply[HEADER.size:HEADER.size + 8], run_id)
        plain = HEADER.pack(MAGIC, token, 1200) + run_id + bytes(1200 - HEADER.size - 8)
        self.assertIsNone(sized_reply_for(plain))
        self.assertIsNone(sized_reply_for(request[:SIZED_REPLY_MIN_BYTES - 1]))

    def test_sender_records_sized_small_and_missing_replies(self):
        def answer(data):
            size = len(data)
            if size >= 1000:
                return None  # same-sized reply lost on the return path
            return sized_reply_for(data) if size >= 500 else small_ack(data)

        with FakeReceiver(answer, 3) as peer:
            report = probe("127.0.0.1", peer.port, [64, 600, 1200], 1, 1, sized_reply=True)
        rows = report["results"]
        self.assertEqual([row["status"] for row in rows], ["acknowledged", "acknowledged", "timeout"])
        self.assertEqual([row["return_status"] for row in rows], ["small_ack_only", "sized_reply_received", "no_reply"])
        self.assertEqual([row.get("reply_bytes") for row in rows], [HEADER.size, 600, None])
        self.assertTrue(report["settings"]["sized_reply"])
        counts = [row["return_status_counts"] for row in report["summary"]["by_payload_size"]]
        self.assertEqual(counts[1], {"sized_reply_received": 1, "small_ack_only": 0, "no_reply": 0})
        # A small-ACK-only answer means the return path was not actually tested.
        self.assertIn("same_sized_reverse_payload_test", report["evidence"]["missing_evidence"])
        text = format_report(report)
        self.assertIn("Sized reply", text)
        self.assertIn("1/1", text)
        self.assertIn("Reply bytes", render_report_html(report))

    def test_all_sized_replies_remove_reverse_test_from_missing_evidence(self):
        with FakeReceiver(sized_reply_for, 2) as peer:
            report = probe("127.0.0.1", peer.port, [64, 1400], 1, 1, sized_reply=True)
        self.assertEqual([row["return_status"] for row in report["results"]], ["sized_reply_received"] * 2)
        self.assertNotIn("same_sized_reverse_payload_test", report["evidence"]["missing_evidence"])

    def test_only_missing_replies_do_not_count_as_a_reverse_test(self):
        with FakeReceiver(lambda data: None, 1) as peer:
            report = probe("127.0.0.1", peer.port, [1400], 1, 1, sized_reply=True)
        self.assertEqual(report["results"][0]["return_status"], "no_reply")
        self.assertIn("same_sized_reverse_payload_test", report["evidence"]["missing_evidence"])

    def test_sender_ignores_sized_reply_it_did_not_request(self):
        def answer(data):
            _, token, size = HEADER.unpack_from(data)
            reply = HEADER.pack(SIZED_ACK, token, size) + data[HEADER.size:HEADER.size + 8]
            return reply + bytes(size - len(reply))

        with FakeReceiver(answer, 1) as peer:
            report = probe("127.0.0.1", peer.port, [1200], 1, 1)
        self.assertEqual(report["results"][0]["status"], "timeout")
        self.assertNotIn("return_status", report["results"][0])
        self.assertNotIn("sized_reply", report["settings"])

    def test_sized_reply_needs_room_for_the_marker(self):
        with self.assertRaisesRegex(ValueError, str(SIZED_REPLY_MIN_BYTES)):
            probe("127.0.0.1", 9, [32, 64], 1, 1, sized_reply=True)

    @unittest.skipIf(sys.platform.startswith("linux"), "non-Linux behavior")
    def test_receiver_sized_reply_requires_linux(self):
        with self.assertRaisesRegex(ValueError, "requires Linux"):
            receive("127.0.0.1", 0, 1, 1, sized_reply=True)

    def test_v07_sender_with_receiver_without_sized_reply_gets_small_ack(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "receiver.json"
            process, port = start_receiver("--max-packets", "2", "--output", str(output))
            try:
                report = probe("127.0.0.1", port, [64, 1400], 1, 1, sized_reply=True)
                self.assertEqual(process.wait(timeout=6), 0)
            finally:
                stop(process)
            observations = json.loads(output.read_text(encoding="utf-8"))["observations"]
        self.assertEqual([row["return_status"] for row in report["results"]], ["small_ack_only"] * 2)
        self.assertEqual([row["reply_bytes"] for row in observations], [HEADER.size] * 2)
        self.assertNotIn("reply_kind", observations[0])

    @unittest.skipUnless(sys.platform.startswith("linux"), "receiver --sized-reply requires Linux")
    def test_real_receiver_sends_sized_replies_only_when_requested(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "receiver.json"
            process, port = start_receiver("--sized-reply", "--max-packets", "4", "--output", str(output))
            try:
                sized = probe("127.0.0.1", port, [64, 1400, 8192], 1, 1, sized_reply=True)
                plain = probe("127.0.0.1", port, [1400], 1, 1)  # a v0.6-style sender
                self.assertEqual(process.wait(timeout=6), 0)
            finally:
                stop(process)
            receiver = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual([row["return_status"] for row in sized["results"]], ["sized_reply_received"] * 3)
        self.assertEqual([row["reply_bytes"] for row in sized["results"]], [64, 1400, 8192])
        self.assertEqual(plain["results"][0]["status"], "acknowledged")
        self.assertTrue(receiver["receiver"]["sized_reply"])
        self.assertEqual([row.get("reply_kind") for row in receiver["observations"]], ["sized"] * 3 + [None])
        self.assertEqual([row["reply_bytes"] for row in receiver["observations"]], [64, 1400, 8192, HEADER.size])
        self.assertIn("sized replies enabled", format_report(receiver))


class SizedReplyCorrelationTests(unittest.TestCase):
    @staticmethod
    def reports():
        run_id = "c" * 16
        sent = [
            {"probe_id": "1" * 32, "payload_bytes": 1200, "status": "acknowledged", "return_status": "sized_reply_received"},
            {"probe_id": "2" * 32, "payload_bytes": 1400, "status": "timeout", "return_status": "no_reply"},
            {"probe_id": "3" * 32, "payload_bytes": 1400, "status": "timeout", "return_status": "no_reply"},
            {"probe_id": "4" * 32, "payload_bytes": 1400, "status": "timeout", "return_status": "no_reply"},
        ]
        probe_report = {"schema_version": 1, "kind": "probe", "run_id": run_id, "settings": {"sized_reply": True},
                        "source": {"ipv4": "192.0.2.1"}, "target": {"ipv4": "198.51.100.2", "port": 9471},
                        "results": sent}
        observations = [
            {"probe_id": "1" * 32, "run_id": run_id, "payload_bytes": 1200, "reply_kind": "sized",
             "reply_bytes": 1200, "ack_send_status": "sent"},
            {"probe_id": "2" * 32, "run_id": run_id, "payload_bytes": 1400, "reply_kind": "sized",
             "reply_bytes": 1400, "ack_send_status": "sent"},
            {"probe_id": "3" * 32, "run_id": run_id, "payload_bytes": 1400, "reply_kind": "sized",
             "reply_bytes": 1400, "ack_send_status": "socket_error", "ack_send_errno": 90},
        ]
        receiver_report = {"schema_version": 1, "kind": "receiver_observations",
                           "receiver": {"bind_ipv4": "198.51.100.2", "port": 9471, "sized_reply": True},
                           "observations": observations}
        return probe_report, receiver_report

    def test_return_evidence_separates_arrival_from_missing_reply(self):
        correlation = correlate_reports(*self.reports())
        self.assertEqual([row["return_evidence"] for row in correlation["results"]], [
            "sized_reply_returned", "receiver_observed_sized_reply_missing",
            "receiver_reply_send_failed", "no_receiver_observation",
        ])
        self.assertEqual(correlation["results"][1]["receiver_reply_bytes"], 1400)
        self.assertEqual(correlation["summary"]["sized_reply_missing_after_arrival"], 1)
        self.assertEqual(correlation["summary"]["receiver_reply_send_failed"], 1)
        self.assertIn("does not identify where", correlation["interpretation"])
        text = format_report(correlation)
        self.assertIn("Sized replies missing after arrival: 1", text)
        self.assertIn("receiver_observed_sized_reply_missing", text)
        self.assertIn("Return evidence", render_report_html(correlation))

    def test_correlation_without_sized_replies_is_unchanged(self):
        probe_report, receiver_report = self.reports()
        del probe_report["settings"]["sized_reply"]
        correlation = correlate_reports(probe_report, receiver_report)
        self.assertNotIn("return_evidence", correlation["results"][0])
        self.assertNotIn("sized_reply_missing_after_arrival", correlation["summary"])
        self.assertNotIn("Return evidence", render_report_html(correlation))

    @unittest.skipUnless(NETNS, "opt-in privileged Linux network lab")
    def test_asymmetric_return_mtu_lab(self):
        if not shutil.which("sysctl"):
            self.skipTest("sysctl is required for the asymmetric return lab")
        script = Path(__file__).resolve().parents[1] / "labs" / "asymmetric_return.py"
        result = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        sized = report["probe"]
        self.assertEqual([row["status"] for row in sized["results"]], ["acknowledged"] * 4 + ["timeout"] * 2)
        self.assertEqual(report["small_ack_probe"]["results"][0]["status"], "acknowledged")
        correlation = report["correlation"]["results"]
        self.assertTrue(all(row["receiver_observed"] for row in correlation))
        self.assertEqual([row["return_evidence"] for row in correlation[:4]], ["sized_reply_returned"] * 4)
        # The first oversized reply leaves the receiver and is dropped by the router;
        # once ICMP feedback reaches the receiver, its kernel may reject the next one.
        self.assertEqual(correlation[4]["return_evidence"], "receiver_observed_sized_reply_missing")
        self.assertIn(correlation[5]["return_evidence"],
                      ("receiver_observed_sized_reply_missing", "receiver_reply_send_failed"))
        self.assertIn("Sized replies missing after arrival", tunnelscope.format_report(report))


if __name__ == "__main__":
    unittest.main()

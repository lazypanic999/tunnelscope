"""A Windows receiver keeps listening after an earlier reply hit a closed port."""

from contextlib import redirect_stdout
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


def probe_bytes(index, size=64):
    data = network.HEADER.pack(network.MAGIC, bytes([index]) * 16, size) + bytes([index]) * 8
    return data + bytes(size - len(data))


def run_receiver(recv_effects, max_packets, platform):
    sock = MagicMock()
    sock.__enter__.return_value = sock
    sock.family = socket.AF_INET
    sock.getsockname.return_value = ("127.0.0.1", 9471)
    sock.recvfrom.side_effect = recv_effects
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "receiver.json"
        with patch.object(network.socket, "socket", return_value=sock), \
                patch.object(network.sys, "platform", platform), redirect_stdout(StringIO()):
            try:
                network.receive("127.0.0.1", 9471, max_packets, 1, path)
                error = None
            except OSError as caught:
                error = caught
        return json.loads(path.read_text(encoding="utf-8")), error, sock


class ReceiverConnectionResetTests(unittest.TestCase):
    peer = ("127.0.0.1", 50000)

    def test_windows_reset_notice_is_skipped_and_not_counted_as_a_packet(self):
        effects = [(probe_bytes(1), self.peer), ConnectionResetError(10054, "reset"),
                   ConnectionResetError(10054, "reset"), (probe_bytes(2), self.peer)]
        report, error, sock = run_receiver(effects, 2, "win32")
        self.assertIsNone(error)
        self.assertEqual(report["exit_reason"], "max_packets")
        self.assertEqual([row["probe_id"] for row in report["observations"]],
                         [(bytes([1]) * 16).hex(), (bytes([2]) * 16).hex()])
        self.assertEqual(sock.sendto.call_count, 2)

    def test_windows_reset_then_idle_timeout_ends_normally(self):
        effects = [ConnectionResetError(10054, "reset"), socket.timeout()]
        report, error, _ = run_receiver(effects, 5, "win32")
        self.assertIsNone(error)
        self.assertEqual(report["exit_reason"], "idle_timeout")
        self.assertEqual(report["observations"], [])

    def test_reset_on_other_platforms_is_still_a_socket_error(self):
        effects = [(probe_bytes(1), self.peer), ConnectionResetError(104, "reset")]
        report, error, _ = run_receiver(effects, 5, "linux")
        self.assertIsInstance(error, ConnectionResetError)
        self.assertEqual(report["exit_reason"], "socket_error")
        self.assertEqual(len(report["observations"]), 1)


if __name__ == "__main__":
    unittest.main()

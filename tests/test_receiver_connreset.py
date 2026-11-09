"""A Windows receiver keeps listening after receive errors that are not about probes."""

from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import socket
import sys
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tunnelscope_core import network


def then_idle(effects):
    """Mocked receive results followed by endless idle timeouts.

    On Windows the receiver waits in slices and treats one timeout as "keep
    waiting" until its own idle deadline passes, so a finite list would run out.
    """
    yield from effects
    while True:
        yield socket.timeout()


def probe_bytes(index, size=64):
    data = network.HEADER.pack(network.MAGIC, bytes([index]) * 16, size) + bytes([index]) * 8
    return data + bytes(size - len(data))


def run_receiver(recv_effects, max_packets, platform):
    sock = MagicMock()
    sock.__enter__.return_value = sock
    sock.family = socket.AF_INET
    sock.getsockname.return_value = ("127.0.0.1", 9471)
    sock.recvfrom.side_effect = then_idle(recv_effects)
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

    def test_windows_oversized_datagram_is_counted_and_skipped(self):
        oversized = OSError(10040, "message too long")
        oversized.winerror = 10040
        effects = [oversized, (probe_bytes(1), self.peer), socket.timeout()]
        report, error, sock = run_receiver(effects, 5, "win32")
        self.assertIsNone(error)
        self.assertEqual(report["exit_reason"], "idle_timeout")
        self.assertEqual(len(report["observations"]), 1)
        # Like a truncated datagram on Linux, it uses one of the --max-packets slots.
        report, error, _ = run_receiver([oversized, (probe_bytes(1), self.peer)], 1, "win32")
        self.assertIsNone(error)
        self.assertEqual(report["exit_reason"], "max_packets")
        self.assertEqual(report["observations"], [])

    def test_other_windows_receive_errors_still_stop_the_receiver(self):
        failure = OSError(10050, "network is down")
        failure.winerror = 10050
        report, error, _ = run_receiver([failure], 5, "win32")
        self.assertIs(error, failure)
        self.assertEqual(report["exit_reason"], "socket_error")

    def test_reset_on_other_platforms_is_still_a_socket_error(self):
        effects = [(probe_bytes(1), self.peer), ConnectionResetError(104, "reset")]
        report, error, _ = run_receiver(effects, 5, "linux")
        self.assertIsInstance(error, ConnectionResetError)
        self.assertEqual(report["exit_reason"], "socket_error")
        self.assertEqual(len(report["observations"]), 1)


class WindowsSlicedWaitTests(unittest.TestCase):
    def test_idle_deadline_is_kept_across_short_waits(self):
        started = time.monotonic()
        report, error, sock = run_receiver([], 5, "win32")
        elapsed = time.monotonic() - started
        self.assertIsNone(error)
        self.assertEqual(report["exit_reason"], "idle_timeout")
        self.assertGreaterEqual(elapsed, 0.9)  # run_receiver uses a 1-second idle timeout
        waits = [call.args[0] for call in sock.settimeout.call_args_list[1:]]
        self.assertTrue(waits and all(0 < wait <= network.WINDOWS_RECV_SLICE_SECONDS for wait in waits))

    def test_other_platforms_wait_once_for_the_whole_idle_timeout(self):
        report, _, sock = run_receiver([socket.timeout()], 5, "linux")
        self.assertEqual(report["exit_reason"], "idle_timeout")
        self.assertEqual([call.args[0] for call in sock.settimeout.call_args_list], [1])

    @unittest.skipUnless(sys.platform == "win32", "Windows-only: Ctrl+C does not wake a socket wait there")
    def test_interrupt_on_windows_saves_the_capture_promptly(self):
        import _thread
        import threading
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receiver.json"
            timer = threading.Timer(0.5, _thread.interrupt_main)
            started = time.monotonic()
            timer.start()
            try:
                with redirect_stdout(StringIO()), self.assertRaises(KeyboardInterrupt):
                    network.receive("127.0.0.1", 0, 10, 20, path)
            finally:
                timer.cancel()
            elapsed = time.monotonic() - started
            report = json.loads(path.read_text(encoding="utf-8"))
        self.assertLess(elapsed, 5)
        self.assertEqual(report["exit_reason"], "interrupted")


if __name__ == "__main__":
    unittest.main()

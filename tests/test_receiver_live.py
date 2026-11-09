"""The receiver prints one line per probe so operators see arrivals as they happen."""

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
from tunnelscope_core.network import live_line


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


def fake_socket(recv_effects, send_effect=None):
    sock = MagicMock()
    sock.__enter__.return_value = sock
    sock.family = socket.AF_INET
    sock.getsockname.return_value = ("127.0.0.1", 9471)
    sock.recvfrom.side_effect = then_idle(recv_effects)
    sock.sendto.side_effect = send_effect
    return sock


class BrokenStdout(StringIO):
    def write(self, text):
        if "bytes from" in text:
            raise BrokenPipeError(32, "broken pipe")
        return super().write(text)


class LiveLineTests(unittest.TestCase):
    def test_sent_small_ack_and_sized_reply(self):
        base = {"payload_bytes": 1400, "source_ipv4": "192.0.2.1", "run_id": "ab" * 8,
                "probe_id": "cd" * 16, "reply_bytes": 24, "ack_send_status": "sent"}
        self.assertEqual(live_line(base),
                         " 1400 bytes from 192.0.2.1  run abababab  probe cdcdcdcd  ACK sent (24 bytes)")
        sized = {**base, "reply_kind": "sized", "reply_bytes": 1400}
        self.assertTrue(live_line(sized).endswith("sized reply sent (1400 bytes)"))

    def test_failed_send_and_ipv6_source(self):
        row = {"payload_bytes": 1600, "source_ipv6": "fd00::1", "run_id": "01" * 8,
               "probe_id": "02" * 16, "reply_kind": "sized", "reply_bytes": 1600,
               "ack_send_status": "socket_error", "ack_send_errno": 10040}
        line = live_line(row)
        self.assertIn("from fd00::1", line)
        self.assertTrue(line.endswith("sized reply send failed (errno 10040)"))


class ReceiverLiveOutputTests(unittest.TestCase):
    peer = ("127.0.0.1", 50000)

    def run_receiver(self, sock, live, stdout):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receiver.json"
            with patch.object(network.socket, "socket", return_value=sock), redirect_stdout(stdout):
                network.receive("127.0.0.1", 9471, 5, 1, path, live=live)
            return json.loads(path.read_text(encoding="utf-8"))

    def test_live_prints_one_line_per_probe_after_the_listening_line(self):
        out = StringIO()
        sock = fake_socket([(probe_bytes(1), self.peer), (b"junk" * 10, self.peer),
                            (probe_bytes(2, 200), self.peer), socket.timeout()])
        report = self.run_receiver(sock, True, out)
        lines = out.getvalue().splitlines()
        self.assertEqual(lines[0], "Listening on 127.0.0.1:9471")
        self.assertEqual(len(lines), 3)  # the junk datagram gets no line
        self.assertIn("   64 bytes from 127.0.0.1", lines[1])
        self.assertIn("  200 bytes from 127.0.0.1", lines[2])
        self.assertEqual(len(report["observations"]), 2)

    def test_library_default_stays_quiet(self):
        out = StringIO()
        self.run_receiver(fake_socket([(probe_bytes(1), self.peer), socket.timeout()]), False, out)
        self.assertEqual(out.getvalue().splitlines(), ["Listening on 127.0.0.1:9471"])

    def test_broken_stdout_does_not_end_the_capture(self):
        sock = fake_socket([(probe_bytes(1), self.peer), (probe_bytes(2), self.peer), socket.timeout()])
        report = self.run_receiver(sock, True, BrokenStdout())
        self.assertEqual(report["exit_reason"], "idle_timeout")
        self.assertEqual(len(report["observations"]), 2)
        self.assertEqual(sock.sendto.call_count, 2)

    def test_cli_quiet_flag_turns_live_output_off(self):
        import tunnelscope
        for argv, expected in ((["receive"], True), (["receive", "--quiet"], False)):
            with self.subTest(argv=argv), patch.object(tunnelscope, "receive") as receive, \
                    patch.object(sys, "argv", ["tunnelscope", *argv]):
                tunnelscope.main()
                self.assertIs(receive.call_args.kwargs["live"], expected)


if __name__ == "__main__":
    unittest.main()

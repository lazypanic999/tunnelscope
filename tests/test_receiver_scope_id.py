"""Receiver reports retain a nonzero IPv6 scope ID as local metadata."""

import json
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tunnelscope_core.network import receive


class ReceiverScopeIdTests(unittest.TestCase):
    def _run_with_mock_socket(self, family, getsockname_return, expected_key, bind_host):
        mock_sock = MagicMock()
        mock_sock.family = family
        mock_sock.getsockname.return_value = getsockname_return
        mock_sock.recvfrom.side_effect = socket.timeout
        # Context manager support.
        mock_sock.__enter__.return_value = mock_sock
        mock_sock.__exit__.return_value = None

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "receiver.json"
            with patch("socket.socket", return_value=mock_sock), \
                    patch("tunnelscope_core.network.utc_now", return_value="2000-01-01T00:00:00+00:00"), \
                    patch("socket.getaddrinfo", return_value=[(family, socket.SOCK_DGRAM, 0, "", (bind_host, 9471))]):
                receive(bind_host, 9471, 1, 1, output=output,
                        family="ipv6" if family == socket.AF_INET6 else "ipv4")
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["receiver"][expected_key], getsockname_return[0])
            self.assertEqual(report["receiver"]["port"], getsockname_return[1])
            return report["receiver"]

    def test_ipv6_nonzero_scope_id_is_retained(self):
        receiver = self._run_with_mock_socket(
            socket.AF_INET6, ("fe80::1", 9471, 0, 7), "bind_ipv6", "fe80::1")
        self.assertEqual(receiver["scope_id"], 7)

    def test_ipv6_zero_scope_id_is_omitted(self):
        receiver = self._run_with_mock_socket(
            socket.AF_INET6, ("::1", 9471, 0, 0), "bind_ipv6", "::1")
        self.assertNotIn("scope_id", receiver)

    def test_ipv4_has_no_scope_id(self):
        receiver = self._run_with_mock_socket(
            socket.AF_INET, ("127.0.0.1", 9471), "bind_ipv4", "127.0.0.1")
        self.assertNotIn("scope_id", receiver)


if __name__ == "__main__":
    unittest.main()

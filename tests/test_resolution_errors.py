"""Name resolution failures say which host and address family failed."""

from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tunnelscope_core.network import udp_address


def failing_lookup(*args, **kwargs):
    raise socket.gaierror(11001, "getaddrinfo failed")


class ResolutionErrorTests(unittest.TestCase):
    def resolve_error(self, host, family="auto"):
        with patch("socket.getaddrinfo", failing_lookup), self.assertRaises(ValueError) as caught:
            udp_address(host, 9471, family)
        return str(caught.exception)

    def test_unknown_hostname_names_the_host_and_family(self):
        message = self.resolve_error("nonexistent.invalid")
        self.assertIn("cannot resolve 'nonexistent.invalid' to an IPv4 address", message)
        self.assertNotIn("--family", message)
        self.assertIn("IPv6 address", self.resolve_error("nonexistent.invalid", "ipv6"))

    def test_literal_of_the_other_family_suggests_the_fix(self):
        self.assertIn("::1 is an IPv6 address, so drop --family or use --family ipv6",
                      self.resolve_error("::1", "ipv4"))
        self.assertIn("127.0.0.1 is an IPv4 address, so drop --family or use --family ipv4",
                      self.resolve_error("127.0.0.1", "ipv6"))
        self.assertIn("fe80::1%eth0 is an IPv6 address", self.resolve_error("fe80::1%eth0", "ipv4"))

    def test_error_is_a_value_error_for_the_cli(self):
        with patch("socket.getaddrinfo", failing_lookup):
            with self.assertRaises(ValueError) as caught:
                udp_address("nonexistent.invalid", 9471)
        self.assertIsInstance(caught.exception.__cause__, socket.gaierror)

    def test_successful_lookup_is_unchanged(self):
        family, address = udp_address("127.0.0.1", 9471)
        self.assertEqual(family, socket.AF_INET)
        self.assertEqual(address, ("127.0.0.1", 9471))


if __name__ == "__main__":
    unittest.main()

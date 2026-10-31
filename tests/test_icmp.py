"""Linux UDP error-queue parsing and report presentation."""

import errno
import socket
import unittest
from unittest.mock import Mock, patch

import tunnelscope
from tunnelscope_core import icmp
from tunnelscope_view import render_report_html


TOKEN = bytes.fromhex("ab" * 16)
HEADER = tunnelscope.HEADER.pack(tunnelscope.MAGIC, TOKEN, 1400)


class IcmpFeedbackTests(unittest.TestCase):
    def test_ipv4_and_ipv6_remote_size_feedback(self):
        cases = ((socket.AF_INET, socket.IPPROTO_IP, icmp.IP_RECVERR, 2, 3, 4,
                  "fragmentation_needed"),
                 (socket.AF_INET6, socket.IPPROTO_IPV6, icmp.IPV6_RECVERR, 3, 2, 0,
                  "packet_too_big"))
        for family, level, option, origin, icmp_type, code, message in cases:
            with self.subTest(family=family):
                control = icmp.EXTENDED_ERROR.pack(errno.EMSGSIZE, origin, icmp_type, code, 0, 1280, 0)
                event = icmp._decode_event(HEADER + b"body", [(level, option, control)], 0,
                                           family, HEADER)
                self.assertEqual(event["message"], message)
                self.assertEqual(event["origin"], "icmpv4" if family == socket.AF_INET else "icmpv6")
                self.assertEqual(event["reported_mtu_bytes"], 1280)
                self.assertTrue(event["quoted_probe_match"])
                self.assertEqual(event["icmp_type"], icmp_type)

    def test_local_error_and_unmatched_quote_are_not_remote_feedback(self):
        local = icmp.EXTENDED_ERROR.pack(errno.EMSGSIZE, 1, 0, 0, 0, 1280, 0)
        event = icmp._decode_event(HEADER, [(socket.IPPROTO_IP, icmp.IP_RECVERR, local)], 0,
                                   socket.AF_INET, HEADER)
        self.assertEqual(event["message"], "local_error")
        self.assertNotIn("icmp_type", event)
        remote = icmp.EXTENDED_ERROR.pack(errno.EMSGSIZE, 2, 3, 4, 0, 1280, 0)
        event = icmp._decode_event(b"wrong" + HEADER, [(socket.IPPROTO_IP, icmp.IP_RECVERR, remote)], 0,
                                   socket.AF_INET, HEADER)
        self.assertFalse(event["quoted_probe_match"])
        event = icmp._decode_event(b"short", [(socket.IPPROTO_IP, icmp.IP_RECVERR, remote)], 0,
                                   socket.AF_INET, HEADER)
        self.assertIsNone(event["quoted_probe_match"])

    def test_drain_is_bounded_and_distinguishes_empty_queue(self):
        sock = Mock()
        sock.family = socket.AF_INET
        sock.gettimeout.return_value = 1.0
        control = icmp.EXTENDED_ERROR.pack(errno.EMSGSIZE, 2, 3, 4, 0, 1280, 0)
        sock.recvmsg.side_effect = [
            (HEADER, [(socket.IPPROTO_IP, icmp.IP_RECVERR, control)], 0, None),
            BlockingIOError(errno.EAGAIN, "empty"),
        ]
        with patch.object(icmp.socket, "CMSG_SPACE", return_value=144, create=True), \
             patch.object(icmp.socket, "MSG_ERRQUEUE", 8192, create=True), \
             patch.object(icmp.socket, "MSG_DONTWAIT", 64, create=True):
            observation = icmp.drain_error_queue(sock, HEADER)
        self.assertEqual(observation["state"], "completed")
        self.assertEqual(len(observation["events"]), 1)
        self.assertTrue(observation["events"][0]["quoted_probe_match"])
        sock.setblocking.assert_called_with(False)
        sock.settimeout.assert_called_with(1.0)
        sock.recvmsg.reset_mock(side_effect=True)
        sock.recvmsg.return_value = (HEADER, [(socket.IPPROTO_IP, icmp.IP_RECVERR, control)], 0, None)
        with patch.object(icmp.socket, "CMSG_SPACE", return_value=144, create=True), \
             patch.object(icmp.socket, "MSG_ERRQUEUE", 8192, create=True), \
             patch.object(icmp.socket, "MSG_DONTWAIT", 64, create=True):
            limited = icmp.drain_error_queue(sock, HEADER)
        self.assertEqual(limited["state"], "limit_reached")
        self.assertEqual(len(limited["events"]), icmp.MAX_ERROR_QUEUE_ENTRIES)

    def test_unsupported_platform_rejected_before_socket(self):
        with patch.object(tunnelscope.sys, "platform", "win32"), \
             patch.object(tunnelscope.socket, "socket") as sock:
            with self.assertRaisesRegex(ValueError, "requires Linux"):
                tunnelscope.probe("127.0.0.1", 9471, [64], 1, 1,
                                  observe_icmp=True)
            sock.assert_not_called()

    def test_terminal_and_html_show_observation(self):
        report = {"schema_version": 1, "kind": "probe", "results": [{
            "payload_bytes": 1400, "attempt": 1, "status": "packet_too_large",
            "icmp_observation": {"state": "completed", "events": [{
                "message": "packet_too_big", "origin": "icmpv6", "icmp_type": 2,
                "icmp_code": 0, "reported_mtu_bytes": 1280,
                "quoted_probe_match": True,
            }]},
        }], "summary": {"by_payload_size": [{
            "payload_bytes": 1400,
            "status_counts": {"acknowledged": 0, "packet_too_large": 1,
                              "timeout": 0, "socket_error": 0},
            "assessment": "kernel_rejected_df_payload",
        }], "icmp_feedback": {"observation_state": "complete", "size_feedback_events": 1,
                              "token_matched_size_feedback_events": 1, "local_error_events": 0}}}
        rendered = tunnelscope.format_report(report)
        self.assertIn("ICMP size feedback: 1 observed (1 token matched)", rendered)
        self.assertIn("ICMP size", rendered)
        html = render_report_html(report)
        self.assertIn("ICMP feedback", html)
        self.assertIn("packet_too_big (matched, MTU 1280)", html)


if __name__ == "__main__":
    unittest.main()

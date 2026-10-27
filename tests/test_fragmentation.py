import errno
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import tunnelscope


class FragmentationTests(unittest.TestCase):
    def test_unsupported_platform_rejects_df_before_sending(self):
        with patch.object(tunnelscope.sys, "platform", "win32"), patch.object(tunnelscope.socket, "socket") as sock:
            with self.assertRaisesRegex(ValueError, "requires Linux"):
                tunnelscope.probe("127.0.0.1", 9471, [64], 1, 1, True)
            sock.assert_not_called()

    def test_emsgsize_has_separate_status_and_kernel_evidence(self):
        sock = Mock()
        sock.getsockopt.return_value = 1280
        error = OSError(errno.EMSGSIZE, "Message too long")
        result = tunnelscope.socket_failure(error, sock, True)
        self.assertEqual(result["status"], "packet_too_large")
        self.assertEqual(result["kernel_reported_mtu_bytes"], 1280)
        # The same errno outside DF mode must not acquire DF evidence.
        self.assertEqual(tunnelscope.socket_failure(error, sock, False)["status"], "socket_error")

    def test_unavailable_kernel_mtu_is_not_invented(self):
        sock = Mock()
        sock.getsockopt.side_effect = OSError(errno.ENOPROTOOPT, "Unavailable")
        result = tunnelscope.socket_failure(OSError(errno.EMSGSIZE, "Too large"), sock, True)
        self.assertNotIn("kernel_reported_mtu_bytes", result)

    def test_configuration_failure_does_not_fall_back(self):
        sock = Mock()
        sock.setsockopt.side_effect = OSError(errno.ENOPROTOOPT, "Unavailable")
        with self.assertRaises(OSError):
            tunnelscope.configure_fragmentation(sock, True)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux socket option")
    def test_real_socket_has_df_mode_enabled(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            tunnelscope.configure_fragmentation(sock, True)
            mode = sock.getsockopt(socket.IPPROTO_IP, tunnelscope.IP_MTU_DISCOVER)
            self.assertEqual(mode, tunnelscope.IP_PMTUDISC_DO)

    @unittest.skipUnless(os.environ.get("TUNNELSCOPE_RUN_NETNS_TESTS") == "1" and sys.platform.startswith("linux"), "opt-in privileged Linux network lab")
    def test_real_link_mtu_boundary_in_both_directions(self):
        script = Path(__file__).resolve().parents[1] / "labs" / "mtu_boundary.py"
        result = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, timeout=45)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(len(report["directions"]), 2)
        for direction in report["directions"]:
            self.assertEqual([r["status"] for r in direction["results"]], ["acknowledged", "acknowledged", "packet_too_large", "packet_too_large"])
            self.assertEqual([row["assessment"] for row in direction["summary"]["by_payload_size"]], ["delivery_observed", "delivery_observed", "kernel_rejected_df_payload", "kernel_rejected_df_payload"])
            self.assertEqual(direction["source"]["interface_mtu_bytes"], 1280)
            self.assertIn(direction["source"]["interface"], ("ts-a", "ts-b"))
            self.assertEqual(direction["evidence"]["hypotheses"], [])
        combined = tunnelscope.combine_reports(*report["directions"])
        self.assertEqual(combined["endpoint_check"], "reversed_ipv4_match")
        self.assertEqual(combined["comparison"]["by_payload_size"][-1]["b_to_a"], "kernel_rejected_df_payload")

    @unittest.skipUnless(os.environ.get("TUNNELSCOPE_RUN_NETNS_TESTS") == "1" and sys.platform.startswith("linux"), "opt-in privileged Linux network lab")
    def test_routed_blackhole_keeps_timeouts_inconclusive(self):
        if not shutil.which("iptables"):
            self.skipTest("iptables is required for the routed black-hole lab")
        script = Path(__file__).resolve().parents[1] / "labs" / "pmtu_blackhole.py"
        result = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, timeout=45)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["router_egress_mtu_bytes"], 1280)
        self.assertGreaterEqual(report["blocked_feedback_packets"], 2)
        probe = report["probe"]
        self.assertEqual([row["status"] for row in probe["results"]], ["acknowledged", "acknowledged", "timeout", "timeout"])
        self.assertEqual([row["assessment"] for row in probe["summary"]["by_payload_size"]], ["delivery_observed", "delivery_observed", "inconclusive", "inconclusive"])
        self.assertEqual([item["code"] for item in probe["evidence"]["hypotheses"]], ["size_related_delivery_problem_possible", "pmtu_feedback_black_hole_possible"])
        self.assertIn("ordinary_packet_loss", probe["evidence"]["hypotheses"][1]["alternatives"])
        self.assertIn("icmp_feedback_observation", probe["evidence"]["missing_evidence"])


if __name__ == "__main__":
    unittest.main()

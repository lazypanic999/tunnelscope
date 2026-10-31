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

    def test_ipv6_dontfrag_and_kernel_mtu(self):
        sock = Mock()
        sock.family = socket.AF_INET6
        sock.getsockopt.return_value = 1280
        tunnelscope.configure_fragmentation(sock, True)
        sock.setsockopt.assert_called_once_with(socket.IPPROTO_IPV6, tunnelscope.IPV6_DONTFRAG, 1)
        result = tunnelscope.socket_failure(OSError(errno.EMSGSIZE, "Message too long"), sock, True)
        self.assertEqual(result["status"], "packet_too_large")
        self.assertEqual(result["kernel_reported_mtu_bytes"], 1280)
        sock.getsockopt.assert_called_once_with(socket.IPPROTO_IPV6, tunnelscope.IPV6_MTU)

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
            self.assertEqual(direction["summary"]["icmp_feedback"]["local_error_events"], 2)
            self.assertEqual(direction["summary"]["icmp_feedback"]["size_feedback_events"], 0)
            self.assertEqual([row["size_error_origin"] for row in direction["results"][2:]],
                             ["local", "local"])
            self.assertEqual(direction["source"]["interface_mtu_bytes"], 1280)
            self.assertIn(direction["source"]["interface"], ("ts-a", "ts-b"))
            self.assertEqual(direction["evidence"]["hypotheses"], [])
            self.assertEqual(direction["sweep"]["settings"]["payload_sizes"],
                             [1200, 1225, 1250, 1275, 1300])
            self.assertEqual([row["status"] for row in direction["sweep"]["results"]],
                             ["acknowledged"] * 3 + ["packet_too_large"] * 2)
            self.assertEqual(direction["search"]["summary"]["search"]["observed_interval_payload_bytes"],
                             [1252, 1253])
            comparison = direction["fragmentation_comparison"]
            self.assertEqual(comparison["source_check"], "matched")
            self.assertEqual([row["outcomes_differ"] for row in comparison["comparison"]["by_payload_size"]],
                             [False, True, True])
            self.assertEqual([row["status"] for row in comparison["runs"]["fragmentation_permitted"]["results"]],
                             ["acknowledged"] * 6)
        combined = tunnelscope.combine_reports(*report["directions"])
        self.assertEqual(combined["endpoint_check"], "reversed_ipv4_match")
        self.assertEqual(combined["comparison"]["by_payload_size"][-1]["b_to_a"], "kernel_rejected_df_payload")

    @unittest.skipUnless(os.environ.get("TUNNELSCOPE_RUN_NETNS_TESTS") == "1" and sys.platform.startswith("linux"), "opt-in privileged Linux network lab")
    def test_ipv6_boundary_in_both_directions(self):
        script = Path(__file__).resolve().parents[1] / "labs" / "ipv6_boundary.py"
        result = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, timeout=45)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["expected_payload_boundary_bytes"], 1232)
        self.assertEqual(len(report["directions"]), 2)
        for direction in report["directions"]:
            probe = direction["probe"]
            self.assertEqual(probe["settings"]["payload_sizes"], list(range(1228, 1237)))
            self.assertEqual([row["status"] for row in probe["results"]],
                             ["acknowledged"] * 5 + ["packet_too_large"] * 4)
            self.assertEqual(probe["source"]["interface_mtu_bytes"], 1280)
            self.assertEqual(direction["correlation"]["summary"]["receiver_observed"], 5)
            self.assertEqual(direction["search"]["summary"]["search"]["observed_interval_payload_bytes"],
                             [1232, 1233])
            self.assertEqual(direction["search_correlation"]["summary"]["receiver_observed"], 2)
            comparison = direction["fragmentation_comparison"]
            self.assertEqual([row["outcomes_differ"] for row in comparison["comparison"]["by_payload_size"]],
                             [False, True])
            self.assertEqual([row["status"] for row in comparison["runs"]["fragmentation_permitted"]["results"]],
                             ["acknowledged", "acknowledged"])

    @unittest.skipUnless(os.environ.get("TUNNELSCOPE_RUN_NETNS_TESTS") == "1" and sys.platform.startswith("linux"), "opt-in privileged Linux network lab")
    def test_routed_ipv6_packet_too_big_feedback(self):
        script = Path(__file__).resolve().parents[1] / "labs" / "ipv6_packet_too_big.py"
        result = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, timeout=25)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["router_egress_mtu_bytes"], 1280)
        probe = report["probe"]
        self.assertEqual([row["status"] for row in probe["results"]], ["packet_too_large"])
        self.assertEqual(probe["summary"]["icmp_feedback"]["token_matched_size_feedback_events"], 1)
        event = probe["results"][0]["icmp_observation"]["events"][0]
        self.assertEqual(probe["results"][0]["size_error_origin"], "network_icmp_feedback")
        self.assertEqual((event["origin"], event["icmp_type"], event["icmp_code"],
                          event["reported_mtu_bytes"], event["quoted_probe_match"]),
                         ("icmpv6", 2, 0, 1280, True))

    @unittest.skipUnless(os.environ.get("TUNNELSCOPE_RUN_NETNS_TESTS") == "1" and sys.platform.startswith("linux"), "opt-in privileged Linux network lab")
    def test_vxlan_overlay_boundary_in_both_directions(self):
        script = Path(__file__).resolve().parents[1] / "labs" / "vxlan_boundary.py"
        result = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, timeout=45)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["expected_payload_boundary_bytes"], 1422)
        self.assertEqual(len(report["directions"]), 2)
        for direction in report["directions"]:
            probe = direction["probe"]
            self.assertEqual(probe["settings"]["payload_sizes"], list(range(1418, 1427)))
            self.assertEqual([row["status"] for row in probe["results"]],
                             ["acknowledged"] * 5 + ["packet_too_large"] * 4)
            self.assertEqual(probe["source"]["interface"], "ts-vx")
            self.assertEqual(probe["source"]["interface_mtu_bytes"], 1450)
            self.assertEqual(direction["correlation"]["summary"]["receiver_observed"], 5)

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
        self.assertEqual(probe["summary"]["icmp_feedback"]["size_feedback_events"], 0)
        self.assertEqual(probe["summary"]["icmp_feedback"]["observation_state"], "complete")
        self.assertEqual(report["search"]["summary"]["search"]["assessment"], "inconclusive")
        self.assertIsNone(report["search"]["summary"]["search"]["observed_interval_payload_bytes"])
        self.assertEqual(report["search"]["summary"]["icmp_feedback"]["size_feedback_events"], 0)
        visible = report["visible_feedback_probe"]
        self.assertEqual([row["status"] for row in visible["results"]], ["acknowledged", "packet_too_large"])
        self.assertEqual(visible["summary"]["icmp_feedback"]["token_matched_size_feedback_events"], 1)
        event = visible["results"][1]["icmp_observation"]["events"][0]
        self.assertEqual(visible["results"][1]["size_error_origin"], "network_icmp_feedback")
        self.assertEqual((event["origin"], event["icmp_type"], event["icmp_code"], event["reported_mtu_bytes"]),
                         ("icmpv4", 3, 4, 1280))
        comparison = report["fragmentation_comparison"]
        rows = comparison["comparison"]["by_payload_size"]
        self.assertEqual([row["outcomes_differ"] for row in rows], [False, True])
        self.assertEqual(rows[1]["df"]["no_ack_measurement"]["no_ack_rate"], 1.0)
        self.assertEqual(rows[1]["fragmentation_permitted"]["no_ack_measurement"]["no_ack_rate"], 0.0)

    @unittest.skipUnless(os.environ.get("TUNNELSCOPE_RUN_NETNS_TESTS") == "1" and sys.platform.startswith("linux"), "opt-in privileged Linux network lab")
    def test_ack_return_blocked_still_records_receiver_arrival(self):
        if not shutil.which("iptables"):
            self.skipTest("iptables is required for the ACK return lab")
        script = Path(__file__).resolve().parents[1] / "labs" / "ack_return_blocked.py"
        result = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, timeout=45)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertGreaterEqual(report["blocked_ack_packets"], 2)
        self.assertEqual([row["status"] for row in report["probe"]["results"]], ["timeout", "timeout"])
        self.assertEqual([row["ack_send_status"] for row in report["receiver"]["observations"]], ["sent"] * 4)
        self.assertEqual(report["correlation"]["pairing"]["run_id_check"], "matched_with_other_runs")
        self.assertEqual(report["correlation"]["summary"]["timed_out_but_receiver_observed"], 2)
        self.assertEqual(report["search"]["summary"]["search"]["assessment"], "inconclusive")
        self.assertEqual(report["search_correlation"]["summary"]["timed_out_but_receiver_observed"], 2)
        self.assertIn("2/2 observed at receiver", tunnelscope.format_report(report))


if __name__ == "__main__":
    unittest.main()

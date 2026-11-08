"""Opt-in OpenVPN validation; ordinary delivery tests need no VPN tools."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(sys.platform.startswith("linux") and os.environ.get("TUNNELSCOPE_RUN_OPENVPN_TESTS") == "1",
                     "opt-in privileged OpenVPN/TUN lab")
class OpenVPNTests(unittest.TestCase):
    def run_lab(self, scenario="feedback"):
        script = Path(__file__).resolve().parents[1] / "labs/openvpn_routed.py"
        temporary_before = set(Path(tempfile.gettempdir()).glob("tunnelscope-openvpn-*"))
        namespaces_before = subprocess.run(["ip", "netns", "list"], check=True, capture_output=True, text=True).stdout
        result = subprocess.run([sys.executable, str(script), "--scenario", scenario],
                                capture_output=True, text=True, timeout=120)
        output = os.environ.get("TUNNELSCOPE_LAB_OUTPUT_DIR")
        if output:
            directory = Path(output)
            directory.mkdir(parents=True, exist_ok=True)
            name = "openvpn_routed" if scenario == "feedback" else "openvpn_asymmetric_return"
            (directory / f"{name}.json").write_text(result.stdout, encoding="utf-8")
            if result.stderr:
                (directory / f"{name}.stderr.txt").write_text(result.stderr, encoding="utf-8")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(set(Path(tempfile.gettempdir()).glob("tunnelscope-openvpn-*")), temporary_before)
        namespaces_after = subprocess.run(["ip", "netns", "list"], check=True, capture_output=True, text=True).stdout
        names = lambda text: {line.split()[0] for line in text.splitlines() if line.startswith("ts-ov-")}
        self.assertEqual(names(namespaces_after), names(namespaces_before))
        self.assertNotIn("PRIVATE KEY", result.stdout)
        self.assertNotIn("BEGIN CERTIFICATE", result.stdout)
        report = json.loads(result.stdout)
        self.assertTrue(report["openvpn_version"].startswith("OpenVPN "))
        return report

    def test_routed_feedback_crosses_an_authenticated_openvpn_tunnel(self):
        report = self.run_lab()
        self.assertEqual(report["tunnel_mtu_bytes"], 1400)
        self.assertEqual(report["router_egress_mtu_bytes"], 1280)
        self.assertEqual(report["configured_data_cipher"], "AES-256-GCM")
        blocked, visible = (report["cases"][name] for name in ("blocked", "visible"))
        for case, failure in ((blocked, "timeout"), (visible, "packet_too_large")):
            self.assertEqual([row["status"] for row in case["probe"]["results"]],
                             ["acknowledged"] * 2 + [failure] * 2)
            self.assertEqual(case["probe"]["source"]["interface"], "ts-ovpn")
            self.assertEqual(case["probe"]["source"]["interface_mtu_bytes"], 1400)
            self.assertEqual([row["receiver_observed"] for row in case["correlation"]["results"]],
                             [True, True, False, False])
            self.assertTrue(case["correlation"]["pairing"]["endpoint_checks"]["target_ipv4_matches_receiver_bind"])
        self.assertGreaterEqual(blocked["blocked_fragmentation_needed_messages"], 3)
        for probe in (blocked["probe"], blocked["search"]):
            self.assertEqual(probe["summary"]["icmp_feedback"]["size_feedback_events"], 0)
        self.assertEqual(blocked["search"]["summary"]["search"]["assessment"], "inconclusive")
        self.assertIsNone(blocked["search"]["summary"]["search"]["observed_interval_payload_bytes"])
        self.assertEqual(blocked["search_correlation"]["summary"]["receiver_observed"], 1)
        first_large = visible["probe"]["results"][2]
        self.assertEqual(first_large["size_error_origin"], "network_icmp_feedback")
        self.assertTrue(any(event.get("origin") == "icmpv4" and event.get("icmp_type") == 3
                            and event.get("icmp_code") == 4 and event.get("reported_mtu_bytes") == 1280
                            and event.get("quoted_probe_match") is True
                            for event in first_large["icmp_observation"]["events"]))

    def test_sized_replies_expose_lower_openvpn_return_egress(self):
        report = self.run_lab("asymmetric-return")
        self.assertEqual(report["sender_tunnel_mtu_bytes"], 1400)
        self.assertEqual(report["router_tunnel_egress_mtu_bytes"], 1280)
        self.assertGreaterEqual(report["router_fragmentation_needed_messages"], 1)
        small, sized = (report["cases"][name] for name in ("small_ack", "sized_reply"))
        self.assertEqual([row["status"] for row in small["probe"]["results"]], ["acknowledged"] * 4)
        self.assertEqual([row["return_status"] for row in sized["probe"]["results"]],
                         ["sized_reply_received"] * 2 + ["no_reply"] * 2)
        for case in (small, sized):
            self.assertEqual([row["receiver_observed"] for row in case["correlation"]["results"]], [True] * 4)
        joined = sized["correlation"]["results"]
        self.assertTrue(all(row["return_evidence"] == "sized_reply_returned" for row in joined[:2]))
        self.assertTrue(all(row["return_evidence"] in ("receiver_observed_sized_reply_missing", "receiver_reply_send_failed")
                            for row in joined[2:]))
        summary = sized["correlation"]["summary"]
        self.assertEqual(summary["sized_reply_missing_after_arrival"] + summary["receiver_reply_send_failed"], 2)
        self.assertEqual(sized["search"]["summary"]["search"]["assessment"], "inconclusive")
        self.assertIsNone(sized["search"]["summary"]["search"]["observed_interval_payload_bytes"])
        self.assertEqual(sized["search_correlation"]["summary"]["receiver_observed"], 2)


if __name__ == "__main__":
    unittest.main()

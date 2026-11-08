"""Opt-in OpenVPN validation; ordinary delivery tests need no VPN tools."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class OpenVPNTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith("linux") and os.environ.get("TUNNELSCOPE_RUN_OPENVPN_TESTS") == "1",
                         "opt-in privileged OpenVPN/TUN lab")
    def test_routed_feedback_crosses_an_authenticated_openvpn_tunnel(self):
        script = Path(__file__).resolve().parents[1] / "labs/openvpn_routed.py"
        temporary_before = set(Path(tempfile.gettempdir()).glob("tunnelscope-openvpn-*"))
        namespaces_before = subprocess.run(["ip", "netns", "list"], check=True, capture_output=True, text=True).stdout
        result = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, timeout=120)
        output = os.environ.get("TUNNELSCOPE_LAB_OUTPUT_DIR")
        if output:
            directory = Path(output)
            directory.mkdir(parents=True, exist_ok=True)
            (directory / "openvpn_routed.json").write_text(result.stdout, encoding="utf-8")
            if result.stderr:
                (directory / "openvpn_routed.stderr.txt").write_text(result.stderr, encoding="utf-8")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(set(Path(tempfile.gettempdir()).glob("tunnelscope-openvpn-*")), temporary_before)
        namespaces_after = subprocess.run(["ip", "netns", "list"], check=True, capture_output=True, text=True).stdout
        names = lambda text: {line.split()[0] for line in text.splitlines() if line.startswith("ts-ov-")}
        self.assertEqual(names(namespaces_after), names(namespaces_before))
        self.assertNotIn("PRIVATE KEY", result.stdout)
        self.assertNotIn("BEGIN CERTIFICATE", result.stdout)
        report = json.loads(result.stdout)
        self.assertTrue(report["openvpn_version"].startswith("OpenVPN "))
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


if __name__ == "__main__":
    unittest.main()

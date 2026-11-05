"""Checks for report sanitization."""

import copy
from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import tunnelscope
from tunnelscope_core.reports import combine_reports, correlate_reports, format_report
from tunnelscope_core.sanitize import sanitize_reports
from tunnelscope_core.view import render_report_html

SECRETS = ("10.77.0.1", "10.77.0.2", "fd00:77::1", "fe80::1", "enp0s8", "vpn-gw.internal", "2026-")


def probe_report(source_ip, target_ip, interface, host=None, run_id="a" * 16):
    return {
        "schema_version": 1, "kind": "probe", "run_id": run_id,
        "started_at_utc": "2026-11-03T10:00:00.250000+00:00",
        "finished_at_utc": "2026-11-03T10:00:02.000000+00:00",
        "source": {"ipv4": source_ip, "interface": interface, "interface_mtu_bytes": 1420},
        "target": {"host": host or target_ip, "ipv4": target_ip, "port": 9471},
        "settings": {"timeout_seconds": 1, "dont_fragment": True},
        "summary": {"by_payload_size": [
            {"payload_bytes": 1200, "status_counts": {"acknowledged": 1}, "assessment": "delivery_observed"},
            {"payload_bytes": 1400, "status_counts": {"timeout": 1}, "assessment": "inconclusive"},
        ]},
        "results": [
            {"probe_id": "1" * 32, "payload_bytes": 1200, "status": "acknowledged", "rtt_ms": 1.5,
             "send_attempted_at_utc": "2026-11-03T10:00:00.500000+00:00",
             "ack_received_at_utc": "2026-11-03T10:00:00.501500+00:00"},
            {"probe_id": "2" * 32, "payload_bytes": 1400, "status": "timeout",
             "send_attempted_at_utc": "2026-11-03T10:00:01.000000+00:00",
             "icmp_observation": {"events": [{"origin": "icmpv4", "message": "fragmentation_needed",
                                              "reported_mtu_bytes": 1380, "quoted_probe_match": True}]}},
        ],
    }


def receiver_report(bind_ip, source_ip, run_id="a" * 16):
    return {
        "schema_version": 1, "kind": "receiver_observations",
        "receiver": {"bind_ipv4": bind_ip, "port": 9471},
        "started_at_utc": "2026-11-03T09:59:58.000000+00:00",
        "finished_at_utc": "2026-11-03T10:00:30.000000+00:00",
        "exit_reason": "idle_timeout",
        "observations": [
            {"probe_id": "1" * 32, "run_id": run_id, "payload_bytes": 1200, "source_ipv4": source_ip,
             "received_at_utc": "2026-11-03T10:00:00.501000+00:00", "ack_send_status": "sent"},
            {"probe_id": "2" * 32, "run_id": run_id, "payload_bytes": 1400, "source_ipv4": source_ip,
             "received_at_utc": "2026-11-03T10:00:01.001000+00:00", "ack_send_status": "sent"},
        ],
    }


def without_volatile(value):
    """Drop fields whose values are expected to change during sanitization."""
    if isinstance(value, dict):
        return {key: without_volatile(item) for key, item in value.items()
                if key not in ("direction", "sanitization") and not key.endswith("_utc")}
    if isinstance(value, list):
        return [without_volatile(item) for item in value]
    return value


class SanitizeTests(unittest.TestCase):
    def setUp(self):
        self.probe = probe_report("10.77.0.1", "10.77.0.2", "enp0s8")
        self.receiver = receiver_report("10.77.0.2", "10.77.0.1")

    def assert_clean(self, report):
        text = json.dumps(report)
        for secret in SECRETS:
            self.assertNotIn(secret, text)

    def test_replaces_addresses_interfaces_and_times_without_touching_inputs(self):
        original = copy.deepcopy(self.probe)
        clean, = sanitize_reports([self.probe])
        self.assertEqual(self.probe, original)
        self.assert_clean(clean)
        self.assertEqual(clean["source"], {"ipv4": "192.0.2.1", "interface": "if-1", "interface_mtu_bytes": 1420})
        self.assertEqual(clean["target"]["ipv4"], "192.0.2.2")
        self.assertEqual(clean["target"]["host"], "192.0.2.2")
        self.assertEqual(clean["started_at_utc"], "2000-01-01T00:00:00.000000+00:00")
        self.assertEqual(clean["results"][0]["ack_received_at_utc"], "2000-01-01T00:00:00.251500+00:00")
        self.assertEqual(clean["results"][0]["rtt_ms"], 1.5)
        self.assertEqual(clean["results"][1]["icmp_observation"], self.probe["results"][1]["icmp_observation"])
        self.assertEqual(clean["sanitization"]["replaced_addresses"], 2)
        self.assertEqual(clean["sanitization"]["replaced_interfaces"], 1)

    def test_batch_mapping_keeps_correlation_results(self):
        clean_probe, clean_receiver = sanitize_reports([self.probe, self.receiver])
        self.assert_clean(clean_probe)
        self.assert_clean(clean_receiver)
        before = correlate_reports(self.probe, self.receiver)
        after = correlate_reports(clean_probe, clean_receiver)
        self.assertEqual(without_volatile(after), without_volatile(before))
        self.assertTrue(after["pairing"]["endpoint_checks"]["target_ipv4_matches_receiver_bind"])
        self.assertEqual(after["results"][0]["direction"], "192.0.2.1 -> 192.0.2.2")
        # The earliest time in the batch (receiver start) becomes the base;
        # every other time keeps its distance from it across files.
        self.assertEqual(clean_receiver["started_at_utc"], "2000-01-01T00:00:00.000000+00:00")
        self.assertEqual(clean_receiver["observations"][0]["received_at_utc"],
                         "2000-01-01T00:00:02.501000+00:00")
        self.assertEqual(clean_probe["results"][0]["send_attempted_at_utc"],
                         "2000-01-01T00:00:02.500000+00:00")

    def test_separate_batches_do_not_promise_consistent_placeholders(self):
        other = probe_report("10.77.0.9", "10.77.0.2", "wg0")
        _, clean_other = sanitize_reports([self.probe, other])
        self.assertEqual(clean_other["source"]["ipv4"], "192.0.2.3")
        self.assertEqual(clean_other["target"]["ipv4"], "192.0.2.2")
        self.assertEqual(clean_other["source"]["interface"], "if-2")

    def test_combined_report_keeps_endpoint_check(self):
        b_to_a = probe_report("10.77.0.2", "10.77.0.1", "enp0s8", run_id="b" * 16)
        combined = combine_reports(self.probe, b_to_a)
        clean, = sanitize_reports([combined])
        self.assert_clean(clean)
        self.assertEqual(clean.get("endpoint_check"), combined.get("endpoint_check"))
        self.assertEqual(combine_reports(*sanitize_reports([self.probe, b_to_a])).get("endpoint_check"),
                         combined.get("endpoint_check"))

    def test_free_text_ipv6_hostnames_and_kept_addresses(self):
        report = probe_report("10.77.0.1", "10.77.0.2", "enp0s8", host="vpn-gw.internal")
        report["notes"] = ["reached vpn-gw.internal via fe80::1%enp0s8 and fd00:77::1.",
                           "loopback 127.0.0.1 and ::1, documentation 203.0.113.7 and 2001:db8::99",
                           "mapped ::ffff:10.77.0.2, version 0.6.0, time 10:00:01"]
        clean, = sanitize_reports([report])
        self.assert_clean(clean)
        self.assertEqual(clean["target"]["host"], "host-1.example")
        self.assertEqual(clean["notes"][0], "reached host-1.example via 2001:db8::1%if-1 and 2001:db8::2.")
        self.assertEqual(clean["notes"][1], report["notes"][1])
        self.assertEqual(clean["notes"][2], "mapped ::ffff:192.0.2.2, version 0.6.0, time 10:00:01")

    def test_utc_z_timestamps_are_shifted_and_keep_their_form(self):
        report = probe_report("10.77.0.1", "10.77.0.2", "enp0s8")
        report["recorded_at_utc"] = "2026-11-03T10:00:01Z"
        clean, = sanitize_reports([report])
        self.assertEqual(clean["recorded_at_utc"], "2000-01-01T00:00:00Z")
        self.assert_clean(clean)

    def test_replacements_avoid_documentation_addresses_already_present(self):
        report = probe_report("10.77.0.1", "192.0.2.1", "lo")
        clean, = sanitize_reports([report])
        self.assertEqual(clean["target"]["ipv4"], "192.0.2.1")
        self.assertEqual(clean["source"]["ipv4"], "192.0.2.2")
        self.assertEqual(clean["source"]["interface"], "lo")

    def test_keep_timestamps_and_refuse_resanitizing(self):
        clean, = sanitize_reports([self.probe], keep_timestamps=True)
        self.assertEqual(clean["started_at_utc"], self.probe["started_at_utc"])
        self.assertEqual(clean["sanitization"]["timestamps"], "kept")
        with self.assertRaisesRegex(ValueError, "already sanitized"):
            sanitize_reports([clean])
        with self.assertRaisesRegex(ValueError, "schema_version 1"):
            sanitize_reports([{"kind": "probe"}])

    def test_every_example_report_sanitizes_and_renders(self):
        examples = sorted((Path(__file__).resolve().parents[1] / "examples").glob("*.json"))
        self.assertTrue(examples)
        reports = [json.loads(path.read_text(encoding="utf-8")) for path in examples]
        for path, clean in zip(examples, sanitize_reports(reports)):
            with self.subTest(example=path.name):
                self.assertNotIn("2026-", json.dumps(clean))
                self.assertIn("Sanitized report", render_report_html(clean))
                if clean.get("schema_version") == 1:
                    format_report(clean)

    def run_cli(self, *args):
        output = StringIO()
        with patch.object(sys, "argv", ["tunnelscope", *args]), redirect_stdout(output):
            tunnelscope.main()
        return output.getvalue()

    def test_cli_writes_new_files_and_refuses_overwrites(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "out").mkdir()
            probe_path, receiver_path = root / "probe.json", root / "receiver.json"
            probe_path.write_text(json.dumps(self.probe), encoding="utf-8")
            receiver_path.write_text(json.dumps(self.receiver), encoding="utf-8")
            text = self.run_cli("sanitize", str(probe_path), str(receiver_path),
                                "--output-dir", str(root / "out"), "--html")
            self.assertIn("Replaced 2 addresses", text)
            for name in ("probe.json", "probe.html", "receiver.json", "receiver.html"):
                self.assert_clean((root / "out" / name).read_text(encoding="utf-8"))
            self.assertEqual(json.loads(probe_path.read_text(encoding="utf-8")), self.probe)
            shown = self.run_cli("show", str(root / "out" / "probe.json"))
            self.assertTrue(shown.startswith("Sanitized report"))
            for args in ((str(probe_path), "--output-dir", str(root / "out")),
                         (str(probe_path), "--output-dir", str(root)),
                         (str(probe_path), "--output-dir", str(root / "missing"))):
                with self.subTest(args=args), redirect_stdout(StringIO()), \
                        patch.object(sys, "stderr", StringIO()), self.assertRaises(SystemExit) as raised:
                    self.run_cli("sanitize", *args)
                self.assertEqual(raised.exception.code, 1)


if __name__ == "__main__":
    unittest.main()

"""Correlation rejects hex identifiers that only bytes.fromhex() leniency would accept."""

from copy import deepcopy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tunnelscope_core.diagnose import build_diagnosis, correlate_diagnosis
from tunnelscope_core.reports import correlate_reports

# bytes.fromhex() skips ASCII whitespace, so each value still has the expected
# string length while encoding fewer bytes.
BAD_PROBE_IDS = ("aa" * 14 + "\n\nbb", "aa" * 15 + " b", "aa" * 15 + "\tb")
BAD_RUN_IDS = ("0" * 14 + "\n0", "0" * 12 + " 00 ", "0" * 14 + "\r\n")


def pair(probe_id="1" * 32, sender_run="0" * 16, receiver_run="0" * 16):
    probe = {"schema_version": 1, "kind": "probe", "run_id": sender_run,
             "results": [{"probe_id": probe_id, "payload_bytes": 100, "status": "timeout"}]}
    receiver = {"schema_version": 1, "kind": "receiver_observations",
                "observations": [{"probe_id": probe_id, "payload_bytes": 100, "run_id": receiver_run}]}
    return probe, receiver


def diagnosis_pair():
    def run(run_id, probe_id):
        return {"schema_version": 1, "kind": "probe", "run_id": run_id, "settings": {},
                "results": [{"probe_id": probe_id, "payload_bytes": 1200, "status": "timeout"}]}
    search = run("c" * 16, "3" * 32)
    search["summary"] = {"search": {"assessment": "inconclusive"}}
    comparison = {"kind": "fragmentation_comparison",
                  "runs": {"df": run("a" * 16, "1" * 32),
                           "fragmentation_permitted": run("b" * 16, "2" * 32)}}
    receiver = {"schema_version": 1, "kind": "receiver_observations",
                "observations": [{"run_id": "a" * 16, "probe_id": "1" * 32, "payload_bytes": 1200}]}
    return build_diagnosis(comparison, search), receiver


class CorrelationIdentifierTests(unittest.TestCase):
    def test_canonical_identifiers_still_correlate(self):
        joined = correlate_reports(*pair())
        self.assertEqual(joined["summary"]["receiver_observed"], 1)
        self.assertEqual(joined["pairing"]["run_id_check"], "matched")

    def test_uppercase_hex_identifiers_remain_accepted(self):
        joined = correlate_reports(*pair(probe_id="ABCDEF0123456789" * 2,
                                         sender_run="ABCDEF0123456789",
                                         receiver_run="ABCDEF0123456789"))
        self.assertEqual(joined["summary"]["receiver_observed"], 1)
        self.assertEqual(joined["pairing"]["run_id_check"], "matched")
        diagnosis, receiver = diagnosis_pair()
        diagnosis["runs"]["fragmentation_comparison"]["runs"]["df"]["run_id"] = "A" * 16
        receiver["observations"][0].update(run_id="A" * 16, probe_id="1" * 31 + "F")
        joined = correlate_diagnosis(diagnosis, receiver)
        summary = joined["receiver_evidence"]["summary"]
        self.assertEqual(summary["receiver_observed"], 0)
        self.assertEqual(summary["unmatched_receiver_observations"], 1)

    def test_rejects_noncanonical_probe_ids(self):
        for value in BAD_PROBE_IDS:
            with self.subTest(probe_id=value), \
                    self.assertRaisesRegex(ValueError, "hexadecimal probe IDs"):
                correlate_reports(*pair(probe_id=value))

    def test_rejects_noncanonical_run_ids(self):
        for value in BAD_RUN_IDS:
            with self.subTest(sender=value), self.assertRaisesRegex(ValueError, "invalid probe run ID"):
                correlate_reports(*pair(sender_run=value))
            with self.subTest(receiver=value), self.assertRaisesRegex(ValueError, "invalid receiver run ID"):
                correlate_reports(*pair(receiver_run=value))

    def test_diagnosis_rejects_noncanonical_identifiers(self):
        diagnosis, receiver = diagnosis_pair()
        joined = correlate_diagnosis(diagnosis, receiver)
        self.assertEqual(joined["receiver_evidence"]["summary"]["receiver_observed"], 1)
        for value in BAD_RUN_IDS:
            with self.subTest(diagnosis_run=value):
                changed = deepcopy(diagnosis)
                changed["runs"]["size_search"]["run_id"] = value
                with self.assertRaisesRegex(ValueError, "hexadecimal run IDs"):
                    correlate_diagnosis(changed, receiver)
            with self.subTest(receiver_run=value):
                changed = deepcopy(receiver)
                changed["observations"][0]["run_id"] = value
                with self.assertRaisesRegex(ValueError, "hexadecimal receiver identifier"):
                    correlate_diagnosis(diagnosis, changed)
        for value in BAD_PROBE_IDS:
            with self.subTest(receiver_probe=value):
                changed = deepcopy(receiver)
                changed["observations"][0]["probe_id"] = value
                with self.assertRaisesRegex(ValueError, "hexadecimal receiver identifier"):
                    correlate_diagnosis(diagnosis, changed)


if __name__ == "__main__":
    unittest.main()

"""correlate and combine say what was passed when the inputs are wrong."""

from contextlib import redirect_stderr
from io import StringIO
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import tunnelscope


def nested(kind):
    report = json.loads((ROOT / "examples" / "asymmetric-return-v07.json").read_text(encoding="utf-8"))
    found = []

    def walk(value):
        if isinstance(value, dict):
            if value.get("kind") == kind:
                found.append(value)
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)
    walk(report)
    return found[0]


class WrongInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        root = Path(cls.directory.name)
        cls.files = {}
        for kind in ("probe", "receiver_observations", "probe_receiver_correlation"):
            path = root / f"{kind}.json"
            path.write_text(json.dumps(nested(kind)), encoding="utf-8")
            cls.files[kind] = str(path)
        cls.files["lab"] = str(ROOT / "examples" / "pmtu-blackhole.json")

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def error_for(self, *argv):
        stderr = StringIO()
        with patch.object(sys, "argv", ["tunnelscope", *argv]), redirect_stderr(stderr), \
                self.assertRaises(SystemExit) as caught:
            tunnelscope.main()
        self.assertEqual(caught.exception.code, 1)
        return stderr.getvalue().strip()

    def test_swapped_correlate_inputs_are_named(self):
        message = self.error_for("correlate", self.files["receiver_observations"], self.files["probe"])
        self.assertEqual(message, "Error: the two files look swapped: give the sender report "
                                  "(probe or diagnosis) first and the receiver report second")

    def test_wrong_kinds_are_listed(self):
        message = self.error_for("correlate", self.files["probe"], self.files["probe"])
        self.assertIn("expected a schema_version 1 receiver observations report", message)
        self.assertIn("(first file is a probe report, second is a probe report)", message)
        message = self.error_for("correlate", self.files["probe_receiver_correlation"],
                                 self.files["receiver_observations"])
        self.assertIn("first file is a probe_receiver_correlation report", message)
        message = self.error_for("correlate", self.files["lab"], self.files["receiver_observations"])
        self.assertIn("first file is a lab report", message)

    def test_combine_lists_kinds(self):
        message = self.error_for("combine", self.files["receiver_observations"], self.files["probe"])
        self.assertIn("a-to-b: missing probe target or results", message)
        self.assertIn("(first file is a receiver_observations report, second is a probe report)", message)

    def test_other_correlation_errors_are_unchanged(self):
        probe = nested("probe")
        receiver = json.loads(json.dumps(nested("receiver_observations")))
        for row in receiver["observations"]:
            row["run_id"] = "f" * 16
        with tempfile.TemporaryDirectory() as directory:
            other = Path(directory) / "other-run.json"
            other.write_text(json.dumps(receiver), encoding="utf-8")
            message = self.error_for("correlate", self.files["probe"], str(other))
        self.assertEqual(message, "Error: receiver report has observations from a different run")
        self.assertNotEqual(probe["run_id"], "f" * 16)

    def test_describe_kind(self):
        self.assertEqual(tunnelscope.describe_kind([1]), "not a JSON object")
        self.assertEqual(tunnelscope.describe_kind({"results": []}), "a report without a kind (legacy probe?)")
        self.assertEqual(tunnelscope.describe_kind({}), "not a TunnelScope report")
        self.assertEqual(tunnelscope.describe_kind({"kind": 3}), "not a TunnelScope report")


if __name__ == "__main__":
    unittest.main()

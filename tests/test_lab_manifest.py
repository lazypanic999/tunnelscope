"""Retained report bytes and explicit provenance are independently checkable."""

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.write_lab_manifest import build_manifest


class LabManifestTests(unittest.TestCase):
    def test_nested_reports_have_byte_hashes_and_distinct_commit_roles(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nested = root / "routed"
            nested.mkdir()
            content = '{"lab":"test-path","tunnelscope_version":"0.9.0.dev0"}\n'.encode("utf-16")
            report = nested / "report.json"
            report.write_bytes(content)
            (root / "manifest.json").write_text("old manifest", encoding="utf-8")
            (root / "daemon.log").write_text("not a report", encoding="utf-8")
            with patch.dict("os.environ", {"GITHUB_SHA": "merge-commit", "TUNNELSCOPE_SOURCE_SHA": "head-commit",
                                           "GITHUB_RUN_ID": "123", "PRIVATE_TEST_SECRET": "never-copy-this"}, clear=True):
                manifest = build_manifest(root)
            self.assertEqual(len(manifest["reports"]), 1)
            item = manifest["reports"][0]
            self.assertEqual(item["path"], "routed/report.json")
            self.assertEqual(item["sha256"], hashlib.sha256(content).hexdigest())
            self.assertEqual(item["bytes"], len(content))
            self.assertEqual(item["lab"], "test-path")
            self.assertEqual(manifest["github"]["tested_commit"], "merge-commit")
            self.assertEqual(manifest["github"]["source_commit"], "head-commit")
            self.assertNotIn("never-copy-this", json.dumps(manifest))
            self.assertEqual(report.read_bytes(), content)

    def test_partial_or_failed_output_is_retained_without_invented_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "failed.json").write_bytes(b'{"unfinished":')
            (root / "old.json").write_text('{"schema_version":1}', encoding="utf-8")
            reports = {item["path"]: item for item in build_manifest(root)["reports"]}
            self.assertEqual(reports["failed.json"]["json_state"], "invalid")
            self.assertEqual(reports["old.json"]["json_state"], "parsed")
            self.assertNotIn("tunnelscope_version", reports["old.json"])
            self.assertIn("sha256", reports["failed.json"])


if __name__ == "__main__":
    unittest.main()

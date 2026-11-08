"""Invalid output destinations must fail before opening a receiver or probing."""

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import tunnelscope


class OutputPreflightTests(unittest.TestCase):
    def test_bad_destinations_fail_before_network_operations(self):
        commands = (
            (["receive"], "receive"),
            (["probe", "127.0.0.1"], "probe"),
            (["search", "127.0.0.1", "--min", "1200", "--max", "1300"], "probe"),
            (["compare-fragmentation", "127.0.0.1"], "compare_fragmentation"),
            (["diagnose", "127.0.0.1", "--min", "1200", "--max", "1300"], "diagnose"),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for arguments, operation in commands:
                for target in (root / "missing" / "report.json", root / "directory.json"):
                    if target.name == "directory.json":
                        target.mkdir(exist_ok=True)
                    with self.subTest(command=arguments[0], target=target.name):
                        errors = StringIO()
                        with patch.object(sys, "argv", ["tunnelscope", *arguments, "--output", str(target)]), \
                                patch.object(tunnelscope, operation, return_value={"schema_version": 1}) as run, \
                                redirect_stderr(errors), redirect_stdout(StringIO()), \
                                self.assertRaises(SystemExit) as stopped:
                            tunnelscope.main()
                        self.assertEqual(stopped.exception.code, 1)
                        run.assert_not_called()
                        self.assertTrue("output directory" in errors.getvalue() or "output path" in errors.getvalue()
                                        or "refusing to overwrite" in errors.getvalue())
            self.assertFalse((root / "missing").exists())

    def test_valid_probe_output_keeps_existing_overwrite_behavior(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "probe.json"
            target.write_text("previous report", encoding="utf-8")
            report = {"schema_version": 1, "kind": "probe", "results": []}
            with patch.object(sys, "argv", ["tunnelscope", "probe", "127.0.0.1", "--output", str(target)]), \
                    patch.object(tunnelscope, "probe", return_value=report) as run, redirect_stdout(StringIO()):
                tunnelscope.main()
            run.assert_called_once()
            self.assertEqual(json.loads(target.read_text(encoding="utf-8")), report)

    def test_hard_link_alias_cannot_overwrite_any_offline_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sender, receiver = root / "sender.json", root / "receiver.json"
            sender.write_text('{"schema_version":1,"kind":"probe","results":[]}', encoding="utf-8")
            receiver.write_text('{"schema_version":1,"kind":"receiver_observations","observations":[]}', encoding="utf-8")
            originals = (sender.read_bytes(), receiver.read_bytes())
            commands = (
                (["html", str(sender)], sender, "--output"),
                (["combine", str(sender), str(receiver)], receiver, "--output"),
                (["correlate", str(sender), str(receiver)], sender, "--output"),
                (["correlate", str(sender), str(receiver)], receiver, "--html"),
            )
            for index, (arguments, source, option) in enumerate(commands):
                alias = root / f"alias-{index}{'.html' if option == '--html' or arguments[0] == 'html' else '.json'}"
                try:
                    os.link(source, alias)
                except OSError as error:
                    self.skipTest(f"test filesystem does not support hard links: {error}")
                with self.subTest(command=arguments[0], option=option):
                    errors = StringIO()
                    with patch.object(sys, "argv", ["tunnelscope", *arguments, option, str(alias)]), \
                            redirect_stderr(errors), redirect_stdout(StringIO()), self.assertRaises(SystemExit) as stopped:
                        tunnelscope.main()
                    self.assertEqual(stopped.exception.code, 1)
                    self.assertIn("must differ", errors.getvalue())
                    self.assertEqual((sender.read_bytes(), receiver.read_bytes()), originals)


if __name__ == "__main__":
    unittest.main()

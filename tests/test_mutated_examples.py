"""Every field of every example, broken one at a time, renders or fails cleanly.

The CLI reports ValueError as "Error: ..."; any other exception is a traceback.
This replaces each field (to a bounded depth) with a few wrong types, or
deletes it, and runs the text, HTML and Markdown renderers.

By default it covers one example of each report shape with fewer values, which
takes a few seconds. Set TUNNELSCOPE_FULL_MUTATION_TESTS=1 to break every field
of every example with every value (several minutes).
"""

import copy
import json
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tunnelscope_core.markdown import render_report_markdown
from tunnelscope_core.reports import format_report
from tunnelscope_core.view import render_report_html

RENDERERS = (format_report, render_report_html, render_report_markdown)
FULL = os.environ.get("TUNNELSCOPE_FULL_MUTATION_TESTS") == "1"
DELETE = object()
WRONG = (None, [], {}, "x", 1.5, True, [None], DELETE) if FULL else (None, [], "x", DELETE)
# HTML rendering is the slow part; by default it only sees missing fields.
HTML_WRONG = WRONG if FULL else (None, DELETE)
# One example per report shape: probe lab, receiver, diagnosis, correlation lab,
# multi-case lab and a bidirectional lab.
DEFAULT_EXAMPLES = ("pmtu-blackhole.json", "receiver-v06.json", "diagnosis-v06.json",
                    "asymmetric-return-v07.json", "ipv6-routed-feedback.json", "mtu-boundary.json")
MAX_DEPTH = 6
LIST_ITEMS = 1


def field_paths(value, prefix=()):
    yield prefix
    if len(prefix) >= MAX_DEPTH:
        return
    if isinstance(value, dict):
        for key, child in value.items():
            yield from field_paths(child, prefix + (key,))
    elif isinstance(value, list):
        for index, child in enumerate(value[:LIST_ITEMS]):
            yield from field_paths(child, prefix + (index,))


def without_derived(value):
    """Drop stored figures that renderers recompute when missing (no_ack_measurement),
    so the fallback paths see the broken fields too."""
    if isinstance(value, dict):
        return {key: without_derived(child) for key, child in value.items() if key != "no_ack_measurement"}
    if isinstance(value, list):
        return [without_derived(child) for child in value]
    return value


def replaced(report, path, value):
    if not path:
        return value
    report = copy.deepcopy(report)
    parent = report
    for key in path[:-1]:
        parent = parent[key]
    if value is DELETE:
        if isinstance(parent, dict):
            del parent[path[-1]]
        else:
            parent.pop(path[-1])
    else:
        parent[path[-1]] = value
    return report


class MutatedExampleTests(unittest.TestCase):
    def test_renderers_raise_only_value_error(self):
        failures = []
        examples = sorted((ROOT / "examples").glob("*.json"))
        if not FULL:
            examples = [path for path in examples if path.name in DEFAULT_EXAMPLES]
            self.assertEqual(len(examples), len(DEFAULT_EXAMPLES))
        bases = []
        for example in examples:
            report = json.loads(example.read_text(encoding="utf-8"))
            bases.append((example.name, report))
            stripped = without_derived(report)
            if stripped != report:
                bases.append((f"{example.name} without no_ack_measurement", stripped))
        for name, report in bases:
            for path in field_paths(report):
                for value in WRONG:
                    broken = replaced(report, path, value)
                    for render in RENDERERS:
                        if render is render_report_html and value not in HTML_WRONG:
                            continue
                        try:
                            render(broken)
                        except ValueError:
                            pass
                        except Exception as error:  # noqa: BLE001 - collecting all
                            failures.append(f"{name} {list(path)} = "
                                            f"{'<deleted>' if value is DELETE else value!r}: "
                                            f"{render.__name__} raised {type(error).__name__}: {error}")
        self.assertEqual(failures[:20], [], f"{len(failures)} renderer failures")


if __name__ == "__main__":
    unittest.main()

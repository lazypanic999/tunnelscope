"""Check installed report workflows without importing the repository checkout.

Run after ``python -m pip install .`` with ``python -I scripts/check_installed.py``.
The isolated flag removes the working directory and PYTHONPATH from imports.
"""

import copy
from importlib import metadata
from pathlib import Path

import tunnelscope
from tunnelscope_core._version import VERSION
from tunnelscope_core.markdown import render_report_markdown
from tunnelscope_core.reports import correlate_reports, format_report, summarize_results
from tunnelscope_core.sanitize import sanitize_reports
from tunnelscope_core.view import render_report_html


def main():
    distribution = metadata.distribution("tunnelscope")
    installed = Path(distribution.locate_file("tunnelscope.py")).resolve()
    checkout = Path(__file__).resolve().parents[1] / "tunnelscope.py"
    if Path(tunnelscope.__file__).resolve() != installed or installed == checkout:
        raise RuntimeError("Expected the installed distribution, not checkout imports")
    if distribution.version != VERSION or tunnelscope.VERSION != VERSION:
        raise RuntimeError("Installed metadata and runtime versions disagree")

    probe_id = "a" * 32
    results = [{"probe_id": probe_id, "payload_bytes": 64, "status": "acknowledged", "attempt": 1}]
    probe = {"schema_version": 1, "kind": "probe", "tunnelscope_version": VERSION,
             "target": {"ipv4": "127.0.0.1", "port": 9471},
             "results": results, "summary": {"by_payload_size": summarize_results([64], results)}}
    receiver = {"schema_version": 1, "kind": "receiver_observations",
                "receiver": {"bind_ipv4": "127.0.0.1", "port": 9471},
                "observations": [{"probe_id": probe_id, "payload_bytes": 64, "ack_send_status": "sent"}]}
    joined = correlate_reports(probe, receiver)
    before = copy.deepcopy(joined)
    clean, = sanitize_reports([joined])
    text = format_report(clean)
    html = render_report_html(clean)
    markdown = render_report_markdown(clean)
    checks = (
        joined == before,
        joined["input_versions"] == {"probe": VERSION, "receiver": None},
        "Correlation: 1/1" in text,
        "data:image/png;base64," in html,
        "Sanitized report" in html,
        "## Observations (1 of 1 rows)" in markdown,
        len(markdown) <= 24000,
    )
    if not all(checks):
        raise RuntimeError(f"Installed report workflow checks failed: {checks}")
    markdown.encode("ascii")
    print(f"Installed TunnelScope {VERSION}: correlation, sanitize, text, HTML/logo and Markdown passed")


if __name__ == "__main__":
    main()

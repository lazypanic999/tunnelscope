"""Build a small local HTML view of a TunnelScope JSON report."""

import base64
from html import escape
from importlib.resources import files
import json


def _cell(value):
    return "—" if value is None else str(value)


def _logo_data_uri():
    logo = files("tunnelscope_assets").joinpath("tunnelscope-logo-blue.png").read_bytes()
    return "data:image/png;base64," + base64.b64encode(logo).decode("ascii")


def _records(value):
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise ValueError("report contains invalid result rows")
    return value


def _table_data(report):
    kind = report.get("kind", "probe")
    if kind == "probe":
        return ["Bytes", "Attempt", "Status", "RTT ms", "Kernel MTU"], [
            [row.get("payload_bytes"), row.get("attempt"), row.get("status"),
             row.get("rtt_ms"), row.get("kernel_reported_mtu_bytes")]
            for row in _records(report.get("results"))
        ]
    if kind == "receiver_observations":
        return ["Run ID", "Bytes", "Source", "ACK send"], [
            [row.get("run_id"), row.get("payload_bytes"),
             row.get("source_ipv4", row.get("source_ipv6")), row.get("ack_send_status")]
            for row in _records(report.get("observations"))
        ]
    if kind == "probe_receiver_correlation":
        return ["Bytes", "Sender", "Receiver saw", "ACK send"], [
            [row.get("payload_bytes"), row.get("sender_status"),
             "yes" if row.get("receiver_observed") else "no", row.get("ack_send_status")]
            for row in _records(report.get("results"))
        ]
    if kind == "bidirectional_comparison":
        comparison = report.get("comparison")
        if not isinstance(comparison, dict):
            raise ValueError("comparison report has no per-size summary")
        return ["Bytes", "A to B", "B to A"], [
            [row.get("payload_bytes"), row.get("a_to_b"), row.get("b_to_a")]
            for row in _records(comparison.get("by_payload_size"))
        ]
    return [], []


def _lab_data(report):
    headers = ["Direction", "Bytes", "Status", "Receiver saw"]
    rows = []
    for direction in _records(report.get("directions")):
        probe = direction.get("probe", direction)
        correlation = direction.get("correlation", {})
        if not isinstance(probe, dict) or not isinstance(correlation, dict):
            raise ValueError("lab report has invalid direction results")
        observed = {row.get("probe_id"): row.get("receiver_observed")
                    for row in _records(correlation.get("results", []))}
        for row in _records(probe.get("results")):
            seen = observed.get(row.get("probe_id"))
            rows.append([direction.get("direction"), row.get("payload_bytes"),
                         row.get("status"), "yes" if seen else "no" if seen is False else None])
    return headers, rows


def render_report_html(report):
    """Return an HTML report; escape every value from the untrusted JSON input."""
    if not isinstance(report, dict):
        raise ValueError("expected a TunnelScope JSON object")
    if isinstance(report.get("lab"), str):
        title = f"Lab: {report['lab']}"
        if isinstance(report.get("directions"), list):
            headers, rows = _lab_data(report)
        else:
            nested = report.get("correlation", report.get("probe"))
            if not isinstance(nested, dict):
                raise ValueError("lab report has no supported results")
            headers, rows = _table_data(nested)
    elif report.get("schema_version") == 1:
        kind = report.get("kind", "probe")
        if not isinstance(kind, str):
            raise ValueError("invalid report kind")
        title = kind.replace("_", " ").title()
        headers, rows = _table_data(report)
        if not headers:
            raise ValueError("unsupported report kind")
    else:
        raise ValueError("expected a schema_version 1 TunnelScope report")
    header_html = "".join(f"<th scope='col'>{escape(label)}</th>" for label in headers)
    row_html = "".join("<tr>" + "".join(f"<td>{escape(_cell(value))}</td>" for value in row) + "</tr>"
                       for row in rows)
    if not rows:
        row_html = f"<tr class='empty-report'><td colspan='{len(headers)}'>No observations in this report.</td></tr>"
    raw_json = escape(json.dumps(report, indent=2, ensure_ascii=False))
    safe_title = escape(title)
    logo_data_uri = _logo_data_uri()
    row_count = len(rows)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TunnelScope · {safe_title}</title>
<style>
:root {{ color-scheme: dark; font-family: system-ui, sans-serif; background: #090f22; color: #eef4ff; }}
body {{ max-width: 1100px; margin: 0 auto; padding: 24px; }}
header {{ display:flex; align-items:center; gap:16px; margin-bottom:24px; }}
header .mark {{ width:64px; height:64px; border-radius:14px; flex:0 0 64px;
background: #0a1024 url('{logo_data_uri}') center / 180px auto no-repeat; }}
h1 {{ margin:0; font-size:1.8rem; }} small {{ color:#9eb5d8; }}
main {{ background:#101a33; border:1px solid #274473; border-radius:16px; padding:24px; }}
input {{ box-sizing:border-box; width:100%; padding:12px; margin:8px 0 18px; color:inherit;
background:#0b1430; border:1px solid #4269af; border-radius:8px; font:inherit; }}
#match-count {{ display:block; color:#9eb5d8; margin-bottom:8px; }}
#no-matches[hidden] {{ display:none; }}
.scroll {{ overflow-x:auto; }} table {{ width:100%; border-collapse:collapse; }}
th,td {{ padding:10px 12px; border-bottom:1px solid #273a61; text-align:left; white-space:nowrap; }}
th {{ color:#9dc4ff; }} tr:hover td {{ background:#17264a; }}
details {{ margin-top:24px; }} summary {{ cursor:pointer; color:#9dc4ff; }}
pre {{ overflow:auto; white-space:pre-wrap; overflow-wrap:anywhere; padding:16px;
background:#0b1430; border-radius:8px; }}
footer {{ margin-top:20px; color:#9eb5d8; font-size:.9rem; }}
</style></head><body>
<header><span class="mark" role="img" aria-label="TunnelScope logo"></span>
<div><h1>TunnelScope</h1><small>{safe_title} · local report view</small></div></header>
<main><label for="filter">Filter rows</label><input id="filter" type="search" placeholder="Search sizes, statuses, directions…">
<output id="match-count" role="status" aria-live="polite">Showing {row_count} of {row_count} rows</output>
<div class="scroll"><table><thead><tr>{header_html}</tr></thead><tbody>{row_html}</tbody></table></div>
<p id="no-matches" hidden>No matching rows.</p>
<details><summary>Raw JSON evidence</summary><pre>{raw_json}</pre></details></main>
<footer>Observed results only. Timeouts do not prove an MTU problem. Keep unsanitized reports private.</footer>
<script>const search=document.getElementById('filter');
const resultRows=[...document.querySelectorAll('tbody tr:not(.empty-report)')];
search.addEventListener('input',()=>{{
const q=search.value.toLowerCase();let visible=0;
for(const row of resultRows){{
row.hidden=!row.textContent.toLowerCase().includes(q);
if(!row.hidden)visible++;
}}
document.getElementById('match-count').textContent=`Showing ${{visible}} of ${{resultRows.length}} rows`;
document.getElementById('no-matches').hidden=visible!==0 || resultRows.length===0;
}});</script></body></html>"""

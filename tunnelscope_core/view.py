"""Build a small local HTML view of a TunnelScope JSON report."""

import base64
from html import escape
from importlib.resources import files
import json

from .reports import no_ack_measurement, no_ack_text


def _cell(value):
    return "—" if value is None else str(value)


def _logo_data_uri():
    logo = files("tunnelscope_assets").joinpath("tunnelscope-logo-blue.png").read_bytes()
    return "data:image/png;base64," + base64.b64encode(logo).decode("ascii")


def _records(value):
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise ValueError("report contains invalid result rows")
    return value


def _feedback_cell(row):
    observation = row.get("icmp_observation")
    if not isinstance(observation, dict):
        return "-"
    events = observation.get("events")
    if not isinstance(events, list):
        return "read unavailable"
    if not events:
        return "none observed" if observation.get("state") == "completed" else "read incomplete"
    labels = []
    for event in events:
        if not isinstance(event, dict):
            labels.append("unparsed")
            continue
        match = event.get("quoted_probe_match")
        association = "matched" if match is True else "socket only" if match is None else "mismatch"
        mtu = event.get("reported_mtu_bytes")
        labels.append(f"{event.get('message', 'unknown')} ({association}" +
                      (f", MTU {mtu}" if isinstance(mtu, int) else "") + ")")
    return "; ".join(labels)


def _table_data(report):
    kind = report.get("kind", "probe")
    if kind == "probe":
        headers = ["Bytes", "Attempt", "Status", "RTT ms", "Kernel MTU"]
        feedback_enabled = isinstance(report.get("summary"), dict) and isinstance(report["summary"].get("icmp_feedback"), dict)
        if feedback_enabled:
            headers.extend(("Size error origin", "ICMP feedback"))
        return headers, [
            [row.get("payload_bytes"), row.get("attempt"), row.get("status"),
             row.get("rtt_ms"), row.get("kernel_reported_mtu_bytes"),
             *([row.get("size_error_origin"), _feedback_cell(row)] if feedback_enabled else [])]
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
    if kind == "fragmentation_comparison":
        comparison = report.get("comparison")
        if not isinstance(comparison, dict):
            raise ValueError("fragmentation comparison has no per-size summary")
        rows = []
        for row in _records(comparison.get("by_payload_size")):
            df, allowed = row.get("df"), row.get("fragmentation_permitted")
            if not isinstance(df, dict) or not isinstance(allowed, dict):
                raise ValueError("invalid fragmentation comparison row")
            rows.append([row.get("payload_bytes"), df.get("assessment"),
                         no_ack_text(df.get("no_ack_measurement")), allowed.get("assessment"),
                         no_ack_text(allowed.get("no_ack_measurement"))])
        return ["Bytes", "DF", "DF no ACK", "Permitted", "Permitted no ACK"], rows
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
    search_report = report
    if isinstance(report.get("lab"), str):
        title = f"Lab: {report['lab']}"
        if isinstance(report.get("directions"), list):
            headers, rows = _lab_data(report)
        else:
            nested = report.get("correlation", report.get("probe"))
            if not isinstance(nested, dict):
                raise ValueError("lab report has no supported results")
            search_report = nested
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
    search = search_report.get("summary") if isinstance(search_report, dict) else None
    search = search.get("search") if isinstance(search, dict) else None
    search_html = ""
    if isinstance(search, dict):
        interval = search.get("observed_interval_payload_bytes")
        interval_text = (f"{interval[0]}..{interval[1]} UDP payload bytes"
                         if isinstance(interval, list) and len(interval) == 2 else "none")
        fields = (
            ("Assessment", search.get("assessment")),
            ("Observed interval", interval_text),
            ("Largest acknowledged", search.get("largest_acknowledged_payload_bytes")),
            ("Smallest explicit size error", search.get("smallest_packet_too_large_payload_bytes")),
        )
        search_html = "<section class='search-summary'><h2>Size search evidence</h2>" + "".join(
            f"<p><strong>{escape(label)}:</strong> {escape(_cell(value))}</p>" for label, value in fields
        ) + "<p>Timeouts and mixed outcomes do not establish a boundary.</p></section>"
    measurement_html = ""
    if search_report.get("kind") == "probe":
        summary = search_report.get("summary")
        size_rows = summary.get("by_payload_size") if isinstance(summary, dict) else None
        if isinstance(size_rows, list) and size_rows:
            cells = []
            for row in _records(size_rows):
                counts = row.get("status_counts")
                if not isinstance(counts, dict):
                    raise ValueError("invalid probe size summary")
                measurement = row.get("no_ack_measurement") or no_ack_measurement(counts)
                cells.append("<tr><td>" + escape(_cell(row.get("payload_bytes"))) +
                             "</td><td>" + escape(no_ack_text(measurement)) + "</td></tr>")
            measurement_html = ("<section class='search-summary'><h2>Repeated measurements</h2>"
                                "<table><thead><tr><th>UDP payload bytes</th><th>No ACK (95% CI)</th></tr>"
                                "</thead><tbody>" + "".join(cells) + "</tbody></table>"
                                "<p>A timeout means no matching ACK arrived; it does not prove packet loss. "
                                "Intervals use the Wilson method on sent probes only.</p></section>")
    elif search_report.get("kind") == "fragmentation_comparison":
        measurement_html = ("<section class='search-summary'><h2>Fragmentation modes</h2>"
                            "<p>DF first, source fragmentation permitted second. Fragment arrival was not "
                            "observed; differing outcomes do not identify a cause.</p></section>")
    if isinstance(search_report.get("summary"), dict):
        feedback = search_report["summary"].get("icmp_feedback")
        if isinstance(feedback, dict):
            fields = (("Size feedback events", feedback.get("size_feedback_events")),
                      ("Token matched", feedback.get("token_matched_size_feedback_events")),
                      ("Local errors", feedback.get("local_error_events")),
                      ("Read state", feedback.get("observation_state")))
            measurement_html += ("<section class='search-summary'><h2>ICMP feedback</h2>" +
                                 "".join(f"<p><strong>{escape(label)}:</strong> {escape(_cell(value))}</p>"
                                         for label, value in fields) +
                                 "<p>Observed ICMP is untrusted feedback. No observed message does not prove it was blocked.</p></section>")
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
.search-summary {{ border:1px solid #4269af; border-radius:10px; padding:12px 18px; margin-bottom:18px; }}
.search-summary h2 {{ margin:0 0 8px; font-size:1.2rem; }}
.search-summary p {{ margin:6px 0; }}
pre {{ overflow:auto; white-space:pre-wrap; overflow-wrap:anywhere; padding:16px;
background:#0b1430; border-radius:8px; }}
footer {{ margin-top:20px; color:#9eb5d8; font-size:.9rem; }}
</style></head><body>
<header><span class="mark" role="img" aria-label="TunnelScope logo"></span>
<div><h1>TunnelScope</h1><small>{safe_title} · local report view</small></div></header>
<main>{search_html}{measurement_html}<label for="filter">Filter rows</label><input id="filter" type="search" placeholder="Search sizes, statuses, directions…">
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

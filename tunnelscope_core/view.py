"""Build a small local HTML view of a TunnelScope JSON report."""

import base64
from datetime import timezone
from html import escape as html_escape
from importlib.resources import files
import json
import re

from .reports import no_ack_measurement, no_ack_text, version_details
from .tables import _records, _table_data, _lab_data, report_table
from .timestamps import parse_timestamp


def escape(value, quote=True):
    """Escape markup and display non-UTF-8 OS bytes as visible backslash escapes."""
    return html_escape(value, quote=quote).encode("utf-8", "backslashreplace").decode("utf-8")


def _cell(value):
    return "—" if value is None else str(value)


PROBE_ID = re.compile(r"^[0-9a-f]{32}$")


def _short(value):
    """Return a compact display text for long identifiers and timestamps, or None to show the value as is."""
    if not isinstance(value, str):
        return None
    if PROBE_ID.match(value):
        return value[:8] + "…"
    moment = parse_timestamp(value)
    if moment is None:
        return None
    try:
        utc = moment.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return None
    short = utc.strftime("%H:%M:%S")
    return short + f".{utc.microsecond // 1000:03d}" if "." in value else short


def _td(value):
    short = _short(value)
    if short is None:
        return f"<td>{escape(_cell(value))}</td>"
    return f"<td title='{escape(value)}'>{escape(short)}</td>"


def _row(row):
    # Full values stay searchable even where the cell shows a shortened form.
    full = " ".join(str(value) for value in row if _short(value) is not None)
    attribute = f" data-search='{escape(full)}'" if full else ""
    return f"<tr{attribute}>" + "".join(_td(value) for value in row) + "</tr>"


def _logo_data_uri():
    logo = files("tunnelscope_assets").joinpath("tunnelscope-logo-blue.png").read_bytes()
    return "data:image/png;base64," + base64.b64encode(logo).decode("ascii")


def render_report_html(report):
    """Return an HTML report; escape every value from the untrusted JSON input."""
    title, headers, rows, search_report = report_table(report)
    header_html = "".join(f"<th scope='col'>{escape(label)}</th>" for label in headers)
    row_html = "".join(_row(row) for row in rows)
    if not rows:
        row_html = f"<tr class='empty-report'><td colspan='{len(headers)}'>No observations in this report.</td></tr>"
    raw_json = escape(json.dumps(report, indent=2, ensure_ascii=False))
    search = search_report.get("summary") if isinstance(search_report, dict) else None
    search = search.get("search") if isinstance(search, dict) else None
    if search_report.get("kind") == "diagnosis":
        if not isinstance(search_report.get("summary", {}), dict):
            raise ValueError("invalid diagnosis summary")
        if not isinstance(search_report.get("consistency", {}), dict):
            raise ValueError("invalid diagnosis consistency")
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
    versions = version_details(search_report)
    if versions:
        search_html += ("<section class='search-summary'><h2>Declared producer versions</h2>"
                        + "".join(f"<p><strong>{escape(label)}:</strong> {escape(_cell(value))}</p>"
                                  for label, value in versions)
                        + "<p>Recorded metadata is not authentication. Missing legacy versions remain unknown.</p></section>")
    sanitization = report.get("sanitization")
    if isinstance(sanitization, dict):
        search_html = ("<section class='search-summary'><h2>Sanitized report</h2>"
                       f"<p><strong>Addresses:</strong> {escape(_cell(sanitization.get('addresses')))}</p>"
                       f"<p><strong>Timestamps:</strong> {escape(_cell(sanitization.get('timestamps')))}</p>"
                       "<p>Equal placeholders mean equal original values within one sanitized batch.</p></section>"
                       + search_html)
    if search_report.get("kind") == "probe_receiver_correlation":
        measurement_html = ("<section class='search-summary'><h2>Joined probe observations</h2>"
                            "<p>receiver_observed_no_ack means the receiver logged the probe but the sender did not receive a matching ACK. "
                            "no_ack_no_receiver_observation means neither receipt was logged; this remains inconclusive "
                            "without verified receiver coverage. Timestamps from different hosts are shown without clock comparison.</p></section>")
    if search_report.get("kind") == "diagnosis":
        consistency = search_report.get("consistency", {})
        summary = search_report.get("summary", {})
        returns = summary.get("return")
        fields = (("Scope", search_report.get("scope")), ("Attempts", summary.get("attempts")),
                  *((("Same-sized replies",
                      f"{returns.get('sized_reply_received', 0)} received, "
                      f"{returns.get('small_ack_only', 0)} small ACK only, "
                      f"{returns.get('no_reply', 0)} no reply"),) if isinstance(returns, dict) else ()),
                  ("ICMP size feedback events", summary.get("icmp_size_feedback_events")),
                  ("Target check", consistency.get("search_target_check")),
                  ("Source check", consistency.get("search_source_check")))
        measurement_html = ("<section class='search-summary'><h2>Workflow scope</h2>" +
                            "".join(f"<p><strong>{escape(label)}:</strong> {escape(_cell(value))}</p>"
                                    for label, value in fields) +
                            "<p>Sequential runs in one sender direction. The interval is not a proven path MTU.</p></section>")
        receiver_evidence = search_report.get("receiver_evidence")
        if isinstance(receiver_evidence, dict):
            receiver_summary = receiver_evidence.get("summary", {})
            if not isinstance(receiver_summary, dict):
                raise ValueError("diagnosis has invalid receiver summary")
            fields = (("Receiver observed", receiver_summary.get("receiver_observed")),
                      ("Sender attempts", receiver_summary.get("sent_probes")),
                      ("Unmatched receiver observations", receiver_summary.get("unmatched_receiver_observations")),
                      ("Other run observations", receiver_summary.get("unassigned_receiver_observations")),
                      ("Receiver exit", receiver_summary.get("capture_exit_reason")))
            measurement_html += ("<section class='search-summary'><h2>Joined receiver evidence</h2>" +
                                 "".join(f"<p><strong>{escape(label)}:</strong> {escape(_cell(value))}</p>"
                                         for label, value in fields) +
                                 "<p>No receiver observation is inconclusive without verified capture coverage. "
                                 "Clocks on separate hosts are not compared.</p></section>")
    send_summary = (search_report.get("receiver_evidence", {}).get("summary", {})
                    if isinstance(search_report.get("receiver_evidence"), dict)
                    else search_report.get("summary", {}))
    if isinstance(send_summary, dict) and send_summary.get("receiver_reply_send_unverified"):
        measurement_html += ("<section class='search-summary'><h2>Unverified receiver reply sends</h2>"
                             f"<p>Without a recorded local send outcome: {escape(_cell(send_summary['receiver_reply_send_unverified']))}.</p>"
                             "<p>Receiver arrival was logged, but a missing send outcome does not establish that a reply was sent or rejected.</p></section>")
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
:root {{
  color-scheme: light dark;
  --bg: #f5f7fb; --panel: #ffffff; --panel-2: #f0f4fa; --line: #dde4ef; --text: #172033;
  --muted: #5b6b85; --accent: #2f6fde; --accent-soft: #e6eefc;
  --good: #137a4b; --good-bg: #e3f5ec; --warn: #8a5a00; --warn-bg: #fdf1d8;
  --bad: #b42335; --bad-bg: #fde6e9; --info: #4b5a75; --info-bg: #eaeef5;
  --shadow: 0 1px 2px rgba(16, 24, 40, .06), 0 1px 3px rgba(16, 24, 40, .08);
  font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}}
@media (prefers-color-scheme: dark) {{
  :root {{
    --bg: #0b1020; --panel: #121a2e; --panel-2: #172238; --line: #26324d; --text: #e8eefb;
    --muted: #93a3c0; --accent: #7aa8ff; --accent-soft: #1b2a4a;
    --good: #5fd39a; --good-bg: #12392a; --warn: #f2c163; --warn-bg: #3d3014;
    --bad: #ff8a96; --bad-bg: #44161e; --info: #b4c1d9; --info-bg: #222e47;
    --shadow: none;
  }}
}}
* {{ box-sizing: border-box; }}
body {{ margin: 0; background: var(--bg); color: var(--text); line-height: 1.5; }}
.wrap {{ max-width: 1400px; margin: 0 auto; padding: 28px 24px 40px; }}
header {{ display: flex; align-items: center; gap: 16px; margin-bottom: 22px; }}
header .mark {{ width: 56px; height: 56px; border-radius: 14px; flex: 0 0 56px;
  background: #0a1024 url('{logo_data_uri}') center / 160px auto no-repeat; box-shadow: var(--shadow); }}
h1 {{ margin: 0; font-size: 1.6rem; letter-spacing: -.01em; }}
header small {{ color: var(--muted); font-size: .95rem; }}
main {{ display: grid; gap: 16px; min-width: 0; }}
main > *, .cards > * {{ min-width: 0; }}
.cards {{ display: grid; gap: 14px; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); }}
.search-summary {{ background: var(--panel); border: 1px solid var(--line); border-radius: 12px;
  padding: 14px 18px; box-shadow: var(--shadow); }}
.search-summary h2 {{ margin: 0 0 8px; font-size: .8rem; text-transform: uppercase; letter-spacing: .06em;
  color: var(--accent); }}
.search-summary p {{ margin: 5px 0; }}
.search-summary p:last-child {{ color: var(--muted); font-size: .88rem; margin-top: 10px; }}
.search-summary strong {{ color: var(--muted); font-weight: 600; }}
.search-summary table {{ font-size: .92rem; }}
.panel {{ background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 18px;
  box-shadow: var(--shadow); }}
label {{ font-weight: 600; font-size: .9rem; }}
input {{ width: 100%; padding: 10px 12px; margin: 6px 0 10px; color: inherit; background: var(--panel-2);
  border: 1px solid var(--line); border-radius: 8px; font: inherit; }}
input:focus {{ outline: 2px solid var(--accent); outline-offset: 1px; }}
#match-count {{ display: block; color: var(--muted); font-size: .9rem; }}
.hint {{ color: var(--muted); font-size: .82rem; margin: 2px 0 12px; }}
#no-matches[hidden] {{ display: none; }}
.scroll {{ overflow: auto; max-height: 72vh; border: 1px solid var(--line); border-radius: 10px; }}
table {{ width: 100%; border-collapse: collapse; font-variant-numeric: tabular-nums; }}
th, td {{ padding: 9px 12px; border-bottom: 1px solid var(--line); text-align: left; white-space: nowrap; }}
th {{ position: sticky; top: 0; z-index: 1; background: var(--panel-2); color: var(--muted);
  font-size: .78rem; text-transform: uppercase; letter-spacing: .05em; }}
tbody tr:nth-child(even) td {{ background: color-mix(in srgb, var(--panel-2) 45%, transparent); }}
tbody tr:hover td {{ background: var(--accent-soft); }}
td[title] {{ cursor: help; text-decoration: underline dotted var(--muted); text-underline-offset: 3px; }}
td.s-good, td.s-warn, td.s-bad, td.s-info {{ font-weight: 600; }}
td.s-good {{ color: var(--good); }} td.s-warn {{ color: var(--warn); }}
td.s-bad {{ color: var(--bad); }} td.s-info {{ color: var(--info); }}
td.s-good::before, td.s-warn::before, td.s-bad::before, td.s-info::before {{
  content: ""; display: inline-block; width: .55em; height: .55em; border-radius: 50%;
  margin-right: .45em; vertical-align: .08em; background: currentColor; }}
details {{ margin-top: 16px; }} summary {{ cursor: pointer; color: var(--accent); font-weight: 600; }}
pre {{ overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; padding: 16px; margin: 10px 0 0;
  background: var(--panel-2); border: 1px solid var(--line); border-radius: 8px; font-size: .85rem; }}
.legend {{ display: flex; flex-wrap: wrap; gap: 14px; color: var(--muted); font-size: .82rem; margin: 0 0 10px; }}
.legend span::before {{ content: ""; display: inline-block; width: .55em; height: .55em; border-radius: 50%;
  margin-right: .4em; background: currentColor; }}
.legend .good {{ color: var(--good); }} .legend .warn {{ color: var(--warn); }} .legend .bad {{ color: var(--bad); }}
footer {{ margin-top: 22px; color: var(--muted); font-size: .85rem; }}
@media (max-width: 640px) {{ .wrap {{ padding: 18px 14px 30px; }} h1 {{ font-size: 1.3rem; }} }}
@media print {{
  :root {{ color-scheme: light; }}
  body {{ background: #fff; }} .scroll {{ max-height: none; overflow: visible; }}
  input, label[for="filter"], #match-count, .hint {{ display: none; }}
  .search-summary, .panel {{ box-shadow: none; }}
}}
</style></head><body><div class="wrap">
<header><span class="mark" role="img" aria-label="TunnelScope logo"></span>
<div><h1>TunnelScope</h1><small>{safe_title} · local report view</small></div></header>
<main><div class="cards">{search_html}{measurement_html}</div>
<section class="panel"><label for="filter">Filter rows</label><input id="filter" type="search" placeholder="Search sizes, statuses, directions…">
<output id="match-count" role="status" aria-live="polite">Showing {row_count} of {row_count} rows</output>
<p class="hint">Probe IDs show their first 8 characters and timestamps their UTC time of day; hover a cell for the full value. Search matches full values.</p>
<p class="legend" aria-hidden="true"><span class="good">delivered / returned</span><span class="warn">no answer, inconclusive</span><span class="bad">refused or failed</span></p>
<div class="scroll"><table><thead><tr>{header_html}</tr></thead><tbody>{row_html}</tbody></table></div>
<p id="no-matches" hidden>No matching rows.</p>
<details><summary>Raw JSON evidence</summary><pre>{raw_json}</pre></details></section></main>
<footer>Observed results only. Timeouts do not prove an MTU problem. Keep unsanitized reports private.</footer></div>
<script>const search=document.getElementById('filter');
const resultRows=[...document.querySelectorAll('tbody tr:not(.empty-report)')];
// Colour known status values; the report text itself is unchanged.
const statusClass={{good:['acknowledged','sized_reply_received','sized_reply_returned','acknowledged_and_receiver_observed','delivery_observed'],
warn:['timeout','no_reply','inconclusive','receiver_observed_no_ack','no_ack_no_receiver_observation','receiver_observed_sized_reply_missing','acknowledged_receiver_log_missing','mixed_observations'],
bad:['packet_too_large','kernel_rejected_df_payload','receiver_reply_send_failed','socket_error','socket_error_or_unknown','explicit_size_error'],
info:['small_ack_only','receiver_reply_send_unverified','receiver_sent_small_reply','no_receiver_observation']}};
const lookup=new Map();for(const [k,v] of Object.entries(statusClass))for(const s of v)lookup.set(s,'s-'+k);
for(const cell of document.querySelectorAll('tbody td')){{const c=lookup.get(cell.textContent.trim());if(c)cell.classList.add(c);}}
search.addEventListener('input',()=>{{
const q=search.value.toLowerCase();let visible=0;
for(const row of resultRows){{
row.hidden=!(row.textContent+' '+(row.dataset.search||'')).toLowerCase().includes(q);
if(!row.hidden)visible++;
}}
document.getElementById('match-count').textContent=`Showing ${{visible}} of ${{resultRows.length}} rows`;
document.getElementById('no-matches').hidden=visible!==0 || resultRows.length===0;
}});</script></body></html>"""

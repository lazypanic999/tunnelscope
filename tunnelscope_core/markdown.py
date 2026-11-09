"""Render bounded, pasteable Markdown from stored observation tables."""

from datetime import timezone
import re

from .tables import report_table
from .reports import refused_attempts, version_details
from .timestamps import parse_timestamp

MAX_ROWS = 50
MAX_CELL_CHARACTERS = 160
MAX_OUTPUT_CHARACTERS = 24000


NEWLINE = " [newline] "
# Characters that can start Markdown or HTML structure, links or strikethrough
# anywhere in a table cell.
ALWAYS_ENCODED = set("\\`|*[]<&~")
WORD = re.compile(r"[A-Za-z0-9]")
# GitHub links @mentions and #123 / GH-123 references and renders $math$ after
# character references are decoded, so those need a different break: a zero
# width space after the reference trigger and before every dollar sign.
ZERO_WIDTH_SPACE = "&#8203;"
REFERENCE_TRIGGER = re.compile(r"[@#][A-Za-z0-9_-]")
GH_REFERENCE = re.compile(r"(?<![A-Za-z0-9])GH-[0-9]", re.IGNORECASE)
# A colon followed by an emoji-shortcode-like token (":abc:", ":+1:", ":100:")
# or by "//" (scheme links). Plain timestamps and IPv4 addresses stay readable.
COLON_HAZARD = re.compile(r"//|[A-Za-z0-9_+-]*[A-Za-z_][A-Za-z0-9_+-]*:|(?:100|1234|[+-]1):")


def _encode(char):
    return f"&#{ord(char)};"


def _escape(text):
    """Encode only characters that could add Markdown structure; keep the rest readable."""
    out = []
    for index, char in enumerate(text):
        before = text[index - 1] if index else ""
        after = text[index + 1] if index + 1 < len(text) else ""
        if char == "$":
            # GitHub renders "\$" and "&#36;" as math inside tables; a leading
            # zero width space is the break that held in a rendering check.
            out.append(ZERO_WIDTH_SPACE + "$")
            continue
        if (char in "@#" and REFERENCE_TRIGGER.match(text, index)) or (
                char == "-" and index >= 2 and GH_REFERENCE.match(text, index - 2)):
            out.append(char + ZERO_WIDTH_SPACE)
            continue
        if (char in ALWAYS_ENCODED or not 32 <= ord(char) <= 126
                # Intraword underscores never emphasize in GFM; boundary ones can.
                or (char == "_" and not (WORD.match(before) and WORD.match(after)))
                or (char == ":" and COLON_HAZARD.match(text, index + 1))
                # "www." starts an automatic link.
                or (char == "." and text[max(0, index - 3):index].lower() == "www")):
            out.append(_encode(char))
        else:
            out.append(char)
    return "".join(out)


def _text(value):
    text = "-" if value is None else str(value)
    text = NEWLINE.join(text.splitlines()).replace("\t", " ").replace("\x00", "\ufffd")
    if len(text) > MAX_CELL_CHARACTERS:
        text = text[:MAX_CELL_CHARACTERS - 3] + "..."
    # The [newline] marker is ours; brackets alone cannot form a link.
    return _escape(text).replace("&#91;newline&#93;", "[newline]")


def _display(value, header):
    if header == "Probe ID" and isinstance(value, str) and re.fullmatch(r"[0-9a-f]{32}", value):
        return value[:8] + "..."
    if "(UTC)" in header:
        moment = parse_timestamp(value)
        if moment is not None:
            try:
                return moment.astimezone(timezone.utc).isoformat()
            except (ValueError, OverflowError):
                pass
    return value


def _result_lists(report, detail):
    """Collect distinct result lists from a probe report or a lab report that wraps one."""
    seen = set()
    sections = [report, report.get("probe"), report.get("correlation"), detail]
    for section in sections:
        if not isinstance(section, dict):
            continue
        rows = section.get("results")
        if isinstance(rows, list) and id(rows) not in seen:
            seen.add(id(rows))
            yield rows


def render_report_markdown(report):
    """Return observations only; keep the source JSON unchanged and complete."""
    title, headers, rows, detail = report_table(report)
    lines = [f"# TunnelScope - {_text(title)}", "",
             "Stored observations; this export does not run a new network test.", ""]
    sanitization = report.get("sanitization")
    if isinstance(sanitization, dict):
        lines.extend(["**Sanitization record present.** Review the copies before sharing; "
                      "the record is metadata, not a guarantee that all identifiers were removed.",
                      f"Timestamps: {_text(sanitization.get('timestamps', 'unknown'))}.", ""])
    else:
        lines.extend(["**No sanitization record.** Use `tunnelscope sanitize` and review the copies before sharing.", ""])

    facts = version_details(detail)
    if "scope" in detail:
        facts.append(("Scope", detail["scope"]))
    pairing = detail.get("pairing")
    if isinstance(pairing, dict):
        facts.append(("Run ID pairing", pairing.get("run_id_check")))
    summary = detail.get("summary")
    summary = summary if isinstance(summary, dict) else {}
    search = summary.get("search")
    if isinstance(search, dict):
        facts.extend((("Search assessment", search.get("assessment")),
                      ("Observed UDP payload interval", search.get("observed_interval_payload_bytes"))))
    receiver = detail.get("receiver_evidence")
    if isinstance(receiver, dict) and isinstance(receiver.get("summary"), dict):
        joined = receiver["summary"]
        facts.append(("Receiver observed / sender attempts",
                      f"{joined.get('receiver_observed', '?')} / {joined.get('sent_probes', '?')}"))
    elif "receiver_observed" in summary:
        facts.append(("Receiver observed / sender attempts",
                      f"{summary.get('receiver_observed', '?')} / {summary.get('sent_probes', '?')}"))
    send_summary = receiver.get("summary", {}) if isinstance(receiver, dict) else summary
    if isinstance(send_summary, dict) and send_summary.get("receiver_reply_send_unverified"):
        facts.append(("Receiver reply sends without recorded outcome", send_summary["receiver_reply_send_unverified"]))
    refused = sum(refused_attempts(rows) for rows in _result_lists(report, detail))
    if refused:
        facts.append(("Port unreachable attempts", refused))
    for label, value in facts:
        lines.append(f"- {label}: {_text(value)}")
    if facts:
        lines.append("")

    table_head = ["| " + " | ".join(_text(header) for header in headers) + " |",
                  "| " + " | ".join("---" for _ in headers) + " |"]
    # Leave room for headings, the truncation notice and interpretation limits.
    remaining = MAX_OUTPUT_CHARACTERS - len("\n".join([*lines, *table_head])) - 2000
    shown = []
    for row in rows[:MAX_ROWS]:
        text = "| " + " | ".join(_text(_display(value, header))
                                  for header, value in zip(headers, row)) + " |"
        if len(text) + 1 > remaining:
            break
        shown.append(text)
        remaining -= len(text) + 1
    lines.extend([f"## Observations ({len(shown)} of {len(rows)} rows)", ""])
    if shown:
        lines.extend([*table_head, *shown])
    else:
        lines.append("No rows fit the Markdown size limit." if rows else "No observations in this report.")
    lines.append("")
    if len(rows) > len(shown):
        lines.extend([f"Truncated to the first {len(shown)} rows (50-row / 24,000-character limit); "
                      "attach the full sanitized JSON for all observations.", ""])
    lines.extend(["Cells are limited to 160 characters; probe IDs show eight characters; "
                  "line breaks are shown as [newline]. The full values remain in the JSON.", "",
                  "## Interpretation limits", "",
                  "A timeout means no matching acknowledgement arrived; it does not prove packet loss or an MTU fault. "
                  "No receiver observation remains inconclusive without confirmed capture coverage. "
                  "A small ACK does not prove same-sized return delivery. Observed intervals are not independently "
                  "measured end-to-end path MTUs. ICMP and receiver logs are unauthenticated; clocks on different "
                  "hosts are not compared."])
    return "\n".join(lines) + "\n"

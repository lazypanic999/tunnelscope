# Markdown report export

Available in v0.9.0 and newer. Install with
`python -m pip install --upgrade tunnelscope==0.9.1`. The existing text and
HTML views remain available.

After collecting a sender report and receiver capture, correlate and sanitize
them as in the [field report guide](field-reports.md), then:

```sh
tunnelscope show shared/correlation.json --format markdown > evidence.md
```

Open `evidence.md`, review it, and paste it into an issue. Attach the full
sanitized JSON alongside it so another person can inspect every probe and
identifier. This command reads a stored report, initiates no network test,
and posts nothing. Choose a fresh output filename for shell redirection;
the shell opens the redirected file before TunnelScope runs.

`tunnelscope show REPORT` and `--format text` keep the existing terminal table.
Markdown works for probes, receiver logs, size searches, fragmentation and
bidirectional comparisons, receiver correlations, diagnoses and the checked-in
lab examples. Both HTML and Markdown use the same observation-table data.

## What the summary keeps

- Scope, run-ID pairing, observed search bounds and receiver counts when the
  report supplies them.
- Per-attempt or per-size observations, including same-sized return evidence
  in joined reports.
- The sanitization record's presence and timestamp policy. A record is
  metadata; review is still needed. The exporter does not sanitize its input.
- Limits on interpretation: missing ACKs and receiver entries remain
  inconclusive, a small ACK does not test same-sized return delivery, and
  observed bounds are not a proven end-to-end path MTU.

Timestamp columns labeled UTC are normalized to UTC with their full date.
Clocks on different hosts are not compared.

## Output limits

The summary contains at most 50 observation rows and 24,000 ASCII characters.
Cells are limited to 160 original characters, probe IDs display their first
eight characters, and multiline values display `[newline]`. A notice states
when rows were omitted. Full values and all observations remain in the JSON;
the exporter never changes it.

Report values use numeric character references for punctuation and non-ASCII
characters. GitHub displays the original characters as text, without letting
an address, hostname or other field introduce a link, image, HTML tag, table
column or new Markdown section. The plain source therefore contains entities
such as `&#124;` for a literal pipe. This follows
[GitHub Flavored Markdown's character-reference rules](https://github.github.com/gfm/#entity-and-numeric-character-references).
The export is ASCII so redirected output also works with older Windows
console encodings. It adds no runtime dependencies.

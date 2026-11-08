# Markdown report export

Available in v0.9.0 and newer. Install or upgrade with
`python -m pip install --upgrade tunnelscope`. The existing text and
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
eight characters followed by `...`, missing values display `-`, and multiline
values display `[newline]`. A notice states
when rows were omitted. Full values and all observations remain in the JSON;
the exporter never changes it.

Report values stay readable in the plain source: addresses, timestamps,
statuses and most punctuation appear as written. Only characters that could
change how GitHub renders the summary are altered:

- `|`, `` ` ``, `*`, `[`, `]`, `<`, `&`, `\` and `~`, non-ASCII characters,
  underscores at word boundaries, `://`, `www.` and colons that would form an
  emoji shortcode such as `:abc:` become numeric character references (for
  example `&#124;` for a pipe). See
  [GitHub Flavored Markdown's character-reference rules](https://github.github.com/gfm/#entity-and-numeric-character-references).
- GitHub links `@mentions`, `#123` and `GH-123` references and renders `$...$`
  math even after character references are decoded, so a zero-width space
  (`&#8203;`) follows `@`, `#` and `GH-` before a name or number and precedes
  every `$`. The text still reads the same on GitHub, but a copied value can
  contain that invisible character; use the JSON for exact values.

A report field therefore cannot add a link, image, HTML tag, mention, issue
reference, emoji, math, table column or new section. This was checked by
rendering hostile values through GitHub's Markdown API in the repository
context. The export is ASCII so redirected output also works with older Windows
console encodings. It adds no runtime dependencies.

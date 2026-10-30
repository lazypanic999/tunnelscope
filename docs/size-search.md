# Bounded payload-size search (v0.5)

`search` narrows an *observed* UDP payload interval in a controlled Linux lab.
It uses no-fragment mode and tests the requested endpoints before choosing
midpoints. It does not discover an exact end-to-end path MTU or explain a
timeout on an unknown network.

Start a receiver on a lab address, then run on the sender:

```sh
tunnelscope receive --bind 192.0.2.2 --max-packets 100 --output receiver.json
tunnelscope search 192.0.2.2 --min 1200 --max 1400 --count 2 --output search.json
tunnelscope show search.json
tunnelscope html search.json --output search.html
tunnelscope correlate search.json receiver.json --output correlation.json
```

Run the receiver and sender on their respective machines. `192.0.2.2` is an
example address; use your lab receiver's address. The receiver exits after its
packet or idle limit. Search and correlation remain separate commands because
the sender does not control the remote receiver. Repeat with roles reversed
for evidence about the other direction.

`--family ipv6` or an IPv6 literal selects IPv6. `search` enables Linux
no-fragment behavior automatically; it rejects unsupported platforms. It
tests 2–16 sizes, at most 100 attempts and a 120-second timeout allowance.
The default is 12 sizes, three attempts per size and a one-second timeout.
`--max-sizes`, `--count` and `--timeout` adjust those bounds.

The normal schema-version-1 probe report is preserved. Individual attempts
remain in `results`, tested sizes in `settings.payload_sizes`, and per-size
counts in `summary.by_payload_size`. An additive `summary.search` object holds
the requested range, tested sizes, largest size with *all* attempts
acknowledged, smallest size with *all* attempts reporting `packet_too_large`,
ambiguous sizes, and an assessment:

| Assessment | Meaning |
| --- | --- |
| `adjacent_observed_bounds` | Acknowledged and explicit-error sizes are one payload byte apart. This is still an observed interval, not a measured path MTU. |
| `budget_limited_interval` | Both sides were observed, but the configured size budget ended before adjacency. |
| `no_explicit_bracket` | No pair of acknowledged and explicit-error sizes was observed. |
| `inconclusive` | A timeout, socket error, mixed outcomes or contradictory sizes prevent a clean boundary claim. |

The HTML report shows the search assessment above its attempt table. A small
acknowledgement is not a same-sized reverse-path test. Correlating a receiver
report can confirm arrival of individual probes, but does not by itself
identify the cause of missing replies. Use only in a controlled lab; the
protocol is unauthenticated and unencrypted.

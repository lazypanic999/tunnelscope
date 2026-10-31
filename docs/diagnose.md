# Single-command sender diagnosis (development `main`)

`diagnose` runs three sequential experiments from **one Linux sender** to an
already running cooperating receiver: DF probes at the minimum, midpoint and
maximum payload sizes; probes at the same sizes with source fragmentation
permitted; and a bounded adaptive DF size search. All three runs observe the
Linux UDP error queue for ICMP size feedback. It writes a bundled JSON report
and an offline HTML view, then prints a short terminal summary.

```sh
# On the controlled receiving host, bind to its test address first:
tunnelscope receive --bind 192.0.2.2 --max-packets 100

# On the Linux sender, using a development checkout or installation:
python tunnelscope.py diagnose 192.0.2.2 --min 1200 --max 1400 \
  --count 2 --max-sizes 8 --output diagnosis.json
python tunnelscope.py show diagnosis.json
```

The default HTML path is `diagnosis.html`; `--html` can select another path.
Both output directories must already exist and existing files are never
overwritten. `--family ipv6` selects IPv6. The command requires Linux DF and
UDP error-queue support. The maximum is 100 probe attempts or 120 seconds of
configured timeout allowance; exceeding either bound fails before probing.
The receiver has its own packet and idle-time limits and should cover the
expected run. The sender does not start, configure or authenticate a remote
receiver.

The report retains every underlying attempt and its run ID. It records source
and target consistency checks between runs. An adjacent observed interval is
an interval of UDP payload sizes under these conditions, **not** a verified
path MTU. Missing ACKs and absent ICMP are inconclusive. ICMP feedback may be
spoofed. Permitting source fragmentation does not prove fragments traversed
the path. The receiver's small ACK cannot establish same-sized return-path
delivery. Route and PMTU-cache changes between sequential runs can affect the
comparison.

For receiver observations, run `receive --output receiver.json` and correlate
each nested probe run separately with the receiver report. For the reverse
direction, run a separate experiment after swapping the sender and receiver;
`diagnose` does not coordinate both endpoints.

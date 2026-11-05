# Single-command sender diagnosis (v0.6)

`diagnose` runs three sequential experiments from **one Linux sender** to an
already running cooperating receiver: DF probes at the minimum, midpoint and
maximum payload sizes; probes at the same sizes with source fragmentation
permitted; and a bounded adaptive DF size search. All three runs observe the
Linux UDP error queue for ICMP size feedback. It writes a bundled JSON report
and an offline HTML view, then prints a short terminal summary.

```sh
# On the controlled receiving host, bind to its test address first:
tunnelscope receive --bind 192.0.2.2 --max-packets 100

# On the Linux sender, using v0.6 or newer:
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
delivery; with `--sized-reply` on both sides, an acknowledged attempt covers
both directions and the interval reflects the smaller one (see
[sized replies](sized-reply.md)). Route and PMTU-cache changes between sequential runs can affect the
comparison.

To join receiver observations after the capture ends, give the diagnosis and
receiver reports to `correlate`:

```sh
# On the receiver, before running diagnose on the sender:
tunnelscope receive --bind 192.0.2.2 --max-packets 100 \
  --idle-timeout 30 --output receiver.json

# After the receiver has exited and written receiver.json:
tunnelscope correlate diagnosis.json receiver.json \
  --output joined.json --html joined.html
```

The joined report retains all three sender runs and matches receiver entries
to each run ID and probe ID. A run with no matching receiver entries remains
`unverified_no_receiver_observations`; unrelated receiver runs are counted,
and a capture with no observations from this diagnosis is rejected. An absent
receiver observation does not prove loss unless capture coverage is confirmed
independently. For the reverse direction, run a separate experiment after
swapping sender and receiver; `diagnose` does not coordinate both endpoints.

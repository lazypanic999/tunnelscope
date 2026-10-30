# Repeated measurements and fragmentation comparison

This page describes development work on `main` after the published v0.5.0
release. Install from the repository to try `compare-fragmentation`.

## Repeated measurements

Every probe report keeps its individual attempts. Each
`summary.by_payload_size` row also contains `no_ack_measurement`:

- `sent_attempts` counts acknowledged probes and sender timeouts. A local
  `packet_too_large` or socket error is excluded because it is not a valid
  delivery trial.
- `no_ack_count` counts sender timeouts among those sent attempts.
- `no_ack_rate` is the observed timeout fraction, or `null` when no valid
  attempts were sent.
- `no_ack_wilson_95` is a descriptive 95% Wilson score interval for that
  fraction, or `null` when no valid attempts were sent.

For example, seven timeouts among ten sent probes yield a 70% no-ACK rate.
This is **not** a measured network packet-loss rate: the probe may have
reached the receiver while its small ACK failed on the return path. Trials
close together can also be correlated; the interval assumes independent,
similarly distributed attempts and is wide for small samples. Check a
receiver report with `correlate` before drawing conclusions about forward
delivery. Mixed results remain inconclusive for adaptive size search.

## Compare two fragmentation modes

On controlled Linux endpoints, start a receiver at the destination address:

```sh
tunnelscope receive --bind 192.0.2.2 --max-packets 30 --output receiver.json
```

In another terminal, use a reachable address from your lab in place of the
example address:

```sh
tunnelscope compare-fragmentation 192.0.2.2 --sizes 1200,1300,1400 --count 5 --output comparison.json
tunnelscope show comparison.json
tunnelscope html comparison.json --output comparison.html
```

The command runs two **sequential** experiments against the same target,
sizes, count and timeout. First it requests Linux no-fragment mode. Then it
sets `IP_PMTUDISC_DONT` for IPv4 or clears `IPV6_DONTFRAG` for IPv6, allowing
the source to fragment when the kernel decides to. Each run has its own
`run_id`, source snapshot, attempts and summaries in `runs.df` and
`runs.fragmentation_permitted`. The comparison records `source_check` and
`comparison.by_payload_size`; a changed source address or interface is
flagged. The receiver can be correlated separately with each run.

Allowing fragmentation does not prove that fragments crossed the path. A
change in results does not identify PMTU feedback, filtering or another
cause. Packet captures or receiver observations may be needed. The command
is capped at 16 distinct payload sizes, 10 attempts per size, 100 attempts
total across both modes and 120 seconds of configured timeout allowance.
Size, count and timeout limits still apply. It requires Linux, including
WSL2. The ordinary `probe` command continues to use OS-default fragmentation
behavior unless `--dont-fragment` is given.

## Validation

The [controlled comparison record](validation/fragmentation-comparison.md)
documents direct IPv4/IPv6 links and routed blocked-ICMP feedback. The
observations are from isolated Linux namespaces, not a real VPN or cluster.

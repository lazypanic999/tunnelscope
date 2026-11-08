# Routed IPv6 feedback: visible and blocked

Recorded on 2026-11-08 in Ubuntu under WSL2, Python 3.12.3 and Linux
6.6.87.2-microsoft-standard-WSL2. The runtime is v0.8.1 with the report fixes
from PR #26; this validation extends the existing lab, not the probe protocol.
The recorded JSON is [examples/ipv6-routed-feedback.json](../../examples/ipv6-routed-feedback.json).

## Topology and commands

`labs/ipv6_packet_too_big.py` creates three temporary Linux namespaces:

```text
sender -- MTU 1500 -- router -- MTU 1280 -- receiver
```

Both endpoints route through the router. Addresses use documentation prefixes
`2001:db8:5453:1::/64` and `2001:db8:5453:2::/64`. With the standard 40-byte
IPv6 header and 8-byte UDP header, the known egress link accommodates a
1232-byte UDP payload. TunnelScope's own header is included in that payload.

The lab starts a receiver with an eight-second idle timeout, runs no-fragment
probes at 64, 1232, 1233 and 1400 bytes with `--observe-icmp`, then joins the
receiver log by probe ID. Each probe waits up to two seconds. It tests the
blocked case first so previously learned PMTU information cannot turn the
blocked packets into local rejections. The router drops only its outgoing
ICMPv6 Packet Too Big messages, and its isolated firewall counter is recorded.
A bounded 1200–1400-byte search runs while feedback is still blocked.
The rule is then removed and the probe experiment is repeated.

To reproduce from a source checkout, with Linux root, `iproute2`, `ip6tables`
and `sysctl` available:

```sh
sudo python3 labs/ipv6_packet_too_big.py > ipv6-routed-feedback.json
```

All links, routes, forwarding settings and firewall changes are inside the
disposable namespaces. Processes and namespaces are cleaned up in `finally`.
No `ts6-` namespaces remained after the recorded run.

## Observations

| UDP payload | PTB blocked: sender | PTB visible: sender | Receiver in each case |
| --- | --- | --- | --- |
| 64 | acknowledged | acknowledged | observed |
| 1232 | acknowledged | acknowledged | observed |
| 1233 | timeout | packet_too_large, token-matched ICMPv6 | no matching observation |
| 1400 | timeout | packet_too_large, local cached size error | no matching observation |

The blocked probe and search observed zero ICMP size events. The router's
firewall counted three dropped PTB messages: two from the probe run and one
from the search. Search acknowledged 1200 bytes, timed out at 1400 bytes and
reported `assessment: inconclusive` with no observed boundary interval.

In the visible run, the 1233-byte attempt received an ICMPv6 type 2/code 0
event, reporting MTU 1280 and `quoted_probe_match: true`. The next oversized
attempt was rejected locally after the kernel learned the smaller MTU. The
test preserves this distinction; it does not count the local rejection as
another network ICMP message.

The blocked receiver capture includes both the probe and search run IDs.
Correlation records `matched_with_other_runs` for each join and leaves the
other run's observation unmatched. Those extra observations are expected.

## Limits and checks

`test_routed_ipv6_packet_too_big_feedback` runs this experiment in the opt-in
privileged Linux suite. It checks delivery on both sides of the configured
boundary, receiver pairing, blocked-rule counters, absence of feedback in
the blocked case, an inconclusive search, and the matched type/code/MTU in
the visible case. CI retains its full JSON as a lab artifact.

This is a controlled single-kernel experiment, not an independent VPN field
report or a physical multi-host test. One attempt per size is a demonstration,
not a reliable loss-rate estimate. A missing receiver entry on an unknown
path does not prove forward loss unless capture coverage is established;
zero observed ICMP does not prove filtering. The router's configuration and
counter are the independent context available in this lab. A small returned
ACK does not establish same-sized return delivery.

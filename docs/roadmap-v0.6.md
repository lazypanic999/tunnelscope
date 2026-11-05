# v0.6 scope and next steps

v0.6 extends bounded adaptive size search with repeated no-ACK measurements,
the `compare-fragmentation` command, Linux ICMP feedback observations,
`diagnose` and joined receiver evidence. See the [release notes](releases/v0.6.0.md).

## Included in v0.6

- Preserve per-attempt outcomes and summarize the no-ACK fraction with a
  descriptive Wilson interval for each payload size. Explicit local size
  errors and socket errors are excluded from the sent-attempt denominator.
- Compare the same sizes under Linux no-fragment mode and explicit
  fragmentation-permitted mode. Keep both full reports, their run IDs and a
  source snapshot check. Do not infer a cause from a difference.
- Validate direct IPv4/IPv6 boundaries and routed blocked-feedback behavior
  in isolated network namespaces.
- Observe Linux UDP error-queue size feedback with `--observe-icmp` and
  separate local errors from ICMPv4 fragmentation-needed and ICMPv6 Packet
  Too Big. Validate visible and blocked feedback in isolated namespaces.
- Run a bounded, single-sender `diagnose` workflow that bundles DF,
  fragmentation-permitted and adaptive search evidence in one JSON and HTML
  report. See the [diagnose guide](diagnose.md).
- Join sender and receiver evidence by probe ID in the correlation HTML view,
  including direction, payload size and per-attempt timestamps. Keep missing
  receiver observations inconclusive when capture coverage is unknown.
- Let `correlate` join a three-run diagnosis with one receiver capture, and
  render the joined evidence as a single JSON and HTML report. See the
  [diagnose guide](diagnose.md).
- Validate the workflow across a disposable, two-namespace WireGuard tunnel.
  The [lab record](validation/wireguard-namespace.md) shows a local tunnel MTU
  boundary and does not count as independent-host VPN field validation.
- Validate both directions across separate Ubuntu and Debian VMs joined by a
  controlled WireGuard tunnel. The [two-VM record](validation/two-vm-wireguard.md)
  confirms sender/receiver pairing and a local tunnel MTU boundary; it is not
  a production VPN incident or multi-hop path test.

## Validation after v0.6.0

- A [routed WireGuard lab](validation/wireguard-routed.md) checks a lower-MTU
  LAN beyond the receiving VPN gateway. Both directions record token-matched
  ICMP when visible and inconclusive timeouts when feedback is blocked. This
  controlled namespace topology remains separate from production field tests.
- A [two-node Kubernetes/Calico lab](validation/kubernetes-calico.md) validates
  both pod directions, joined receiver reports and a scoped NetworkPolicy
  block/recovery experiment using the released v0.6.0 package.

## Next evidence and workflow tasks

1. Validate production-like VPN constraints and additional Kubernetes CNI
   modes or physical multi-host paths with permission from the operators.
   Publish sanitized reports and topology details. The controlled WireGuard
   and Calico records above define the coverage already obtained.

The README quick start now joins sender and receiver logs in JSON and HTML.
The [Windows PowerShell guide](windows-loopback.md) is also available.
CI now tests Python 3.10 and 3.12 on Linux and Windows. Authentication,
encryption and internet-facing receiver operation are outside the current
scope; see [security boundaries](security-boundaries.md).

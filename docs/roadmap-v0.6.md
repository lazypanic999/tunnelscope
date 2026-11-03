# v0.6 development roadmap

The published v0.5.0 release provides bounded adaptive size search. The
current `main` branch is 0.6.0.dev0 and adds repeated no-ACK measurements and
the `compare-fragmentation` command. These are development features, not yet
published to PyPI.

## Implemented on `main`

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

## Next evidence and workflow tasks

1. Validate on a production-like VPN path with a real network constraint and
   on a Kubernetes pod path with permission from the operators. Publish
   sanitized reports and topology details. Open
   [issues #2 and #3](https://github.com/lazypanic999/tunnelscope/issues)
   track these community field tests.

Python 3.10 CI, receiver correlation in the quick start and a Windows
PowerShell loopback guide remain open good-first-issue tasks. Authentication,
encryption and internet-facing receiver operation are outside the current
scope; see [security boundaries](security-boundaries.md).

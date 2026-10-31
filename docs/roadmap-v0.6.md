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

## Next evidence and workflow tasks

1. Design a single-command controlled `diagnose` workflow that coordinates
   reporting without silently changing the security boundary or assuming
   symmetric delivery.
2. Validate on a real VPN and Kubernetes pod path with permission from the
   operators. Publish sanitized reports and topology details. Open
   [issues #2 and #3](https://github.com/lazypanic999/tunnelscope/issues)
   track these community field tests.

Python 3.10 CI, receiver correlation in the quick start and a Windows
PowerShell loopback guide remain open good-first-issue tasks. Authentication,
encryption and internet-facing receiver operation are outside the current
scope; see [security boundaries](security-boundaries.md).

# v0.5 scope: bounded size-boundary evidence

v0.5.0 implements a bounded size search for controlled Linux paths. It helps
a user choose useful UDP payload sizes and identify an
*observed interval* between successful delivery and explicit size failure.
It must not present a timeout as a known MTU boundary or claim to discover
an exact end-to-end path MTU.

## Implemented behavior

- Run a bounded number of repeated probes between user-selected minimum and
  maximum UDP payload sizes. Reuse the existing probe and receiver protocol,
  Linux no-fragment mode and JSON schema where possible.
- Preserve every individual result and the tested sizes. Report the largest
  acknowledged payload and any smallest explicit `packet_too_large` payload
  separately from timed-out sizes. Label mixed or timeout-only patterns as
  inconclusive.
- Keep each direction independent. Correlate receiver observations when the
  user supplies them, without treating a small acknowledgement as proof that
  same-sized reverse traffic works.
- Expose a short terminal summary and the same evidence in the HTML view.
  The CLI option and JSON field names will be set when implementation starts.

## Validation

The [v0.5 validation record](validation/size-search.md) covers the controlled
IPv4/IPv6 boundaries, blocked ICMP feedback, blocked ACK return, mixed
outcomes and output handling described below.

- Exercise known IPv4 and IPv6 link boundaries in isolated Linux labs and
  confirm that the reported interval contains the known boundary.
- Exercise blocked PMTU feedback, blocked ACK return and mixed/loss patterns;
  these must remain inconclusive unless independent evidence resolves them.
- Check maximum probe count, runtime and payload limits; verify the receiver
  and sender reports remain parseable by current report commands.
- Document what a result means on an unknown path. Real VPN and Kubernetes
  validation remain open community tasks, not release gates.

Authentication, encryption, internet-facing operation, 5G tunnel support and
automatic root-cause diagnosis are outside v0.5. See
[security boundaries](security-boundaries.md) for current operating limits.

## Community issues

These issues support the roadmap without changing the validation gates above:

| Issue | Contribution | Roadmap role |
| --- | --- | --- |
| [#4](https://github.com/lazypanic999/tunnelscope/issues/4) | Add Python 3.10 to CI checks | Release compatibility; good first issue |
| [#5](https://github.com/lazypanic999/tunnelscope/issues/5) | Show receiver correlation in the README quick start | Make existing evidence easier to use; good first issue |
| [#6](https://github.com/lazypanic999/tunnelscope/issues/6) | Document a Windows PowerShell loopback quick start | Improve first use without promising Windows DF support; good first issue |
| [#1](https://github.com/lazypanic999/tunnelscope/issues/1) | Validate IPv6 Packet Too Big feedback on a routed path | Independent field evidence for the IPv6 boundary work |
| [#2](https://github.com/lazypanic999/tunnelscope/issues/2) | Validate bidirectional probes and correlation on a real VPN | Post-lab deployment evidence; not a v0.5 release gate |
| [#3](https://github.com/lazypanic999/tunnelscope/issues/3) | Validate pod-to-pod workflow on Kubernetes | Post-lab deployment evidence; not a v0.5 release gate |

The v0.5 implementation is split into network, reports, search and view
modules under `tunnelscope_core`. Compatibility entry modules preserve the
installed CLI and existing imports. Lab scripts remain separate because they
are privileged, opt-in validation tools.

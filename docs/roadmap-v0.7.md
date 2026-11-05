# v0.7 plan: reverse-path size evidence and shareable field reports

Status: **in progress**. Report sanitization ([guide](sanitize.md)) and
same-sized replies ([guide](sized-reply.md)) are implemented on `main`; the
workflow pass-through in item 3 is still proposed. It follows the
[v0.6 scope](roadmap-v0.6.md) and keeps its rules: measurements stay
separate from conclusions, a timeout alone is never presented as an MTU
problem, and an observed payload interval is not an end-to-end path MTU.

v0.6 answered "did a payload of this size reach the receiver?" for one
direction at a time. Two gaps remain:

1. The receiver always returns a fixed 24-byte acknowledgement. A sender
   therefore learns nothing about same-sized traffic on the return path
   unless the operators swap roles and run `combine`. Asymmetric paths, such
   as a VPN whose two gateways have different tunnel MTUs, need both runs
   and two cooperating operators.
2. Field validation ([#1](https://github.com/lazypanic999/tunnelscope/issues/1),
   [#2](https://github.com/lazypanic999/tunnelscope/issues/2)) requires
   publishing reports, but JSON and HTML contain addresses, interface names
   and timestamps. [Security boundaries](security-boundaries.md) ask users to
   sanitize reports by hand before sharing them.

## Proposed for v0.7.0

### 1. Report sanitization (`tunnelscope sanitize`): implemented

- Read any schema-version-1 report (probe, receiver, search, comparison,
  diagnosis, combined or correlated) and write a sanitized JSON copy, with
  `--html` producing the matching offline view.
- Replace each IPv4/IPv6 address with a documentation address (RFC 5737,
  RFC 3849) so the same address maps to the same placeholder across every
  file sanitized in one run. Placeholders remain valid addresses, which keeps
  the address family and whether two addresses matched, because
  `endpoint_check` and receiver joins depend on it.
- Redact interface names and non-address hostnames. Shift timestamps by one
  constant per batch by default. Keep payload sizes, outcomes, RTTs, probe IDs and ICMP
  event types, since they carry the evidence.
- Record what was changed under a top-level `sanitization` object. Never
  modify the input file.
- A sanitized correlation must still join. Tests must show that
  `correlate` on sanitized inputs gives the same per-probe result as on the
  originals.

### 2. Opt-in sized replies for return-path evidence: implemented

- Receiver flag `--sized-reply`. For each probe that requests it, the
  receiver returns a reply of the **same size** as the received datagram
  instead of the fixed acknowledgement. The reply is never larger than the
  request, so the receiver adds no amplification. On Linux the reply is
  sent with DF set, so an oversized reply fails instead of being fragmented.
- New reply magic (`TA02`). A sender with `--sized-reply` puts a request
  marker (`SR01`) after the run ID; v0.6 receivers ignore it and send the
  small acknowledgement, which the sender records as `small_ack_only`.
  Unmarked probes from v0.6 senders always get the small acknowledgement.
- New sender outcome per attempt, added to the existing schema:
  `reply_bytes` and `return_status` (`sized_reply_received`,
  `small_ack_only`, `no_reply`). With receiver evidence joined, the report can separate
  "forward probe arrived, same-sized reply did not return" from forward loss.
  Without receiver evidence, a missing sized reply stays inconclusive, as a
  timeout does today.
- Receiver reports record the reply size and send result for each
  observation, including local `EMSGSIZE` errors on the reply.
- Keep the fixed small acknowledgement as the default. Sized replies double
  the bytes on the path, so the documentation must say when to use them.

### 3. Workflow and report updates

- Let `diagnose` pass the sized-reply option through and show forward and
  return evidence in separate columns of the HTML view.
- Show sanitization status in `show` and the HTML header.
- Update the usage reference, the security boundaries and the README
  evidence table.

## Release gates for v0.7.0

- Unit tests for sanitization, covering every report kind and placeholder
  consistency across files.
- A new isolated network-namespace lab with an **asymmetric** MTU:
  - the forward direction delivers a known payload size (for example 1400 bytes);
  - the return direction has a lower MTU.

  The report must show forward delivery confirmed by the receiver and a
  missing same-sized reply. Visible and blocked ICMP feedback on the return
  path must both be exercised. A validation record goes under
  `docs/validation/`.
- A mixed-version check: v0.7 sender with a v0.6 receiver, and v0.6 sender
  with a v0.7 receiver, both without errors.
- The `Delivery checks` matrix (Linux and Windows, Python 3.10 and 3.12)
  passes. Windows must at least handle `sanitize`, `show` and `html`.
- The PyPI publish workflow completes on the v0.7.0 tag. It moved to new
  action versions in [PR #11](https://github.com/lazypanic999/tunnelscope/pull/11)
  and has not run since.

## Field evidence (not release gates)

These depend on operators and networks outside the project. Sanitized reports
from `tunnelscope sanitize` should make them easier to publish.

| Item | Evidence wanted |
| --- | --- |
| [#2](https://github.com/lazypanic999/tunnelscope/issues/2) Real VPN | Bidirectional or sized-reply runs across a production-like VPN, with topology and MTU settings described |
| [#1](https://github.com/lazypanic999/tunnelscope/issues/1) Routed IPv6 Packet Too Big | Token-matched ICMPv6 feedback from a router outside a single-kernel lab |
| Other Kubernetes CNI modes | VXLAN or Geneve encapsulation (for example Cilium or Flannel), in addition to the [Calico IP-in-IP record](validation/kubernetes-calico.md) |
| Physical multi-host path | At least one routed hop between separate machines rather than VMs on one host |

## Maintenance

- `ubuntu-latest` is migrating to Ubuntu 26. Watch the netns and WireGuard
  labs on the new image; pin `ubuntu-24.04` only if a lab breaks and the fix
  is not immediate.
- Keep the `Delivery checks` job name stable; `main` branch protection
  requires it.

## Outside v0.7

Peer authentication, integrity protection, encryption, internet-facing
receivers, 5G user-plane tunnels and automatic root-cause diagnosis remain
outside scope. Sized replies do not change the trust model: replies are as
unauthenticated as today's acknowledgements.

## Open questions

- Resolved: a sized reply mirrors the probe size exactly. A separately
  requested reply size would allow a return-path search but adds protocol
  surface; it can be revisited after field use.
- Resolved: sanitization shifts timestamps by one constant per batch, which
  keeps RTT and ordering checks working; `--keep-timestamps` opts out.
- Is one asymmetric namespace lab enough for the release, or should the
  two-VM WireGuard setup also be repeated with different gateway MTUs?

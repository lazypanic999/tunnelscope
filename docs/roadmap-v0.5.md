# v0.5 scope: bounded size-boundary evidence

The next development target is a bounded size search for controlled Linux
paths. It should help a user choose useful UDP payload sizes and identify an
*observed interval* between successful delivery and explicit size failure.
It must not present a timeout as a known MTU boundary or claim to discover
an exact end-to-end path MTU.

## Intended behavior

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

## Validation before release

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

# v0.8 plan: field evidence and wider return-path coverage

Status: **released**. All four items landed on `main` on
2026-11-06 and shipped in [v0.8.0](releases/v0.8.0.md), followed by the
[v0.8.1 report-table update](releases/v0.8.1.md) and
[v0.8.2 report fixes and IPv6 feedback validation](releases/v0.8.2.md). Two checks remain
open: a maintainer dry run of the field report guide on two machines and a
cross-host run with a Windows receiver ([#28](https://github.com/lazypanic999/tunnelscope/issues/28)).
These remain follow-up validation work, not claims made by the released
loopback checks. It follows [v0.7](roadmap-v0.7.md) and keeps the same rules:
measurements stay separate from conclusions, a timeout alone is never an MTU
diagnosis, and an observed payload interval is not an end-to-end path MTU.

v0.7 made return-path evidence and shareable reports possible. v0.8 added
controlled IPv6 return-path validation and Windows receiver loopback tests.
Independent field reports and Windows cross-host validation remain open;
the controlled results do not establish behavior on arbitrary VPN or overlay paths.

## Proposed for v0.8.0

### 1. A path for field reports: implemented

- Add a "Field report" issue template. It asks for the environment (VPN or
  overlay type, configured MTUs where known, number of hops if known), the
  exact commands, and sanitized `diagnose --sized-reply` and receiver reports
  as attachments. It reminds contributors to run `tunnelscope sanitize` and to
  test only paths they are allowed to test.
- Add `docs/field-reports.md`: how to collect a report on two hosts, how to
  sanitize it, and how a maintainer turns an accepted report into a
  validation record. Link it from the README and from issues
  [#1](https://github.com/lazypanic999/tunnelscope/issues/1) and
  [#2](https://github.com/lazypanic999/tunnelscope/issues/2). The template,
  guide and README link are in place; #2 now directs volunteers to the guide.

### 2. IPv6 return-path lab: implemented

- Extend `labs/asymmetric_return.py` (or add an IPv6 variant) so the return
  link has a lower IPv6 MTU. The sized-reply probe should show arrival with
  missing or locally rejected replies, as the IPv4 lab does, and the small
  ACK should still return. Run it in CI next to the IPv4 lab.

### 3. Sized replies from a Windows receiver: implemented

- At the start of v0.8, `receive --sized-reply` refused to run outside Linux because the
  reply must be sent without fragmentation. Windows exposes
  `IP_DONTFRAGMENT` (Winsock option 14, not exported by Python's `socket`
  module) and `IPV6_DONTFRAG`. Enable the flag on Windows only if setting the
  option succeeds, record which option was used in the receiver report, and
  keep refusing on platforms where it cannot be set.
- Validation: loopback tests in the Windows CI job, plus one manual
  Windows-receiver run against a Linux sender documented as a record.
  The loopback tests and a local send test are done; the cross-host run is
  still open because it needs a firewall rule on the Windows receiver.

### 4. Keep lab output from CI: implemented

- Upload the JSON printed by the privileged namespace labs as a workflow
  artifact, so validation records can cite a specific CI run and its data,
  not only a passing test.

## Original v0.8.0 release gates and follow-up

- Field-report template and guide merged; at least one maintainer dry run of
  the guide on two machines.
- IPv6 return-path lab passing in CI.
- Windows receiver sized replies: either shipped with the tests above, or
  explicitly deferred with the reason recorded here.
- Full test matrix (Linux and Windows, Python 3.10 and 3.12) passing.

Field reports themselves are not a release gate: they depend on operators
outside the project. The two-machine guide dry run and Windows cross-host
run were deferred explicitly in the [v0.8.0 release notes](releases/v0.8.0.md#not-yet-validated);
CI loopback checks verify the command workflow but do not complete those gates.

## Open questions

- Should a separately requested reply size (capped at the probe size) be
  reconsidered now, to allow a return-direction size search? v0.7 chose
  mirrored sizes only.
- Windows receiver support shipped in v0.8.0; cross-host evidence is the
  remaining validation question, tracked in #28.
- Should `ubuntu-latest` be pinned while GitHub moves it to Ubuntu 26, or
  should the labs be checked on the new image as soon as it is available?

## Outside v0.8

Peer authentication, encryption, internet-facing receivers, 5G user-plane
tunnels and automatic root-cause diagnosis remain outside scope, as in
[security boundaries](security-boundaries.md).

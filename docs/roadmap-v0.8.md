# v0.8 plan: field evidence and wider return-path coverage

Status: **in progress**. The maintainer asked on 2026-11-06 for work to
continue on this plan; items are marked below as they land. It follows [v0.7](roadmap-v0.7.md) and keeps the same rules:
measurements stay separate from conclusions, a timeout alone is never an MTU
diagnosis, and an observed payload interval is not an end-to-end path MTU.

v0.7 made return-path evidence and shareable reports possible. Every
validation so far is still a controlled lab, and same-sized replies have been
exercised only on IPv4 and only with a Linux receiver. v0.8 proposes to make
outside contributions easy to collect and to close those two coverage gaps.

## Proposed for v0.8.0

### 1. A path for field reports

- Add a "Field report" issue template. It asks for the environment (VPN or
  overlay type, configured MTUs where known, number of hops if known), the
  exact commands, and sanitized `diagnose --sized-reply` and receiver reports
  as attachments. It reminds contributors to run `tunnelscope sanitize` and to
  test only paths they are allowed to test.
- Add `docs/field-reports.md`: how to collect a report on two hosts, how to
  sanitize it, and how a maintainer turns an accepted report into a
  validation record. Link it from the README and from issues
  [#1](https://github.com/lazypanic999/tunnelscope/issues/1) and
  [#2](https://github.com/lazypanic999/tunnelscope/issues/2).

### 2. IPv6 return-path lab

- Extend `labs/asymmetric_return.py` (or add an IPv6 variant) so the return
  link has a lower IPv6 MTU. The sized-reply probe should show arrival with
  missing or locally rejected replies, as the IPv4 lab does, and the small
  ACK should still return. Run it in CI next to the IPv4 lab.

### 3. Sized replies from a Windows receiver

- `receive --sized-reply` currently refuses to run outside Linux because the
  reply must be sent without fragmentation. Windows exposes
  `IP_DONTFRAGMENT` (Winsock option 14, not exported by Python's `socket`
  module) and `IPV6_DONTFRAG`. Enable the flag on Windows only if setting the
  option succeeds, record which option was used in the receiver report, and
  keep refusing on platforms where it cannot be set.
- Validation: loopback tests in the Windows CI job, plus one manual
  Windows-receiver run against a Linux sender documented as a record.

### 4. Keep lab output from CI

- Upload the JSON printed by the privileged namespace labs as a workflow
  artifact, so validation records can cite a specific CI run and its data,
  not only a passing test.

## Release gates for v0.8.0

- Field-report template and guide merged; at least one maintainer dry run of
  the guide on two machines.
- IPv6 return-path lab passing in CI.
- Windows receiver sized replies: either shipped with the tests above, or
  explicitly deferred with the reason recorded here.
- Full test matrix (Linux and Windows, Python 3.10 and 3.12) passing.

Field reports themselves are not a release gate: they depend on operators
outside the project.

## Open questions

- Should a separately requested reply size (capped at the probe size) be
  reconsidered now, to allow a return-direction size search? v0.7 chose
  mirrored sizes only.
- Is a Windows receiver worth the extra platform surface, or should the
  documentation recommend a Linux or WSL2 receiver instead?
- Should `ubuntu-latest` be pinned while GitHub moves it to Ubuntu 26, or
  should the labs be checked on the new image as soon as it is available?

## Outside v0.8

Peer authentication, encryption, internet-facing receivers, 5G user-plane
tunnels and automatic root-cause diagnosis remain outside scope, as in
[security boundaries](security-boundaries.md).

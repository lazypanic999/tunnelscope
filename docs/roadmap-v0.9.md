# v0.9 development: sharing evidence

Status: development work after [v0.8.2](releases/v0.8.2.md). This is not a
published release plan with a promised date.

## Markdown evidence summaries

[#32](https://github.com/lazypanic999/tunnelscope/issues/32) adds
`tunnelscope show REPORT --format markdown` for issue discussions. The text
default stays available. HTML and Markdown share observation-table data, and
the export is bounded, escapes report values, states sanitization metadata,
and preserves conservative interpretation. See the
[development guide](markdown-reports.md).

Release checks: all existing report kinds and examples render; untrusted
values cannot add active markup; large captures are visibly truncated; the
Linux/Windows Python 3.10/3.12 matrix passes; installed distributions include
the new renderer and table module. The source JSON remains the full evidence.

## Validation still needing separate endpoints

Controlled [OpenVPN routed validation](validation/openvpn-routed.md) is also
being added under [#36](https://github.com/lazypanic999/tunnelscope/issues/36),
with temporary TLS peers and visible/blocked feedback. This adds lab coverage
without closing the independent evidence below.

- Independent VPN evidence: [#2](https://github.com/lazypanic999/tunnelscope/issues/2).
- A Windows receiver reached from a separate Linux host or VM:
  [#28](https://github.com/lazypanic999/tunnelscope/issues/28).
- A maintainer dry run of the field guide on two separate machines.

The new CLI integration tests check loopback collection and sharing; they
do not claim to complete these path-validation tasks. Real field reports
remain separate from controlled namespace, VM and loopback evidence.

Authentication, internet-facing receivers, automatic root-cause diagnosis
and 5G tunnel support remain outside scope. No new remote control channel
or default network exposure is introduced by report export.

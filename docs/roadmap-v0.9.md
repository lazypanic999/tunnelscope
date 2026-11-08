# v0.9: sharing evidence

Release scope: [v0.9.0](releases/v0.9.0.md), implemented after
[v0.8.2](releases/v0.8.2.md). The independent endpoint checks below remain
follow-ups; controlled lab evidence does not close them.

## Markdown evidence summaries

[#32](https://github.com/lazypanic999/tunnelscope/issues/32) adds
`tunnelscope show REPORT --format markdown` for issue discussions. The text
default stays available. HTML and Markdown share observation-table data, and
the export is bounded, escapes report values, states sanitization metadata,
and preserves conservative interpretation. See the
[Markdown guide](markdown-reports.md).

Release checks: all existing report kinds and examples render; untrusted
values cannot add active markup; large captures are visibly truncated; the
Linux/Windows Python 3.10/3.12 matrix passes; installed distributions include
the new renderer and table module. The source JSON remains the full evidence.

## Producer versions and offline views

[#40](https://github.com/lazypanic999/tunnelscope/issues/40) records producer
versions and immediate input versions for new reports. Existing diagnoses
keep their original measurement producer when receiver evidence is joined
later. Missing legacy versions remain unknown; see
[report versions](report-versions.md).

Text views also support the named visible/blocked cases and separate
directions in checked-in lab examples, alongside HTML and Markdown.

## Endpoint validation and remaining field work

Controlled [OpenVPN routed validation](validation/openvpn-routed.md) was
added under [#36](https://github.com/lazypanic999/tunnelscope/issues/36),
with temporary TLS peers and visible/blocked feedback. This adds lab coverage
without closing the independent evidence below.
The [asymmetric OpenVPN return scenario](validation/openvpn-asymmetric-return.md)
also joins receiver arrivals to missing same-sized replies, including
separate local send failures, under [#44](https://github.com/lazypanic999/tunnelscope/issues/44).

- Independent VPN evidence: [#2](https://github.com/lazypanic999/tunnelscope/issues/2).
- The Windows receiver's Linux-VM path is now recorded in
  [#28](https://github.com/lazypanic999/tunnelscope/issues/28) and the
  [Windows host/WSL2 guest validation](validation/windows-wsl2-receiver.md).
  This is two kernels on one physical machine, using non-loopback IPv4.
  A separate [IPv6 link-local follow-up](validation/windows-wsl2-receiver-ipv6.md)
  passed the same experiments; routed IPv6 and physical hosts remain separate.
  The [oversized Windows reply record](validation/windows-oversized-replies.md)
  additionally joins actual local `WSAEMSGSIZE` failures in both families.
- A field-guide dry run with physically separate machines and network file
  transfer still needs separate evidence. The host/guest run exercised
  collection, joining, sanitization and Markdown using a shared directory.

The new CLI integration tests check loopback collection and sharing; they
do not replace the host/guest record or complete the remaining physical-path tasks. Real field reports
remain separate from controlled namespace, VM and loopback evidence.

Authentication, internet-facing receivers, automatic root-cause diagnosis
and 5G tunnel support remain outside scope. No new remote control channel
or default network exposure is introduced by report export.

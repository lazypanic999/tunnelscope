<p align="center">
  <img src="https://raw.githubusercontent.com/lazypanic999/tunnelscope/main/tunnelscope-logo-blue.png" alt="TunnelScope blue compass and vortex logo" width="260">
</p>

<h1 align="center">TunnelScope</h1>

<p align="center">
  Find out which packet sizes get through a tunnel, in which direction, and what both ends actually saw.
</p>

<p align="center">
  <a href="https://pypi.org/project/tunnelscope/"><img src="https://img.shields.io/pypi/v/tunnelscope?color=2f6fde" alt="PyPI version"></a>
  <a href="https://pypi.org/project/tunnelscope/"><img src="https://img.shields.io/pypi/pyversions/tunnelscope" alt="Python versions"></a>
  <a href="https://github.com/lazypanic999/tunnelscope/actions/workflows/tests.yml"><img src="https://github.com/lazypanic999/tunnelscope/actions/workflows/tests.yml/badge.svg" alt="Tests"></a>
  <a href="https://github.com/lazypanic999/tunnelscope/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT license"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#test-the-return-direction">Return direction</a> ·
  <a href="#reading-the-results">Reading the results</a> ·
  <a href="#where-it-has-been-tested">Tested on</a> ·
  <a href="https://github.com/lazypanic999/tunnelscope/releases">Releases</a>
</p>

---

Ping works, SSH works, but a file copy over the VPN hangs. That pattern
usually points at packet size: somewhere on the path, large packets are
dropped or their error messages never come back. TunnelScope sends UDP
probes of chosen sizes to a small receiver you run on the other end and
writes down what happened to each one: acknowledged, rejected locally as too
large, or timed out. You then join the sender's log with the receiver's log
by probe ID, so you can tell "never arrived" apart from "arrived, but the
answer got lost".

With `--sized-reply`, the receiver answers with a packet as big as the probe,
so one run checks both directions. That catches paths where large packets go
out fine and can't come back.

**Status:** alpha (v0.9.6), Python 3.10+, MIT. Reports are plain JSON plus an
offline HTML view; nothing is uploaded anywhere.

![tunnelscope show output: 64- and 1200-byte probes return same-sized replies; 1400-byte probes reach the receiver but their replies are lost or rejected](https://raw.githubusercontent.com/lazypanic999/tunnelscope/main/docs/images/v07-terminal.png)

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/lazypanic999/tunnelscope/main/docs/images/v07-report-dark.png">
  <img src="https://raw.githubusercontent.com/lazypanic999/tunnelscope/main/docs/images/v07-report.png" alt="HTML view of the same run after joining the receiver log: each probe arrived; the 1400-byte replies were lost or rejected">
</picture>

Both images come from a real run of the
[asymmetric return-path lab](https://github.com/lazypanic999/tunnelscope/blob/main/docs/validation/asymmetric-return.md)
(Ubuntu under WSL2, 2026-11-05). The return link is 1280 bytes. Every
1400-byte probe reached the receiver; the same-sized replies did not make it
back, while a normal 24-byte ACK at 1400 bytes did. The lab gives the same
result over [IPv6](https://github.com/lazypanic999/tunnelscope/blob/main/docs/validation/asymmetric-return.md#ipv6).
The images are rebuilt from the
[checked-in report](https://github.com/lazypanic999/tunnelscope/blob/main/examples/asymmetric-return-v07.json)
by [`scripts/build_v07_images.py`](https://github.com/lazypanic999/tunnelscope/blob/main/scripts/build_v07_images.py).
There is also a [30-second replay](https://github.com/lazypanic999/tunnelscope/blob/main/docs/demo-v09.md)
of an OpenVPN return-path run and the report-sharing steps.

## Quick start

This runs on one machine over loopback, with no root access and no network
changes. On native Windows PowerShell, follow the
[Windows loopback guide](https://github.com/lazypanic999/tunnelscope/blob/main/docs/windows-loopback.md)
instead. On Linux or WSL2, in an empty directory:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install tunnelscope==0.9.6
```

Terminal 1, start the receiver:

```sh
tunnelscope receive --max-packets 2 --output receiver.json
```

Terminal 2 (same environment), once the receiver prints
`Listening on 127.0.0.1:9471`:

```sh
tunnelscope probe 127.0.0.1 --sizes 64,1200 --count 1 --output probe.json
```

The receiver stops after two probes. Join the two logs and open the result:

```sh
tunnelscope correlate probe.json receiver.json --output correlation.json --html correlation.html
tunnelscope show correlation.json
```

`correlation.html` opens in any browser. A receiver entry for a probe means
it arrived, even if the sender never got an ACK. A timeout on its own does
not mean there is an MTU problem. For two machines, see the
[two-endpoint guide](https://github.com/lazypanic999/tunnelscope/blob/main/docs/bidirectional.md).

### One command on a Linux sender

With a receiver already running on the other end of a path you control:

```sh
tunnelscope diagnose PEER_IP --min 1200 --max 1400 --count 2 --output diagnosis.json
```

`diagnose` runs three bounded passes in one sender direction: probes with the
don't-fragment bit set, the same sizes with fragmentation allowed, and a
size search between `--min` and `--max`. It writes JSON and HTML. Once the
receiver has saved its log, `correlate` joins all three passes into one
report. The [diagnose guide](https://github.com/lazypanic999/tunnelscope/blob/main/docs/diagnose.md)
covers setup and how to read it.

## Test the return direction

The normal ACK is 24 bytes. It proves the probe arrived, not that a packet of
the same size can travel back. With `--sized-reply` on both ends, the
receiver replies with a packet as large as the probe, never larger:

```sh
tunnelscope receive --bind B_IP --sized-reply --output receiver.json
tunnelscope probe B_IP --sizes 64,1200,1400 --count 2 --dont-fragment --sized-reply --output probe.json
tunnelscope correlate probe.json receiver.json --html correlation.html
```

The receiver can be Linux (WSL2 included) or Windows. `search`,
`compare-fragmentation` and `diagnose` take the same flag. The
[sized-reply guide](https://github.com/lazypanic999/tunnelscope/blob/main/docs/sized-reply.md)
lists every field. Run
[`tunnelscope sanitize`](https://github.com/lazypanic999/tunnelscope/blob/main/docs/sanitize.md)
before you post a report anywhere, and
`tunnelscope show REPORT --format markdown` gives a
[summary you can paste into an issue](https://github.com/lazypanic999/tunnelscope/blob/main/docs/markdown-reports.md).

## Reading the results

| Result | What it means |
| --- | --- |
| `acknowledged` | The payload arrived and the small ACK came back. |
| `packet_too_large` | Linux refused to send it because it was too big. ICMP data, when present, shows whether the limit was local or reported by a router. |
| `timeout` | No matching ACK arrived. The cause is unknown. |
| `sized_reply_received` | With `--sized-reply`: the payload arrived and a reply of the same size came back. |
| `receiver_observed_sized_reply_missing` | After `correlate`: the receiver got the probe and its socket accepted a same-sized reply, but the sender saw nothing before its deadline. Where it was lost is unknown. |
| `receiver_reply_send_unverified` | The receiver logged the probe, but its log has no outcome for the reply. TunnelScope does not guess whether a reply was sent. |

Payload sizes include the 24-byte TunnelScope header.

A few things the tool cannot tell you. An observed size interval is what got
through during the run, not a measured end-to-end path MTU. ICMP messages and
receiver logs are not authenticated. Clocks on different machines are never
compared. `ping`, `tracepath`, route tables and packet captures are still
worth having next to these reports.

## Where it has been tested

| Setup | What was checked | Scope |
| --- | --- | --- |
| [Ubuntu ↔ Debian VMs over WireGuard](https://github.com/lazypanic999/tunnelscope/blob/main/docs/validation/two-vm-wireguard.md) | Both directions, receiver pairing, a 1252/1253-byte boundary | Local tunnel MTU, host-only link |
| [Routed WireGuard](https://github.com/lazypanic999/tunnelscope/blob/main/docs/validation/wireguard-routed.md) | Matched ICMP when visible, inconclusive timeouts when blocked | 4 namespaces, one kernel |
| [Routed OpenVPN](https://github.com/lazypanic999/tunnelscope/blob/main/docs/validation/openvpn-routed.md) and [its return path](https://github.com/lazypanic999/tunnelscope/blob/main/docs/validation/openvpn-asymmetric-return.md) | Matched ICMP, blocked search, missing sized replies joined with the receiver log | 3 namespaces, one kernel, IPv4 |
| [Routed IPv6 feedback](https://github.com/lazypanic999/tunnelscope/blob/main/docs/validation/ipv6-routed-feedback.md) | Packet Too Big matched vs. blocked, receiver pairing | 3 namespaces, one kernel, in CI |
| [Asymmetric return path](https://github.com/lazypanic999/tunnelscope/blob/main/docs/validation/asymmetric-return.md) | 1400-byte probes arrive, replies lost or rejected, small ACK returns | 3 namespaces, IPv4 and IPv6, in CI |
| [Windows receiver from WSL2](https://github.com/lazypanic999/tunnelscope/blob/main/docs/validation/windows-wsl2-receiver.md) ([IPv6](https://github.com/lazypanic999/tunnelscope/blob/main/docs/validation/windows-wsl2-receiver-ipv6.md)) | 3/3 small ACKs, 6/6 sized replies, 8/8 diagnosis replies per family | Two kernels, one physical host |
| [Windows oversized replies](https://github.com/lazypanic999/tunnelscope/blob/main/docs/validation/windows-oversized-replies.md) | 1600-byte probes arrive; Windows refuses the same-sized reply (WSAEMSGSIZE) | Same host and guest, MTU 1500 |
| [Kubernetes with Calico](https://github.com/lazypanic999/tunnelscope/blob/main/docs/validation/kubernetes-calico.md) | 6/6 baseline deliveries each way, policy block and recovery | Two Minikube nodes, IP-in-IP |

All of these are controlled setups. Nobody has sent in a report from a real
production VPN or a multi-hop physical path yet. If you can test one you are
allowed to, the
[field report guide](https://github.com/lazypanic999/tunnelscope/blob/main/docs/field-reports.md)
walks through collecting and sanitizing it, and
[issue #2](https://github.com/lazypanic999/tunnelscope/issues/2) is where it
would help most.

## Docs

- Commands and report fields: [usage and JSON reference](https://github.com/lazypanic999/tunnelscope/blob/main/docs/usage-and-report-reference.md), [size search](https://github.com/lazypanic999/tunnelscope/blob/main/docs/size-search.md), [fragmentation comparison](https://github.com/lazypanic999/tunnelscope/blob/main/docs/fragmentation-comparison.md), [ICMP feedback](https://github.com/lazypanic999/tunnelscope/blob/main/docs/icmp-feedback.md), [receiver logs](https://github.com/lazypanic999/tunnelscope/blob/main/docs/receiver-observations.md), [HTML view](https://github.com/lazypanic999/tunnelscope/blob/main/docs/report-ui.md)
- Sharing: [sanitize](https://github.com/lazypanic999/tunnelscope/blob/main/docs/sanitize.md), [Markdown summaries](https://github.com/lazypanic999/tunnelscope/blob/main/docs/markdown-reports.md), [field reports](https://github.com/lazypanic999/tunnelscope/blob/main/docs/field-reports.md)
- Environments: [Kubernetes lab](https://github.com/lazypanic999/tunnelscope/blob/main/docs/kubernetes.md), [deployment notes](https://github.com/lazypanic999/tunnelscope/blob/main/docs/environments.md), [security boundaries](https://github.com/lazypanic999/tunnelscope/blob/main/docs/security-boundaries.md)
- History: [release notes](https://github.com/lazypanic999/tunnelscope/tree/main/docs/releases), [v0.9 status](https://github.com/lazypanic999/tunnelscope/blob/main/docs/roadmap-v0.9.md), [project history](https://github.com/lazypanic999/tunnelscope/blob/main/docs/project-history.md)

## Contributing

Starter tasks are tagged
[good first issue](https://github.com/lazypanic999/tunnelscope/issues?q=is%3Aissue%20is%3Aopen%20label%3A%22good%20first%20issue%22),
and a field report counts as a contribution too. Read
[CONTRIBUTING.md](https://github.com/lazypanic999/tunnelscope/blob/main/CONTRIBUTING.md)
first and only share synthetic or sanitized reports. CI runs on Linux and
Windows with Python 3.10, 3.12 and 3.13. The unprivileged checks run with:

```sh
python -m unittest discover -s tests -v
```

The Linux network labs need root and an explicit opt-in, described in the
usage reference.

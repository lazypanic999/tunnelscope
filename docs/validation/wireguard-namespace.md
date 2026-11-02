# WireGuard tunnel boundary lab

Validated on 2026-11-02 in Ubuntu under WSL2 (Linux 6.6.87.2). The
reproducible [lab](../../labs/wireguard_boundary.py) creates two disposable
Linux network namespaces connected by a 1500-byte veth underlay. It configures
a real WireGuard `wg0` interface in each namespace, with 1280-byte MTU and
separate ephemeral keys. The namespaces communicate using their WireGuard
overlay addresses. The script removes both namespaces and the key files when
it exits.

Run from the repository root as Linux root with `iproute2`, `wireguard-tools`,
`ping`, and Python 3 installed:

```sh
python3 labs/wireguard_boundary.py --output-dir output/wireguard-lab
```

The output directory must be empty or absent. It receives sender, receiver,
correlation, diagnosis JSON and offline HTML files for both directions, plus
`summary.json`. Local `output/` is excluded from Git.

| Direction | DF payload 64, 1252 | DF payload 1253, 1400 | Receiver observations | Adaptive interval |
| --- | --- | --- | ---: | --- |
| A to B | acknowledged | `packet_too_large` | 2/2 delivered | 1252–1253 |
| B to A | acknowledged | `packet_too_large` | 2/2 delivered | 1252–1253 |

For both directions, the 1253 and 1400 byte DF attempts reported
`size_error_origin: local` and kernel MTU 1280. The 1252/1253 boundary matches
the configured tunnel MTU after 20 bytes of IPv4 and 8 bytes of UDP headers.
The receiver report independently recorded both successful probes; the
correlation matched them by run and probe ID. Each `diagnose` run wrote JSON
and HTML and reported an adjacent observed payload interval of 1252–1253.

This verifies the TunnelScope workflow over an encrypted WireGuard tunnel, but
both endpoints share one WSL2 kernel and the boundary is the **local WireGuard
interface MTU**. It does not establish behavior across independent VPN hosts,
a multi-hop path, blocked ICMP, or a remote PMTU black hole. A two-VM
WireGuard test remains the next field-validation step.

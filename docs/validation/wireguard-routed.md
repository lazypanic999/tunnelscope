# Routed MTU feedback through WireGuard

Validated on 2026-11-04 in Ubuntu under WSL2, Linux 6.6.87.2, with
TunnelScope v0.6.0. The [lab script](../../labs/wireguard_routed.py) creates
four disposable network namespaces: two end hosts and two WireGuard gateways.
The bottleneck is the receiving gateway's LAN egress after tunnel decryption.
It is separate from the sender's local link and the WireGuard interface MTU.

```mermaid
flowchart LR
    A[Sender host] -->|1500-byte LAN| L[VPN gateway A]
    L -->|WireGuard MTU 1420 over 1500-byte underlay| R[VPN gateway B]
    R -->|1280-byte LAN| B[Receiver host]
```

The script rebuilds this topology for both directions and both feedback modes.
When direction is reversed, the sender-side LAN is 1500 bytes and the
receiver-side LAN is 1280 bytes. Fresh namespaces isolate PMTU cache state
between cases. End hosts route through their gateways, including return routes
to tunnel addresses used as ICMP sources. Forwarding and firewall changes are
confined to the temporary gateway namespaces; keys and namespaces are removed
on exit.

## Reproduce

Linux root, Python 3, `iproute2`, `wireguard-tools`, `iptables`, `sysctl` and
`ping` are required. Run from the repository root:

```sh
sudo python3 labs/wireguard_routed.py --output-dir output/wireguard-routed
```

The output directory must be empty or absent. Each case writes a diagnosis,
a receiver capture, a joined JSON report and offline HTML views. `summary.json`
records all four cases. Raw local output is excluded from Git. The
[WireGuard CI workflow](../../.github/workflows/wireguard-labs.yml) runs both
the direct tunnel and routed-feedback labs on Ubuntu.

## Observations

Each case runs `diagnose` with payload bounds 1252..1253, one attempt per
size and two search sizes. There are six attempts across the DF comparison,
fragmentation-permitted comparison and adaptive search. The receiver capture
is joined to each run by run ID and probe ID.

| Direction | Feedback mode | DF 1252 / 1253 | Permitted 1252 / 1253 | Search interval |
| --- | --- | --- | --- | --- |
| Left → right | visible | acknowledged / size error | both acknowledged | 1252–1253 bytes |
| Left → right | blocked | acknowledged / timeout | both acknowledged | none; inconclusive |
| Right → left | visible | acknowledged / size error | both acknowledged | 1252–1253 bytes |
| Right → left | blocked | acknowledged / timeout | both acknowledged | none; inconclusive |

With feedback visible, the DF run recorded an ICMPv4 fragmentation-needed
event carrying MTU 1280 and quoting the matching probe token. Subsequent
search attempts can produce local size errors after the kernel learns this
PMTU; those local events remain distinct from the routed ICMP observation.
The sender's initial link and route MTU were 1500 bytes, so the initial size
feedback did not come from a configured 1280-byte local sender interface.

With feedback blocked, the receiving gateway dropped ICMP fragmentation-needed
messages using an `OUTPUT` rule. Its counter recorded two dropped messages
in each direction, while the sender observed zero ICMP size-feedback events.
The large DF and search attempts timed out; neither run claimed an observed
boundary. Permitting source fragmentation produced acknowledgements at both
sizes, but the sender report alone does not establish where fragmentation
occurred or whether fragments traversed a particular link.

The receiver logged four of six attempts in each case, with zero unassigned
or unmatched observations. In visible cases, the remaining two attempts were
explicit size errors. In blocked cases, the remaining two were sender timeouts
with no matching receiver observation. The router rule counter and known
topology supply the cause in this controlled test; the same timeout pattern
on an unknown path would remain inconclusive.

## Limits

All four namespaces share one WSL2 kernel. This is a controlled routed VPN
lab, not a production deployment or independent-host field test. The configured
constraint is on the inner IP path after WireGuard decryption; this does not
validate a low-MTU outer underlay or prove that inner DF is propagated to outer
WireGuard UDP packets. The comparison is sequential and can be affected by
PMTU cache changes. It uses one attempt per size and small return ACKs, with
no statistical reliability claim. Real VPN incidents and Kubernetes pod-path
validation remain open.

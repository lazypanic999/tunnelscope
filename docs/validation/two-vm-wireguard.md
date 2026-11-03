# Two-VM WireGuard validation

Recorded on 2026-11-03 using separate Ubuntu 24.04 and Debian 12 VirtualBox
guests. Each had a temporary host-only underlay address and a WireGuard
`tswg-vm` interface. The underlay was a 1500-byte virtual link; the tunnel
interface MTU was deliberately set to 1280 bytes on both guests. Temporary
WireGuard keys were unique to each guest and are not in this repository.

| Endpoint | Kernel | Python | TunnelScope | Tunnel interface / route MTU |
| --- | --- | --- | --- | --- |
| Ubuntu | 6.8.0-138-generic | 3.12.3 | 0.6.0.dev0 (`32a7274`) | 1280 / 1280 bytes |
| Debian | 6.1.0-52-amd64 | 3.11.2 | 0.6.0.dev0 (`32a7274`) | 1280 / 1280 bytes |

The same source archive was copied to each VM, with the source file SHA-256
verified on both. Each host's route to the other tunnel address used
`tswg-vm`; two ICMP echo requests succeeded in each direction. The test used
the development source on `main`, not the published v0.5.0 PyPI package.

## Procedure and observations

On the receiving VM, `receive` bound to its tunnel address with JSON output.
The sender ran the following over the WireGuard address pair, once in each
direction:

```sh
python3 tunnelscope.py probe PEER_TUNNEL_IP \
  --sizes 64,1252,1253,1400 --count 2 --timeout 2 \
  --dont-fragment --observe-icmp --output probe.json

python3 tunnelscope.py diagnose PEER_TUNNEL_IP \
  --min 1248 --max 1260 --count 2 --max-sizes 8 --timeout 2 \
  --output diagnosis.json
```

The receiver recorded a separate capture for each command. The corresponding
sender and receiver reports were processed with `correlate`; the direction
reports were also processed with `combine`. `diagnose` receiver captures were
joined with all three nested runs and rendered as offline HTML.

| Direction | 64 and 1252 byte DF payloads | 1253 and 1400 byte DF payloads | Receiver saw | Diagnose interval |
| --- | --- | --- | ---: | --- |
| Ubuntu → Debian | 2/2 acknowledged at each size | 2/2 `packet_too_large` at each size | 4/8 probe attempts | 1252–1253 bytes |
| Debian → Ubuntu | 2/2 acknowledged at each size | 2/2 `packet_too_large` at each size | 4/8 probe attempts | 1252–1253 bytes |

In both directions, all four explicit size errors were reported locally by
the sender kernel with MTU 1280; those datagrams were not sent, so 4/8 is not
a measured loss rate. The 1252/1253 payload boundary corresponds to the
configured 1280-byte tunnel interface after 20 bytes of IPv4 and 8 bytes of
UDP headers.

Each `diagnose` report had 24 attempts: 14 were acknowledged and observed at
the receiver, while 10 were explicit local size errors. In each direction,
the DF comparison had 2/6 receiver observations, the
fragmentation-permitted run had 6/6, and size search had 6/12. The comparison
does not prove that fragments were observed on the path. All three run IDs
matched their receiver observations, with zero unassigned or unmatched
receiver records. `combine` reported `reversed_ipv4_match`; each correlation
reported matching target port and tunnel bind address. No network ICMP size
feedback was observed; local errors are separate evidence.

## Limits

These were **two independent Linux guests**, but both ran on the same physical
host and communicated through a VirtualBox host-only link. The tunnel had no
multi-hop or external network path. The observed boundary was the configured
local WireGuard interface MTU, not an independently measured end-to-end PMTU
or a PMTU black hole. Return acknowledgements were small, and each direction
was measured separately. Timestamps from the two guest clocks were shown
side by side without comparing them. This test does not validate a production
VPN incident, blocked ICMP feedback or Kubernetes pod traffic.

Raw sender and receiver reports, exact temporary addresses, keys and SSH
access material remain outside Git. The source and tunnel setup were removed
from the guests after the test.

# Routed IPv4 PMTU black-hole validation

Recorded on 2026-10-27 using Python 3.12.3 and Linux kernel
6.6.87.2-microsoft-standard-WSL2 (Ubuntu on WSL2).

## Setup

`labs/pmtu_blackhole.py` creates three temporary network namespaces: sender,
router and receiver. The sender-to-router veth pair has MTU 1500, and the
router-to-receiver pair has MTU 1280. The router forwards IPv4 packets but drops
its own outgoing ICMP fragmentation-needed messages (type 3, code 4). Both
endpoints use routes through the router. The sender enables DF for each probe.

The 1280-byte egress link can carry at most 1252 bytes of UDP payload with
standard 20-byte IPv4 and 8-byte UDP headers. TunnelScope's 24-byte header is
included in that UDP payload.

## Observations

| UDP payload bytes | IPv4 datagram bytes | Result |
| --- | --- | --- |
| 64 | 92 | acknowledged |
| 1252 | 1280 | acknowledged |
| 1253 | 1281 | timeout |
| 1400 | 1428 | timeout |

The router's isolated firewall counter recorded the two blocked ICMP
fragmentation-needed messages from the large probes.

The saved output is [examples/pmtu-blackhole.json](../../examples/pmtu-blackhole.json).
To reproduce:

```sh
sudo python3 labs/pmtu_blackhole.py > pmtu-blackhole.json
```

The lab checks its expected statuses and removes its namespaces in `finally`.
No temporary `ts-` namespaces remained after the validation run.

## Interpretation and limits

The known router configuration explains why larger DF probes do not reach the
receiver and why the sender receives no packet-too-large feedback. The probe
report still labels these outcomes `timeout` and `inconclusive`: the same
observation on an unknown path would not prove an MTU problem.

This is a controlled Linux demonstration, not evidence that TunnelScope can
automatically find a path MTU or diagnose a black hole in an arbitrary network.
The acknowledgement is small, so successful probes do not test a same-sized
return packet. The separate [direct-link boundary test](mtu-boundary.md) covers
explicit local `EMSGSIZE` feedback.

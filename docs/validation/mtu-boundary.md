# IPv4 Don't Fragment boundary validation

Recorded on 2026-10-24 using Python 3.12.3 and Linux kernel
6.6.87.2-microsoft-standard-WSL2 (Ubuntu on WSL2).

## Setup

`labs/mtu_boundary.py` creates two temporary namespaces and a direct veth pair.
Both veth endpoints have MTU 1280. The sender uses Linux
`IP_MTU_DISCOVER=IP_PMTUDISC_DO`. The lab reverses the sender and receiver roles
and repeats the experiment on the same link. It does not forward through a router.

The sender's standard IPv4 UDP sockets use a 20-byte IPv4 header and an 8-byte
UDP header, leaving 1252 bytes for UDP payload. TunnelScope's own 24-byte header
is included in that payload.

## Observations

| UDP payload bytes | IPv4 datagram bytes | A to B | B to A |
| --- | --- | --- | --- |
| 64 | 92 | acknowledged | acknowledged |
| 1252 | 1280 | acknowledged | acknowledged |
| 1253 | 1281 | packet_too_large | packet_too_large |
| 1400 | 1428 | packet_too_large | packet_too_large |

All rejected probes recorded Linux `EMSGSIZE` (errno 90) and a
`kernel_reported_mtu_bytes` value of 1280. These are observations from the lab,
not a synthetic example. Exact elapsed times vary between runs.

The saved output is [examples/mtu-boundary.json](../../examples/mtu-boundary.json).
To reproduce:

```sh
sudo python3 labs/mtu_boundary.py > mtu-boundary.json
```

No lab namespaces remained after the validation run.

## Test coverage

- Windows: 7 tests passed; 2 Linux-specific checks skipped.
- Linux with the privileged lab enabled: all 9 tests passed.
- Linux socket configuration was inspected with `getsockopt` to confirm DF mode.
- Unit checks cover unsupported-platform rejection, unavailable socket options,
  `EMSGSIZE` classification and missing kernel MTU evidence.
- The integration check runs the actual CLI in both namespaces and verifies the
  delivery results and reported kernel MTU.

## Limits

This establishes that DF mode and error reporting work at a known local egress
MTU boundary. It does not prove remote ICMP handling, an unknown end-to-end path
MTU, successful black-hole detection or compatibility with VPN/Kubernetes/5G
deployments. UDP acknowledgements are small; success does not demonstrate a
same-sized return datagram. Kernel PMTU caches can influence other topologies.

Without the new flag, fragmentation behavior remains under OS control.

## Reference

[Linux IP_MTU_DISCOVER documentation](https://man7.org/linux/man-pages/man2/IP_MTU_DISCOVER.2const.html)
describes DF behavior, `EMSGSIZE`, and the distinction between kernel-known PMTU
and active diagnostic probing.

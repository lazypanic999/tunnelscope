# Routed OpenVPN feedback validation

Recorded on 2026-11-08 using development TunnelScope `0.9.0.dev0`, Python
3.12.3, OpenVPN 2.6.19 and OpenSSL 3.0.13 in Ubuntu under WSL2 (Linux
6.6.87.2-microsoft-standard-WSL2). The full non-secret output is
[examples/openvpn-routed-v09.json](../../examples/openvpn-routed-v09.json).

This is a controlled, single-kernel lab. It adds an actual OpenVPN data path
to the existing WireGuard evidence; independent operator VPN reports remain
open in [#2](https://github.com/lazypanic999/tunnelscope/issues/2).

## Topology

```text
sender / OpenVPN client -- UDP over MTU 1500 -- OpenVPN server / router
                                                           |
                                                       MTU 1280 LAN
                                                           |
                                                       receiver
```

Three disposable namespaces contain every interface, route and firewall
change. Both OpenVPN peers use user-space TUN interfaces with MTU 1400,
IPv4/UDP transport, temporary mutually verified TLS certificates, and
`AES-256-GCM` as the configured data cipher. Data-channel offload is disabled
to keep this experiment on the user-space TUN path. The lab creates a private
one-day CA and peer certificates, checks certificate purpose and peer name,
and installs no certificate into the host trust store.

The underlay uses `192.0.2.0/30`, the tunnel peers use `203.0.113.1` and
`203.0.113.2`, and the receiver LAN uses `198.51.100.0/30`. A route sends the
sender's receiver-LAN traffic through `ts-ovpn`; the receiver has a return
route to the sender's tunnel address.

The lower router egress accommodates 1252 UDP payload bytes with standard
20-byte IPv4 and 8-byte UDP headers. The 1253- and 1300-byte payloads fit
the sender's 1400-byte TUN interface, so their first failure is not a local
tunnel-interface limit. These configured MTUs do not measure OpenVPN's exact
encapsulation overhead or an unknown path's PMTU.

## Observations

| Payload bytes | ICMP blocked: sender | ICMP visible: sender | Receiver in each case |
| --- | --- | --- | --- |
| 64 | acknowledged | acknowledged | observed |
| 1252 | acknowledged | acknowledged | observed |
| 1253 | timeout | packet_too_large, matched network ICMP | no matching observation |
| 1300 | timeout | packet_too_large, local learned-PMTU error | no matching observation |

The blocked case runs first, before the sender learns the smaller MTU. The
router drops only its outgoing ICMP fragmentation-needed messages. Its
isolated rule counted three messages: two for the probe and one for the
1200–1300-byte search. The probe and search error queues observed zero size
feedback events. Search acknowledged 1200 bytes, timed out at 1300 and kept
`assessment: inconclusive` with no observed interval.

After the rule is removed, the first 1253-byte attempt receives ICMPv4 type
3/code 4 reporting MTU 1280, with a matching probe token. That feedback
crosses the OpenVPN tunnel back to the sender. The later 1300-byte attempt
is rejected locally after the kernel learns the lower MTU. The reports keep
the network feedback and local rejection distinct. Sender snapshots record
`interface: ts-ovpn` and MTU 1400 in both cases.

Receiver captures and correlations are retained for both cases. The blocked
capture includes the search run as well as the fixed-size probe; its extra
run is expected and each join keeps the other run's observation unmatched.

## Reproduce and check

From a source checkout with Linux root, OpenVPN 2.6+, OpenSSL, `iproute2`,
`iptables`, `sysctl` and `/dev/net/tun` available:

```sh
sudo python3 labs/openvpn_routed.py > openvpn-routed.json
```

The opt-in test is separate from the ordinary unprivileged suite:

```sh
sudo env TUNNELSCOPE_RUN_OPENVPN_TESTS=1 python3 -m unittest discover -s tests -p test_openvpn.py -v
```

The dedicated `OpenVPN routed validation` workflow uses Ubuntu 24.04 and
Python 3.10/3.12 and retains only JSON/error output as CI artifacts. Private
keys, certificates and daemon logs stay in the temporary directory and are
never artifacts. The test also checks that temporary certificate directories
and `ts-ov-` namespaces are removed after success. Processes are stopped and
namespaces removed in `finally`; forced termination can prevent cleanup.

For the recorded local run, tools were unpacked from the official Ubuntu
packages into a temporary tool directory because the host package manager
already had an interrupted transaction. That transaction and host service
configuration were left untouched. The lab itself uses the normal `openvpn`
executable found on `PATH` and needs no special extraction in CI.

## Limits

This records one sender direction across a known lower-MTU LAN behind the
VPN server, with small ACKs. It does not validate same-sized reverse replies,
TCP transport, TAP bridges, DCO, arbitrary VPN settings, independent hosts or
production incidents. A missing ACK or absent ICMP on an unknown path stays
inconclusive; a missing receiver entry needs independently verified capture
coverage before it can establish forward loss. TunnelScope's probe protocol
remains unauthenticated even inside this authenticated lab tunnel.

# OpenVPN with a lower return egress

Recorded on 2026-11-08 using development TunnelScope `0.9.0.dev0`, Python
3.12.3, OpenVPN 2.6.19 and Ubuntu/WSL2 Linux
6.6.87.2-microsoft-standard-WSL2. Full observations are in
[examples/openvpn-asymmetric-return-v09.json](../../examples/openvpn-asymmetric-return-v09.json).
This is a controlled single-kernel experiment, separate from independent
operator reports in [#2](https://github.com/lazypanic999/tunnelscope/issues/2).

## Deliberate asymmetry

```text
sender/client TUN 1400 -- encrypted IPv4/UDP, underlay 1500 -- server/router
                                                                  |
                                                             LAN 1500
                                                                  |
                                                               receiver

return: receiver -> server/router -> TUN egress 1280 -> sender/client
```

Both temporary OpenVPN peers complete the same mutually verified TLS setup
as the [feedback lab](openvpn-routed.md), with configured AES-256-GCM and
data-channel offload disabled. After the handshake, the script changes the
server's actual TUN link MTU from 1400 to 1280. The client's link remains
1400 and the receiver LAN is 1500. This is a purposeful lab configuration,
not a recommended OpenVPN deployment. It does not measure encapsulation
overhead or discover an arbitrary path MTU.

The known server return egress accommodates 1252 UDP payload bytes with
20-byte IPv4 and 8-byte UDP headers. Every tested forward payload fits the
client's TUN link and reaches the receiver in this experiment.

## Recorded outcomes

| UDP payload | Small ACK | Same-sized reply | Joined receiver evidence |
| --- | --- | --- | --- |
| 64 | acknowledged | acknowledged | `sized_reply_returned` |
| 1252 | acknowledged | acknowledged | `sized_reply_returned` |
| 1253 | acknowledged | timeout | `receiver_observed_sized_reply_missing`; local reply send accepted |
| 1300 | acknowledged | timeout | `receiver_reply_send_failed`; local send rejected with EMSGSIZE |

The small-ACK case runs first and acknowledges all four sizes. In the
same-sized case, the receiver logs all four forward arrivals. Its first
1253-byte reply is accepted by the local socket, then meets the lower server
TUN egress. A router rule counts one outgoing ICMP fragmentation-needed
message returning to the receiver. The later 1300-byte reply fails at the
receiver socket with errno 90 after the kernel learns the lower route MTU.
The sender sees two missing replies; its timeout alone does not reveal
either distinction. The correlation retains the two separate cases.

A subsequent same-sized search acknowledges 1200 and times out at 1300,
while the receiver records both arrivals. No explicit sender size error
establishes an upper bound, so the search remains `inconclusive` and records
no observed interval. This result must not be presented as exact PMTU
discovery. Learned PMTU state and timing can affect which later receiver
sends are rejected locally; the lab preserves those observations rather
than treating all missing replies as the same failure.

## Reproduce

Use the source checkout with Linux root, OpenVPN 2.6+, OpenSSL, `iproute2`,
`iptables`, `sysctl` and `/dev/net/tun`:

```sh
sudo python3 labs/openvpn_routed.py --scenario asymmetric-return > openvpn-return.json
python3 tunnelscope.py show openvpn-return.json
python3 tunnelscope.py html openvpn-return.json --output openvpn-return.html
```

The default `--scenario feedback` retains the original visible/blocked ICMP
test. Both scenarios run in the opt-in OpenVPN suite and dedicated CI job:

```sh
sudo env TUNNELSCOPE_RUN_OPENVPN_TESTS=1 python3 -m unittest discover -s tests -p test_openvpn.py -v
```

The CI artifact names distinguish `openvpn_routed.json` and
`openvpn_asymmetric_return.json`. Only non-secret JSON/error output is kept.
Certificates, keys and daemon logs remain temporary; processes and
namespaces are cleaned up in `finally`, including failure paths. As with
the feedback record, local tools were extracted separately from official
Ubuntu packages without repairing the host's interrupted package transaction.

## Limits

This validates a known, deliberately reduced return egress on one kernel.
It does not validate independent hosts, production settings, DCO, IPv6 over
OpenVPN, TCP transport or unknown VPN paths. Receiver logs and the probe
protocol remain unauthenticated. On another path, absent receiver entries
need verified capture coverage, and a successful send call does not prove
delivery of the reply. Cross-host clock differences are not used to infer
loss location.

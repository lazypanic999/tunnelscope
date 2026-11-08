# Oversized replies rejected by a native Windows receiver

Recorded on 2026-11-08 with TunnelScope **v0.9.1**. A WSL2 Linux sender
compared DF and fragmentation-permitted experiments against the native
Windows host over existing IPv4 and IPv6 link-local virtual paths. This
extends the healthy [IPv4](windows-wsl2-receiver.md) and
[IPv6](windows-wsl2-receiver-ipv6.md) records with an actual Windows socket
size error, rather than a mocked error.

These are **two kernels on one physical computer**. Both interfaces kept
their existing MTU of 1500. No firewall rule, route, MTU, interface or access
permission was changed. Ports were ephemeral and receivers bound only to
the explicitly owned Windows WSL-interface addresses.

The [full sanitized fixture](../../examples/windows-wsl2-oversized-replies-v09.json)
retains eight sender runs and their correlations, plus the two shared
receiver captures. Related inputs were batch-sanitized with one mapping;
rejoining them preserved all per-attempt results. The wrapper adds reviewed
OS/version and scope facts, not private adapter data.

## Recorded results

For each IP family, two sequential `compare-fragmentation` experiments used
64, 1400 and 1600-byte UDP payloads with one attempt per size and a one-second
timeout. The first requested small ACKs, the second same-sized replies. A
fresh Windows capture covered each family.

| Mode | Payload | Sender observation | Receiver observation |
| --- | --- | --- | --- |
| DF, either reply mode | 64 / 1400 | Acknowledged | Arrived; reply accepted locally |
| DF, either reply mode | 1600 | `packet_too_large` (`EMSGSIZE`) | No matching arrival |
| Permitted, small ACK | 64 / 1400 / 1600 | All acknowledged | Arrived; 24-byte ACK accepted locally |
| Permitted, sized reply | 64 / 1400 | Same-sized reply received | Arrived; reply accepted locally |
| Permitted, sized reply | 1600 | Timeout, `no_reply` | Arrived; 1600-byte reply rejected by local Windows socket with `WSAEMSGSIZE` (10040) |

The same pattern held for IPv4 and IPv6. Across both families there were
**24 sender attempts: 18 acknowledged, four explicit size errors and two
timeouts**. Windows captured **20 arrivals**, including both 1600-byte
fragmentation-permitted sized probes. Each shared capture has expected
observations from other runs; joins retain run IDs and endpoint checks.

Windows recorded `disabled: Windows IP_DONTFRAGMENT` for IPv4 and
`disabled: Windows IPV6_DONTFRAG` for IPv6. In both oversized reply cases,
correlation reported `receiver_reply_send_failed`, with `receiver_observed:
true` and `ack_send_status: socket_error`. The raw receiver observations
retain `ack_send_errno: 10040` and `reply_bytes: 1600`.

The sender alone did not observe the receiver's local error. Its timeout
does not establish an MTU fault or loss location. Joining the capture adds
the specific observation that the receiver's socket rejected the reply;
it does not turn receiver logs into authenticated proof.

## Environment and reproduction

Windows NT build `10.0.26300` / Python 3.10.11 used the SHA-256-verified
official PyPI v0.9.1 wheel. Ubuntu WSL2 / Linux
`6.6.87.2-microsoft-standard-WSL2` / Python 3.12.3 used source commit
`d90345a62722`, whose runtime files matched the `v0.9.1` tag. Files were
exchanged through the mounted working directory.

Choose a permitted reachable Windows address `B_IP`. For link-local IPv6,
use the receiver's own numeric zone on Windows and the local outgoing
interface zone on Linux, as explained in the [scoped-address guide](windows-wsl2-receiver-ipv6.md#scoped-address-handling).
Start one bounded Windows receiver per family:

```powershell
tunnelscope receive --bind B_IP --port 0 --sized-reply --max-packets 10 --idle-timeout 8 --output receiver.json
```

After it prints its port, run these sequentially on Linux, using fresh files:

```sh
tunnelscope compare-fragmentation B_IP --port PORT --sizes 64,1400,1600 \
  --count 1 --timeout 1 --output small.json
tunnelscope compare-fragmentation B_IP --port PORT --sizes 64,1400,1600 \
  --count 1 --timeout 1 --sized-reply --output sized.json
```

Those counts describe this observed path. Another path may deliver a
different number of probes; the receiver still exits at its idle timeout.
The checked-in fixture contains the individual DF/permitted probe reports
and correlations. The CLI `correlate` command accepts those individual probe
reports, not a whole fragmentation-comparison wrapper. All retained evidence
can be inspected offline:

```sh
tunnelscope show examples/windows-wsl2-oversized-replies-v09.json
tunnelscope show examples/windows-wsl2-oversized-replies-v09.json --format markdown
tunnelscope html examples/windows-wsl2-oversized-replies-v09.json --output windows-oversized.html
```

## Cleanup and limits

Both receiver processes saved ten observations, reached `max_packets` and
exited successfully. None was left listening. No test-created networking
state needed removal.

This tests a chosen 1600-byte payload, not an exact path-MTU boundary. The
experiment permits source fragmentation but does not capture or count IP
fragments, measure a routed IPv6 PMTU or observe ICMP Packet Too Big here.
Documentation addresses replace the link-local IPv6 addresses in the shared
fixture. Physical multi-host paths, other Windows firewall profiles and
independent operator VPN incidents remain separate work. Cross-kernel
clocks were not compared; UDP messages and receiver logs are unauthenticated.

# Same-sized replies for return-path evidence

By default the receiver answers every probe with a fixed 24-byte
acknowledgement. A sender therefore learns that its payload arrived, but not
whether traffic of the same size can travel back. Asymmetric paths, such as
two VPN gateways with different tunnel MTUs, can pass large packets in one
direction only.

`--sized-reply` lets one sender run test both directions at each payload size.
It was added in v0.7.0.

## Run it

On the receiver (Linux, including WSL2, or Windows):

```sh
tunnelscope receive --bind B_IP --sized-reply --output receiver.json
```

On the sender:

```sh
tunnelscope probe B_IP --sizes 64,1200,1400 --count 3 --dont-fragment --sized-reply --output probe.json
tunnelscope correlate probe.json receiver.json --html correlation.html
```

Both sides must opt in. The sender adds a request marker to each probe, and
the receiver answers a marked probe with a reply of exactly the probe's size
only when it was started with `--sized-reply`. Payload sizes must be at least
36 bytes to hold the marker.

## What the reports record

| Where | Field | Meaning |
| --- | --- | --- |
| Probe result | `return_status: sized_reply_received` | The probe arrived and a same-sized reply returned. |
| Probe result | `return_status: small_ack_only` | The probe arrived, but the receiver sent only the small acknowledgement (no `--sized-reply`, or a v0.6 receiver). The return path was not tested. |
| Probe result | `return_status: no_reply` | No matching reply. On its own this is as inconclusive as any timeout. |
| Probe summary | `return_status_counts` | The three counts per payload size. |
| Receiver observation | `reply_kind`, `reply_bytes` | What the receiver tried to send. `ack_send_status: socket_error` with `ack_send_errno` 90 on Linux (`EMSGSIZE`) or 10040 on Windows (`WSAEMSGSIZE`) means its own kernel rejected the reply. The receiver block records `reply_fragmentation`, the socket option used. |

Joining both logs with `correlate` adds `return_evidence` to each probe:

| `return_evidence` | Meaning |
| --- | --- |
| `sized_reply_returned` | Both directions carried this size. |
| `receiver_observed_sized_reply_missing` | The probe arrived and the receiver's local socket accepted a same-sized reply, but the sender recorded none before its deadline. This does not establish where or why the return failed. |
| `receiver_reply_send_failed` | The probe arrived, but the receiver's socket rejected the attempted reply. Inspect the recorded reply size and errno; for example, a large reply may fail after the kernel learns a smaller route MTU. |
| `receiver_reply_send_unverified` | From v0.9.1: the probe arrived, but the receiver did not record a local send outcome. A reply is not assumed to have been sent or rejected. |
| `receiver_sent_small_reply` | The receiver did not send a sized reply. |
| `no_receiver_observation` | The receiver has no record of the probe. Inconclusive without verified capture coverage. |
| `small_ack_only` | As in the probe result. |

The correlation summary counts `sized_reply_missing_after_arrival` and
`receiver_reply_send_failed`. `show` and the HTML view add a return column.
From v0.9.1, the summary also counts `receiver_reply_send_unverified`, including
across all runs in a joined diagnosis. An interrupted capture can preserve an
arrival before the local send outcome has been recorded. Missing or unknown
send status stays unverified; it is not counted as a sent or failed reply.

A sized-reply run that received only same-sized replies no longer lists
`same_sized_reverse_payload_test` under `missing_evidence`.

## Limits

- A missing reply does not show where it was lost or why. Combine it with
  receiver logs, ICMP observations and packet captures.
- Sized replies double the bytes sent per probe. The reply is never larger
  than the probe, so the receiver does not amplify traffic, but the receiver
  is still an unauthenticated UDP responder. Follow
  [security boundaries](security-boundaries.md).
- The receiver sends sized replies with fragmentation disabled, so an
  oversized reply fails instead of being fragmented: `IP_PMTUDISC_DO` or
  `IPV6_DONTFRAG` on Linux, `IP_DONTFRAGMENT` or `IPV6_DONTFRAG` on Windows.
  If the option cannot be set, the receiver refuses to start. Other platforms
  do not support `receive --sized-reply`; the sender works anywhere.
- Windows receiver support is checked on loopback (64-, 1400- and 8192-byte
  replies) and by a send test in which `IP_DONTFRAGMENT` turned an oversized
  2000-byte datagram into `WSAEMSGSIZE`. A native Windows receiver also passed
  a [controlled non-loopback run from its WSL2 Linux guest](validation/windows-wsl2-receiver.md):
  two kernels on one physical host, IPv4, 64–1400-byte payloads. A separate
  [IPv6 link-local record](validation/windows-wsl2-receiver-ipv6.md) passed the
  same experiments. Physically separate receivers and routed IPv6 paths need
  separate evidence.
  Windows Firewall or another host network policy may require a scoped inbound
  UDP rule for a different test path; the recorded virtual path changed no rules.
- `search`, `compare-fragmentation` and `diagnose` also accept
  `--sized-reply`. There an acknowledged attempt means the size crossed both
  directions, so a search interval reflects the smaller of the two. A
  diagnosis adds `summary.return` with the three counts, and its joined
  receiver evidence counts missing and rejected sized replies across runs.

## Controlled validation

`labs/asymmetric_return.py` builds three network namespaces: sender, router
and receiver, over IPv4 or, with `--family ipv6`, IPv6. Traffic to the receiver uses 1500-byte links; the router sends
traffic back over a 1280-byte link. With `--sized-reply`, 64- and 1200-byte
probes return same-sized replies, while 1400-byte probes reach the receiver
and their replies do not return. An ordinary probe at 1400 bytes is still
acknowledged, because its 24-byte acknowledgement fits. CI runs the lab on
Linux with `TUNNELSCOPE_RUN_NETNS_TESTS=1`; see the
[validation record](validation/asymmetric-return.md).

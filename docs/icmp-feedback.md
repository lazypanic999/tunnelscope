# Optional Linux ICMP feedback observation

This feature is on `main` in 0.6.0.dev0; it is not in the published v0.5.0
PyPI package. It uses Linux UDP error queues rather than raw sockets, so an
ordinary sender does not need raw-socket privileges. The namespace validation
scripts need root only to create their disposable network topologies.

On a controlled Linux path with a receiver already listening:

```sh
tunnelscope probe 192.0.2.2 --sizes 64,1400 --count 2 --dont-fragment --observe-icmp --output probe.json
tunnelscope show probe.json
tunnelscope html probe.json --output probe.html
```

`search` also accepts `--observe-icmp`. The flag requires Linux, including
WSL2. If the platform cannot enable the error queue, the command fails
instead of silently reporting an empty observation. Default probes do not
enable the queue, preserving earlier behavior.

The sender enables `IP_RECVERR` or `IPV6_RECVERR` on a new socket for each
attempt. After the attempt, it reads at most eight error-queue entries. Each
`results[]` row includes `icmp_observation.state` (`completed`, `partial`,
`read_error` or `limit_reached`) and its decoded `events`. The report's
`summary.icmp_feedback` counts observed size feedback, token-matched size
feedback and local errors. Terminal and HTML views show these observations.

An event distinguishes:

- `origin: local`: a socket error produced locally, such as a datagram above
  the connected link MTU. It is **not** an ICMP message from the path.
- `origin: icmpv4` with type 3/code 4: ICMP fragmentation needed.
- `origin: icmpv6` with type 2/code 0: IPv6 Packet Too Big.

For `EMSGSIZE`, `reported_mtu_bytes` is the MTU carried by the kernel's
extended error when present. `quoted_probe_match` is `true` when the returned
UDP payload contains the current probe header, `false` for a mismatch, or
`null` when the quote is too short to check. `size_error_origin` separates a
locally reported size error from one accompanied by network ICMP feedback.
The older per-size `kernel_rejected_df_payload` assessment remains for schema
compatibility; inspect the origin field for the stronger distinction.

These are **observations**, not authenticated diagnoses. ICMP may be filtered,
delayed, truncated or forged. The queue is read within the probe's timeout
window; `completed` with zero events means none was read then, not that a
router blocked it. A token match associates feedback with this attempt but
does not authenticate the sender of the ICMP message. Route MTU and ICMP MTU
are kernel/network claims, not an independent path measurement. A timeout
still needs receiver or path evidence.

The [validation record](validation/icmp-feedback.md) covers local errors,
visible IPv4/IPv6 routed feedback and blocked IPv4 feedback. The API behavior
follows the Linux [`IP_RECVERR` manual](https://man7.org/linux/man-pages/man2/IP_RECVERR.2const.html),
Python's [`recvmsg` documentation](https://docs.python.org/3.12/library/socket.html#socket.socket.recvmsg),
and [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html) for IPv6 Packet
Too Big.

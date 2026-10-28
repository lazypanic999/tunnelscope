# IPv6 delivery experiments

From v0.3.0, the CLI supports IPv6 UDP payload probes and receiver observations.
Use an IPv6 literal for `probe` or `receive --bind`; the default receiver still
binds to IPv4 loopback. For a hostname, `--family ipv6` selects an AAAA record.
The default hostname behavior continues to prefer IPv4 for compatibility.

On one machine, start the receiver in one terminal:

```sh
tunnelscope receive --bind ::1 --output receiver-v6.json
```

In another terminal:

```sh
tunnelscope probe ::1 --sizes 64,1200,1400 --count 2 --dont-fragment --output probe-v6.json
```

For a two-host test, use the receiver's reachable IPv6 address and repeat the
procedure with endpoint roles reversed. Link-local addresses need a zone
identifier such as `%eth0` on the sender. Reports use `source.ipv6`,
`target.ipv6`, `receiver.bind_ipv6` and `source_ipv6` in receiver observations.
The existing report schema version remains 1 with additive IPv6 fields.

On Linux, `--dont-fragment` sets `IPV6_DONTFRAG` on the sender socket. An
`EMSGSIZE` error is recorded as `packet_too_large`; a reported `IPV6_MTU`
value is the kernel's current route knowledge, not a separately measured
end-to-end path MTU. Without the flag, source fragmentation follows OS
defaults. Timeouts remain inconclusive. The receiver's acknowledgement is
small, so reverse roles to test the opposite direction with the same payload
size.

The [isolated IPv6 boundary lab](../labs/ipv6_boundary.py) verifies a
1280-byte veth link: 1228–1232-byte UDP payloads arrive, while 1233–1236-byte
payloads are rejected locally in no-fragment mode. It creates and removes
temporary network namespaces and requires root and `iproute2`.

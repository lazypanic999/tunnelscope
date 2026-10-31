# TunnelScope usage and report reference

Run commands from the repository root unless stated otherwise.

## Install from a source checkout

From the repository root, in a Python 3.10+ virtual environment:

```sh
python3 -m pip install .
tunnelscope --help
```

The package installs the `tunnelscope` command. It has no third-party runtime
dependencies. The laboratory scripts still run from a source checkout.

The CLI also supports `--sweep START:STOP:STEP` for a bounded
grid of UDP payload sizes. It includes the stop size even when the step does
not land on it. For example:

```sh
tunnelscope probe 192.0.2.2 --sweep 64:1400:100 --count 2 --dont-fragment --output sweep.json
```

The grid tests at most 16 sizes. The result records observations at those
sizes; it is not an exact path-MTU measurement. See the [size sweep guide](https://github.com/lazypanic999/tunnelscope/blob/main/docs/size-sweep.md).

## Probe and report details

No third-party runtime packages are needed. The commands below also work from
a source checkout by replacing `tunnelscope` with `python tunnelscope.py`.
By default, the receiver exits after 100 datagrams or 30 seconds without a
datagram. Restart it if it has already exited. `--max-packets` and
`--idle-timeout` change these limits.

Probe sizes are **UDP payload bytes**, including TunnelScope's 24-byte header. They exclude IP and UDP headers. The receiver sends only a small acknowledgement, so this is not a same-sized round-trip test. Reverse endpoint roles to investigate delivery in the other direction.

Each probe report includes a `source` snapshot taken from the first connected sender socket. It records the local IPv4 or IPv6 address. On Linux, it also records the selected interface and its link MTU when discoverable, plus `kernel_route_mtu_bytes` when the kernel supplies it. The link MTU and kernel route MTU are different facts; neither is an independently measured end-to-end path MTU. A failed connection may leave `source` as `null`, and optional fields may be absent.

`acknowledged` means that the receiver got that payload and its acknowledgement returned. `timeout` means no matching acknowledgement arrived before the deadline; it does not prove an MTU issue. `socket_error` records a socket error. Without `--dont-fragment`, fragmentation follows OS defaults; the tool does not force it on or off. The CLI exits successfully when it produces a report; inspect per-probe statuses for delivery outcomes.

JSON reports also include `summary.by_payload_size`. Each entry counts `acknowledged`, `packet_too_large`, `timeout` and `socket_error` attempts separately. Its `assessment` is `delivery_observed`, `kernel_rejected_df_payload`, `inconclusive`, `socket_error` or `mixed_observations`. Repeated payload sizes share one entry, while individual attempts remain in `results`. The summary does not infer an exact path MTU or turn a timeout into a diagnosis.

The `evidence` section lists counted observations, tentative hypotheses and missing checks separately. A clean pattern where every acknowledged size is below every timed-out size suggests a possible size-related delivery problem; in DF mode it also lists a possible PMTU-feedback black hole. Filtering and ordinary loss remain alternative explanations. Mixed or reversed size patterns produce no such hypothesis. Missing evidence calls out same-sized reverse traffic, receiver/path observation for timeouts, ICMP feedback visibility in DF mode and fragmentation control when DF is off. These are prompts for investigation, not automatic root-cause findings.

To compare directions, run `probe` once from A to B and once from B to A, then combine the two JSON files:

```sh
tunnelscope combine a-to-b.json b-to-a.json --output bidirectional.json
```

The command preserves the two reports and aligns per-size assessments; it does not initiate a remote measurement. See the [two-endpoint workflow](https://github.com/lazypanic999/tunnelscope/blob/main/docs/bidirectional.md) for the receiver and sender steps. `endpoint_check` compares the recorded IPv4 addresses but cannot authenticate endpoints or account for address translation.

### Linux no-fragment mode

```sh
tunnelscope probe 192.0.2.2 --sizes 64,1252,1253,1400 --count 1 --dont-fragment --output report.json
```

Use the address of your lab receiver; `192.0.2.2` is an example. For IPv4, this mode sets `IP_MTU_DISCOVER=IP_PMTUDISC_DO` on each sender socket. The kernel sets DF and rejects datagrams above its currently known path MTU. For IPv6, it sets Linux `IPV6_DONTFRAG` to prevent source fragmentation. It does not bypass cached PMTU information or search automatically for a boundary. The flag requires Linux, including WSL2. Other platforms reject it; socket-option errors stop the experiment rather than silently reverting to defaults. See the [IPv6 workflow](https://github.com/lazypanic999/tunnelscope/blob/main/docs/ipv6.md).

In DF mode, `EMSGSIZE` is reported as `packet_too_large`, with its numeric `errno`. It can arise from a local limit or received ICMP path feedback. When available, `kernel_reported_mtu_bytes` contains the connected socket's `IP_MTU` value. That value is kernel knowledge, not an independently measured end-to-end MTU. Timeouts remain inconclusive. The JSON schema version remains 1 with additive fields and the new `packet_too_large` status; consumers must handle it explicitly. The development version on `main` can use `--observe-icmp` to record error-queue origin and type; see the [ICMP guide](https://github.com/lazypanic999/tunnelscope/blob/main/docs/icmp-feedback.md).

### Reproduce a known MTU boundary

On Linux with root access and iproute2 installed:

```sh
sudo python3 labs/mtu_boundary.py > mtu-boundary.json
```

The lab creates two temporary network namespaces connected by a veth pair with MTU 1280. It probes both directions and checks that 1252-byte UDP payloads succeed while 1253-byte payloads fail in DF mode (20-byte IPv4 header + 8-byte UDP header). It changes no host interface MTU or host route and removes its namespaces on completion or ordinary interruption. As with any process, forced termination such as SIGKILL can prevent cleanup.

This validates a directly attached link boundary, not an unknown multi-hop bottleneck or a PMTU black hole. See the [validation record](https://github.com/lazypanic999/tunnelscope/blob/main/docs/validation/mtu-boundary.md) and [captured example report](https://github.com/lazypanic999/tunnelscope/blob/main/examples/mtu-boundary.json).

### Reproduce blocked PMTU feedback

On Linux with root access, iproute2, iptables and sysctl installed:

```sh
sudo python3 labs/pmtu_blackhole.py > pmtu-blackhole.json
```

This lab creates a sender, router and receiver in temporary network namespaces. The sender-facing link has MTU 1500; the router's receiver-facing link has MTU 1280. The router drops only its outgoing ICMP fragmentation-needed messages. In DF mode, 64- and 1252-byte UDP payloads are acknowledged, while 1253- and 1400-byte payloads time out. The lab changes no host routes, interfaces or firewall rules and removes its namespaces on ordinary completion or interruption. Forced termination such as SIGKILL can prevent cleanup.

The known lab topology explains these timeouts; a timeout on an unknown network remains inconclusive. See the [validation record](https://github.com/lazypanic999/tunnelscope/blob/main/docs/validation/pmtu-blackhole.md) and [captured report](https://github.com/lazypanic999/tunnelscope/blob/main/examples/pmtu-blackhole.json). This lab demonstrates one controlled failure mode; it does not establish automatic black-hole detection.

The receiver binds to IPv4 loopback by default. For your own two-host lab, use `--bind <receiver-lab-address>` and probe that address. Wildcard binds (`0.0.0.0` and `::`) are refused; select one lab interface and restrict the UDP port to the intended sender. An IPv6 literal such as `::1` selects IPv6; `--family ipv6` selects an AAAA record for a hostname. The experimental protocol is unencrypted and unauthenticated; use a controlled lab, not a public service. See the [security boundaries](https://github.com/lazypanic999/tunnelscope/blob/main/docs/security-boundaries.md).

Run checks:

```sh
python -m unittest discover -s tests -v
```

Privileged Linux integration check (also run by CI on Ubuntu):

```sh
sudo env TUNNELSCOPE_RUN_NETNS_TESTS=1 python3 -m unittest discover -s tests -v
```

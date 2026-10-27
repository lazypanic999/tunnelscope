<p align="center">
  <img src="tunnelscope-logo-blue.png" alt="TunnelScope blue compass and vortex logo" width="400">
</p>

# TunnelScope

Evidence-based MTU and packet-size diagnostics for Linux networks.

**Status: v0.1 installable prototype. UDP delivery probes, Linux IPv4 Don't Fragment mode, per-direction report combination, a link-MTU boundary lab and a routed PMTU black-hole lab are available. Automatic path-MTU discovery and root-cause diagnosis are not implemented. No public package release is available.**

## The problem

A connection can appear healthy while larger transfers fail. Small probes may succeed even when larger packets cannot traverse the path. Tunnel overhead, MTU configuration and blocked Path MTU Discovery feedback can contribute to this behavior. Other causes can produce similar symptoms.

TunnelScope aims to help network engineers, system administrators and learners investigate these failures through repeatable measurements and inspectable evidence.

## Planned first version

- A Python command-line tool and a cooperating receiver for controlled Linux environments.
- Repeated, size-controlled IPv4 UDP probes with fragmentation disabled.
- Separate measurements for each direction, with timeouts and loss recorded explicitly.
- JSON reports containing probe sizes, outcomes, relevant interface information and test settings.
- A reproducible Linux lab demonstrating healthy delivery, explicit packet-too-large feedback and a possible PMTU black hole.

A failed probe alone will not be labeled as proof of an MTU problem. Reports separate observations, hypotheses and missing evidence. An observed working packet size is not presented as the exact path MTU.

## Milestones

- [x] **M0 - Reproduce the problem:** build a small Linux network-namespace lab and record a healthy baseline and a controlled MTU failure.
- [x] **M1 - Probe and receive:** implement bounded, identifiable probes and acknowledgements between two endpoints.
- [x] **M2 - Explain the evidence:** export JSON and distinguish successful delivery, explicit errors and inconclusive timeouts.
- [x] **M3 - Validate:** check the tool against known lab configurations, document limitations and publish a short demo.

Kubernetes, VPN-specific workflows, IPv6 and 5G user-plane tunnels are possible later directions. They are not currently supported features.

For a quick walkthrough of both controlled failure modes, see the [two-minute Linux demo](docs/demo.md).
The [two-VM validation record](docs/validation/two-vm-field-test.md) documents a successful bidirectional DF run between Ubuntu and Debian guests.
The [v0.1 scope](docs/v0.1-scope.md) lists what the installable prototype does and does not cover.

## Install locally

From the repository root, in a Python 3.10+ virtual environment:

```sh
python3 -m pip install .
tunnelscope --help
```

The package installs the `tunnelscope` command. It has no third-party runtime dependencies. Building it requires setuptools; no package has been published to PyPI. The laboratory scripts still run from a source checkout.

## Getting started

Requires Python 3.10 or newer. No third-party runtime packages are needed. Start with a local experiment in two terminals, from the repository directory. Use `tunnelscope` in place of `python tunnelscope.py` after installing the package.

Terminal 1 (receiver):

```sh
python tunnelscope.py receive
```

Terminal 2 (sender):

```sh
python tunnelscope.py probe 127.0.0.1 --sizes 64,512,1200,1400 --count 3 --output report.json
```

The receiver exits after 100 datagrams or 30 seconds without a datagram. Restart it if it has already exited. `--max-packets` and `--idle-timeout` change these limits.

Probe sizes are **UDP payload bytes**, including TunnelScope's 24-byte header. They exclude IP and UDP headers. The receiver sends only a small acknowledgement, so this is not a same-sized round-trip test. Reverse endpoint roles to investigate delivery in the other direction.

Each probe report includes a `source` snapshot taken from the first connected sender socket. It records the local IPv4 address. On Linux, it also records the selected interface and its link MTU when discoverable, plus `kernel_route_mtu_bytes` when the kernel supplies it. The link MTU and kernel route MTU are different facts; neither is an independently measured end-to-end path MTU. A failed connection may leave `source` as `null`, and optional fields may be absent.

`acknowledged` means that the receiver got that payload and its acknowledgement returned. `timeout` means no matching acknowledgement arrived before the deadline; it does not prove an MTU issue. `socket_error` records a socket error. Without `--dont-fragment`, fragmentation follows OS defaults; the tool does not force it on or off. The CLI exits successfully when it produces a report; inspect per-probe statuses for delivery outcomes.

JSON reports also include `summary.by_payload_size`. Each entry counts `acknowledged`, `packet_too_large`, `timeout` and `socket_error` attempts separately. Its `assessment` is `delivery_observed`, `kernel_rejected_df_payload`, `inconclusive`, `socket_error` or `mixed_observations`. Repeated payload sizes share one entry, while individual attempts remain in `results`. The summary does not infer an exact path MTU or turn a timeout into a diagnosis.

The `evidence` section lists counted observations, tentative hypotheses and missing checks separately. A clean pattern where every acknowledged size is below every timed-out size suggests a possible size-related delivery problem; in DF mode it also lists a possible PMTU-feedback black hole. Filtering and ordinary loss remain alternative explanations. Mixed or reversed size patterns produce no such hypothesis. Missing evidence calls out same-sized reverse traffic, receiver/path observation for timeouts, ICMP feedback visibility in DF mode and fragmentation control when DF is off. These are prompts for investigation, not automatic root-cause findings.

To compare directions, run `probe` once from A to B and once from B to A, then combine the two JSON files:

```sh
python tunnelscope.py combine a-to-b.json b-to-a.json --output bidirectional.json
```

The command preserves the two reports and aligns per-size assessments; it does not initiate a remote measurement. See the [two-endpoint workflow](docs/bidirectional.md) for the receiver and sender steps. `endpoint_check` compares the recorded IPv4 addresses but cannot authenticate endpoints or account for address translation.

### Linux IPv4 Don't Fragment mode

```sh
python tunnelscope.py probe 192.0.2.2 --sizes 64,1252,1253,1400 --count 1 --dont-fragment --output report.json
```

Use the address of your lab receiver; `192.0.2.2` is an example. This mode sets `IP_MTU_DISCOVER=IP_PMTUDISC_DO` on each sender socket. The kernel sets DF and rejects datagrams above its currently known path MTU. It does not bypass cached PMTU information or search automatically for a boundary. The flag requires Linux, including WSL2. Other platforms reject it; socket-option errors stop the experiment rather than silently reverting to defaults.

In DF mode, `EMSGSIZE` is reported as `packet_too_large`, with its numeric `errno`. When available, `kernel_reported_mtu_bytes` contains the connected socket's `IP_MTU` value. That value is kernel knowledge, not an independently measured end-to-end MTU. Timeouts remain inconclusive. The JSON schema version remains 1 with additive fields and the new `packet_too_large` status; consumers must handle it explicitly.

### Reproduce a known MTU boundary

On Linux with root access and iproute2 installed:

```sh
sudo python3 labs/mtu_boundary.py > mtu-boundary.json
```

The lab creates two temporary network namespaces connected by a veth pair with MTU 1280. It probes both directions and checks that 1252-byte UDP payloads succeed while 1253-byte payloads fail in DF mode (20-byte IPv4 header + 8-byte UDP header). It changes no host interface MTU or host route and removes its namespaces on completion or ordinary interruption. As with any process, forced termination such as SIGKILL can prevent cleanup.

This validates a directly attached link boundary, not an unknown multi-hop bottleneck or a PMTU black hole. See the [validation record](docs/validation/mtu-boundary.md) and [captured example report](examples/mtu-boundary.json).

### Reproduce blocked PMTU feedback

On Linux with root access, iproute2, iptables and sysctl installed:

```sh
sudo python3 labs/pmtu_blackhole.py > pmtu-blackhole.json
```

This lab creates a sender, router and receiver in temporary network namespaces. The sender-facing link has MTU 1500; the router's receiver-facing link has MTU 1280. The router drops only its outgoing ICMP fragmentation-needed messages. In DF mode, 64- and 1252-byte UDP payloads are acknowledged, while 1253- and 1400-byte payloads time out. The lab changes no host routes, interfaces or firewall rules and removes its namespaces on ordinary completion or interruption. Forced termination such as SIGKILL can prevent cleanup.

The known lab topology explains these timeouts; a timeout on an unknown network remains inconclusive. See the [validation record](docs/validation/pmtu-blackhole.md) and [captured report](examples/pmtu-blackhole.json). This lab demonstrates one controlled failure mode; it does not establish automatic black-hole detection.

The receiver binds to loopback by default. For your own two-host lab, use `--bind <receiver-lab-IPv4>` and probe that address. The experimental protocol is unencrypted and unauthenticated; use a controlled lab, not a public service.

Run checks:

```sh
python -m unittest discover -s tests -v
```

Privileged Linux integration check (also run by CI on Ubuntu):

```sh
sudo env TUNNELSCOPE_RUN_NETNS_TESTS=1 python3 -m unittest discover -s tests -v
```

## Prior art and scope

Existing tools such as ping, tracepath and packet analyzers already provide important building blocks. TunnelScope will explore whether controlled two-endpoint tests and evidence-oriented reporting make this investigation easier. It is not a replacement for a full packet analyzer.

## Contributing

Early feedback is welcome through GitHub Issues, especially reproducible examples where small traffic succeeds and larger transfers fail. Describe the environment, expected behavior and observed behavior. Use synthetic or sanitized examples; do not attach credentials or private packet captures.

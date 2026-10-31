<p align="center">
  <img src="https://raw.githubusercontent.com/lazypanic999/tunnelscope/main/tunnelscope-logo-blue.png" alt="TunnelScope blue compass and vortex logo" width="400">
</p>

# TunnelScope

Evidence-based MTU and packet-size diagnostics for Linux networks.

**v0.5.0 alpha:** IPv4/IPv6 UDP probes, a cooperating receiver, bounded
payload-size search, JSON evidence, per-direction comparison and offline HTML
reports. Automatic path-MTU discovery and root-cause diagnosis are not implemented.

[GitHub Release](https://github.com/lazypanic999/tunnelscope/releases/tag/v0.5.0) ·
[PyPI](https://pypi.org/project/tunnelscope/0.5.0/)

**Development on `main` (0.6.0.dev0):** repeated no-ACK summaries, a Linux
DF/fragmentation-permitted comparison and optional ICMP feedback observations.
These changes are not in the v0.5.0 PyPI package. See the
[comparison guide](https://github.com/lazypanic999/tunnelscope/blob/main/docs/fragmentation-comparison.md)
and [ICMP guide](https://github.com/lazypanic999/tunnelscope/blob/main/docs/icmp-feedback.md).

![Terminal demo of TunnelScope showing a controlled blocked-feedback lab report](https://raw.githubusercontent.com/lazypanic999/tunnelscope/main/docs/images/terminal-demo.gif)

The animation runs `tunnelscope show` on a checked-in [controlled lab report](https://github.com/lazypanic999/tunnelscope/blob/main/examples/pmtu-blackhole.json).
It is not a live network capture. A timeout on an unknown path remains inconclusive.

## Why use TunnelScope?

Small pings can work while larger traffic fails. `ping` checks selected ICMP
sizes, `tracepath` depends on path feedback, and `ip route get` reports the
kernel's route and available MTU information; none alone confirms that a chosen
UDP payload reached the other endpoint. TunnelScope sends bounded payloads to
a cooperating receiver and saves both endpoints' observations for comparison.
Packet captures and these existing tools remain useful for root-cause work.

## Quick start

Requires Python 3.10 or newer. In an empty working directory on Linux (or
WSL2), install the published package in a virtual environment:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install tunnelscope
tunnelscope --help
```

Open a second terminal and activate the same environment there with
`source .venv/bin/activate`. Run these commands in order on one machine; no
root access or network setup is needed for this loopback example.

Terminal 1 (receiver):

```sh
tunnelscope receive --max-packets 2 --output receiver.json
```

Wait for `Listening on 127.0.0.1:9471`, then run Terminal 2 (sender):

```sh
tunnelscope probe 127.0.0.1 --sizes 64,1200 --count 1 --output probe.json
```

The receiver exits after the two probes and saves `receiver.json`. Back in
either terminal, inspect the sender report and create a local HTML view:

```sh
tunnelscope show probe.json
tunnelscope html probe.json --output probe.html
```

Open `probe.html` in a browser. The receiver sends small acknowledgements, so
this example checks delivery in one direction only. A timeout is inconclusive;
it does not prove an MTU problem. For two machines, see the
[two-endpoint workflow](https://github.com/lazypanic999/tunnelscope/blob/main/docs/bidirectional.md).

## Bounded size search

On a controlled Linux path, `search` tests the endpoints and then narrows an
observed interval using repeated no-fragment probes:

```sh
tunnelscope search 192.0.2.2 --min 1200 --max 1400 --count 2 --output search.json
tunnelscope show search.json
```

Start a receiver at that lab address first. A timeout stops the search as
inconclusive; even adjacent successful and explicit-error sizes are not an
independently measured path MTU. See the [size-search guide](https://github.com/lazypanic999/tunnelscope/blob/main/docs/size-search.md).

On Linux, the development version can also repeat the same sizes with DF
enabled and source fragmentation permitted. Use a controlled receiver and
read the [comparison guide](https://github.com/lazypanic999/tunnelscope/blob/main/docs/fragmentation-comparison.md)
before interpreting differences.

## What the results mean

- `acknowledged`: the receiver got the UDP payload and a small reply returned.
- `packet_too_large`: Linux reported `EMSGSIZE` in no-fragment mode; optional
  ICMP evidence can distinguish a local error from received path feedback.
- `timeout`: no matching reply arrived; the cause is unknown without more evidence.

Probe sizes are UDP payload bytes, including the 24-byte TunnelScope header.
Success does not prove same-sized reverse delivery. The tool reports observed
sizes, not an exact end-to-end path MTU.

## Documentation

- [Usage and report reference](https://github.com/lazypanic999/tunnelscope/blob/main/docs/usage-and-report-reference.md): source install,
  size sweeps, JSON fields, no-fragment behavior and lab commands.
- [Bounded size-search guide](https://github.com/lazypanic999/tunnelscope/blob/main/docs/size-search.md): adaptive probes and how to
  interpret the observed interval.
- [Repeated measurements and fragmentation comparison](https://github.com/lazypanic999/tunnelscope/blob/main/docs/fragmentation-comparison.md):
  development command and its limits.
- [ICMP feedback observation](https://github.com/lazypanic999/tunnelscope/blob/main/docs/icmp-feedback.md):
  optional Linux error-queue evidence and its limits.
- [Two-endpoint workflow](https://github.com/lazypanic999/tunnelscope/blob/main/docs/bidirectional.md) and
  [receiver correlation](https://github.com/lazypanic999/tunnelscope/blob/main/docs/receiver-observations.md): compare both directions.
- [Two-minute Linux demo](https://github.com/lazypanic999/tunnelscope/blob/main/docs/demo.md) and
  [validation records](https://github.com/lazypanic999/tunnelscope/tree/main/docs/validation): controlled failure scenarios.
- [HTML report view](https://github.com/lazypanic999/tunnelscope/blob/main/docs/report-ui.md),
  [deployment guidance](https://github.com/lazypanic999/tunnelscope/blob/main/docs/environments.md) and
  [security boundaries](https://github.com/lazypanic999/tunnelscope/blob/main/docs/security-boundaries.md).
- [v0.6 development roadmap](https://github.com/lazypanic999/tunnelscope/blob/main/docs/roadmap-v0.6.md),
  [v0.5 scope](https://github.com/lazypanic999/tunnelscope/blob/main/docs/roadmap-v0.5.md) and
  [completed milestones](https://github.com/lazypanic999/tunnelscope/blob/main/docs/project-history.md).

## Contributing

Good first issues: [Python 3.10 CI](https://github.com/lazypanic999/tunnelscope/issues/4),
[receiver correlation quick start](https://github.com/lazypanic999/tunnelscope/issues/5), and
[Windows PowerShell loopback guide](https://github.com/lazypanic999/tunnelscope/issues/6).
The [roadmap](https://github.com/lazypanic999/tunnelscope/blob/main/docs/roadmap-v0.5.md#community-issues) connects all six open issues
to the next release and field validation. Read [CONTRIBUTING.md](https://github.com/lazypanic999/tunnelscope/blob/main/CONTRIBUTING.md)
before opening a PR; share only synthetic or sanitized reports.

Run the unprivileged checks with `python -m unittest discover -s tests -v`.
Linux network-namespace checks require root and explicit opt-in; see the
[usage reference](https://github.com/lazypanic999/tunnelscope/blob/main/docs/usage-and-report-reference.md).

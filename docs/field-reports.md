# Field reports

Every TunnelScope validation so far comes from controlled labs and VMs. Reports
from real VPN, overlay and routed paths are the evidence the project needs
most (see [#1](https://github.com/lazypanic999/tunnelscope/issues/1) and
[#2](https://github.com/lazypanic999/tunnelscope/issues/2)). This guide shows
how to collect one report, sanitize it and share it with the
[field report issue template](https://github.com/lazypanic999/tunnelscope/issues/new?template=field_report.md).

Test only paths you own or have permission to test. The receiver answers UDP
probes without authentication; run it only for the duration of the test and
restrict its port to the sender. See [security boundaries](security-boundaries.md).

## What you need

- TunnelScope v0.7.0 or newer on both endpoints (`python -m pip install --upgrade tunnelscope`).
- A Linux receiver for `--sized-reply`; the sender for `diagnose` must also be
  Linux (WSL2 works). With a Windows sender, use `probe` instead (below).
- UDP port 9471 reachable from the sender to the receiver's address.

Replace `B_IP` below with the receiver's address on the path you are testing.

## 1. Start the receiver (endpoint B)

```sh
tunnelscope receive --bind B_IP --sized-reply --max-packets 200 --idle-timeout 120 --output receiver.json
```

It exits after 200 probes or 120 seconds without traffic and then writes
`receiver.json`.

## 2. Run the sender (endpoint A)

```sh
tunnelscope diagnose B_IP --min 1200 --max 1450 --count 2 --sized-reply --output diagnosis.json
```

This sends at most 28 probes in three sequential runs and writes
`diagnosis.json` and `diagnosis.html`. Choose `--min` and `--max` around the
sizes you care about; `--min` must be at least 36 with `--sized-reply`.

From a Windows sender, use a fixed list of sizes instead:

```sh
tunnelscope probe B_IP --sizes 64,1200,1300,1400,1450 --count 3 --sized-reply --output probe.json
```

## 3. Join and sanitize

Copy `receiver.json` to the sender (or both files to any machine with
TunnelScope), then:

```sh
tunnelscope correlate diagnosis.json receiver.json --output correlation.json --html correlation.html
mkdir shared
tunnelscope sanitize diagnosis.json receiver.json correlation.json --output-dir shared --html
```

Sanitize the files **together** so the same address gets the same placeholder
in every copy. Open the copies in `shared/` and read them before attaching:
`sanitize` replaces addresses, interface names, hostnames and absolute times it
can recognize, but not names you may have typed elsewhere. See
[sanitize reports](sanitize.md).

To test the other direction, swap the roles of A and B and repeat with new
file names.

## 4. Open the issue

Use the [field report template](https://github.com/lazypanic999/tunnelscope/issues/new?template=field_report.md),
attach the files from `shared/` and describe the path as far as you know it.
"Unknown" is a useful answer; please do not guess MTUs or topology.

## How a maintainer uses a report

1. Check that the reports parse (`tunnelscope show`), that their run IDs pair
   and that they are sanitized (`sanitization` block present).
2. Ask questions in the issue instead of filling gaps with assumptions.
3. With the reporter's agreement, add the sanitized files under `examples/`
   and write a record under `docs/validation/` stating the environment, the
   commands, what the reports show and what they do not.
4. Link the record from the README validation table, marked as field evidence
   rather than a controlled lab.

A report that shows nothing unusual is still useful: it records that a path
type carried the tested sizes in both directions.

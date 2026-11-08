# Field reports

Every TunnelScope validation so far comes from controlled labs and VMs. Reports
from real VPN, overlay and routed paths are the evidence the project needs
most (see [VPN field evidence #2](https://github.com/lazypanic999/tunnelscope/issues/2)).
The [Windows host/WSL2 guest record](validation/windows-wsl2-receiver.md) is a
controlled two-kernel example; physical host links need their own evidence. This guide shows
how to collect one report, sanitize it and share it with the
[field report issue template](https://github.com/lazypanic999/tunnelscope/issues/new?template=field_report.md).

Test only paths you own or have permission to test. The receiver answers UDP
probes without authentication; run it only for the duration of the test and
restrict its port to the sender. See [security boundaries](security-boundaries.md).

## What you need

- Use the latest published TunnelScope release on both endpoints and the
  sharing machine (`python -m pip install --upgrade tunnelscope`). The optional
  Markdown summary below requires v0.9.0 or newer. Same-sized replies on Linux
  are supported since v0.7.0.
- A Linux (including WSL2) or Windows receiver for `--sized-reply`; Windows
  receivers need v0.8.0 or newer, and Windows Firewall must allow inbound
  UDP 9471 for the test. The sender for
  `diagnose` must be Linux (WSL2 works). With a Windows sender, use `probe`
  instead (below).
- UDP port 9471 reachable from the sender to the receiver's address.

Replace `B_IP` below with the receiver's address on the path you are testing.

## 1. Start the receiver (endpoint B)

```sh
tunnelscope receive --bind B_IP --sized-reply --max-packets 200 --idle-timeout 120 --output receiver.json
```

It exits after 200 datagrams or 120 seconds without traffic and then writes
`receiver.json`. After the sender finishes, you can press Ctrl+C once in the
receiver terminal to save the capture immediately (`exit_reason: interrupted`);
the command exits with code 130. Wait for that terminal to return to its prompt
before copying the file. Do not close or kill the terminal before the capture
has been saved.

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

This writes `probe.json`; `diagnose` and its DF comparison remain Linux-only.

## 3. Join and sanitize

Copy `receiver.json` to the sender (or both files to any machine with
TunnelScope). For the Linux `diagnose` workflow:

```sh
tunnelscope correlate diagnosis.json receiver.json --output correlation.json --html correlation.html
mkdir shared
tunnelscope sanitize diagnosis.json receiver.json correlation.json --output-dir shared --html
```

For the Windows `probe` workflow, use its sender file instead. These commands
also work in PowerShell:

```sh
tunnelscope correlate probe.json receiver.json --output correlation.json --html correlation.html
mkdir shared
tunnelscope sanitize probe.json receiver.json correlation.json --output-dir shared --html
```

Run each experiment in a new directory, or choose fresh filenames and a fresh
`shared` directory. In particular, `diagnose` and `sanitize` refuse existing
outputs. Do not run both command blocks against the same files.

Sanitize the files **together** so the same address gets the same placeholder
in every copy. Open the copies in `shared/` and read them before attaching:
`sanitize` replaces addresses, interface names, hostnames and absolute times it
can recognize, but not names you may have typed elsewhere. See
[sanitize reports](sanitize.md).

Optionally, export the reviewed sanitized correlation as an issue summary:

```sh
tunnelscope show shared/correlation.json --format markdown > evidence.md
```

Choose a fresh `evidence.md` filename: shell redirection opens the file before
TunnelScope runs and can overwrite an existing file. Review the summary before
sharing it. The Markdown exporter **does not sanitize its input**; its row and
character limits do not replace the full evidence. Attach the full sanitized
JSON alongside the summary. See [Markdown report export](markdown-reports.md).

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
type carried the tested sizes. With same-sized replies acknowledged, each
successful attempt carried that size in both directions; a small ACK only
confirms the forward payload and the small reply.

The CLI collection → correlation → sanitization → display workflow is checked
on loopback in CI on Linux and Windows. That checks the commands and saved
files; it does not replace the two-machine dry run or independent field evidence.

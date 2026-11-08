---
title: "A small ACK can hide a failed return path: collecting both endpoint logs"
published: false
tags: networking,linux,python,opensource
---

When a tunnel or routed path passes `ping` but stalls on bulk transfers, testing large UDP payloads in one direction is only half the story. If a receiver answers a 1400-byte probe with a 24-byte acknowledgement, an `acknowledged` result only proves that 1400 bytes arrived forward and 24 bytes made it back. When the return path has a narrower MTU than the forward path, small ACKs succeed while large return payloads fail silently.

I maintain [TunnelScope](https://github.com/lazypanic999/tunnelscope), an alpha Python CLI that combines bounded UDP probes, `--sized-reply`, and offline endpoint log correlation. With `--sized-reply` enabled on both sides, a Linux (including WSL2) or Windows receiver attempts a reply of the probe's own payload size. Joining both logs records receiver arrival, the receiver socket's send outcome, and whether the sender received that reply. A missing receiver entry is inconclusive without verified capture coverage; a successful socket send alone does not locate a later failure. A timeout alone does not establish an MTU fault.

## What the controlled asymmetric-return lab shows

In the recorded [asymmetric return-path lab](https://github.com/lazypanic999/tunnelscope/blob/main/docs/validation/asymmetric-return.md), forward traffic crosses 1500-byte links from sender A through router R to receiver B, while return traffic from R to A crosses a 1280-byte link.

When testing 64-, 1200-, and 1400-byte payloads with `--dont-fragment --sized-reply`:

- **64 and 1200 bytes:** Both probes arrive and their same-sized replies return (`sized_reply_returned`).
- **1400 bytes (attempt 1):** The receiver log confirms the 1400-byte probe arrived and the receiver socket sent a 1400-byte reply, but R drops the return packet and the sender times out (`receiver_observed_sized_reply_missing`).
- **1400 bytes (attempt 2):** After R's ICMP feedback updates B's route cache, B's kernel rejects the next 1400-byte reply locally with `EMSGSIZE` (`receiver_reply_send_failed`).
- **1400 bytes with a default 24-byte ACK:** The probe is acknowledged because the tiny reply fits the 1280-byte return link.

## Try the workflow locally on loopback

You can run the collection, correlation, and batch sanitization workflow locally in a fresh directory without root privileges or network setup:

```sh
mkdir tunnelscope-demo && cd tunnelscope-demo
python3 -m venv .venv
source .venv/bin/activate
python -m pip install tunnelscope==0.9.5

# Terminal 1: bounded loopback receiver
tunnelscope receive --max-packets 2 --idle-timeout 30 --sized-reply --output receiver.json

# Terminal 2: activate the same venv in this shell, then send and process
source .venv/bin/activate
tunnelscope probe 127.0.0.1 --sizes 64,1400 --count 1 --sized-reply --output probe.json
tunnelscope correlate probe.json receiver.json --output correlation.json --html correlation.html
mkdir shared
tunnelscope sanitize probe.json receiver.json correlation.json --output-dir shared --html
```

Wait for `receive` to finish writing `receiver.json` before running `correlate`. Passing `probe.json`, `receiver.json`, and `correlation.json` to `sanitize` in a single batch ensures shared IP addresses, interfaces, hostnames, and relative timestamps receive consistent placeholders across all three files.

## Scope and what v0.9.5 changes

Same-sized replies, receiver correlation, and batch sanitization predate v0.9.5. Existing controlled-lab and VM records retain their original producer versions (such as v0.7.0, v0.8.0, and v0.9.1) rather than being relabeled. All current records come from controlled namespace, loopback, and single-host VM labs—not production validation. The v0.9.5 patch changes no wire protocol, JSON schema, or measurement logic; it only hardens offline correlation input validation, IPv6 and placeholder collision handling in `sanitize`, and exclusive output-file creation.

Sanitization remains a best-effort replacement of recognized fields, not a guarantee that arbitrary free text or filenames are clean. Always inspect the files in `shared/` manually before sharing.

## One operator feedback request

If you own or have permission to test a two-host WireGuard, OpenVPN, IPsec, or routed tunnel path, we would value one sanitized `--sized-reply` report in [issue #2](https://github.com/lazypanic999/tunnelscope/issues/2) using the [field report guide](https://github.com/lazypanic999/tunnelscope/blob/main/docs/field-reports.md). Reports from healthy paths where all tested sizes pass are just as useful as failure cases. Never share credentials, unreviewed raw captures, or remote access—only the reviewed, sanitized artifacts you choose to post.

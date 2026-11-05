---
title: "Small ACKs hide one-way MTU problems: same-sized replies in TunnelScope v0.7"
published: false
description: "TunnelScope v0.7 can ask the receiver for a reply of the probe's own size, so one run shows whether large packets can come back, and it can sanitize reports before you share them."
tags: networking, linux, python, opensource
cover_image: https://raw.githubusercontent.com/lazypanic999/tunnelscope/main/tunnelscope-logo-blue.png
---

In my [first post about TunnelScope](https://dev.to/lazypanic999/i-built-tunnelscope-to-inspect-mtu-and-packet-size-failures-with-evidence-b4p), the receiver confirmed every probe with a small 24-byte ACK. That answers "did a 1400-byte payload arrive?", but not "can a 1400-byte packet come back?". On an asymmetric path, such as two VPN gateways with different tunnel MTUs, the answers differ, and the small ACK still makes the exchange look healthy.

[v0.7.0 is on PyPI](https://pypi.org/project/tunnelscope/0.7.0/). It adds two things: **same-sized replies**, so one sender run tests both directions at each size, and **report sanitization**, so you can share what you measured without exposing your network.

## The case a small ACK cannot show

I built a three-namespace lab: sender A, router R and receiver B. Traffic from A to B uses 1500-byte links. R sends traffic back to A over a second link with a 1280-byte MTU. The receiver runs with `--sized-reply`, and the sender probes 64, 1200 and 1400 bytes, twice each:

| Payload | Same-sized reply | After joining the receiver log | Ordinary small ACK |
| --- | --- | --- | --- |
| 64 bytes | 2/2 received | `sized_reply_returned` | — |
| 1200 bytes | 2/2 received | `sized_reply_returned` | — |
| 1400 bytes | 0/2, timeout | `receiver_observed_sized_reply_missing`, then possibly `receiver_reply_send_failed` | acknowledged |

A 1200-byte reply needs a 1228-byte IPv4 packet and fits the 1280-byte return link; a 1400-byte reply does not. The receiver log shows that both 1400-byte probes **arrived**, so the missing reply is not a forward-path loss. After the router's ICMP feedback reaches the receiver, its kernel may refuse the second large reply locally, and the report records that separately as a send error. The last column is the point: an ordinary probe at 1400 bytes is acknowledged, because its 24-byte ACK fits.

The lab runs in CI on every pull request. The [validation record](https://github.com/lazypanic999/tunnelscope/blob/main/docs/validation/asymmetric-return.md) has the topology, the commands and the logged results.

## Try it on loopback

On Linux or WSL2, in an empty directory:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install tunnelscope==0.7.0
```

Terminal 1:

```sh
tunnelscope receive --sized-reply --max-packets 2 --output receiver.json
```

Terminal 2, with the same environment activated:

```sh
tunnelscope probe 127.0.0.1 --sizes 64,1400 --count 1 --sized-reply --output probe.json
tunnelscope correlate probe.json receiver.json --html correlation.html
```

On loopback both replies come back (`sized_reply_received`). Between two hosts, start the receiver with `--bind B_IP --sized-reply` and add `--dont-fragment` to the probe. `search`, `compare-fragmentation` and `diagnose` accept the same flag; there an acknowledged attempt means the size crossed both directions, so a search interval reflects the narrower one.

Both sides opt in. A v0.7 sender marks its probes, and a v0.6 receiver ignores the mark and sends the small ACK, which the report labels `small_ack_only` rather than pretending the return path was tested. The reply is never larger than the probe, so the receiver does not amplify traffic. `receive --sized-reply` currently needs Linux. The [sized-reply guide](https://github.com/lazypanic999/tunnelscope/blob/main/docs/sized-reply.md) lists every field.

## Share reports without sharing your network

Reports contain addresses, interface names and timestamps. `sanitize` writes copies with addresses replaced by documentation addresses (`192.0.2.x`, `2001:db8::x`), interfaces and hostnames replaced by labels, and timestamps shifted by one constant:

```sh
mkdir shared
tunnelscope sanitize probe.json receiver.json --output-dir shared --html
```

Reports sanitized together keep one mapping, so the copies still join with `correlate` and give the same per-probe evidence as the originals. Payload sizes, outcomes, RTTs and ICMP fields stay unchanged. It only replaces values it recognizes, so read the copies before posting them. The [sanitize guide](https://github.com/lazypanic999/tunnelscope/blob/main/docs/sanitize.md) has the details.

## What this does not tell you

A missing same-sized reply does not say where or why it was lost. The asymmetric lab is a controlled topology on one kernel, not a production VPN. An observed payload interval is not an independently measured end-to-end path MTU, missing ACKs and absent ICMP stay inconclusive, and the receiver is an unauthenticated UDP responder meant for controlled paths.

## Looking for real paths

The lab results are reproducible, but I still have no field evidence from production-like VPNs or from routed IPv6 Packet Too Big outside a lab ([#2](https://github.com/lazypanic999/tunnelscope/issues/2), [#1](https://github.com/lazypanic999/tunnelscope/issues/1)). If you run WireGuard, IPsec or a Kubernetes overlay and have a path you are allowed to test, a sanitized `diagnose --sized-reply` report would help a lot.

The [code and v0.7.0 release notes](https://github.com/lazypanic999/tunnelscope/releases/tag/v0.7.0) are on GitHub. Have you run into a path that carried large packets one way but not the other, and how did you find out?

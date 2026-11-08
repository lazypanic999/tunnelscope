# TunnelScope project history

## Original first-version scope

- A Python command-line tool and a cooperating receiver for controlled Linux environments.
- Repeated, size-controlled IPv4 UDP probes with fragmentation disabled.
- Separate measurements for each direction, with timeouts and loss recorded explicitly.
- JSON reports containing probe sizes, outcomes, relevant interface information and test settings.
- A reproducible Linux lab demonstrating healthy delivery, explicit packet-too-large feedback and a possible PMTU black hole.

A failed probe alone is not labeled as proof of an MTU problem. Reports separate observations, hypotheses and missing evidence. An observed working packet size is not presented as the exact path MTU.

## Milestones

- [x] **M0 - Reproduce the problem:** build a small Linux network-namespace lab and record a healthy baseline and a controlled MTU failure.
- [x] **M1 - Probe and receive:** implement bounded, identifiable probes and acknowledgements between two endpoints.
- [x] **M2 - Explain the evidence:** export JSON and distinguish successful delivery, explicit errors and inconclusive timeouts.
- [x] **M3 - Validate:** check the tool against known lab configurations, document limitations and publish a short demo.
- [x] **M4 - Observe at the receiver:** record which identified probes reached the cooperating receiver and correlate them with sender outcomes.
- [x] **M5 - Make evidence usable:** validate receiver-observed timeouts in a controlled lab and provide a concise terminal view of reports.

The [tunnel and pod workflows](https://github.com/lazypanic999/tunnelscope/blob/main/docs/environments.md) include controlled VXLAN and WireGuard labs and a [two-node Calico pod validation](validation/kubernetes-calico.md). Production VPN and Kubernetes deployments need separate validation. 5G user-plane tunnels remain outside the current scope.

For a quick walkthrough of both controlled failure modes, see the [two-minute Linux demo](https://github.com/lazypanic999/tunnelscope/blob/main/docs/demo.md).
The [two-VM validation record](https://github.com/lazypanic999/tunnelscope/blob/main/docs/validation/two-vm-field-test.md) documents a successful bidirectional DF run between Ubuntu and Debian guests.
The [v0.1 scope](https://github.com/lazypanic999/tunnelscope/blob/main/docs/v0.1-scope.md) lists what the installable prototype does and does not cover.
The [v0.2 receiver workflow](https://github.com/lazypanic999/tunnelscope/blob/main/docs/receiver-observations.md) explains how to capture and correlate receiver evidence.
The [two-VM correlation record](https://github.com/lazypanic999/tunnelscope/blob/main/docs/validation/two-vm-receiver-correlation.md) documents the new workflow on independent Linux guests.
The [blocked ACK return lab](https://github.com/lazypanic999/tunnelscope/blob/main/docs/validation/ack-return-blocked.md) validates a receiver-observed sender timeout.
The [v0.5 scope](https://github.com/lazypanic999/tunnelscope/blob/main/docs/roadmap-v0.5.md) records the bounded size-boundary experiment and its validation gates.
The [v0.6 release](releases/v0.6.0.md) adds repeated measurements, Linux ICMP
feedback, a bounded `diagnose` workflow and joined receiver evidence.
The [two-VM WireGuard record](validation/two-vm-wireguard.md) validates these
workflows across independent Ubuntu and Debian guests on a controlled tunnel.
The [v0.7 release](releases/v0.7.0.md) adds same-sized replies for return-path
evidence and report sanitization; the
[asymmetric return-path lab](validation/asymmetric-return.md) validates the former.
[v0.7.1](releases/v0.7.1.md) fixes `Z`-suffixed timestamps in `sanitize`.
[v0.8.0](releases/v0.8.0.md) adds Windows receivers for sized replies, an IPv6
asymmetric lab, CI lab artifacts and a [field report guide](field-reports.md).
[v0.8.1](releases/v0.8.1.md) makes joined HTML tables readable.
[v0.8.2](releases/v0.8.2.md) fixes sanitization identity and UTC display,
completes the routed IPv6 blocked-feedback experiment, and checks the field
report sharing workflow through real CLI processes.
[v0.9.0](releases/v0.9.0.md) adds bounded Markdown evidence summaries,
declared producer/input versions, controlled OpenVPN feedback and return-path
labs, grouped lab views, BOM-aware JSON input and installed-package/CI
artifact provenance checks.

[v0.9.1](releases/v0.9.1.md) keeps missing receiver reply-send outcomes
unverified and handles malformed report kinds without a traceback.
The subsequent [native Windows/WSL2 receiver record](validation/windows-wsl2-receiver.md)
validates v0.9.1 over non-loopback IPv4 between two kernels on one physical
host, including the full sender/correlation/sanitization workflow.

# Native Windows receiver reached from a WSL2 Linux guest

Recorded on 2026-11-08 with TunnelScope **v0.9.1**. A Linux WSL2 guest sent
IPv4 UDP probes to the native Windows host's explicit WSL virtual-interface
address. These are **two kernels on one physical computer**, using an existing
private virtual network. Traffic used non-loopback addresses; this extends
the earlier Windows-only loopback checks.

Full reviewed evidence is in
[examples/windows-wsl2-receiver-v09.json](../../examples/windows-wsl2-receiver-v09.json).
It contains the small-ACK and sized-reply runs, their shared receiver capture,
and the separate diagnosis/receiver/joined reports. Related measurement files
were sanitized together with one mapping before this fixture was assembled.
Addresses, the sender interface label and absolute measurement timestamps
were replaced; the wrapper adds reviewed OS/version and scope facts. Raw
reports and host-adapter information remain in Git-ignored local output.

## Environment and scope

| Endpoint | Recorded environment |
| --- | --- |
| Receiver | Native Windows; Python `platform.version()` reported NT build `10.0.26300`; Python 3.10.11 |
| Sender | Ubuntu WSL2; Linux `6.6.87.2-microsoft-standard-WSL2`; Python 3.12.3 |
| Tool | Windows used the verified official PyPI v0.9.1 wheel; Linux used the clean matching `v0.9.1` source tag, commit `0e456a2ab602` |
| Interfaces | Sender `eth0` and host-side WSL virtual interface each reported MTU 1500 |
| Network policy | Existing virtual-network policy; no test-created firewall rules, routes or interface changes |
| Bind/port | Explicit Windows WSL-interface address, with separate temporary ephemeral UDP ports for the two capture sessions |

The WSL default gateway was cross-checked against an address actually owned
by the Windows WSL adapter before testing. The guest and host addresses were
distinct. No third-party gateway or public endpoint was probed. The receiver
recorded `reply_fragmentation: disabled: Windows IP_DONTFRAGMENT`.

This checks the Linux-VM-to-Windows receiver scope of
[#28](https://github.com/lazypanic999/tunnelscope/issues/28). Physically
separate Windows/Linux machines, other firewall profiles, IPv6 cross-host
paths and independent operator VPN evidence remain separate validation work.

## Small ACK versus same-sized reply

One Windows receiver accepted nine probes in two sequential sender runs:

| Mode | Payload sizes | Attempts | Observed result |
| --- | --- | --- | --- |
| Small ACK | 64, 1200, 1400 | One per size | 3/3 acknowledged; each receiver reply was 24 bytes |
| Same-sized reply | 64, 1200, 1400 | Two per size | 6/6 `sized_reply_received`; actual reply lengths were 64, 64, 1200, 1200, 1400, 1400 |

The receiver captured all nine arrivals and recorded successful local sends.
Each run was correlated separately by run ID and probe ID. The other run's
observations in the shared capture are expected unmatched observations, not
missing data. Endpoint checks matched the receiver bind address and port.
The small-ACK baseline alone does not establish same-sized return delivery.

## Complete Linux sender workflow

A second Windows capture covered:

```sh
tunnelscope diagnose B_IP --port PORT --min 1200 --max 1400 --count 1 \
  --timeout 1 --max-sizes 4 --sized-reply --output diagnosis.json
```

The DF and fragmentation-permitted runs each tested 1200, 1300 and 1400
bytes. The size search tested its 1200/1400 endpoints. All **8/8** attempts
received same-sized replies and all eight arrivals were retained in the
Windows capture and joined diagnosis. Search reported `no_explicit_bracket`
with no observed interval: successful tested sizes do not find an upper
boundary. Permitting fragmentation did not demonstrate that any fragments
crossed this path.

Correlation, batch sanitization with HTML, and Markdown export ran on Windows
using the installed public package. The sender used a shared mounted working
directory; network file transfer between physically separate machines was
not exercised. Rejoining the sanitized sender/receiver reports preserved
their per-attempt evidence.

## Reproduce on a permitted host/guest path

Choose an address owned by the Windows WSL adapter and confirm it matches the
Linux guest's route. Another machine's network policy may require an
operator-approved scoped rule; this record changed no policy. Use two
terminals and new output names. On Windows:

```powershell
tunnelscope receive --bind B_IP --port 0 --sized-reply --max-packets 9 --idle-timeout 10 --output receiver-baseline-sized.json
```

Use the printed port as `PORT`. From Linux, run these sequentially:

```sh
tunnelscope probe B_IP --port PORT --sizes 64,1200,1400 --count 1 --timeout 1 \
  --dont-fragment --output baseline.json
tunnelscope probe B_IP --port PORT --sizes 64,1200,1400 --count 2 --timeout 1 \
  --dont-fragment --sized-reply --output sized.json
```

After the receiver saves its capture, join each sender file with that capture.
For the diagnosis phase, start a fresh Windows receiver with `--port 0`,
`--max-packets 100`, `--idle-timeout 5` and `--output receiver-diagnosis.json`.
Use its printed port for the diagnosis command above. It saves the capture
after the idle timeout. Then:

```powershell
tunnelscope correlate diagnosis.json receiver-diagnosis.json --output diagnosis-correlation.json --html diagnosis-correlation.html
```

Use one batch mapping when sanitizing all related files. The
[field-report guide](../field-reports.md) explains the shared JSON/HTML and
optional Markdown steps. Fresh test commands require a reachable cooperating
receiver; the retained fixture can be viewed entirely offline:

```sh
tunnelscope show examples/windows-wsl2-receiver-v09.json
tunnelscope html examples/windows-wsl2-receiver-v09.json --output windows-wsl2.html
```

## Cleanup and limitations

Both Windows receiver processes exited successfully: the first reached its
nine-datagram limit, and the second saved eight observations on idle timeout.
No receiver was left listening. No test-created rule or interface required
removal.

This is a healthy 64–1400-byte controlled virtual path. It does not establish
an exact end-to-end PMTU, force an oversized Windows reply, validate every
Windows firewall configuration, or demonstrate a physical multi-host/VPN
incident. Separate kernels' clocks were not compared. The UDP protocol and
receiver logs remain unauthenticated. Independent VPN reports remain tracked
in [#2](https://github.com/lazypanic999/tunnelscope/issues/2).

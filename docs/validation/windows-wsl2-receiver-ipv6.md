# IPv6 link-local traffic to a native Windows receiver

Recorded on 2026-11-08 with TunnelScope **v0.9.1**, after the separate
[IPv4 host/guest run](windows-wsl2-receiver.md). An Ubuntu WSL2 sender
reached the native Windows host over their existing IPv6 link-local virtual
network: **two kernels on one physical computer**. This is not a routed IPv6
or physical multi-host validation.

The later [oversized reply experiment](windows-oversized-replies.md) adds
an actual Windows `WSAEMSGSIZE` observation over this IPv6 path and IPv4.
The healthy results below remain a separate run.

Full reviewed evidence is retained in
[examples/windows-wsl2-receiver-ipv6-v09.json](../../examples/windows-wsl2-receiver-ipv6-v09.json).
Eight related files were batch-sanitized before assembling the wrapper.
Documentation addresses replace the original link-local addresses, so the
sanitized `2001:db8::` addresses are placeholders, not evidence of a global
IPv6 route. Interface labels and absolute measurement timestamps were also
replaced. Probe/run IDs, local scope IDs and observed outcomes were retained.

## Environment and observations

The endpoints matched the IPv4 record: Windows NT build `10.0.26300`, Python
3.10.11 and the SHA-256-verified official PyPI v0.9.1 wheel; Ubuntu WSL2,
Linux `6.6.87.2-microsoft-standard-WSL2`, Python 3.12.3. Linux used source
commit `d574d6a948c4`; its runtime files matched the `v0.9.1` tag. Both
interfaces reported MTU 1500. The Windows address was checked against its
owned WSL virtual adapter; no external endpoint was contacted.

| Run | UDP payloads | Result |
| --- | --- | --- |
| Small ACK | 64, 1200, 1400 bytes, one each | 3/3 acknowledged; each reply was 24 bytes |
| Sized reply | Same sizes, two each | 6/6 `sized_reply_received`; replies were 64, 64, 1200, 1200, 1400, 1400 bytes |
| Diagnose | DF and permitted at 1200/1300/1400; search at 1200/1400 | 8/8 same-sized replies |

The shared first capture retained nine observations. The second retained
eight. All recorded local sends were `sent`; the Windows receiver recorded
`disabled: Windows IPV6_DONTFRAG`. Both processes exited normally and no
test-created firewall rules, routes, interface settings or permissions were
needed. Correlation, HTML, batch sanitization and Markdown export succeeded;
rejoining the sanitized files preserved the per-attempt results.

Search retained `no_explicit_bracket` and no observed interval. A healthy
tested range does not locate an upper boundary. Permitting fragmentation
does not establish that fragments crossed the path.

## Scoped address handling

Link-local destinations need a zone identifying the **local** outgoing
interface. The zone is not a shared endpoint identifier. On this run Windows
used its adapter's numeric index and Linux used `eth0`; those scopes must not
be copied between operating systems. Replace `WIN_SCOPE`, `LINUX_SCOPE` and
the address below with the values belonging to your permitted host/guest path.

On Windows, start a bounded receiver on its owned address:

```powershell
tunnelscope receive --bind "WINDOWS_LINK_LOCAL%WIN_SCOPE" --family ipv6 --port 0 --sized-reply --max-packets 9 --idle-timeout 10 --output receiver.json
```

Use the printed port in the two sequential Linux commands:

```sh
tunnelscope probe 'WINDOWS_LINK_LOCAL%LINUX_SCOPE' --port PORT \
  --sizes 64,1200,1400 --count 1 --timeout 1 --dont-fragment --output baseline.json
tunnelscope probe 'WINDOWS_LINK_LOCAL%LINUX_SCOPE' --port PORT \
  --sizes 64,1200,1400 --count 2 --timeout 1 --dont-fragment --sized-reply --output sized.json
```

`WINDOWS_LINK_LOCAL` represents the same address in both commands; the zone
belongs to each local machine. The listening line prints an address and
port but omits the socket's numeric scope; retain the explicitly chosen bind
scope.

For diagnosis, use a fresh receiver with `--max-packets 100 --idle-timeout 5`
and then the scoped destination with `diagnose --min 1200 --max 1400
--count 1 --timeout 1 --max-sizes 4 --sized-reply`. Save fresh sender and
receiver filenames, then follow the [field guide](../field-reports.md) to
join, sanitize together and review before sharing. The checked-in fixture
also renders offline with `tunnelscope show` or `tunnelscope html`.

## Remaining limits

No IPv6 router, Packet Too Big failure, oversized Windows reply or production
VPN was exercised in this run. Physically separate hosts, routed IPv6,
different host firewall profiles and network file transfer need separate
evidence. Files used a shared mounted working directory. Clocks across
kernels were not compared; receiver logs and UDP messages remain
unauthenticated. Independent operator VPN reports remain tracked in
[#2](https://github.com/lazypanic999/tunnelscope/issues/2).

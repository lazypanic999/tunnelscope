# Measure both directions

TunnelScope's receiver sends a small acknowledgement. One `probe` run therefore
measures delivery of the requested payload in one direction, plus return of the
small acknowledgement. To measure the reverse direction, the endpoints must
exchange sender and receiver roles. This workflow is for a controlled Linux
environment where both sides can run Python 3.10+ and reach each other over UDP.

Use the actual endpoint IPv4 addresses in place of `A_IP` and `B_IP`. Start each
receiver shortly before its probe; by default it exits after 30 seconds idle.

## Before the first run: open UDP 9471 to the sender only

The receiver needs inbound UDP on port 9471 from the other endpoint. Allow just
that address, and remove the rule when you are done. On the receiving endpoint
(here B, accepting from A):

```sh
# ufw (Ubuntu, Debian)
sudo ufw allow from A_IP to any port 9471 proto udp
sudo ufw delete allow from A_IP to any port 9471 proto udp    # afterwards

# firewalld (Fedora, RHEL); runtime only, gone after a reload or reboot
sudo firewall-cmd --add-rich-rule='rule family="ipv4" source address="A_IP" port port="9471" protocol="udp" accept'
```

On a Windows receiver, in an administrator PowerShell:

```powershell
New-NetFirewallRule -DisplayName "TunnelScope test" -Direction Inbound -Protocol UDP -LocalPort 9471 -RemoteAddress A_IP -Action Allow
Remove-NetFirewallRule -DisplayName "TunnelScope test"    # afterwards
```

Cloud VMs usually also need the port in the provider's security group or
firewall. Do the same on A before the B-to-A run.

### When nothing comes back

Include a small size such as 64 in every run. It tells you whether the problem
has anything to do with size:

- **64 bytes is acknowledged, larger sizes time out:** the pattern this tool is
  for. Add the receiver log (`receive --output`) to see whether the large probes
  arrived.
- **Every size times out, including 64:** not a size problem. Check the
  firewall rule above, the address and port, and that the receiver printed
  `Listening on B_IP:9471`. Releases after v0.9.6 print a line for every
  probe the receiver gets; if none appear, or the saved log is empty, the
  probes are not reaching it.
- **`socket_error`, with a "port unreachable" note in releases after v0.9.6:** the target answered that
  nothing is listening on that port. Usually the receiver was not running yet
  or was bound to a different address. A firewall can send the same answer.

## A to B

On endpoint B:

```sh
python3 tunnelscope.py receive --bind B_IP
```

On endpoint A:

```sh
python3 tunnelscope.py probe B_IP --sizes 64,1252,1253,1400 --count 3 --dont-fragment --output a-to-b.json
```

## B to A

On endpoint A:

```sh
python3 tunnelscope.py receive --bind A_IP
```

On endpoint B:

```sh
python3 tunnelscope.py probe A_IP --sizes 64,1252,1253,1400 --count 3 --dont-fragment --output b-to-a.json
```

Copy `b-to-a.json` to the machine holding `a-to-b.json`. Then run:

```sh
python3 tunnelscope.py combine a-to-b.json b-to-a.json --output bidirectional.json
```

`bidirectional.json` contains the unmodified probe reports under `directions`,
with `a-to-b` and `b-to-a` labels supplied by the command order. Its
`comparison.by_payload_size` aligns each direction's assessment for the same
UDP payload size. A missing size has a `null` assessment. The command does not
turn two timeouts into a diagnosis.
Each embedded report's `evidence` describes that one run; `combine` preserves
it without retroactively treating the other file as verified evidence.

`endpoint_check` is `reversed_ipv4_match` when both recorded source IPv4
addresses equal the opposite report's target address. It is
`ipv4_mismatch_or_translation` when they differ, or `unavailable` if either
source snapshot is missing. NAT, multiple local addresses and user-selected
files can affect this check; the command cannot verify that the files came
from the intended endpoints.

## Source fields

`source.ipv4` is the first connected sender socket's local IPv4 address. On
Linux, `source.interface` and `source.interface_mtu_bytes` are included when
the address can be matched to a local interface. `source.kernel_route_mtu_bytes`
is the kernel's current MTU value for that connected route when available. A
link MTU is local interface configuration; a kernel route MTU can reflect
cached path knowledge. Neither field alone proves the end-to-end path MTU.

The report contains a source snapshot, not a live record of route changes
during later attempts. When a socket cannot connect, `source` can be `null`.
The probe protocol is unauthenticated and unencrypted; use a controlled lab.

For each direction, you can also save observations at the receiving endpoint
and use `tunnelscope correlate` to check which individual probes arrived. See
the [receiver observation workflow](receiver-observations.md). This provides
different evidence from a reverse-direction probe.

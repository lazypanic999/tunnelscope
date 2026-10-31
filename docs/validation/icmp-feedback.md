# ICMP feedback validation

Validated on 31 October 2026 in isolated Ubuntu WSL2 network namespaces.
No user VM interface, route or firewall was changed.
The privileged Linux suite ran 47 tests with no skips or failures. The
Windows suite ran 47 tests with seven Linux-only skips. An unprivileged WSL2
user also enabled `--observe-icmp` on loopback successfully.

| Scenario | Error-queue observation |
| --- | --- |
| Direct IPv4 1280-byte link, both directions | 1253- and 1400-byte DF probes returned local `EMSGSIZE`; two `origin: local` events and zero network ICMP size messages per direction |
| Routed IPv4 path, 1500-byte ingress and 1280-byte egress | With feedback visible, the 1400-byte DF probe had token-matched ICMP type 3/code 4 and reported MTU 1280 |
| Same IPv4 path with router ICMP fragmentation-needed blocked | Large probes timed out and no ICMP size message appeared in their error queues; search stayed inconclusive |
| Routed IPv6 path, 1500-byte ingress and 1280-byte egress | The 1400-byte no-fragment probe had token-matched ICMPv6 type 2/code 0 and reported MTU 1280 |

The blocked case is known because the lab installs and counts its own router
firewall rule. On an unknown path, zero observed ICMP messages does not prove
filtering. The reported MTU is feedback from the kernel/error message, not
independent proof of an end-to-end path limit. The tests also check local
versus remote origins, mismatched or truncated payload quotes, bounded queue
reads, unsupported platforms and terminal/HTML output.

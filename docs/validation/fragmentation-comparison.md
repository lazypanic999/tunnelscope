# Repeated measurements and fragmentation comparison validation

Validated on 31 October 2026 in isolated Ubuntu WSL2 network namespaces.
The privileged test suite ran 41 tests without skips or failures. Windows
unprivileged checks ran 41 tests with six Linux-only skips.

| Scenario | DF observations | Fragmentation-permitted observations |
| --- | --- | --- |
| IPv4 direct 1280-byte link, both directions | 1252-byte UDP payload acknowledged; 1253 and 1400 explicitly rejected | All three sizes acknowledged |
| IPv6 direct 1280-byte link, both directions | 1232 acknowledged; 1233 explicitly rejected | Both sizes acknowledged |
| Routed IPv4 path, 1280-byte egress, ICMP fragmentation-needed blocked | 64 acknowledged; 1400 timed out | Both sizes acknowledged |

The routed lab knows its firewall rule and topology. In an unknown network,
the same pattern does not establish the cause of a timeout. The permitted
run's ACKs show that those payloads arrived; no packet capture was taken to
show fragment placement or reassembly. The comparison is sequential, so
changing network conditions can affect it. Unit tests cover the 7/10
no-ACK example, empty valid-attempt sets, incompatible reports, changed
source snapshots, Linux socket options, budget limits and terminal/HTML
rendering.

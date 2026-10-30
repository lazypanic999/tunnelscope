# v0.5 bounded size-search validation

Validated on 30 October 2026 in isolated Ubuntu WSL2 Linux network namespaces.
The privileged suite ran 35 tests with no skips or failures. Tests create and
remove their own namespaces and do not use the user's two external VMs.

| Scenario | Expected known lab behavior | Search result |
| --- | --- | --- |
| IPv4 direct 1280-byte veth link, both directions | 1252-byte UDP payload succeeds; 1253 gets `EMSGSIZE` | Adjacent observed bounds 1252–1253 |
| IPv6 direct 1280-byte veth link, both directions | 1232 succeeds; 1233 gets `EMSGSIZE` | Adjacent observed bounds 1232–1233; receiver saw both successful search probes |
| Routed IPv4 path with ICMP fragmentation-needed feedback blocked | Small payload succeeds; large payload times out | `inconclusive`, no observed interval |
| ACK return blocked at sender | Receiver sees both probes, sender times out | `inconclusive`; receiver correlation confirms both arrivals |

Unit tests also check mixed outcomes, contradictory ordering, missing explicit
brackets, configured search budgets, HTML escaping and terminal summaries.
The Linux tests validate these controlled topologies; they do not establish
behavior on arbitrary VPNs or Kubernetes deployments. An observed adjacent
payload interval is not an independently measured path MTU.

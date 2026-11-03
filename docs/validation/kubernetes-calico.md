# Cross-node Kubernetes and Calico validation

Recorded on 2026-11-04 on a dedicated two-node Minikube cluster using the
Docker driver under WSL2. One unprivileged test pod ran on each node. A
separate kubeconfig and a newly generated namespace isolated the test from
other local clusters. Receivers bound to pod addresses on UDP port 9471.

| Component | Recorded value |
| --- | --- |
| Kubernetes | v1.35.1 |
| Minikube | v1.38.1, Docker driver, two nodes |
| Calico | v3.31.3; IPv4 pool configured with IP-in-IP `Always`, VXLAN `Never` |
| Kernel | 6.6.87.2-microsoft-standard-WSL2 |
| Python in both pods | 3.12.16 |
| TunnelScope in both pods | 0.6.0, installed from PyPI |
| Pod address family | IPv4 |
| Selected pod interface | `eth0` in both directions |
| Interface / kernel route MTU | 1480 / 1480 bytes in both directions |
| Container user | UID/GID 10001; all Linux capabilities dropped |

The image was built from the pinned Python base in
[`labs/kubernetes/Dockerfile`](../../labs/kubernetes/Dockerfile). Both pods ran
image ID `sha256:aba1db57fb277752edceb9f2105fd61c5bf3ae65e47912659fbaa8efcadbac5f`.
The root filesystem was read-only with an `emptyDir` report volume at `/tmp`.
No host networking, privileged container or external Service was used.

## Procedure

The [Kubernetes guide](../kubernetes.md) contains cluster creation, image
loading and cleanup commands. The validating command was equivalent to:

```sh
python3 labs/kubernetes_pods.py \
  --kubeconfig TEST_KUBECONFIG --context TEST_CONTEXT \
  --nodes NODE_A NODE_B --image tunnelscope-k8s-test:0.6.0 \
  --output-dir output/kubernetes-lab
```

The script verified both nodes were Ready and each pod's actual `nodeName`
was distinct. It installed a separate ingress policy for each pod, admitting
UDP port 9471 only from the labeled lab peers in the same namespace. Egress
was not isolated by this test's policies. Successful ACKs demonstrate that
return traffic was admitted in this configuration.

For each direction, the receiver saved its observations while the sender ran:

```sh
tunnelscope probe PEER_POD_IP --sizes 64,1200,1400 --count 2 \
  --timeout 1 --dont-fragment --observe-icmp --output probe.json

tunnelscope diagnose PEER_POD_IP --min 1448 --max 1456 --count 1 \
  --max-sizes 8 --timeout 1 --output diagnosis.json
```

Sender and receiver reports were collected with `kubectl exec ... -- cat`,
then correlated and rendered as joined HTML. The two baseline sender reports
were also processed with `combine`.

## Observations

| Experiment | Sender evidence | Receiver evidence |
| --- | --- | --- |
| Pod A → B, 64 / 1200 / 1400 bytes | 2/2 ACKs at each size | 6/6 probes observed |
| Pod B → A, same sizes | 2/2 ACKs at each size | 6/6 probes observed |
| A → B diagnosis, 1448..1456 | adjacent payload interval 1452–1453 | 7/11 attempts observed; four local size errors |
| B → A diagnosis, same bounds | adjacent payload interval 1452–1453 | 7/11 attempts observed; four local size errors |
| B ingress isolated, A → B, 64 bytes | two timeouts | zero matching observations |
| B ingress restored, A → B, 64 / 1200 / 1400 | 1/1 ACK at each size | 3/3 probes observed |

Both baseline correlations matched run IDs, receiver bind addresses and target
ports, with zero unmatched observations. `combine` reported
`reversed_ipv4_match`. Joined diagnosis captures had zero unassigned or
unmatched observations. The 1452/1453 boundary corresponds to the configured
1480-byte pod interface after 20 bytes of IPv4 and 8 bytes of UDP headers;
the four unsent local size errors in each diagnosis are not packet loss.

The policy test changed only Pod B's ingress policy to an empty allowed list.
After the bounded propagation wait, both fresh small probes timed out.
Correlation retained `unverified_no_receiver_observations`; it did not turn
the empty capture into proof of loss. Restoring the allow rule restored ACKs
and receiver observations. The known policy change supplies context for this
controlled experiment; the timeout pattern alone does not diagnose filtering
or an MTU problem on an unknown cluster.

The script deleted its generated namespace after the test. The dedicated
Minikube profile and temporary kubeconfig were subsequently removed. During
setup the host's inotify instance limit was temporarily raised from 128 to
512 to support the extra Docker-based nodes, then restored to 128 after
cleanup. The existing cluster context remained selected throughout.

## Limits

These were separate Kubernetes nodes and pods on one physical WSL2 host,
sharing a kernel. This validates the documented IPv4 workflow on the recorded
Calico IP-in-IP configuration. It does not establish behavior on physical
multi-host links, cloud networks, Cilium, Flannel, IPv6/dual-stack clusters,
Services, Ingress controllers or service meshes. No arbitrary end-to-end PMTU
claim is made. ACKs were small and directions were separate experiments.
The new namespace's policy propagation delay is a lab setting, not a universal
CNI guarantee. Raw pod addresses, metadata and kubeconfig credentials are
excluded from Git; only this sanitized record is published.

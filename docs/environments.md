# Controlled tunnel and pod workflows (development)

TunnelScope sends ordinary UDP payloads between a cooperating sender and
receiver. The tool does not configure a VPN, container network, Kubernetes
cluster or network policy. Run it only where both endpoints and the UDP path
are under your control. Use the tunnel or pod address as the destination, and
measure each direction separately.

## VXLAN overlay lab

On Linux with root and `iproute2`:

```sh
sudo python3 labs/vxlan_boundary.py > vxlan-boundary.json
```

The lab creates two temporary network namespaces. Their 1500-byte underlay
carries a VXLAN overlay with a 1450-byte interface MTU. In IPv4 DF mode, the
known maximum UDP payload on that overlay is 1422 bytes (1450 minus 20-byte
IPv4 and 8-byte UDP headers). The lab checks 1418–1426 bytes in both
directions, correlates receiver observations and removes its namespaces on
ordinary completion. It changes no host interface or route.

This validates an encapsulated virtual path, not a real VPN or a Kubernetes
cluster. A measured local tunnel-interface MTU and a kernel route MTU remain
different from independent proof of an unknown end-to-end path MTU.

## Existing VPN or tunnel

Use the addresses assigned inside the tunnel. Start the receiver on endpoint
B, then probe from endpoint A:

```sh
tunnelscope receive --bind B_TUNNEL_IP --output b-receiver.json
tunnelscope probe B_TUNNEL_IP --sweep 1200:1400:25 --count 2 --dont-fragment --output a-to-b.json
```

Run the commands in separate terminals. Repeat with A and B swapped, then use
`combine` for direction comparison and `correlate` with each receiver report.
Check the selected `source.interface` and its MTU in the probe report. If the
route unexpectedly uses a non-tunnel interface, the experiment did not measure
the intended VPN path. Use `--family ipv6` for an IPv6 hostname or an IPv6
literal address. Timeouts remain inconclusive without receiver or path
evidence.

## Existing Kubernetes pods

If two controlled pods already contain the development CLI and Python 3.10+,
use their pod addresses directly. In separate local terminals, for example:

```sh
kubectl exec -n NAMESPACE POD_B -- tunnelscope receive --bind POD_B_IP --output /tmp/receiver.json
kubectl exec -n NAMESPACE POD_A -- tunnelscope probe POD_B_IP --sizes 64,1200,1400 --count 2 --dont-fragment --output /tmp/probe.json
```

Collect the JSON files from the pods and correlate them. Repeat with the roles
reversed. A pod may have more than one container; add `-c CONTAINER` to
`kubectl exec` when needed. Ensure that the intended UDP port (default 9471)
and the small ACK return traffic are allowed by the cluster's network policy.
Kubernetes [pod networking](https://kubernetes.io/docs/concepts/services-networking/)
and [NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
are implemented by the cluster's network plugin; behavior can differ between
clusters. See the official [`kubectl exec` reference](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_exec/).

This pod recipe is untested here because no Kubernetes cluster was available.
It does not claim cluster-wide MTU discovery, support for every CNI, or the
ability to distinguish overlay loss from filtering on its own.

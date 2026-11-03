# Controlled cross-node Kubernetes validation

The reproducible pod lab uses an explicitly selected kubeconfig, context and
two nodes. It creates a unique namespace, places one pod on each node, and
deletes that namespace on completion or failure. Use a controlled test cluster
with a CNI that enforces Kubernetes NetworkPolicy, such as Calico.

## Create a local test cluster

Requirements: Linux or WSL2, Docker, Minikube, `kubectl` and Python 3.10+.
The image installs TunnelScope v0.6.0 from PyPI and `iproute2`; its Python base
image is pinned by digest in the Dockerfile. The two Minikube nodes each use
two CPUs and 2048 MiB of memory in this example.

Run from the repository root:

```sh
lab_config_dir=$(mktemp -d)
KUBECONFIG="$lab_config_dir/config" minikube start -p tunnelscope-lab \
  --driver=docker --nodes=2 --cni=calico --cpus=2 --memory=2048 \
  --kubernetes-version=v1.35.1 --keep-context
kubectl --kubeconfig "$lab_config_dir/config" --context tunnelscope-lab \
  wait nodes --all --for=condition=Ready --timeout=180s
kubectl --kubeconfig "$lab_config_dir/config" --context tunnelscope-lab \
  -n kube-system rollout status daemonset/calico-node --timeout=180s

docker build -t tunnelscope-k8s-test:0.6.0 labs/kubernetes
KUBECONFIG="$lab_config_dir/config" minikube image load \
  -p tunnelscope-lab tunnelscope-k8s-test:0.6.0

python3 labs/kubernetes_pods.py \
  --kubeconfig "$lab_config_dir/config" --context tunnelscope-lab \
  --nodes tunnelscope-lab tunnelscope-lab-m02 \
  --image tunnelscope-k8s-test:0.6.0 --output-dir output/kubernetes-lab
```

Use a fresh Minikube profile name if that name already exists. The explicit
temporary kubeconfig keeps the test separate from the user's current context.
For an existing controlled cluster, preload the image on both selected nodes
and supply its kubeconfig, context and node names to the same script.

## What the script checks

- Both nodes are Ready and the pods run on distinct nodes with IPv4 addresses.
  Pods run as UID 10001, with all Linux capabilities dropped, a read-only root
  filesystem and a writable temporary report volume.
- An ingress policy for each pod admits UDP port 9471 from the lab peers.
  The observed ACKs verify return delivery in this configuration. No Service
  or external receiver endpoint is created.
- Both directions use the same bounded payload sizes, with two attempts per
  size. The sizes are 64, 1200 and 1400 when the pod interfaces permit them;
  the script reduces them if needed for a smaller local interface MTU.
- `diagnose` tests sizes around the smaller reported pod-interface MTU after
  IPv4/UDP headers. The joined reports retain per-run evidence and uncertainty.
- Sender and receiver reports are correlated, and the two direction reports
  are combined with a reversed endpoint check.
- One pod's ingress policy is changed to admit no traffic. Two small probes
  must time out with no receiver observations. Restoring the policy must
  restore delivery. The script waits two seconds after policy changes; a CNI
  that has not converged or does not enforce policies will fail the check.

The output directory must be empty or absent. It receives raw pod metadata,
versions, sender and receiver JSON, joined JSON/HTML, the bidirectional report
and `summary.json`. These files contain temporary pod addresses and remain in
the Git-ignored `output/` directory. A missing receiver observation remains
inconclusive without independently verified capture coverage.

## Cleanup and scope

The script deletes its own namespace. After collecting reports, remove the
dedicated local cluster and temporary kubeconfig:

```sh
KUBECONFIG="$lab_config_dir/config" minikube delete -p tunnelscope-lab
rm -f "$lab_config_dir/config"
rmdir "$lab_config_dir"
```

Docker-driver Minikube nodes share a physical host and kernel. This test checks
an actual Kubernetes/CNI pod path on distinct logical nodes; physical host
links, cloud networking, Services, Ingress controllers and other CNI modes need
separate validation. A local pod-interface boundary is kernel evidence and
does not establish an arbitrary end-to-end path MTU.

"""Validate IPv4 pod delivery, joined reports and scoped NetworkPolicy behavior.

Use an explicitly selected test cluster with a policy-enforcing CNI and two
nodes. The image must contain TunnelScope v0.6.0 and iproute2. Only a newly
created namespace is changed; it is deleted on completion or failure.
"""

import argparse
import ipaddress
import json
from pathlib import Path
from queue import Empty, Queue
import shutil
import subprocess
import sys
from threading import Thread
import time
import uuid


ROOT = Path(__file__).resolve().parents[1]


class Cluster:
    def __init__(self, kubeconfig, context):
        self.base = ["kubectl", "--kubeconfig", str(kubeconfig), "--context", context]

    def run(self, *args, document=None, timeout=60):
        return subprocess.run(self.base + list(args),
                              input=json.dumps(document) if document is not None else None,
                              check=True, capture_output=True, text=True, timeout=timeout)

    def json(self, *args):
        return json.loads(self.run(*args, "-o", "json").stdout)

    def exec_command(self, namespace, pod, *args):
        return self.base + ["-n", namespace, "exec", pod, "-c", "tunnelscope", "--", *args]


def pod(name, node, image, namespace, run_id):
    return {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "namespace": namespace,
                         "labels": {"app": "tunnelscope-lab", "run": run_id, "role": name}},
            "spec": {"nodeName": node, "restartPolicy": "Never",
                     "automountServiceAccountToken": False,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 10001,
                                         "runAsGroup": 10001, "fsGroup": 10001,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [{"name": "tunnelscope", "image": image,
                         "imagePullPolicy": "Never",
                         "securityContext": {"allowPrivilegeEscalation": False,
                                             "readOnlyRootFilesystem": True,
                                             "capabilities": {"drop": ["ALL"]}},
                         "resources": {"requests": {"cpu": "50m", "memory": "32Mi"},
                                       "limits": {"cpu": "500m", "memory": "128Mi"}},
                         "readinessProbe": {"exec": {"command": ["tunnelscope", "--version"]},
                                            "periodSeconds": 2},
                         "volumeMounts": [{"name": "reports", "mountPath": "/tmp"}]}],
                     "volumes": [{"name": "reports", "emptyDir": {}}]}}


def policy(role, namespace, run_id, allow=True):
    selector = {"app": "tunnelscope-lab", "run": run_id}
    return {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": f"ingress-{role}", "namespace": namespace},
            "spec": {"podSelector": {"matchLabels": {**selector, "role": role}},
                     "policyTypes": ["Ingress"],
                     "ingress": [{"from": [{"podSelector": {"matchLabels": selector}}],
                                  "ports": [{"protocol": "UDP", "port": 9471}]}] if allow else []}}


def collect(cluster, namespace, pod_name, remote, local):
    result = subprocess.run(cluster.exec_command(namespace, pod_name, "cat", remote),
                            check=True, capture_output=True, text=True, timeout=15)
    local.write_text(result.stdout, encoding="utf-8")
    return json.loads(result.stdout)


def measure(cluster, namespace, pods, output, label, sender, target, sizes,
            count=1, diagnosis=False, blocked=False, bounds=None):
    target_ip = pods[target]["status"]["podIP"]
    receiver_name, sender_name = f"{label}-receiver.json", f"{label}-sender.json"
    command = cluster.exec_command(namespace, target, "tunnelscope", "receive",
        "--bind", target_ip, "--max-packets", str(100 if diagnosis or blocked else len(sizes) * count),
        "--idle-timeout", "8", "--output", f"/tmp/{receiver_name}")
    receiver = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    greeting = Queue()
    Thread(target=lambda: greeting.put(receiver.stdout.readline()), daemon=True).start()
    try:
        try:
            started = greeting.get(timeout=10)
        except Empty as error:
            raise RuntimeError(f"Receiver startup timed out for {label}") from error
        if not started.startswith("Listening on"):
            raise RuntimeError(f"Receiver did not start for {label}")
        if diagnosis:
            args = ["diagnose", target_ip, "--min", str(bounds[0]), "--max", str(bounds[1]),
                    "--count", "1", "--max-sizes", "8", "--timeout", "1"]
        else:
            args = ["probe", target_ip, "--sizes", ",".join(map(str, sizes)),
                    "--count", str(count), "--timeout", "1", "--dont-fragment", "--observe-icmp"]
        subprocess.run(cluster.exec_command(namespace, sender, "tunnelscope", *args,
                            "--output", f"/tmp/{sender_name}"), check=True,
                       capture_output=True, text=True, timeout=45)
        receiver.wait(timeout=12)
        if receiver.returncode:
            raise RuntimeError(f"Receiver failed for {label}: {receiver.stderr.read()}")
    finally:
        if receiver.poll() is None:
            receiver.kill()
        receiver.communicate(timeout=5)
    sender_path, receiver_path = output / sender_name, output / receiver_name
    report = collect(cluster, namespace, sender, f"/tmp/{sender_name}", sender_path)
    collect(cluster, namespace, target, f"/tmp/{receiver_name}", receiver_path)
    joined_path = output / f"{label}-joined.json"
    subprocess.run([sys.executable, str(ROOT / "tunnelscope.py"), "correlate",
                    str(sender_path), str(receiver_path), "--output", str(joined_path),
                    "--html", str(output / f"{label}-joined.html")],
                   check=True, capture_output=True, text=True, timeout=15)
    joined = json.loads(joined_path.read_text(encoding="utf-8"))
    if diagnosis:
        summary = joined["receiver_evidence"]["summary"]
        if summary["unassigned_receiver_observations"] or summary["unmatched_receiver_observations"]:
            raise RuntimeError(f"Unmatched diagnosis observations for {label}")
        runs = report["runs"]
        attempts = [row for probe_run in (runs["fragmentation_comparison"]["runs"]["df"],
                                         runs["fragmentation_comparison"]["runs"]["fragmentation_permitted"],
                                         runs["size_search"]) for row in probe_run["results"]]
        acknowledgements = sum(row["status"] == "acknowledged" for row in attempts)
        if not acknowledgements or summary["receiver_observed"] != acknowledgements:
            raise RuntimeError(f"Diagnosis receiver capture did not cover acknowledgements for {label}")
        return {"label": label, "search": report["summary"]["search"],
                "receiver_observed": summary["receiver_observed"], "attempts": summary["sent_probes"]}
    statuses = [row["status"] for row in report["results"]]
    expected = "timeout" if blocked else "acknowledged"
    if statuses != [expected] * (len(sizes) * count):
        raise RuntimeError(f"Unexpected {label} statuses: {statuses}")
    expected_seen = 0 if blocked else len(sizes) * count
    if joined["summary"]["receiver_observed"] != expected_seen:
        raise RuntimeError(f"Unexpected receiver observations for {label}")
    if joined["pairing"]["endpoint_checks"]["target_ipv4_matches_receiver_bind"] is not True:
        raise RuntimeError(f"Pod endpoint mismatch for {label}")
    return {"label": label, "sizes": sizes, "count_per_size": count,
            "statuses": statuses, "receiver_observed": expected_seen,
            "run_id_check": joined["pairing"]["run_id_check"],
            "source_interface": report.get("source", {}).get("interface"),
            "interface_mtu_bytes": report.get("source", {}).get("interface_mtu_bytes"),
            "kernel_route_mtu_bytes": report.get("source", {}).get("kernel_route_mtu_bytes")}


def main(args):
    if not shutil.which("kubectl"):
        raise RuntimeError("kubectl is required")
    if len(set(args.nodes)) != 2:
        raise RuntimeError("Select two distinct test nodes")
    output = args.output_dir.resolve()
    if output.exists() and any(output.iterdir()):
        raise RuntimeError("Output directory must be empty or absent")
    output.mkdir(parents=True, exist_ok=True)
    cluster = Cluster(args.kubeconfig.resolve(), args.context)
    for node in args.nodes:
        obj = cluster.json("get", "node", node)
        if not any(row["type"] == "Ready" and row["status"] == "True" for row in obj["status"]["conditions"]):
            raise RuntimeError(f"Test node is not Ready: {node}")
    run_id = uuid.uuid4().hex[:10]
    namespace = "tunnelscope-" + run_id
    created = False
    summary = {"lab": "kubernetes-cross-node-ipv4", "image": args.image, "measurements": []}
    try:
        cluster.run("create", "-f", "-", document={"apiVersion": "v1", "kind": "Namespace",
                    "metadata": {"name": namespace, "labels": {"app.kubernetes.io/managed-by": "tunnelscope-lab"}}})
        created = True
        objects = [pod(role, node, args.image, namespace, run_id)
                   for role, node in zip(("a", "b"), args.nodes)]
        objects += [policy(role, namespace, run_id) for role in ("a", "b")]
        cluster.run("create", "-f", "-", document={"apiVersion": "v1", "kind": "List", "items": objects})
        cluster.run("-n", namespace, "wait", "pod", "--all", "--for=condition=Ready", "--timeout=180s", timeout=190)
        pods = {role: cluster.json("-n", namespace, "get", "pod", role) for role in ("a", "b")}
        if pods["a"]["spec"]["nodeName"] == pods["b"]["spec"]["nodeName"]:
            raise RuntimeError("Pods were not placed on distinct nodes")
        mtus, versions = {}, {}
        for role in ("a", "b"):
            if ipaddress.ip_address(pods[role]["status"]["podIP"]).version != 4:
                raise RuntimeError("This lab currently covers IPv4 pod addresses")
            links = json.loads(subprocess.run(cluster.exec_command(namespace, role, "ip", "-j", "link", "show", "eth0"),
                                            check=True, capture_output=True, text=True, timeout=15).stdout)
            mtus[role] = links[0]["mtu"]
            versions[role] = subprocess.run(cluster.exec_command(namespace, role, "python", "-c",
                 "import platform,importlib.metadata; print(platform.python_version(),importlib.metadata.version('tunnelscope'))"),
                 check=True, capture_output=True, text=True, timeout=15).stdout.strip()
            if versions[role].split()[-1] != "0.6.0":
                raise RuntimeError("Use the validated TunnelScope v0.6.0 test image")
        environment = {"kubernetes": cluster.json("version"), "pods": pods, "pod_mtu_bytes": mtus,
                       "versions": versions, "daemonsets": cluster.json("-n", "kube-system", "get", "daemonsets")}
        (output / "environment.json").write_text(json.dumps(environment, indent=2) + "\n", encoding="utf-8")
        ceiling = min(mtus.values()) - 28
        if not 32 <= ceiling - 4 < ceiling + 4 <= 8192:
            raise RuntimeError("Pod interface MTU is outside this lab's bounded payload range")
        sizes = list(dict.fromkeys((64, min(1200, ceiling), min(1400, ceiling))))
        summary.update(pod_mtu_bytes=mtus, versions=versions,
                       kubernetes_version=environment["kubernetes"]["serverVersion"]["gitVersion"])
        time.sleep(2)  # Give the CNI time to install the initial scoped policies.
        for sender, target in (("a", "b"), ("b", "a")):
            label = f"{sender}-to-{target}"
            result = measure(cluster, namespace, pods, output, label, sender, target, sizes, count=2)
            summary["measurements"].append(result)
            print(json.dumps(result), flush=True)
            result = measure(cluster, namespace, pods, output, label + "-diagnosis", sender, target,
                             sizes, diagnosis=True, bounds=(ceiling - 4, ceiling + 4))
            summary["measurements"].append(result)
            print(json.dumps(result), flush=True)
        combined_path = output / "bidirectional.json"
        subprocess.run([sys.executable, str(ROOT / "tunnelscope.py"), "combine",
                        str(output / "a-to-b-sender.json"), str(output / "b-to-a-sender.json"),
                        "--output", str(combined_path)], check=True, capture_output=True, text=True, timeout=15)
        summary["endpoint_check"] = json.loads(combined_path.read_text(encoding="utf-8"))["endpoint_check"]
        if summary["endpoint_check"] != "reversed_ipv4_match":
            raise RuntimeError("Bidirectional pod endpoints did not reverse-match")
        cluster.run("-n", namespace, "patch", "networkpolicy", "ingress-b", "--type=merge",
                    "-p", json.dumps({"spec": {"ingress": []}}))
        time.sleep(2)
        result = measure(cluster, namespace, pods, output, "policy-blocked", "a", "b", [64], count=2, blocked=True)
        summary["measurements"].append(result)
        print(json.dumps(result), flush=True)
        cluster.run("-n", namespace, "patch", "networkpolicy", "ingress-b", "--type=merge",
                    "-p", json.dumps({"spec": {"ingress": policy("b", namespace, run_id)["spec"]["ingress"]}}))
        time.sleep(2)
        result = measure(cluster, namespace, pods, output, "policy-restored", "a", "b", sizes)
        summary["measurements"].append(result)
        print(json.dumps(result), flush=True)
    finally:
        if created:
            cluster.run("delete", "namespace", namespace, "--wait=true", "--timeout=60s", timeout=70)
    summary["namespace_deleted"] = True
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubeconfig", type=Path, required=True)
    parser.add_argument("--context", required=True)
    parser.add_argument("--nodes", nargs=2, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        main(args)
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        print(f"Kubernetes lab failed: {error}", file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError) and error.stderr:
            print(error.stderr, file=sys.stderr)
        sys.exit(1)

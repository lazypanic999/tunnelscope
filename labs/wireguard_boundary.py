"""Exercise TunnelScope across a real WireGuard tunnel in Linux namespaces.

Run as root on Linux with iproute2 and wireguard-tools. The lab creates two
disposable namespaces and never changes the host's routes or firewall.
This is a single-kernel lab, not an independent-host or production VPN test.
"""

import argparse
import json
import os
from pathlib import Path
import selectors
import shutil
import subprocess
import sys
import tempfile
import uuid


SCRIPT = str(Path(__file__).resolve().parents[1] / "tunnelscope.py")


def run(*command, input_text=None, timeout=20):
    return subprocess.run(command, input=input_text, check=True, capture_output=True,
                          text=True, timeout=timeout)


def ip(*args):
    return run("ip", *args)


def start_receiver(namespace, address, output=None, max_packets=None):
    command = ["ip", "netns", "exec", namespace, sys.executable, "-u", SCRIPT,
               "receive", "--bind", address, "--idle-timeout", "10"]
    if output:
        command += ["--output", str(output)]
    if max_packets:
        command += ["--max-packets", str(max_packets)]
    process = subprocess.Popen(command, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        if not selector.select(timeout=5) or not process.stdout.readline().startswith("Listening on"):
            process.kill()
            raise RuntimeError("Receiver did not start")
    return process


def stop_receiver(process):
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)
    process.stdout.close()
    process.stderr.close()


def main(output_dir):
    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        raise RuntimeError("Linux root is required")
    if not all(shutil.which(tool) for tool in ("ip", "wg", "ping")):
        raise RuntimeError("iproute2, wireguard-tools and ping are required")
    if output_dir.exists() and any(output_dir.iterdir()):
        raise RuntimeError("Output directory must be empty or absent")
    output_dir.mkdir(parents=True, exist_ok=True)
    suffix = uuid.uuid4().hex[:8]
    left, right = f"tswg-{suffix}-a", f"tswg-{suffix}-b"
    created = []
    with tempfile.TemporaryDirectory(prefix="tswg-keys-") as key_dir:
        try:
            for namespace in (left, right):
                ip("netns", "add", namespace)
                created.append(namespace)
            ip("-n", left, "link", "add", "under-a", "type", "veth", "peer", "name", "under-b")
            ip("-n", left, "link", "set", "under-b", "netns", right)
            peers = [
                (left, "under-a", "192.0.2.1/30", "198.51.100.1/30", 51820),
                (right, "under-b", "192.0.2.2/30", "198.51.100.2/30", 51821),
            ]
            public = {}
            private = {}
            for namespace, interface, underlay, overlay, _ in peers:
                ip("-n", namespace, "link", "set", "lo", "up")
                ip("-n", namespace, "addr", "add", underlay, "dev", interface)
                ip("-n", namespace, "link", "set", interface, "mtu", "1500", "up")
                ip("-n", namespace, "link", "add", "wg0", "type", "wireguard")
                ip("-n", namespace, "addr", "add", overlay, "dev", "wg0")
                ip("-n", namespace, "link", "set", "wg0", "mtu", "1280", "up")
                secret = run("wg", "genkey").stdout.strip()
                key_file = Path(key_dir) / namespace
                key_file.write_text(secret + "\n", encoding="ascii")
                key_file.chmod(0o600)
                private[namespace] = key_file
                public[namespace] = run("wg", "pubkey", input_text=secret + "\n").stdout.strip()
            for namespace, _, _, _, port in peers:
                other = peers[1] if namespace == left else peers[0]
                ip("netns", "exec", namespace, "wg", "set", "wg0", "private-key",
                   str(private[namespace]), "listen-port", str(port), "peer",
                   public[other[0]], "allowed-ips", other[3].split("/")[0] + "/32",
                   "endpoint", other[2].split("/")[0] + ":" + str(other[4]))
            ip("netns", "exec", left, "ping", "-c", "1", "-W", "3", "198.51.100.2")
            summary = {"lab": "wireguard-single-kernel-two-namespace",
                       "underlay_mtu_bytes": 1500, "tunnel_mtu_bytes": 1280,
                       "directions": []}
            for label, source, target, target_ip in (
                ("a-to-b", left, right, "198.51.100.2"),
                ("b-to-a", right, left, "198.51.100.1"),
            ):
                sender_path = output_dir / f"{label}-sender.json"
                receiver_path = output_dir / f"{label}-receiver.json"
                correlation_path = output_dir / f"{label}-correlation.json"
                receiver = start_receiver(target, target_ip, receiver_path, max_packets=2)
                try:
                    ip("netns", "exec", source, sys.executable, SCRIPT, "probe", target_ip,
                       "--sizes", "64,1252,1253,1400", "--count", "1",
                       "--dont-fragment", "--observe-icmp", "--output", str(sender_path))
                    receiver.wait(timeout=5)
                finally:
                    stop_receiver(receiver)
                sender = json.loads(sender_path.read_text(encoding="utf-8"))
                statuses = [row["status"] for row in sender["results"]]
                if statuses != ["acknowledged", "acknowledged", "packet_too_large", "packet_too_large"]:
                    raise RuntimeError(f"Unexpected {label} probe statuses: {statuses}")
                run(sys.executable, SCRIPT, "correlate", str(sender_path),
                    str(receiver_path), "--output", str(correlation_path))
                correlation = json.loads(correlation_path.read_text(encoding="utf-8"))
                if correlation["summary"]["receiver_observed"] != 2:
                    raise RuntimeError(f"Unexpected {label} receiver coverage")
                diagnosis_path = output_dir / f"{label}-diagnosis.json"
                diagnosis_receiver_path = output_dir / f"{label}-diagnosis-receiver.json"
                receiver = start_receiver(target, target_ip, diagnosis_receiver_path,
                                          max_packets=4)
                try:
                    ip("netns", "exec", source, sys.executable, SCRIPT, "diagnose", target_ip,
                       "--min", "1252", "--max", "1253", "--count", "1",
                       "--max-sizes", "2", "--output", str(diagnosis_path))
                    receiver.wait(timeout=5)
                finally:
                    stop_receiver(receiver)
                diagnosis = json.loads(diagnosis_path.read_text(encoding="utf-8"))
                observed = diagnosis["summary"]["search"]["observed_interval_payload_bytes"]
                if observed != [1252, 1253] or not diagnosis_path.with_suffix(".html").is_file():
                    raise RuntimeError(f"Unexpected {label} diagnosis interval or missing HTML")
                joined_path = output_dir / f"{label}-joined.json"
                joined_html_path = output_dir / f"{label}-joined.html"
                run(sys.executable, SCRIPT, "correlate", str(diagnosis_path),
                    str(diagnosis_receiver_path), "--output", str(joined_path),
                    "--html", str(joined_html_path))
                joined = json.loads(joined_path.read_text(encoding="utf-8"))
                joined_summary = joined["receiver_evidence"]["summary"]
                if joined_summary["receiver_observed"] != 4 or not joined_html_path.is_file():
                    raise RuntimeError(f"Unexpected {label} joined receiver evidence")
                summary["directions"].append({"direction": label, "probe_statuses": statuses,
                    "receiver_observed": 2, "diagnosis_receiver_observed": 4,
                    "observed_interval_payload_bytes": observed})
            (output_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
            print(json.dumps(summary, indent=2))
        finally:
            for namespace in reversed(created):
                ip("netns", "delete", namespace)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        main(args.output_dir)
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        print(f"WireGuard lab failed: {error}", file=sys.stderr)
        sys.exit(1)

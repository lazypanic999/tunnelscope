"""Validate an IPv4 UDP payload boundary across an isolated VXLAN overlay."""

import json
import os
from pathlib import Path
import selectors
import shutil
import subprocess
import sys
import tempfile
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import tunnelscope


def ip(*args):
    return subprocess.run(["ip", *args], check=True, capture_output=True, text=True, timeout=10)


def main():
    if not sys.platform.startswith("linux") or os.geteuid() != 0 or not shutil.which("ip"):
        raise RuntimeError("This lab requires root on Linux and the iproute2 'ip' command")
    suffix = uuid.uuid4().hex[:10]
    left, right = f"ts-vx-{suffix}-a", f"ts-vx-{suffix}-b"
    created = []
    script = str(Path(tunnelscope.__file__).resolve())
    report = {"lab": "vxlan-overlay-ipv4-df", "underlay_mtu_bytes": 1500,
              "overlay_mtu_bytes": 1450, "expected_payload_boundary_bytes": 1422,
              "directions": []}
    try:
        for namespace in (left, right):
            ip("netns", "add", namespace)
            created.append(namespace)
        ip("-n", left, "link", "add", "ts-under-a", "type", "veth", "peer", "name", "ts-under-b")
        ip("-n", left, "link", "set", "ts-under-b", "netns", right)
        for namespace, underlay, local, remote, overlay in (
            (left, "ts-under-a", "192.0.2.1", "192.0.2.2", "198.51.100.1"),
            (right, "ts-under-b", "192.0.2.2", "192.0.2.1", "198.51.100.2"),
        ):
            ip("-n", namespace, "link", "set", "lo", "up")
            ip("-n", namespace, "addr", "add", local + "/30", "dev", underlay)
            ip("-n", namespace, "link", "set", underlay, "mtu", "1500", "up")
            ip("-n", namespace, "link", "add", "ts-vx", "type", "vxlan", "id", "42",
               "local", local, "remote", remote, "dev", underlay, "dstport", "4789", "nolearning")
            ip("-n", namespace, "addr", "add", overlay + "/24", "dev", "ts-vx")
            ip("-n", namespace, "link", "set", "ts-vx", "mtu", "1450", "up")
        with tempfile.TemporaryDirectory() as directory:
            for label, source, target, target_ip in (
                ("a-to-b", left, right, "198.51.100.2"),
                ("b-to-a", right, left, "198.51.100.1"),
            ):
                receiver_path = Path(directory) / f"{label}-receiver.json"
                receiver = subprocess.Popen(
                    ["ip", "netns", "exec", target, sys.executable, "-u", script,
                     "receive", "--bind", target_ip, "--max-packets", "5",
                     "--idle-timeout", "10", "--output", str(receiver_path)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )
                try:
                    with selectors.DefaultSelector() as ready:
                        ready.register(receiver.stdout, selectors.EVENT_READ)
                        if not ready.select(timeout=5):
                            raise RuntimeError("VXLAN receiver startup timed out")
                    if not receiver.stdout.readline().startswith("Listening on"):
                        raise RuntimeError("VXLAN receiver did not start")
                    sent = subprocess.run(
                        ["ip", "netns", "exec", source, sys.executable, script,
                         "probe", target_ip, "--sweep", "1418:1426:1",
                         "--count", "1", "--timeout", "2", "--dont-fragment"],
                        check=True, capture_output=True, text=True, timeout=25,
                    )
                    probe = json.loads(sent.stdout)
                    if receiver.wait(timeout=12) != 0:
                        raise RuntimeError("VXLAN receiver failed")
                    observed = json.loads(receiver_path.read_text(encoding="utf-8"))
                    correlation = tunnelscope.correlate_reports(probe, observed)
                    expected = ["acknowledged"] * 5 + ["packet_too_large"] * 4
                    if [row["status"] for row in probe["results"]] != expected:
                        raise RuntimeError(f"Unexpected VXLAN boundary: {probe}")
                    if probe["source"].get("interface_mtu_bytes") != 1450:
                        raise RuntimeError(f"Unexpected VXLAN source interface: {probe['source']}")
                    if correlation["summary"]["receiver_observed"] != 5:
                        raise RuntimeError("Unexpected VXLAN receiver observation count")
                    report["directions"].append({"direction": label, "probe": probe,
                                                  "receiver": observed, "correlation": correlation})
                finally:
                    if receiver.poll() is None:
                        receiver.terminate()
                    try:
                        receiver.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        receiver.kill()
                        receiver.wait(timeout=3)
                    receiver.stdout.close()
                    receiver.stderr.close()
    finally:
        for namespace in reversed(created):
            ip("netns", "delete", namespace)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        print(f"Lab failed: {error}", file=sys.stderr)
        sys.exit(1)

"""Validate an IPv6 no-fragment payload boundary on an isolated 1280-byte link."""

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
    left, right = f"ts6-{suffix}-a", f"ts6-{suffix}-b"
    created = []
    script = str(Path(tunnelscope.__file__).resolve())
    report = {"lab": "direct-veth-ipv6-no-fragment", "link_mtu_bytes": 1280,
              "ipv6_header_bytes": 40, "udp_header_bytes": 8,
              "expected_payload_boundary_bytes": 1232, "directions": []}
    try:
        for namespace in (left, right):
            ip("netns", "add", namespace)
            created.append(namespace)
        ip("-n", left, "link", "add", "ts6-a", "type", "veth", "peer", "name", "ts6-b")
        ip("-n", left, "link", "set", "ts6-b", "netns", right)
        for namespace, interface, address in ((left, "ts6-a", "fd00:5453::1/64"),
                                              (right, "ts6-b", "fd00:5453::2/64")):
            ip("-n", namespace, "link", "set", "lo", "up")
            ip("-n", namespace, "link", "set", interface, "mtu", "1280", "up")
            ip("-n", namespace, "-6", "addr", "add", address, "dev", interface, "nodad")
        with tempfile.TemporaryDirectory() as directory:
            for label, source, target, target_ip in (
                ("a-to-b", left, right, "fd00:5453::2"),
                ("b-to-a", right, left, "fd00:5453::1"),
            ):
                receiver_path = Path(directory) / f"{label}-receiver.json"
                receiver = subprocess.Popen(
                    ["ip", "netns", "exec", target, sys.executable, "-u", script,
                     "receive", "--bind", target_ip, "--max-packets", "7",
                     "--idle-timeout", "10", "--output", str(receiver_path)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )
                try:
                    with selectors.DefaultSelector() as ready:
                        ready.register(receiver.stdout, selectors.EVENT_READ)
                        if not ready.select(timeout=5):
                            raise RuntimeError("IPv6 receiver startup timed out")
                    if not receiver.stdout.readline().startswith("Listening on"):
                        raise RuntimeError("IPv6 receiver did not start")
                    sent = subprocess.run(
                        ["ip", "netns", "exec", source, sys.executable, script,
                         "probe", target_ip, "--sweep", "1228:1236:1",
                         "--count", "1", "--timeout", "2", "--dont-fragment"],
                        check=True, capture_output=True, text=True, timeout=25,
                    )
                    probe = json.loads(sent.stdout)
                    search_run = subprocess.run(
                        ["ip", "netns", "exec", source, sys.executable, script,
                         "search", target_ip, "--min", "1228", "--max", "1236",
                         "--count", "1", "--timeout", "2"],
                        check=True, capture_output=True, text=True, timeout=20,
                    )
                    search = json.loads(search_run.stdout)
                    search_evidence = search["summary"]["search"]
                    if search_evidence["assessment"] != "adjacent_observed_bounds" or search_evidence["observed_interval_payload_bytes"] != [1232, 1233]:
                        raise RuntimeError(f"Unexpected IPv6 search interval: {search_evidence}")
                    if receiver.wait(timeout=12) != 0:
                        raise RuntimeError("IPv6 receiver failed")
                    observed = json.loads(receiver_path.read_text(encoding="utf-8"))
                    correlation = tunnelscope.correlate_reports(probe, observed)
                    expected = ["acknowledged"] * 5 + ["packet_too_large"] * 4
                    if [row["status"] for row in probe["results"]] != expected:
                        raise RuntimeError(f"Unexpected IPv6 boundary: {probe}")
                    if probe["source"].get("interface_mtu_bytes") != 1280:
                        raise RuntimeError(f"Unexpected IPv6 source interface: {probe['source']}")
                    if correlation["summary"]["receiver_observed"] != 5:
                        raise RuntimeError("Unexpected IPv6 receiver observation count")
                    search_correlation = tunnelscope.correlate_reports(search, observed)
                    if search_correlation["summary"]["receiver_observed"] != 2:
                        raise RuntimeError("Unexpected IPv6 search receiver observation count")
                    report["directions"].append({"direction": label, "probe": probe,
                                                  "search": search, "receiver": observed,
                                                  "correlation": correlation,
                                                  "search_correlation": search_correlation})
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

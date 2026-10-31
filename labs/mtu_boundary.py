"""Reproduce an IPv4 DF boundary on an isolated 1280-byte veth link.

Run as root on Linux with iproute2 installed. No host MTU or route is changed.
Namespaces created by this process are removed in finally, including on Ctrl+C.
"""

import json
import os
from pathlib import Path
import selectors
import shutil
import subprocess
import sys
import tempfile
import uuid


def ip(*args):
    return subprocess.run(["ip", *args], check=True, capture_output=True, text=True, timeout=10)


def main():
    if not sys.platform.startswith("linux") or os.geteuid() != 0 or not shutil.which("ip"):
        raise RuntimeError("This lab requires root on Linux and the iproute2 'ip' command")
    suffix = uuid.uuid4().hex[:10]
    left, right = f"ts-{suffix}-a", f"ts-{suffix}-b"
    created = []
    script = str(Path(__file__).resolve().parents[1] / "tunnelscope.py")
    report = {"lab": "direct-veth-ipv4-df", "link_mtu_bytes": 1280, "ipv4_header_bytes": 20, "udp_header_bytes": 8, "expected_payload_boundary_bytes": 1252, "directions": []}
    try:
        for namespace in [left, right]:
            ip("netns", "add", namespace)
            created.append(namespace)
        ip("-n", left, "link", "add", "ts-a", "type", "veth", "peer", "name", "ts-b")
        ip("-n", left, "link", "set", "ts-b", "netns", right)
        for namespace, interface, address in [(left, "ts-a", "192.0.2.1/30"), (right, "ts-b", "192.0.2.2/30")]:
            ip("-n", namespace, "link", "set", "lo", "up")
            ip("-n", namespace, "addr", "add", address, "dev", interface)
            ip("-n", namespace, "link", "set", interface, "mtu", "1280", "up")
        for label, source, target, target_ip in [("a-to-b", left, right, "192.0.2.2"), ("b-to-a", right, left, "192.0.2.1")]:
            receiver = subprocess.Popen(["ip", "netns", "exec", target, sys.executable, "-u", script, "receive", "--bind", target_ip, "--idle-timeout", "10"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                with selectors.DefaultSelector() as ready:
                    ready.register(receiver.stdout, selectors.EVENT_READ)
                    if not ready.select(timeout=5):
                        raise RuntimeError("Receiver startup timed out")
                greeting = receiver.stdout.readline()
                if not greeting.startswith("Listening on"):
                    raise RuntimeError("Receiver did not start")
                result = subprocess.run(["ip", "netns", "exec", source, sys.executable, script, "probe", target_ip, "--sizes", "64,1252,1253,1400", "--count", "1", "--dont-fragment", "--observe-icmp"], check=True, capture_output=True, text=True, timeout=15)
                direction = json.loads(result.stdout)
                direction["direction"] = label
                expected = ["acknowledged", "acknowledged", "packet_too_large", "packet_too_large"]
                if [r["status"] for r in direction["results"]] != expected:
                    raise RuntimeError(f"Unexpected boundary result: {direction}")
                for row in direction["results"][2:]:
                    if row.get("kernel_reported_mtu_bytes") != 1280:
                        raise RuntimeError(f"Expected kernel MTU 1280: {row}")
                sweep_result = subprocess.run(
                    ["ip", "netns", "exec", source, sys.executable, script, "probe", target_ip,
                     "--sweep", "1200:1300:25", "--count", "1", "--dont-fragment"],
                    check=True, capture_output=True, text=True, timeout=15,
                )
                sweep = json.loads(sweep_result.stdout)
                expected_sweep = ["acknowledged"] * 3 + ["packet_too_large"] * 2
                if [row["status"] for row in sweep["results"]] != expected_sweep:
                    raise RuntimeError(f"Unexpected sweep result: {sweep}")
                direction["sweep"] = sweep
                search_result = subprocess.run(
                    ["ip", "netns", "exec", source, sys.executable, script, "search", target_ip,
                     "--min", "1200", "--max", "1300", "--count", "1"],
                    check=True, capture_output=True, text=True, timeout=15,
                )
                search = json.loads(search_result.stdout)
                evidence = search["summary"]["search"]
                if evidence["assessment"] != "adjacent_observed_bounds" or evidence["observed_interval_payload_bytes"] != [1252, 1253]:
                    raise RuntimeError(f"Unexpected search interval: {evidence}")
                direction["search"] = search
                compare_result = subprocess.run(
                    ["ip", "netns", "exec", source, sys.executable, script,
                     "compare-fragmentation", target_ip, "--sizes", "1252,1253,1400",
                     "--count", "2"],
                    check=True, capture_output=True, text=True, timeout=15,
                )
                comparison = json.loads(compare_result.stdout)
                df_statuses = [row["status"] for row in comparison["runs"]["df"]["results"]]
                allowed_statuses = [row["status"] for row in comparison["runs"]["fragmentation_permitted"]["results"]]
                if df_statuses != ["acknowledged"] * 2 + ["packet_too_large"] * 4 or allowed_statuses != ["acknowledged"] * 6:
                    raise RuntimeError(f"Unexpected fragmentation comparison: {comparison}")
                direction["fragmentation_comparison"] = comparison
                with tempfile.TemporaryDirectory() as report_dir:
                    output = Path(report_dir) / "diagnosis.json"
                    diagnosed = subprocess.run(
                        ["ip", "netns", "exec", source, sys.executable, script, "diagnose", target_ip,
                         "--min", "1252", "--max", "1253", "--max-sizes", "2", "--count", "1",
                         "--output", str(output)],
                        check=True, capture_output=True, text=True, timeout=15,
                    )
                    diagnosis = json.loads(output.read_text(encoding="utf-8"))
                    if diagnosis["summary"]["search"]["assessment"] != "adjacent_observed_bounds":
                        raise RuntimeError(f"Unexpected diagnosis: {diagnosis}")
                    if diagnosis["summary"]["search"]["observed_interval_payload_bytes"] != [1252, 1253]:
                        raise RuntimeError(f"Unexpected diagnosis interval: {diagnosis}")
                    if not output.with_suffix(".html").is_file() or "single sender direction" not in diagnosed.stdout.lower():
                        raise RuntimeError("Diagnosis outputs missing")
                    direction["diagnosis"] = diagnosis
                report["directions"].append(direction)
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

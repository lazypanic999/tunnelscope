"""Reproduce inconclusive large-packet timeouts behind blocked PMTU feedback.

Run as root on Linux with iproute2 and iptables. All links, forwarding settings
and firewall rules are confined to temporary network namespaces.
"""

import json
import os
from pathlib import Path
import re
import selectors
import shutil
import subprocess
import sys
import uuid


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=10)


def ip(*args):
    return run("ip", *args)


def main():
    if not sys.platform.startswith("linux") or os.geteuid() != 0 or any(not shutil.which(tool) for tool in ("ip", "iptables", "sysctl")):
        raise RuntimeError("This lab requires root on Linux, iproute2, iptables and sysctl")

    suffix = uuid.uuid4().hex[:10]
    sender, router, receiver_ns = (f"ts-{suffix}-{role}" for role in ("s", "r", "d"))
    created = []
    script = str(Path(__file__).resolve().parents[1] / "tunnelscope.py")
    receiver = None
    try:
        for namespace in (sender, router, receiver_ns):
            ip("netns", "add", namespace)
            created.append(namespace)
        ip("-n", sender, "link", "add", "ts-s", "type", "veth", "peer", "name", "ts-r1")
        ip("-n", sender, "link", "set", "ts-r1", "netns", router)
        ip("-n", router, "link", "add", "ts-r2", "type", "veth", "peer", "name", "ts-d")
        ip("-n", router, "link", "set", "ts-d", "netns", receiver_ns)

        for namespace, interface, address, mtu in (
            (sender, "ts-s", "192.0.2.1/30", "1500"),
            (router, "ts-r1", "192.0.2.2/30", "1500"),
            (router, "ts-r2", "198.51.100.1/30", "1280"),
            (receiver_ns, "ts-d", "198.51.100.2/30", "1280"),
        ):
            ip("-n", namespace, "link", "set", "lo", "up")
            ip("-n", namespace, "addr", "add", address, "dev", interface)
            ip("-n", namespace, "link", "set", interface, "mtu", mtu, "up")
        ip("-n", sender, "route", "add", "198.51.100.0/30", "via", "192.0.2.2")
        ip("-n", receiver_ns, "route", "add", "192.0.2.0/30", "via", "198.51.100.1")
        ip("netns", "exec", router, "sysctl", "-qw", "net.ipv4.ip_forward=1")
        # Only the router's ICMP fragmentation-needed feedback is suppressed.
        ip("netns", "exec", router, "iptables", "-A", "OUTPUT", "-p", "icmp", "--icmp-type", "fragmentation-needed", "-j", "DROP")

        receiver = subprocess.Popen(
            ["ip", "netns", "exec", receiver_ns, sys.executable, "-u", script, "receive", "--bind", "198.51.100.2", "--idle-timeout", "15"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        with selectors.DefaultSelector() as ready:
            ready.register(receiver.stdout, selectors.EVENT_READ)
            if not ready.select(timeout=5):
                raise RuntimeError("Receiver startup timed out")
        if not receiver.stdout.readline().startswith("Listening on"):
            raise RuntimeError("Receiver did not start")

        result = subprocess.run(
            ["ip", "netns", "exec", sender, sys.executable, script, "probe", "198.51.100.2", "--sizes", "64,1252,1253,1400", "--count", "1", "--dont-fragment", "--observe-icmp"],
            check=True, capture_output=True, text=True, timeout=15,
        )
        probe = json.loads(result.stdout)
        observed = [row["status"] for row in probe["results"]]
        expected = ["acknowledged", "acknowledged", "timeout", "timeout"]
        if observed != expected:
            raise RuntimeError(f"Unexpected black-hole result: {observed}")
        search_result = subprocess.run(
            ["ip", "netns", "exec", sender, sys.executable, script, "search", "198.51.100.2",
             "--min", "1200", "--max", "1400", "--count", "1", "--observe-icmp"],
            check=True, capture_output=True, text=True, timeout=15,
        )
        search = json.loads(search_result.stdout)
        evidence = search["summary"]["search"]
        if evidence["assessment"] != "inconclusive" or evidence["observed_interval_payload_bytes"] is not None:
            raise RuntimeError(f"Blocked-feedback search claimed a boundary: {evidence}")
        if probe["summary"]["icmp_feedback"]["size_feedback_events"] or search["summary"]["icmp_feedback"]["size_feedback_events"]:
            raise RuntimeError("Blocked ICMP feedback unexpectedly reached the sender error queue")
        compared = subprocess.run(
            ["ip", "netns", "exec", sender, sys.executable, script,
             "compare-fragmentation", "198.51.100.2", "--sizes", "64,1400", "--count", "2"],
            check=True, capture_output=True, text=True, timeout=15,
        )
        comparison = json.loads(compared.stdout)
        if ([row["status"] for row in comparison["runs"]["df"]["results"]] !=
                ["acknowledged"] * 2 + ["timeout"] * 2 or
                [row["status"] for row in comparison["runs"]["fragmentation_permitted"]["results"]] !=
                ["acknowledged"] * 4):
            raise RuntimeError(f"Unexpected blocked-feedback comparison: {comparison}")
        firewall = ip("netns", "exec", router, "iptables", "-L", "OUTPUT", "-n", "-v", "-x", "--line-numbers").stdout
        counter = re.search(r"^\s*1\s+(\d+)\s+\d+\s+DROP\s+(?:icmp|1)\b", firewall, re.MULTILINE)
        if counter is None or int(counter.group(1)) < 2:
            raise RuntimeError(f"Expected blocked ICMP feedback for both large probes: {firewall}")
        # Restore ICMP within the disposable router namespace, then observe
        # the same routed path with the UDP error queue enabled.
        ip("netns", "exec", router, "iptables", "-D", "OUTPUT", "-p", "icmp",
           "--icmp-type", "fragmentation-needed", "-j", "DROP")
        visible_result = subprocess.run(
            ["ip", "netns", "exec", sender, sys.executable, script,
             "probe", "198.51.100.2", "--sizes", "64,1400", "--count", "1",
             "--dont-fragment", "--observe-icmp"],
            check=True, capture_output=True, text=True, timeout=10,
        )
        visible_feedback_probe = json.loads(visible_result.stdout)
        visible_summary = visible_feedback_probe["summary"]["icmp_feedback"]
        if visible_summary["observation_state"] != "complete" or visible_summary["token_matched_size_feedback_events"] < 1:
            raise RuntimeError(f"ICMP feedback was not matched to the large probe: {visible_feedback_probe}")
        print(json.dumps({
            "lab": "routed-ipv4-df-blocked-icmp",
            "sender_link_mtu_bytes": 1500,
            "router_egress_mtu_bytes": 1280,
            "blocked_feedback": "router ICMP fragmentation-needed (type 3, code 4)",
            "blocked_feedback_packets": int(counter.group(1)),
            "known_egress_payload_boundary_bytes": 1252,
            "interpretation": "Small probes were acknowledged; large probes timed out with ICMP feedback blocked. A timeout alone does not identify the cause on an unknown path.",
            "probe": probe,
            "search": search,
            "fragmentation_comparison": comparison,
            "visible_feedback_probe": visible_feedback_probe,
        }, indent=2))
    finally:
        if receiver is not None:
            if receiver.poll() is None:
                receiver.terminate()
            try:
                receiver.wait(timeout=3)
            except subprocess.TimeoutExpired:
                receiver.kill()
                receiver.wait(timeout=3)
            receiver.stdout.close()
            receiver.stderr.close()
        for namespace in reversed(created):
            ip("netns", "delete", namespace)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        print(f"Lab failed: {error}", file=sys.stderr)
        sys.exit(1)

"""Compare visible and blocked IPv6 Packet Too Big feedback with receiver logs.

Only disposable namespaces are changed. Run the blocked case first, before
the sender can learn the router's smaller MTU from visible feedback.
"""

import json
import os
from pathlib import Path
import re
import selectors
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tunnelscope_core.reports import correlate_reports


def ip(*args):
    return subprocess.run(["ip", *args], check=True, capture_output=True, text=True, timeout=10)


def run_case(sender, destination, script, directory, label):
    receiver_path = Path(directory) / f"receiver-{label}.json"
    target = "2001:db8:5453:2::2"
    receiver = subprocess.Popen(
        ["ip", "netns", "exec", destination, sys.executable, "-u", script,
         "receive", "--bind", target, "--max-packets", "200", "--idle-timeout", "8",
         "--output", str(receiver_path)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        with selectors.DefaultSelector() as ready:
            ready.register(receiver.stdout, selectors.EVENT_READ)
            if not ready.select(timeout=5):
                raise RuntimeError("IPv6 receiver startup timed out")
        if not receiver.stdout.readline().startswith("Listening on"):
            raise RuntimeError("IPv6 receiver did not start")
        command = ["ip", "netns", "exec", sender, sys.executable, script]
        sent = subprocess.run(
            [*command, "probe", target, "--family", "ipv6", "--sizes", "64,1232,1233,1400",
             "--count", "1", "--timeout", "2", "--dont-fragment", "--observe-icmp"],
            check=True, capture_output=True, text=True, timeout=15,
        )
        result = {"probe": json.loads(sent.stdout)}
        if label == "blocked":
            searched = subprocess.run(
                [*command, "search", target, "--family", "ipv6", "--min", "1200",
                 "--max", "1400", "--count", "1", "--timeout", "2", "--observe-icmp"],
                check=True, capture_output=True, text=True, timeout=15,
            )
            result["search"] = json.loads(searched.stdout)
        if receiver.wait(timeout=12) != 0:
            raise RuntimeError(f"IPv6 receiver failed: {receiver.stderr.read()}")
        result["receiver"] = json.loads(receiver_path.read_text(encoding="utf-8"))
        result["correlation"] = correlate_reports(result["probe"], result["receiver"])
        if "search" in result:
            result["search_correlation"] = correlate_reports(result["search"], result["receiver"])
        return result
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


def main():
    if not sys.platform.startswith("linux") or os.geteuid() != 0 or any(
        not shutil.which(tool) for tool in ("ip", "ip6tables", "sysctl")
    ):
        raise RuntimeError("This lab requires root on Linux, iproute2, ip6tables and sysctl")
    suffix = uuid.uuid4().hex[:10]
    sender, router, destination = (f"ts6-{suffix}-{role}" for role in ("s", "r", "d"))
    created = []
    script = str(Path(__file__).resolve().parents[1] / "tunnelscope.py")
    try:
        for namespace in (sender, router, destination):
            ip("netns", "add", namespace)
            created.append(namespace)
        ip("-n", sender, "link", "add", "ts6-s", "type", "veth", "peer", "name", "ts6-r1")
        ip("-n", sender, "link", "set", "ts6-r1", "netns", router)
        ip("-n", router, "link", "add", "ts6-r2", "type", "veth", "peer", "name", "ts6-d")
        ip("-n", router, "link", "set", "ts6-d", "netns", destination)
        for namespace, interface, address, mtu in (
            (sender, "ts6-s", "2001:db8:5453:1::1/64", "1500"),
            (router, "ts6-r1", "2001:db8:5453:1::2/64", "1500"),
            (router, "ts6-r2", "2001:db8:5453:2::1/64", "1280"),
            (destination, "ts6-d", "2001:db8:5453:2::2/64", "1280"),
        ):
            ip("-n", namespace, "link", "set", "lo", "up")
            ip("-n", namespace, "link", "set", interface, "mtu", mtu, "up")
            ip("-n", namespace, "-6", "addr", "add", address, "dev", interface, "nodad")
        ip("-n", sender, "-6", "route", "add", "2001:db8:5453:2::/64", "via", "2001:db8:5453:1::2")
        ip("-n", destination, "-6", "route", "add", "2001:db8:5453:1::/64", "via", "2001:db8:5453:2::1")
        ip("netns", "exec", router, "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1")
        deadline = time.monotonic() + 10
        while any(ip("-n", namespace, "-6", "addr", "show", "tentative").stdout.strip()
                  for namespace in (sender, router, destination)):
            if time.monotonic() > deadline:
                raise RuntimeError("IPv6 addresses stayed tentative")
            time.sleep(0.1)

        firewall = ["netns", "exec", router, "ip6tables"]
        rule = ["OUTPUT", "-p", "ipv6-icmp", "--icmpv6-type", "packet-too-big", "-j", "DROP"]
        ip(*firewall, "-A", *rule)
        with tempfile.TemporaryDirectory() as directory:
            blocked = run_case(sender, destination, script, directory, "blocked")
            counters = ip(*firewall, "-L", "OUTPUT", "-n", "-v", "-x", "--line-numbers").stdout
            match = re.search(r"^\s*1\s+(\d+)\s+\d+\s+DROP\b", counters, re.MULTILINE)
            if match is None or int(match.group(1)) < 3:
                raise RuntimeError(f"Expected blocked IPv6 feedback for probe and search: {counters}")
            blocked["blocked_packet_too_big_messages"] = int(match.group(1))
            ip(*firewall, "-D", *rule)
            visible = run_case(sender, destination, script, directory, "visible")
        expected_prefix = ["acknowledged", "acknowledged"]
        for case, suffix_status in ((blocked, "timeout"), (visible, "packet_too_large")):
            if [row["status"] for row in case["probe"]["results"]] != expected_prefix + [suffix_status] * 2:
                raise RuntimeError(f"Unexpected IPv6 routed probe outcomes: {case['probe']}")
            if case["correlation"]["summary"]["receiver_observed"] != 2:
                raise RuntimeError("Only the 64- and 1232-byte probes should reach the receiver")
        if blocked["probe"]["summary"]["icmp_feedback"]["size_feedback_events"]:
            raise RuntimeError("Blocked IPv6 Packet Too Big feedback reached the sender")
        search = blocked["search"]["summary"]["search"]
        if search["assessment"] != "inconclusive" or search["observed_interval_payload_bytes"] is not None:
            raise RuntimeError(f"Blocked IPv6 search claimed a boundary: {search}")
        events = [event for row in visible["probe"]["results"]
                  for event in row["icmp_observation"]["events"]]
        if not any(event.get("message") == "packet_too_big" and event.get("quoted_probe_match") is True
                   and event.get("reported_mtu_bytes") == 1280 for event in events):
            raise RuntimeError("Visible IPv6 Packet Too Big feedback was not matched")
        print(json.dumps({
            "lab": "routed-ipv6-packet-too-big",
            "sender_link_mtu_bytes": 1500,
            "router_egress_mtu_bytes": 1280,
            "known_egress_payload_boundary_bytes": 1232,
            "cases": {"blocked": blocked, "visible": visible},
            "limitations": ["Controlled namespaces on one kernel; not independent field evidence.",
                            "No observed ICMP on an unknown path does not prove filtering.",
                            "Later visible attempts may use PMTU cached from earlier feedback."],
        }, indent=2))
    finally:
        for namespace in reversed(created):
            ip("netns", "delete", namespace)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        print(f"Lab failed: {error}", file=sys.stderr)
        sys.exit(1)

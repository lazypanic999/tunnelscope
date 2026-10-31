"""Observe routed IPv6 Packet Too Big feedback in disposable namespaces."""

import json
import os
from pathlib import Path
import selectors
import shutil
import subprocess
import sys
import uuid


def ip(*args):
    return subprocess.run(["ip", *args], check=True, capture_output=True, text=True, timeout=10)


def main():
    if not sys.platform.startswith("linux") or os.geteuid() != 0 or any(
        not shutil.which(tool) for tool in ("ip", "sysctl")
    ):
        raise RuntimeError("This lab requires root on Linux, iproute2 and sysctl")
    suffix = uuid.uuid4().hex[:10]
    sender, router, destination = (f"ts6-{suffix}-{role}" for role in ("s", "r", "d"))
    created = []
    script = str(Path(__file__).resolve().parents[1] / "tunnelscope.py")
    receiver = None
    try:
        for namespace in (sender, router, destination):
            ip("netns", "add", namespace)
            created.append(namespace)
        ip("-n", sender, "link", "add", "ts6-s", "type", "veth", "peer", "name", "ts6-r1")
        ip("-n", sender, "link", "set", "ts6-r1", "netns", router)
        ip("-n", router, "link", "add", "ts6-r2", "type", "veth", "peer", "name", "ts6-d")
        ip("-n", router, "link", "set", "ts6-d", "netns", destination)
        for namespace, interface, address, mtu in (
            (sender, "ts6-s", "fd00:5453:1::1/64", "1500"),
            (router, "ts6-r1", "fd00:5453:1::2/64", "1500"),
            (router, "ts6-r2", "fd00:5453:2::1/64", "1280"),
            (destination, "ts6-d", "fd00:5453:2::2/64", "1280"),
        ):
            ip("-n", namespace, "link", "set", "lo", "up")
            ip("-n", namespace, "link", "set", interface, "mtu", mtu, "up")
            ip("-n", namespace, "-6", "addr", "add", address, "dev", interface, "nodad")
        ip("-n", sender, "-6", "route", "add", "fd00:5453:2::/64", "via", "fd00:5453:1::2")
        ip("-n", destination, "-6", "route", "add", "fd00:5453:1::/64", "via", "fd00:5453:2::1")
        ip("netns", "exec", router, "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1")

        receiver = subprocess.Popen(
            ["ip", "netns", "exec", destination, sys.executable, "-u", script,
             "receive", "--bind", "fd00:5453:2::2", "--family", "ipv6",
             "--max-packets", "1", "--idle-timeout", "8"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        with selectors.DefaultSelector() as ready:
            ready.register(receiver.stdout, selectors.EVENT_READ)
            if not ready.select(timeout=5):
                raise RuntimeError("IPv6 receiver startup timed out")
        if not receiver.stdout.readline().startswith("Listening on"):
            raise RuntimeError("IPv6 receiver did not start")
        sent = subprocess.run(
            ["ip", "netns", "exec", sender, sys.executable, script,
             "probe", "fd00:5453:2::2", "--family", "ipv6", "--sizes", "64,1400",
             "--count", "1", "--timeout", "2", "--dont-fragment", "--observe-icmp"],
            check=True, capture_output=True, text=True, timeout=12,
        )
        probe = json.loads(sent.stdout)
        if [row["status"] for row in probe["results"]] != ["acknowledged", "packet_too_large"]:
            raise RuntimeError(f"Unexpected IPv6 routed statuses: {probe}")
        feedback = probe["results"][1]["icmp_observation"]
        if feedback["state"] != "completed" or not any(
            event.get("message") == "packet_too_big" and event.get("quoted_probe_match") is True
            and event.get("reported_mtu_bytes") == 1280 for event in feedback["events"]
        ):
            raise RuntimeError(f"IPv6 Packet Too Big feedback was not matched: {probe}")
        if receiver.wait(timeout=8) != 0:
            raise RuntimeError("IPv6 receiver failed")
        print(json.dumps({
            "lab": "routed-ipv6-packet-too-big",
            "sender_link_mtu_bytes": 1500,
            "router_egress_mtu_bytes": 1280,
            "known_egress_payload_boundary_bytes": 1232,
            "probe": probe,
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

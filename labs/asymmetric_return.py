"""Show a return-path MTU problem that small acknowledgements hide.

Three isolated namespaces: sender A, router R and receiver B. Traffic from A
to B uses 1500-byte links. R routes traffic back to A over a second link with
a 1280-byte MTU, so a 1400-byte UDP payload reaches B but a same-sized reply
cannot return. The lab runs:

1. a --sized-reply probe (64, 1200 and 1400 bytes, two attempts each);
2. an ordinary probe at 1400 bytes, whose small ACK still returns;
3. a correlation of the sized run with the receiver's observations.

`--family ipv6` builds the same topology with IPv6 documentation addresses;
there the router drops the oversized reply and sends ICMPv6 Packet Too Big.

Run as root on Linux with iproute2 and sysctl. No host MTU or route is changed.
Namespaces created by this process are removed in finally, including on Ctrl+C.
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
import time
import uuid

RETURN_MTU = 1280
# Per family: sender links 1 and 2, receiver link, the address B listens on,
# the route A uses to reach B, and R's host route that sends return traffic over link 2.
FAMILIES = {
    "ipv4": {
        "lab": "asymmetric-return-mtu",
        "links": (("192.0.2.1/30", "192.0.2.2/30"), ("192.0.2.5/30", "192.0.2.6/30"),
                  ("198.51.100.2/30", "198.51.100.1/30")),
        "receiver": "198.51.100.2",
        "sender_route": ("198.51.100.0/30", "192.0.2.2"),
        "return_route": ("192.0.2.1/32", "192.0.2.5"),
        "receiver_gateway": "198.51.100.1",
    },
    "ipv6": {
        "lab": "asymmetric-return-mtu-ipv6",
        "links": (("2001:db8:a1::1/64", "2001:db8:a1::2/64"), ("2001:db8:a2::1/64", "2001:db8:a2::2/64"),
                  ("2001:db8:b::2/64", "2001:db8:b::1/64")),
        "receiver": "2001:db8:b::2",
        "sender_route": ("2001:db8:b::/64", "2001:db8:a1::2"),
        "return_route": ("2001:db8:a1::1/128", "2001:db8:a2::1"),
        "receiver_gateway": "2001:db8:b::1",
    },
}


def ip(*args):
    return subprocess.run(["ip", *args], check=True, capture_output=True, text=True, timeout=10)


def sysctl(namespace, *settings):
    ip("netns", "exec", namespace, "sysctl", "-qw", *settings)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--family", choices=sorted(FAMILIES), default="ipv4")
    family = parser.parse_args().family
    config = FAMILIES[family]
    inet = ("-6",) if family == "ipv6" else ()
    target = config["receiver"]
    if not sys.platform.startswith("linux") or os.geteuid() != 0 or any(
        not shutil.which(tool) for tool in ("ip", "sysctl")
    ):
        raise RuntimeError("This lab requires root on Linux, iproute2 and sysctl")
    suffix = uuid.uuid4().hex[:8]
    sender, router, receiver_ns = f"ts-{suffix}-a", f"ts-{suffix}-r", f"ts-{suffix}-b"
    created = []
    script = str(Path(__file__).resolve().parents[1] / "tunnelscope.py")
    report = {
        "lab": config["lab"],
        "address_family": family,
        "topology": "A -> R -> B over 1500-byte links; R -> A over a 1280-byte link",
        "forward_mtu_bytes": 1500,
        "return_mtu_bytes": RETURN_MTU,
    }
    receiver = None
    try:
        for namespace in (sender, router, receiver_ns):
            ip("netns", "add", namespace)
            created.append(namespace)
            ip("-n", namespace, "link", "set", "lo", "up")
            if family == "ipv6":
                # Link-local addresses must not stay tentative, or neighbour
                # discovery drops the first packets of the experiment.
                sysctl(namespace, "net.ipv6.conf.all.accept_dad=0", "net.ipv6.conf.default.accept_dad=0")
        (a1, r1), (a2, r2), (b, r3) = config["links"]
        links = (
            (sender, "ts-a1", a1, router, "ts-r1", r1, 1500),
            (sender, "ts-a2", a2, router, "ts-r2", r2, RETURN_MTU),
            (receiver_ns, "ts-b", b, router, "ts-r3", r3, 1500),
        )
        for left_ns, left, left_ip, right_ns, right, right_ip, mtu in links:
            ip("-n", left_ns, "link", "add", left, "type", "veth", "peer", "name", right)
            ip("-n", left_ns, "link", "set", right, "netns", right_ns)
            for namespace, interface, address in ((left_ns, left, left_ip), (right_ns, right, right_ip)):
                ip("-n", namespace, "link", "set", interface, "mtu", str(mtu), "up")
                ip("-n", namespace, *inet, "addr", "add", address, "dev", interface,
                   *(("nodad",) if family == "ipv6" else ()))
        if family == "ipv4":
            # Forward and return traffic use different links, so strict reverse-path
            # filtering must be off on A and R. (Linux has no IPv6 rp_filter sysctl.)
            for namespace, interfaces in ((sender, ("ts-a1", "ts-a2")), (router, ("ts-r1", "ts-r2", "ts-r3"))):
                sysctl(namespace, "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.default.rp_filter=0",
                       *(f"net.ipv4.conf.{name}.rp_filter=0" for name in interfaces))
            sysctl(router, "net.ipv4.ip_forward=1")
        else:
            sysctl(router, "net.ipv6.conf.all.forwarding=1")
        destination, via = config["sender_route"]
        ip("-n", sender, *inet, "route", "add", destination, "via", via, "dev", "ts-a1")
        destination, via = config["return_route"]
        ip("-n", router, *inet, "route", "add", destination, "via", via, "dev", "ts-r2")
        ip("-n", receiver_ns, *inet, "route", "add", "default", "via", config["receiver_gateway"])
        if family == "ipv6":
            deadline = time.monotonic() + 10
            while any(ip("-n", namespace, "-6", "addr", "show", "tentative").stdout.strip()
                      for namespace in (sender, router, receiver_ns)):
                if time.monotonic() > deadline:
                    raise RuntimeError("IPv6 addresses stayed tentative")
                time.sleep(0.1)

        with tempfile.TemporaryDirectory() as directory:
            receiver_path = Path(directory) / "receiver.json"
            receiver = subprocess.Popen(
                ["ip", "netns", "exec", receiver_ns, sys.executable, "-u", script, "receive",
                 "--bind", target, "--sized-reply", "--max-packets", "7", "--idle-timeout", "10",
                 "--output", str(receiver_path)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            with selectors.DefaultSelector() as ready:
                ready.register(receiver.stdout, selectors.EVENT_READ)
                if not ready.select(timeout=5):
                    raise RuntimeError("Receiver startup timed out")
            if not receiver.stdout.readline().startswith("Listening on"):
                raise RuntimeError(f"Receiver did not start: {receiver.stderr.read()}")
            sized = subprocess.run(
                ["ip", "netns", "exec", sender, sys.executable, script, "probe", target,
                 "--sizes", "64,1200,1400", "--count", "2", "--dont-fragment", "--sized-reply"],
                check=True, capture_output=True, text=True, timeout=30,
            )
            small = subprocess.run(
                ["ip", "netns", "exec", sender, sys.executable, script, "probe", target,
                 "--sizes", "1400", "--count", "1", "--dont-fragment"],
                check=True, capture_output=True, text=True, timeout=15,
            )
            receiver.wait(timeout=15)
            if receiver.returncode != 0:
                raise RuntimeError(f"Receiver failed: {receiver.stderr.read()}")
            sized_path = Path(directory) / "sized.json"
            sized_path.write_text(sized.stdout, encoding="utf-8")
            correlated = subprocess.run(
                [sys.executable, script, "correlate", str(sized_path), str(receiver_path)],
                check=True, capture_output=True, text=True, timeout=15,
            )
            report["probe"] = json.loads(sized.stdout)
            report["small_ack_probe"] = json.loads(small.stdout)
            report["receiver"] = json.loads(receiver_path.read_text(encoding="utf-8"))
            report["correlation"] = json.loads(correlated.stdout)
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

    returns = [row.get("return_status") for row in report["probe"]["results"]]
    if returns != ["sized_reply_received"] * 4 + ["no_reply"] * 2:
        raise RuntimeError(f"Unexpected sized reply results: {returns}")
    if [row["status"] for row in report["small_ack_probe"]["results"]] != ["acknowledged"]:
        raise RuntimeError("The small ACK did not return at 1400 bytes")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        print(f"Lab failed: {error}", file=sys.stderr)
        sys.exit(1)

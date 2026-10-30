"""Show a receiver-observed probe whose small acknowledgement is blocked.

Run as root on Linux with iproute2 and iptables. All interfaces and firewall
rules live in temporary network namespaces.
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
import uuid


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=15)


def ip(*args):
    return run("ip", *args)


def main():
    if not sys.platform.startswith("linux") or os.geteuid() != 0 or any(not shutil.which(tool) for tool in ("ip", "iptables")):
        raise RuntimeError("This lab requires root on Linux, iproute2 and iptables")

    suffix = uuid.uuid4().hex[:10]
    sender, receiver_ns = (f"ts-{suffix}-{role}" for role in ("s", "d"))
    created = []
    script = str(Path(__file__).resolve().parents[1] / "tunnelscope.py")
    receiver = None
    try:
        for namespace in (sender, receiver_ns):
            ip("netns", "add", namespace)
            created.append(namespace)
        ip("-n", sender, "link", "add", "ts-s", "type", "veth", "peer", "name", "ts-d")
        ip("-n", sender, "link", "set", "ts-d", "netns", receiver_ns)
        for namespace, interface, address in (
            (sender, "ts-s", "192.0.2.1/30"),
            (receiver_ns, "ts-d", "192.0.2.2/30"),
        ):
            ip("-n", namespace, "link", "set", "lo", "up")
            ip("-n", namespace, "addr", "add", address, "dev", interface)
            ip("-n", namespace, "link", "set", interface, "mtu", "1500", "up")
        # The receiver sends ACKs, but the sender's incoming filter drops them.
        ip("netns", "exec", sender, "iptables", "-A", "INPUT", "-p", "udp", "--sport", "9471", "-j", "DROP")

        with tempfile.TemporaryDirectory(prefix="tunnelscope-ack-lab-") as directory:
            directory = Path(directory)
            receiver_path = directory / "receiver.json"
            probe_path = directory / "probe.json"
            correlation_path = directory / "correlation.json"
            search_path = directory / "search.json"
            search_correlation_path = directory / "search-correlation.json"
            receiver = subprocess.Popen(
                ["ip", "netns", "exec", receiver_ns, sys.executable, "-u", script,
                 "receive", "--bind", "192.0.2.2", "--max-packets", "4",
                 "--idle-timeout", "10", "--output", str(receiver_path)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            with selectors.DefaultSelector() as ready:
                ready.register(receiver.stdout, selectors.EVENT_READ)
                if not ready.select(timeout=5):
                    raise RuntimeError("Receiver startup timed out")
            if not receiver.stdout.readline().startswith("Listening on"):
                raise RuntimeError("Receiver did not start")

            run("ip", "netns", "exec", sender, sys.executable, script,
                "probe", "192.0.2.2", "--sizes", "64,1400", "--count", "1",
                "--timeout", "1", "--dont-fragment", "--output", str(probe_path))
            search_run = run("ip", "netns", "exec", sender, sys.executable, script,
                             "search", "192.0.2.2", "--min", "64", "--max", "1400",
                             "--count", "1", "--timeout", "1")
            search = json.loads(search_run.stdout)
            search_path.write_text(json.dumps(search), encoding="utf-8")
            if search["summary"]["search"]["assessment"] != "inconclusive":
                raise RuntimeError("Blocked-ACK search should remain inconclusive")
            if receiver.wait(timeout=5) != 0:
                raise RuntimeError("Receiver failed")
            run(sys.executable, script, "correlate", str(probe_path), str(receiver_path),
                "--output", str(correlation_path))
            probe = json.loads(probe_path.read_text(encoding="utf-8"))
            observations = json.loads(receiver_path.read_text(encoding="utf-8"))
            correlation = json.loads(correlation_path.read_text(encoding="utf-8"))
            run(sys.executable, script, "correlate", str(search_path), str(receiver_path),
                "--output", str(search_correlation_path))
            search_correlation = json.loads(search_correlation_path.read_text(encoding="utf-8"))
            if search_correlation["summary"]["timed_out_but_receiver_observed"] != 2:
                raise RuntimeError("Expected both search probes at receiver despite timeouts")
            if [row["status"] for row in probe["results"]] != ["timeout", "timeout"]:
                raise RuntimeError("Expected sender timeouts")
            if correlation["summary"]["timed_out_but_receiver_observed"] != 2:
                raise RuntimeError("Expected both timed-out probes at receiver")
            if [row["ack_send_status"] for row in correlation["results"]] != ["sent", "sent"]:
                raise RuntimeError("Expected local ACK send calls to succeed")
            firewall = ip("netns", "exec", sender, "iptables", "-L", "INPUT", "-n", "-v", "-x", "--line-numbers").stdout
            counter = re.search(r"^\s*1\s+(\d+)\s+\d+\s+DROP\s+(?:udp|17)\b", firewall, re.MULTILINE)
            if counter is None or int(counter.group(1)) < 2:
                raise RuntimeError("Expected the sender firewall to drop both ACKs")
            print(json.dumps({
                "lab": "receiver-ack-return-blocked",
                "blocked_ack_packets": int(counter.group(1)),
                "interpretation": "The receiver saw both probes and locally sent ACKs; the sender's isolated firewall blocked those ACKs. On an unknown path, the same correlation would not identify the failing hop.",
                "probe": probe,
                "search": search,
                "receiver": observations,
                "correlation": correlation,
                "search_correlation": search_correlation,
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

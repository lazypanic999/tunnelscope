"""Validate routed MTU feedback through WireGuard in disposable namespaces.

Two hosts communicate through two WireGuard gateways. The receiving gateway
has a 1280-byte LAN egress; the sender link is 1500 and tunnel MTU is 1420.
Each direction is rebuilt for visible and blocked ICMP to isolate PMTU caches.
Requires Linux root, iproute2, wireguard-tools, ping, sysctl and iptables.
"""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import uuid

from wireguard_boundary import SCRIPT, ip, run, start_receiver, stop_receiver


def connect(left, left_name, right, right_name):
    ip("-n", left, "link", "add", left_name, "type", "veth", "peer", "name", right_name)
    ip("-n", left, "link", "set", right_name, "netns", right)


def configure_tunnel(left, right, key_dir):
    gateways = ((left, "198.18.0.1", "10.77.0.1", "192.0.2.0/30", 51820),
                (right, "198.18.0.2", "10.77.0.2", "198.51.100.0/30", 51821))
    private, public = {}, {}
    for namespace, _, overlay, _, _ in gateways:
        ip("-n", namespace, "link", "add", "wg0", "type", "wireguard")
        ip("-n", namespace, "addr", "add", overlay + "/30", "dev", "wg0")
        ip("-n", namespace, "link", "set", "wg0", "mtu", "1420", "up")
        secret = run("wg", "genkey").stdout.strip()
        private[namespace] = Path(key_dir) / namespace
        private[namespace].write_text(secret + "\n", encoding="ascii")
        private[namespace].chmod(0o600)
        public[namespace] = run("wg", "pubkey", input_text=secret + "\n").stdout.strip()
    for index, (namespace, _, _, _, port) in enumerate(gateways):
        peer, endpoint, overlay, subnet, peer_port = gateways[1 - index]
        ip("netns", "exec", namespace, "wg", "set", "wg0", "private-key",
           str(private[namespace]), "listen-port", str(port), "peer", public[peer],
           "allowed-ips", f"{overlay}/32,{subnet}", "endpoint", f"{endpoint}:{peer_port}")
        ip("-n", namespace, "route", "add", subnet, "dev", "wg0")
        ip("netns", "exec", namespace, "sysctl", "-qw", "net.ipv4.ip_forward=1")


def scenario(output, direction, blocked):
    suffix = uuid.uuid4().hex[:8]
    host_l, gateway_l, gateway_r, host_r = [f"tswgr-{suffix}-{role}" for role in ("l", "gl", "gr", "r")]
    created, receiver = [], None
    case = f"{direction}-{'blocked' if blocked else 'visible'}"
    output = output / case
    output.mkdir()
    with tempfile.TemporaryDirectory(prefix="tswgr-keys-") as key_dir:
        try:
            for namespace in (host_l, gateway_l, gateway_r, host_r):
                ip("netns", "add", namespace)
                created.append(namespace)
                ip("-n", namespace, "link", "set", "lo", "up")
            connect(host_l, "host-l", gateway_l, "lan-l")
            connect(gateway_l, "under-l", gateway_r, "under-r")
            connect(gateway_r, "lan-r", host_r, "host-r")
            left_mtu, right_mtu = (1500, 1280) if direction == "left-to-right" else (1280, 1500)
            for namespace, interface, address, mtu in (
                (host_l, "host-l", "192.0.2.1/30", left_mtu),
                (gateway_l, "lan-l", "192.0.2.2/30", left_mtu),
                (gateway_l, "under-l", "198.18.0.1/30", 1500),
                (gateway_r, "under-r", "198.18.0.2/30", 1500),
                (gateway_r, "lan-r", "198.51.100.1/30", right_mtu),
                (host_r, "host-r", "198.51.100.2/30", right_mtu),
            ):
                ip("-n", namespace, "addr", "add", address, "dev", interface)
                ip("-n", namespace, "link", "set", interface, "mtu", str(mtu), "up")
            # Gateways can originate ICMP using a tunnel address. Default
            # routes keep those sources reachable for reverse-path filtering.
            ip("-n", host_l, "route", "add", "default", "via", "192.0.2.2")
            ip("-n", host_r, "route", "add", "default", "via", "198.51.100.1")
            configure_tunnel(gateway_l, gateway_r, key_dir)
            if direction == "left-to-right":
                source, destination, target, bottleneck = host_l, host_r, "198.51.100.2", gateway_r
            else:
                source, destination, target, bottleneck = host_r, host_l, "192.0.2.1", gateway_l
            if blocked:
                ip("netns", "exec", bottleneck, "iptables", "-A", "OUTPUT", "-p", "icmp",
                   "--icmp-type", "fragmentation-needed", "-j", "DROP")
            ip("netns", "exec", source, "ping", "-c", "1", "-W", "3", target)
            receiver_path = output / "receiver.json"
            receiver = start_receiver(destination, target, receiver_path, idle_timeout=3)
            diagnosis_path = output / "diagnosis.json"
            ip("netns", "exec", source, sys.executable, SCRIPT, "diagnose", target,
               "--min", "1252", "--max", "1253", "--count", "1", "--max-sizes", "2",
               "--timeout", "1", "--output", str(diagnosis_path))
            receiver.wait(timeout=8)
            if receiver.returncode != 0:
                raise RuntimeError("Receiver failed to save capture")
            joined_path = output / "joined.json"
            run(sys.executable, SCRIPT, "correlate", str(diagnosis_path), str(receiver_path),
                "--output", str(joined_path), "--html", str(output / "joined.html"))
            report = json.loads(joined_path.read_text(encoding="utf-8"))
            compared = report["runs"]["fragmentation_comparison"]["runs"]
            df = compared["df"]
            permitted = compared["fragmentation_permitted"]
            expected_large = "timeout" if blocked else "packet_too_large"
            if [row["status"] for row in df["results"]] != ["acknowledged", expected_large]:
                raise RuntimeError(f"Unexpected DF outcomes in {case}")
            if [row["status"] for row in permitted["results"]] != ["acknowledged"] * 2:
                raise RuntimeError(f"Fragmentation-permitted delivery failed in {case}")
            search = report["summary"]["search"]
            expected_assessment = "inconclusive" if blocked else "adjacent_observed_bounds"
            expected_interval = None if blocked else [1252, 1253]
            if search["assessment"] != expected_assessment or search["observed_interval_payload_bytes"] != expected_interval:
                raise RuntimeError(f"Unexpected search assessment in {case}: {search}")
            remote_feedback = [event for row in df["results"]
                               for event in row.get("icmp_observation", {}).get("events", [])
                               if event.get("origin") == "icmpv4"
                               and event.get("message") == "fragmentation_needed"
                               and event.get("quoted_probe_match") is True
                               and event.get("reported_mtu_bytes") == 1280]
            blocked_packets = 0
            if blocked:
                firewall = ip("netns", "exec", bottleneck, "iptables", "-L", "OUTPUT",
                              "-n", "-v", "-x", "--line-numbers").stdout
                counter = re.search(r"^\s*1\s+(\d+)\s+\d+\s+DROP\s+(?:icmp|1)\b", firewall, re.MULTILINE)
                if counter is None or int(counter.group(1)) < 2:
                    raise RuntimeError(f"Missing blocked-feedback evidence in {case}")
                blocked_packets = int(counter.group(1))
                if report["summary"]["icmp_size_feedback_events"] != 0:
                    raise RuntimeError(f"Blocked feedback unexpectedly observed in {case}")
            elif not remote_feedback:
                raise RuntimeError(f"No token-matched routed ICMP in {case}")
            capture = report["receiver_evidence"]["summary"]
            if capture["receiver_observed"] != 4 or capture["unassigned_receiver_observations"] or capture["unmatched_receiver_observations"]:
                raise RuntimeError(f"Unexpected receiver pairing in {case}: {capture}")
            return {"case": case, "direction": direction, "icmp_blocked": blocked,
                    "df_statuses": [row["status"] for row in df["results"]],
                    "fragmentation_permitted_statuses": [row["status"] for row in permitted["results"]],
                    "token_matched_routed_size_feedback": len(remote_feedback),
                    "router_blocked_feedback_packets": blocked_packets,
                    "receiver_observed": capture["receiver_observed"],
                    "attempts": capture["sent_probes"],
                    "search_assessment": search["assessment"],
                    "observed_interval_payload_bytes": search["observed_interval_payload_bytes"]}
        finally:
            if receiver is not None:
                stop_receiver(receiver)
            for namespace in reversed(created):
                ip("netns", "delete", namespace)


def main(output):
    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        raise RuntimeError("Linux root is required")
    if any(not shutil.which(tool) for tool in ("ip", "wg", "ping", "sysctl", "iptables")):
        raise RuntimeError("iproute2, wireguard-tools, ping, sysctl and iptables are required")
    if output.exists() and any(output.iterdir()):
        raise RuntimeError("Output directory must be empty or absent")
    output.mkdir(parents=True, exist_ok=True)
    report = {"lab": "wireguard-routed-inner-mtu", "single_kernel": True,
              "sender_link_mtu_bytes": 1500, "tunnel_mtu_bytes": 1420,
              "receiver_lan_mtu_bytes": 1280, "cases": []}
    for direction in ("left-to-right", "right-to-left"):
        for blocked in (False, True):
            result = scenario(output, direction, blocked)
            report["cases"].append(result)
            print(json.dumps(result), flush=True)
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        main(args.output_dir.resolve())
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        print(f"WireGuard routed lab failed: {error}", file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError) and error.stderr:
            print(error.stderr, file=sys.stderr)
        sys.exit(1)

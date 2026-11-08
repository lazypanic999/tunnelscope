"""Validate routed OpenVPN/TUN feedback with temporary TLS peers and namespaces.

Requires Linux root, OpenVPN 2.6+, OpenSSL, iproute2, iptables and /dev/net/tun.
Certificates are created in a private temporary directory and never exported.
"""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from labs._routed_feedback import run_case
from tunnelscope_core.network import VERSION


def command(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=30)


def ip(*args):
    return command("ip", *args)


def certificates(directory):
    """Make a one-day lab CA and role-checked peer certificates; install no trust."""
    ca_key, ca_cert = directory / "ca.key", directory / "ca.crt"
    command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "1",
            "-subj", "/CN=TunnelScope-Lab-CA", "-keyout", str(ca_key), "-out", str(ca_cert),
            "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    for role, purpose in (("server", "serverAuth"), ("client", "clientAuth")):
        key, csr, cert = (directory / f"{role}.{suffix}" for suffix in ("key", "csr", "crt"))
        extension = directory / f"{role}.ext"
        extension.write_text("basicConstraints=critical,CA:FALSE\n"
                             "keyUsage=critical,digitalSignature,keyEncipherment\n"
                             f"extendedKeyUsage={purpose}\n", encoding="ascii")
        command("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256",
                "-subj", f"/CN=TunnelScope-Lab-{role}", "-keyout", str(key), "-out", str(csr))
        command("openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca_cert), "-CAkey", str(ca_key),
                "-CAcreateserial", "-days", "1", "-sha256", "-extfile", str(extension), "-out", str(cert))


def start_vpn(namespace, role, directory):
    server = role == "server"
    local, remote = ("192.0.2.2", "192.0.2.1") if server else ("192.0.2.1", "192.0.2.2")
    tunnel_local, tunnel_remote = ("203.0.113.1", "203.0.113.2") if server else ("203.0.113.2", "203.0.113.1")
    peer_role = "client" if server else "server"
    log = directory / f"{role}.log"
    args = ["ip", "netns", "exec", namespace, "openvpn", "--dev", "ts-ovpn", "--dev-type", "tun",
            "--topology", "p2p", "--proto", "udp4", "--local", local, "--remote", remote,
            "--port", "1194", "--ifconfig", tunnel_local, tunnel_remote, "--tun-mtu", "1400",
            "--disable-dco", "--data-ciphers", "AES-256-GCM", "--tls-version-min", "1.2",
            "--ca", str(directory / "ca.crt"), "--cert", str(directory / f"{role}.crt"),
            "--key", str(directory / f"{role}.key"), "--remote-cert-tls", peer_role,
            "--verify-x509-name", f"TunnelScope-Lab-{peer_role}", "name", "--tls-exit",
            "--verb", "3", "--log", str(log), "--tls-server" if server else "--tls-client"]
    if server:
        args.extend(("--dh", "none"))  # ECDH, without generating finite-field DH parameters.
    process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    return process, log


def wait_ready(process, log):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        text = log.read_text(encoding="utf-8", errors="replace") if log.exists() else ""
        if process.poll() is not None:
            raise RuntimeError(f"OpenVPN exited before readiness: {process.stderr.read()} {text[-1800:]}")
        if "Initialization Sequence Completed" in text:
            return
        time.sleep(0.05)
    raise RuntimeError(f"OpenVPN startup timed out: {text[-1800:]}")


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
    process.stderr.close()


def main():
    if (not sys.platform.startswith("linux") or os.geteuid() != 0
            or any(not shutil.which(tool) for tool in ("ip", "iptables", "sysctl", "openvpn", "openssl"))
            or not Path("/dev/net/tun").is_char_device()):
        raise RuntimeError("This lab requires Linux root, OpenVPN 2.6+, OpenSSL, iproute2, iptables, sysctl and /dev/net/tun")
    suffix = uuid.uuid4().hex[:10]
    sender, router, receiver = (f"ts-ov-{suffix}-{role}" for role in ("s", "r", "d"))
    created, processes = [], []
    script = str(Path(__file__).resolve().parents[1] / "tunnelscope.py")
    with tempfile.TemporaryDirectory(prefix="tunnelscope-openvpn-") as temporary:
        directory = Path(temporary)
        try:
            certificates(directory)
            for namespace in (sender, router, receiver):
                ip("netns", "add", namespace)
                created.append(namespace)
                ip("-n", namespace, "link", "set", "lo", "up")
            ip("-n", sender, "link", "add", "ts-under-a", "type", "veth", "peer", "name", "ts-under-r")
            ip("-n", sender, "link", "set", "ts-under-r", "netns", router)
            ip("-n", router, "link", "add", "ts-lan-r", "type", "veth", "peer", "name", "ts-lan-d")
            ip("-n", router, "link", "set", "ts-lan-d", "netns", receiver)
            for namespace, interface, address, mtu in (
                    (sender, "ts-under-a", "192.0.2.1/30", "1500"),
                    (router, "ts-under-r", "192.0.2.2/30", "1500"),
                    (router, "ts-lan-r", "198.51.100.1/30", "1280"),
                    (receiver, "ts-lan-d", "198.51.100.2/30", "1280")):
                ip("-n", namespace, "addr", "add", address, "dev", interface)
                ip("-n", namespace, "link", "set", interface, "mtu", mtu, "up")
            ip("netns", "exec", router, "sysctl", "-qw", "net.ipv4.ip_forward=1")
            for namespace, role in ((router, "server"), (sender, "client")):
                process, log = start_vpn(namespace, role, directory)
                processes.append((process, log))
            for process, log in processes:
                wait_ready(process, log)
            ip("-n", sender, "route", "add", "198.51.100.0/30", "via", "203.0.113.1", "dev", "ts-ovpn")
            ip("-n", receiver, "route", "add", "203.0.113.2/32", "via", "198.51.100.1")

            firewall = ["netns", "exec", router, "iptables"]
            rule = ["OUTPUT", "-p", "icmp", "--icmp-type", "fragmentation-needed", "-j", "DROP"]
            ip(*firewall, "-A", *rule)
            settings = {"target": "198.51.100.2", "sizes": "64,1252,1253,1300", "family": "ipv4",
                        "search_maximum": 1300}
            blocked = run_case(sender, receiver, script, directory, "blocked", **settings)
            counter_text = ip(*firewall, "-L", "OUTPUT", "-n", "-v", "-x", "--line-numbers").stdout
            counter = re.search(r"^\s*1\s+(\d+)\s+\d+\s+DROP\b", counter_text, re.MULTILINE)
            if counter is None or int(counter.group(1)) < 3:
                raise RuntimeError(f"Expected blocked fragmentation-needed messages: {counter_text}")
            blocked["blocked_fragmentation_needed_messages"] = int(counter.group(1))
            ip(*firewall, "-D", *rule)
            visible = run_case(sender, receiver, script, directory, "visible", **settings)
            for case, failure in ((blocked, "timeout"), (visible, "packet_too_large")):
                probe = case["probe"]
                if [row["status"] for row in probe["results"]] != ["acknowledged"] * 2 + [failure] * 2:
                    raise RuntimeError(f"Unexpected OpenVPN outcomes: {probe}")
                if probe["source"].get("interface") != "ts-ovpn" or probe["source"].get("interface_mtu_bytes") != 1400:
                    raise RuntimeError("The probe did not select the 1400-byte OpenVPN TUN interface")
                if case["correlation"]["summary"]["receiver_observed"] != 2:
                    raise RuntimeError("Unexpected OpenVPN receiver observation count")
            for probe in (blocked["probe"], blocked["search"]):
                if probe["summary"]["icmp_feedback"]["size_feedback_events"]:
                    raise RuntimeError("Blocked feedback reached the OpenVPN sender")
            search = blocked["search"]["summary"]["search"]
            if search["assessment"] != "inconclusive" or search["observed_interval_payload_bytes"] is not None:
                raise RuntimeError("Blocked OpenVPN search claimed a size boundary")
            events = [event for row in visible["probe"]["results"] for event in row["icmp_observation"]["events"]]
            if not any(event.get("message") == "fragmentation_needed" and event.get("quoted_probe_match") is True
                       and event.get("reported_mtu_bytes") == 1280 for event in events):
                raise RuntimeError("No token-matched fragmentation-needed feedback crossed the OpenVPN tunnel")
            report = {
                "lab": "openvpn-routed-feedback", "tunnelscope_version": VERSION,
                "openvpn_version": command("openvpn", "--version").stdout.splitlines()[0],
                "transport": "IPv4 UDP; mutually verified temporary TLS certificates; user-space TUN",
                "configured_data_cipher": "AES-256-GCM", "underlay_mtu_bytes": 1500,
                "tunnel_mtu_bytes": 1400, "router_egress_mtu_bytes": 1280,
                "known_egress_payload_boundary_bytes": 1252,
                "cases": {"blocked": blocked, "visible": visible},
                "limitations": ["Controlled namespaces and TLS peers on one kernel; not independent field evidence.",
                                "The lower receiver LAN MTU is configured; this is not automatic PMTU discovery.",
                                "Small ACKs do not establish same-sized reverse delivery.",
                                "No observed ICMP on an unknown path does not prove filtering."],
            }
        finally:
            for process, _ in reversed(processes):
                stop(process)
            for namespace in reversed(created):
                ip("netns", "delete", namespace)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        print(f"Lab failed: {error}", file=sys.stderr)
        sys.exit(1)

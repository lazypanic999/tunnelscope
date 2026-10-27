"""Small, bounded UDP delivery experiments. This is not an MTU detector yet."""

import argparse
import errno
import json
import secrets
import socket
import struct
import sys
import time
from pathlib import Path

MAGIC = b"TS01"
HEADER = struct.Struct("!4s16sI")
ACK = b"TA01"
# Linux UAPI values, used when Python does not expose the constants.
IP_MTU_DISCOVER = getattr(socket, "IP_MTU_DISCOVER", 10)
IP_PMTUDISC_DO = getattr(socket, "IP_PMTUDISC_DO", 2)
IP_MTU = getattr(socket, "IP_MTU", 14)
SIOCGIFADDR = 0x8915
SIOCGIFMTU = 0x8921


def require_df_support(dont_fragment):
    if dont_fragment and not sys.platform.startswith("linux"):
        raise ValueError("--dont-fragment currently requires Linux (including WSL2)")


def configure_fragmentation(sock, dont_fragment):
    if dont_fragment:
        # Fail the experiment if the option cannot be enabled; never fall back.
        sock.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO)


def socket_failure(error, sock, dont_fragment):
    result = {"status": "socket_error", "error": str(error), "errno": error.errno}
    if dont_fragment and error.errno == errno.EMSGSIZE:
        result["status"] = "packet_too_large"
        try:
            result["kernel_reported_mtu_bytes"] = sock.getsockopt(socket.IPPROTO_IP, IP_MTU)
        except OSError:
            pass
    return result


def bounded_int(low, high):
    def parse(value):
        number = int(value)
        if not low <= number <= high:
            raise argparse.ArgumentTypeError(f"expected {low}..{high}")
        return number
    return parse


def sizes_arg(value):
    try:
        sizes = [int(item) for item in value.split(",")]
    except ValueError as error:
        raise argparse.ArgumentTypeError("use comma-separated integers") from error
    if not 1 <= len(sizes) <= 16 or any(not 32 <= size <= 8192 for size in sizes):
        raise argparse.ArgumentTypeError("use 1..16 payload sizes, each 32..8192 bytes")
    return sizes


def receive(bind, port, max_packets, idle_timeout):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((bind, port))
        sock.settimeout(idle_timeout)
        print(f"Listening on {sock.getsockname()[0]}:{sock.getsockname()[1]}", flush=True)
        for _ in range(max_packets):
            try:
                data, peer = sock.recvfrom(8193)
            except socket.timeout:
                break
            if not 32 <= len(data) <= 8192:
                continue
            magic, token, declared_size = HEADER.unpack_from(data)
            if magic != MAGIC or declared_size != len(data):
                continue
            # A fixed small acknowledgement does not echo the large payload.
            sock.sendto(HEADER.pack(ACK, token, len(data)), peer)


def summarize_results(sizes, results):
    """Keep delivery, explicit errors and missing replies distinct per payload size."""
    summary = []
    for size in dict.fromkeys(sizes):
        counts = {status: 0 for status in ("acknowledged", "packet_too_large", "timeout", "socket_error")}
        for result in results:
            if result["payload_bytes"] == size:
                counts[result["status"]] += 1
        observed = [status for status, count in counts.items() if count]
        assessment = {
            "acknowledged": "delivery_observed",
            "packet_too_large": "kernel_rejected_df_payload",
            "timeout": "inconclusive",
            "socket_error": "socket_error",
        }[observed[0]] if len(observed) == 1 else "mixed_observations"
        summary.append({"payload_bytes": size, "status_counts": counts, "assessment": assessment})
    return summary


def explain_evidence(by_payload_size, dont_fragment):
    """State observations, tentative size patterns and evidence still needed."""
    observations = [
        {"payload_bytes": row["payload_bytes"], "status": status, "attempts": count}
        for row in by_payload_size
        for status, count in row["status_counts"].items()
        if count
    ]
    acknowledged = [row["payload_bytes"] for row in by_payload_size if row["status_counts"]["acknowledged"]]
    timed_out = [row["payload_bytes"] for row in by_payload_size if row["status_counts"]["timeout"]]
    hypotheses = []
    if acknowledged and timed_out and max(acknowledged) < min(timed_out):
        basis = {"largest_acknowledged_payload_bytes": max(acknowledged), "smallest_timed_out_payload_bytes": min(timed_out)}
        hypotheses.append({"code": "size_related_delivery_problem_possible", "basis": basis})
        if dont_fragment:
            hypotheses.append({
                "code": "pmtu_feedback_black_hole_possible",
                "basis": basis,
                "alternatives": ["size_dependent_filtering", "ordinary_packet_loss"],
            })
    missing_evidence = ["same_sized_reverse_payload_test"]
    if timed_out:
        missing_evidence.append("receiver_or_path_packet_observation")
        if dont_fragment:
            missing_evidence.append("icmp_feedback_observation")
    if not dont_fragment:
        missing_evidence.append("controlled_fragmentation_behavior")
    return {"observations": observations, "hypotheses": hypotheses, "missing_evidence": missing_evidence}


def source_snapshot(sock):
    """Capture sender-side route and interface facts after connecting a socket."""
    source = {"ipv4": sock.getsockname()[0]}
    if not sys.platform.startswith("linux"):
        return source
    try:
        source["kernel_route_mtu_bytes"] = sock.getsockopt(socket.IPPROTO_IP, IP_MTU)
    except OSError:
        pass
    try:
        import fcntl
        for _, name in socket.if_nameindex():
            request = struct.pack("256s", name.encode())
            try:
                address = socket.inet_ntoa(fcntl.ioctl(sock.fileno(), SIOCGIFADDR, request)[20:24])
            except OSError:
                continue
            if address == source["ipv4"]:
                source["interface"] = name
                try:
                    source["interface_mtu_bytes"] = struct.unpack_from("I", fcntl.ioctl(sock.fileno(), SIOCGIFMTU, request), 16)[0]
                except OSError:
                    pass
                break
    except OSError:
        pass
    return source


def probe(host, port, sizes, count, timeout, dont_fragment=False):
    require_df_support(dont_fragment)
    address = socket.gethostbyname(host)
    results = []
    source = None
    for size in sizes:
        for attempt in range(1, count + 1):
            token = secrets.token_bytes(16)
            payload = HEADER.pack(MAGIC, token, size) + bytes(size - HEADER.size)
            result = {"payload_bytes": size, "attempt": attempt}
            # A new connected socket isolates replies from earlier attempts.
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                # Configuration failures are fatal, not delivery observations.
                configure_fragmentation(sock, dont_fragment)
                try:
                    sock.connect((address, port))
                    if source is None:
                        source = source_snapshot(sock)
                    start = time.monotonic()
                    deadline = start + timeout
                    sock.send(payload)
                    while True:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise socket.timeout()
                        sock.settimeout(remaining)
                        reply = sock.recv(1024)
                        if reply == HEADER.pack(ACK, token, size):
                            result.update(status="acknowledged", rtt_ms=round((time.monotonic() - start) * 1000, 3))
                            break
                except socket.timeout:
                    result["status"] = "timeout"
                except OSError as error:
                    result.update(socket_failure(error, sock, dont_fragment))
            results.append(result)
            time.sleep(0.05)
    by_payload_size = summarize_results(sizes, results)
    return {
        "schema_version": 1,
        "source": source,
        "target": {"host": host, "ipv4": address, "port": port},
        "settings": {"payload_sizes": sizes, "count": count, "timeout_seconds": timeout, "dont_fragment": dont_fragment},
        "fragmentation": "disabled: Linux IP_PMTUDISC_DO" if dont_fragment else "OS default; fragmentation behavior is not controlled",
        "interpretation": "Acknowledgement confirms delivery and a small reply. Timeout is inconclusive. packet_too_large records EMSGSIZE in DF mode; a kernel-reported MTU is current kernel knowledge, not an independently measured path MTU.",
        "summary": {"by_payload_size": by_payload_size},
        "evidence": explain_evidence(by_payload_size, dont_fragment),
        "results": results,
    }


def combine_reports(a_to_b, b_to_a):
    """Keep two independently gathered directions and their outcomes separate."""
    for label, report in (("a-to-b", a_to_b), ("b-to-a", b_to_a)):
        if not isinstance(report, dict) or report.get("schema_version") != 1:
            raise ValueError(f"{label}: expected a schema_version 1 probe report")
        if not isinstance(report.get("target"), dict) or not isinstance(report.get("results"), list):
            raise ValueError(f"{label}: missing probe target or results")
        summary = report.get("summary")
        if not isinstance(summary, dict) or not isinstance(summary.get("by_payload_size"), list):
            raise ValueError(f"{label}: missing per-size summary")
        if any(
            not isinstance(row, dict)
            or not isinstance(row.get("payload_bytes"), int)
            or not isinstance(row.get("assessment"), str)
            for row in summary["by_payload_size"]
        ):
            raise ValueError(f"{label}: invalid per-size summary")
    sizes = dict.fromkeys(
        row["payload_bytes"]
        for report in (a_to_b, b_to_a)
        for row in report["summary"]["by_payload_size"]
    )
    assessments = []
    for size in sizes:
        row = {"payload_bytes": size}
        for label, report in (("a_to_b", a_to_b), ("b_to_a", b_to_a)):
            match = next((item for item in report["summary"]["by_payload_size"] if item["payload_bytes"] == size), None)
            row[label] = match["assessment"] if match else None
        assessments.append(row)
    first_source, second_source = a_to_b.get("source"), b_to_a.get("source")
    if (isinstance(first_source, dict) and isinstance(second_source, dict)
            and isinstance(first_source.get("ipv4"), str) and isinstance(second_source.get("ipv4"), str)):
        reversed_endpoints = (
            first_source.get("ipv4") == b_to_a["target"].get("ipv4")
            and second_source.get("ipv4") == a_to_b["target"].get("ipv4")
        )
        endpoint_check = "reversed_ipv4_match" if reversed_endpoints else "ipv4_mismatch_or_translation"
    else:
        endpoint_check = "unavailable"
    return {
        "schema_version": 1,
        "kind": "bidirectional_comparison",
        "endpoint_check": endpoint_check,
        "interpretation": "Each direction is a separate delivery experiment. A timeout remains inconclusive; differing outcomes do not by themselves identify the cause.",
        "comparison": {"by_payload_size": assessments},
        "directions": [
            {"direction": "a-to-b", "report": a_to_b},
            {"direction": "b-to-a", "report": b_to_a},
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    receiver = commands.add_parser("receive", help="receive probes and send small acknowledgements")
    receiver.add_argument("--bind", default="127.0.0.1")
    receiver.add_argument("--port", type=bounded_int(0, 65535), default=9471)
    receiver.add_argument("--max-packets", type=bounded_int(1, 1000), default=100)
    receiver.add_argument("--idle-timeout", type=bounded_int(1, 300), default=30)
    sender = commands.add_parser("probe", help="run a bounded delivery experiment")
    sender.add_argument("host")
    sender.add_argument("--port", type=bounded_int(1, 65535), default=9471)
    sender.add_argument("--sizes", type=sizes_arg, default=[64, 512, 1200, 1400])
    sender.add_argument("--count", type=bounded_int(1, 10), default=3)
    sender.add_argument("--timeout", type=bounded_int(1, 5), default=1)
    sender.add_argument("--output", type=Path)
    sender.add_argument("--dont-fragment", action="store_true", help="Linux IPv4 only: set DF and reject datagrams above the known path MTU")
    combined = commands.add_parser("combine", help="combine two independently measured directions")
    combined.add_argument("a_to_b", type=Path, help="probe JSON from endpoint A to B")
    combined.add_argument("b_to_a", type=Path, help="probe JSON from endpoint B to A")
    combined.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "receive":
            receive(args.bind, args.port, args.max_packets, args.idle_timeout)
        elif args.command == "probe":
            require_df_support(args.dont_fragment)
            report = probe(args.host, args.port, args.sizes, args.count, args.timeout, args.dont_fragment)
        else:
            a_to_b = json.loads(args.a_to_b.read_text(encoding="utf-8"))
            b_to_a = json.loads(args.b_to_a.read_text(encoding="utf-8"))
            report = combine_reports(a_to_b, b_to_a)
        if args.command != "receive":
            rendered = json.dumps(report, indent=2)
            if args.output:
                args.output.write_text(rendered + "\n", encoding="utf-8")
            print(rendered)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Error: {error}\n")
    except KeyboardInterrupt:
        parser.exit(130, "Stopped.\n")


if __name__ == "__main__":
    main()

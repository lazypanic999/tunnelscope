"""Small, bounded UDP delivery experiments. This is not an MTU detector yet."""

import argparse
from datetime import datetime, timezone
import errno
import ipaddress
import json
import secrets
import socket
import struct
import sys
import time
from pathlib import Path

MAGIC = b"TS01"
VERSION = "0.4.1"
HEADER = struct.Struct("!4s16sI")
ACK = b"TA01"
# Linux UAPI values, used when Python does not expose the constants.
IP_MTU_DISCOVER = getattr(socket, "IP_MTU_DISCOVER", 10)
IP_PMTUDISC_DO = getattr(socket, "IP_PMTUDISC_DO", 2)
IP_MTU = getattr(socket, "IP_MTU", 14)
IPV6_DONTFRAG = getattr(socket, "IPV6_DONTFRAG", 62)
IPV6_MTU = getattr(socket, "IPV6_MTU", 24)
SIOCGIFADDR = 0x8915
SIOCGIFMTU = 0x8921


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def require_distinct_output(output, *inputs):
    if output is not None and any(output.resolve() == source.resolve() for source in inputs):
        raise ValueError("--output must differ from the input report path")


def require_df_support(dont_fragment):
    if dont_fragment and not sys.platform.startswith("linux"):
        raise ValueError("--dont-fragment currently requires Linux (including WSL2)")


def configure_fragmentation(sock, dont_fragment):
    if dont_fragment:
        # Fail the experiment if the option cannot be enabled; never fall back.
        if sock.family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, IPV6_DONTFRAG, 1)
        else:
            sock.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO)


def socket_failure(error, sock, dont_fragment):
    result = {"status": "socket_error", "error": str(error), "errno": error.errno}
    if dont_fragment and error.errno == errno.EMSGSIZE:
        result["status"] = "packet_too_large"
        try:
            if sock.family == socket.AF_INET6:
                result["kernel_reported_mtu_bytes"] = sock.getsockopt(socket.IPPROTO_IPV6, IPV6_MTU)
            else:
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


def sweep_arg(value):
    """Expand a bounded, inclusive payload-size grid."""
    try:
        start, stop, step = (int(part) for part in value.split(":"))
    except ValueError as error:
        raise argparse.ArgumentTypeError("use START:STOP:STEP for --sweep") from error
    if not (32 <= start < stop <= 8192) or step < 1:
        raise argparse.ArgumentTypeError("sweep needs 32 <= START < STOP <= 8192 and STEP >= 1")
    sizes = list(range(start, stop + 1, step))
    if sizes[-1] != stop:
        sizes.append(stop)
    if len(sizes) > 16:
        raise argparse.ArgumentTypeError("sweep may contain at most 16 payload sizes; increase STEP")
    return sizes


def udp_address(host, port, family="auto"):
    """Keep IPv4 as the hostname default while accepting explicit IPv6 targets."""
    chosen = socket.AF_INET6 if family == "ipv6" or (family == "auto" and ":" in host) else socket.AF_INET
    resolved = socket.getaddrinfo(host, port, chosen, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    return resolved[0][0], resolved[0][4]


def receive(bind, port, max_packets, idle_timeout, output=None, family="auto"):
    observations = []
    exit_reason = "max_packets"
    address_family, bind_address = udp_address(bind, port, family)
    if ipaddress.ip_address(bind_address[0]).is_unspecified:
        raise ValueError("receiver requires an explicit lab interface address; wildcard binds are disabled")
    address_key = "ipv6" if address_family == socket.AF_INET6 else "ipv4"
    with socket.socket(address_family, socket.SOCK_DGRAM) as sock:
        if address_family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind(bind_address)
        sock.settimeout(idle_timeout)
        started_at_utc = utc_now()
        print(f"Listening on {sock.getsockname()[0]}:{sock.getsockname()[1]}", flush=True)
        try:
            for _ in range(max_packets):
                try:
                    data, peer = sock.recvfrom(8193)
                except socket.timeout:
                    exit_reason = "idle_timeout"
                    break
                if not 32 <= len(data) <= 8192:
                    continue
                magic, token, declared_size = HEADER.unpack_from(data)
                if magic != MAGIC or declared_size != len(data):
                    continue
                observation = {
                    "probe_id": token.hex(), "run_id": data[HEADER.size:HEADER.size + 8].hex(),
                    "payload_bytes": len(data), f"source_{address_key}": peer[0],
                    "received_at_utc": utc_now(),
                }
                observations.append(observation)
                # A fixed small acknowledgement does not echo the large payload.
                try:
                    sock.sendto(HEADER.pack(ACK, token, len(data)), peer)
                    observation["ack_send_status"] = "sent"
                except OSError as error:
                    observation["ack_send_status"] = "socket_error"
                    observation["ack_send_errno"] = error.errno
        except KeyboardInterrupt:
            exit_reason = "interrupted"
            raise
        except OSError:
            exit_reason = "socket_error"
            raise
        finally:
            if output is not None:
                report = {
                    "schema_version": 1,
                    "kind": "receiver_observations",
                    "receiver": {f"bind_{address_key}": sock.getsockname()[0],
                                 "port": sock.getsockname()[1]},
                    "started_at_utc": started_at_utc,
                    "finished_at_utc": utc_now(),
                    "exit_reason": exit_reason,
                    "observations": observations,
                    "interpretation": "A received probe confirms arrival at this receiver. A successful send call does not confirm delivery of its acknowledgement.",
                }
                output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


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
    address_key = "ipv6" if sock.family == socket.AF_INET6 else "ipv4"
    local = sock.getsockname()
    source = {address_key: local[0]}
    if sock.family == socket.AF_INET6 and local[3]:
        source["scope_id"] = local[3]
    if not sys.platform.startswith("linux"):
        return source
    try:
        if sock.family == socket.AF_INET6:
            source["kernel_route_mtu_bytes"] = sock.getsockopt(socket.IPPROTO_IPV6, IPV6_MTU)
        else:
            source["kernel_route_mtu_bytes"] = sock.getsockopt(socket.IPPROTO_IP, IP_MTU)
    except OSError:
        pass
    try:
        import fcntl
        if sock.family == socket.AF_INET6:
            address = ipaddress.IPv6Address(local[0].split("%")[0])
            with open("/proc/net/if_inet6", encoding="ascii") as interfaces:
                for line in interfaces:
                    encoded, index, _, _, _, name = line.split()
                    if ipaddress.IPv6Address(int(encoded, 16)) == address and (not local[3] or int(index, 16) == local[3]):
                        source["interface"] = name
                        break
        else:
            for _, name in socket.if_nameindex():
                request = struct.pack("256s", name.encode())
                try:
                    address = socket.inet_ntoa(fcntl.ioctl(sock.fileno(), SIOCGIFADDR, request)[20:24])
                except OSError:
                    continue
                if address == source["ipv4"]:
                    source["interface"] = name
                    break
        if "interface" in source:
            request = struct.pack("256s", source["interface"].encode())
            try:
                source["interface_mtu_bytes"] = struct.unpack_from("I", fcntl.ioctl(sock.fileno(), SIOCGIFMTU, request), 16)[0]
            except OSError:
                pass
    except OSError:
        pass
    return source


def probe(host, port, sizes, count, timeout, dont_fragment=False, family="auto"):
    require_df_support(dont_fragment)
    started_at_utc = utc_now()
    run_id = secrets.token_bytes(8)
    address_family, destination = udp_address(host, port, family)
    address_key = "ipv6" if address_family == socket.AF_INET6 else "ipv4"
    results = []
    source = None
    for size in sizes:
        for attempt in range(1, count + 1):
            token = secrets.token_bytes(16)
            payload = HEADER.pack(MAGIC, token, size) + run_id + bytes(size - HEADER.size - len(run_id))
            result = {"payload_bytes": size, "attempt": attempt, "probe_id": token.hex()}
            # A new connected socket isolates replies from earlier attempts.
            with socket.socket(address_family, socket.SOCK_DGRAM) as sock:
                # Configuration failures are fatal, not delivery observations.
                configure_fragmentation(sock, dont_fragment)
                try:
                    sock.connect(destination)
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
        "kind": "probe",
        "run_id": run_id.hex(),
        "started_at_utc": started_at_utc,
        "finished_at_utc": utc_now(),
        "source": source,
        "target": {"host": host, address_key: destination[0], "port": port},
        "settings": {"payload_sizes": sizes, "count": count, "timeout_seconds": timeout, "dont_fragment": dont_fragment},
        "fragmentation": ("disabled: Linux IPV6_DONTFRAG" if address_family == socket.AF_INET6 else "disabled: Linux IP_PMTUDISC_DO") if dont_fragment else "OS default; fragmentation behavior is not controlled",
        "interpretation": "Acknowledgement confirms delivery and a small reply. Timeout is inconclusive. packet_too_large records EMSGSIZE in DF mode; a kernel-reported MTU is current kernel knowledge, not an independently measured path MTU.",
        "summary": {"by_payload_size": by_payload_size},
        "evidence": explain_evidence(by_payload_size, dont_fragment),
        "results": results,
    }


def correlate_reports(probe_report, receiver_report):
    """Match sent probe IDs to receiver observations without claiming a cause for loss."""
    if not isinstance(probe_report, dict) or probe_report.get("schema_version") != 1 or not isinstance(probe_report.get("results"), list):
        raise ValueError("expected a schema_version 1 probe report")
    if not isinstance(receiver_report, dict) or receiver_report.get("schema_version") != 1 or receiver_report.get("kind") != "receiver_observations" or not isinstance(receiver_report.get("observations"), list):
        raise ValueError("expected a schema_version 1 receiver observations report")
    sent = probe_report["results"]
    received = receiver_report["observations"]
    for row in sent + received:
        if not isinstance(row, dict) or not isinstance(row.get("probe_id"), str) or len(row["probe_id"]) != 32 or not isinstance(row.get("payload_bytes"), int):
            raise ValueError("reports need valid probe IDs and payload sizes")
        try:
            bytes.fromhex(row["probe_id"])
        except ValueError as error:
            raise ValueError("reports need hexadecimal probe IDs") from error
    for row in received:
        value = row.get("run_id")
        if value is not None:
            if not isinstance(value, str) or len(value) != 16:
                raise ValueError("invalid receiver run ID")
            try:
                bytes.fromhex(value)
            except ValueError as error:
                raise ValueError("invalid receiver run ID") from error
    if len({row["probe_id"] for row in sent}) != len(sent) or len({row["probe_id"] for row in received}) != len(received):
        raise ValueError("duplicate probe ID in report")
    run_id = probe_report.get("run_id")
    if run_id is not None:
        if not isinstance(run_id, str) or len(run_id) != 16:
            raise ValueError("invalid probe run ID")
        try:
            bytes.fromhex(run_id)
        except ValueError as error:
            raise ValueError("invalid probe run ID") from error
    receiver_run_ids = {row.get("run_id") for row in received}
    if run_id is None or (received and None in receiver_run_ids):
        run_id_check = "unavailable_legacy_report"
    elif not received:
        run_id_check = "unverified_no_receiver_observations"
    elif run_id not in receiver_run_ids:
        raise ValueError("receiver report has observations from a different run")
    else:
        run_id_check = "matched_with_other_runs" if len(receiver_run_ids) > 1 else "matched"
    observations = {row["probe_id"]: row for row in received}
    sent_ids = {row["probe_id"] for row in sent}
    matched = []
    for row in sent:
        observation = observations.get(row["probe_id"])
        if observation is not None and observation["payload_bytes"] != row["payload_bytes"]:
            raise ValueError("matching probe IDs have different payload sizes")
        if observation is not None and run_id_check in ("matched", "matched_with_other_runs") and observation["run_id"] != run_id:
            raise ValueError("matching probe ID has a different run ID")
        matched.append({
            "probe_id": row["probe_id"],
            "payload_bytes": row["payload_bytes"],
            "sender_status": row.get("status"),
            "receiver_observed": observation is not None,
            "ack_send_status": observation.get("ack_send_status") if observation else None,
        })
    target = probe_report.get("target")
    receiver = receiver_report.get("receiver")
    target = target if isinstance(target, dict) else {}
    receiver = receiver if isinstance(receiver, dict) else {}
    endpoint_checks = {
        "target_port_matches_receiver": target.get("port") == receiver.get("port") if isinstance(target.get("port"), int) and isinstance(receiver.get("port"), int) else None,
    }
    for address_key, wildcard in (("ipv4", "0.0.0.0"), ("ipv6", "::")):
        target_ip, bind_ip = target.get(address_key), receiver.get(f"bind_{address_key}")
        endpoint_checks[f"target_{address_key}_matches_receiver_bind"] = (
            target_ip == bind_ip if isinstance(target_ip, str) and isinstance(bind_ip, str) and bind_ip != wildcard else None
        )
    return {
        "schema_version": 1,
        "kind": "probe_receiver_correlation",
        "pairing": {
            "run_id_check": run_id_check,
            "endpoint_checks": endpoint_checks,
            "probe_window_utc": [probe_report.get("started_at_utc"), probe_report.get("finished_at_utc")],
            "receiver_window_utc": [receiver_report.get("started_at_utc"), receiver_report.get("finished_at_utc")],
            "clock_comparison": "not_performed; clocks on different hosts may be unsynchronized",
        },
        "interpretation": "Receiver observation confirms forward arrival. No matching observation is inconclusive unless capture coverage is independently established. A sent acknowledgement does not prove return delivery.",
        "summary": {
            "sent_probes": len(sent),
            "receiver_observed": sum(row["receiver_observed"] for row in matched),
            "timed_out_but_receiver_observed": sum(row["sender_status"] == "timeout" and row["receiver_observed"] for row in matched),
            "unmatched_receiver_observations": len(observations.keys() - sent_ids),
        },
        "results": matched,
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
    endpoint_check = "unavailable"
    if isinstance(first_source, dict) and isinstance(second_source, dict):
        for address_key in ("ipv4", "ipv6"):
            first, second = first_source.get(address_key), second_source.get(address_key)
            if isinstance(first, str) and isinstance(second, str):
                reversed_endpoints = (
                    first == b_to_a["target"].get(address_key)
                    and second == a_to_b["target"].get(address_key)
                )
                endpoint_check = (f"reversed_{address_key}_match" if reversed_endpoints
                                  else f"{address_key}_mismatch_or_translation")
                break
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


def text_table(headers, rows):
    cells = [[str(value) for value in row] for row in rows]
    widths = [max([len(header), *(len(row[index]) for row in cells)]) for index, header in enumerate(headers)]
    def line(values):
        return "  ".join(value.ljust(width) for value, width in zip(values, widths))
    return "\n".join([line(headers), line(["-" * width for width in widths]), *(line(row) for row in cells)])


def format_report(report):
    """Render existing JSON evidence as a compact terminal view."""
    if isinstance(report, dict) and isinstance(report.get("lab"), str):
        for key in ("correlation", "probe"):
            if isinstance(report.get(key), dict):
                return f"Lab: {report['lab']}\n" + format_report(report[key])
    if not isinstance(report, dict) or report.get("schema_version") != 1:
        raise ValueError("expected a schema_version 1 TunnelScope report")
    kind = report.get("kind", "probe")
    if kind == "probe":
        summary = report.get("summary")
        rows = summary.get("by_payload_size") if isinstance(summary, dict) else None
        if not isinstance(rows, list):
            raise ValueError("probe report has no per-size summary")
        values = []
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("status_counts"), dict):
                raise ValueError("invalid probe size summary")
            counts = row["status_counts"]
            values.append((row.get("payload_bytes", "?"), counts.get("acknowledged", 0),
                           counts.get("packet_too_large", 0), counts.get("timeout", 0),
                           counts.get("socket_error", 0), row.get("assessment", "?")))
        return "Probe results (UDP payload bytes)\n" + text_table(
            ["Bytes", "Ack", "Too large", "Timeout", "Error", "Assessment"], values
        ) + "\nTimeouts are inconclusive; an ACK confirms delivery and a small reply."
    if kind == "receiver_observations":
        observations = report.get("observations")
        if not isinstance(observations, list) or any(not isinstance(row, dict) for row in observations):
            raise ValueError("receiver report has no valid observations")
        counts = {}
        for row in observations:
            run_id, size = row.get("run_id") or "unknown", row.get("payload_bytes")
            if not isinstance(run_id, str) or not isinstance(size, int):
                raise ValueError("invalid receiver observation")
            key = (run_id, size)
            if key not in counts:
                counts[key] = {"observed": 0, "ack_sent": 0, "ack_errors": 0}
            counts[key]["observed"] += 1
            if row.get("ack_send_status") == "sent":
                counts[key]["ack_sent"] += 1
            elif row.get("ack_send_status") == "socket_error":
                counts[key]["ack_errors"] += 1
        values = [(run_id, size, item["observed"], item["ack_sent"], item["ack_errors"])
                  for (run_id, size), item in sorted(counts.items())]
        return (f"Receiver observations: {len(observations)} probes; exit: {report.get('exit_reason', 'unknown')}\n"
                + text_table(["Run ID", "Bytes", "Seen", "ACK sent", "ACK error"], values)
                + "\nACK sent means the local socket accepted the reply, not that it arrived.")
    if kind == "bidirectional_comparison":
        comparison = report.get("comparison")
        rows = comparison.get("by_payload_size") if isinstance(comparison, dict) else None
        if not isinstance(rows, list):
            raise ValueError("comparison report has no per-size summary")
        if any(not isinstance(row, dict) for row in rows):
            raise ValueError("invalid comparison size summary")
        values = [(row.get("payload_bytes", "?"), row.get("a_to_b") or "-", row.get("b_to_a") or "-")
                  for row in rows]
        return "Bidirectional comparison\n" + text_table(["Bytes", "A to B", "B to A"], values) + \
            "\nEach direction is a separate experiment; timeouts remain inconclusive."
    if kind == "probe_receiver_correlation":
        summary, rows = report.get("summary"), report.get("results")
        if not isinstance(summary, dict) or not isinstance(rows, list):
            raise ValueError("correlation report has no results")
        if any(not isinstance(row, dict) for row in rows):
            raise ValueError("invalid correlation result")
        values = [(row.get("payload_bytes", "?"), row.get("sender_status", "?"),
                   "yes" if row.get("receiver_observed") else "no", row.get("ack_send_status") or "-")
                  for row in rows]
        pairing = report.get("pairing")
        run_check = pairing.get("run_id_check", "unavailable") if isinstance(pairing, dict) else "unavailable"
        return (f"Correlation: {summary.get('receiver_observed', '?')}/{summary.get('sent_probes', '?')} observed at receiver; "
                f"{summary.get('timed_out_but_receiver_observed', '?')} timed out after arrival; "
                f"{summary.get('unmatched_receiver_observations', '?')} unmatched receiver observations; run ID: {run_check}\n"
                + text_table(["Bytes", "Sender", "Receiver saw", "ACK send"], values)
                + "\nNo receiver observation is inconclusive without confirmed capture coverage.")
    raise ValueError(f"unsupported report kind: {kind}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=f"TunnelScope {VERSION}")
    commands = parser.add_subparsers(dest="command", required=True)
    receiver = commands.add_parser("receive", help="receive probes and send small acknowledgements")
    receiver.add_argument("--bind", default="127.0.0.1")
    receiver.add_argument("--family", choices=("auto", "ipv4", "ipv6"), default="auto",
                          help="address family; auto treats an IPv6 literal as IPv6")
    receiver.add_argument("--port", type=bounded_int(0, 65535), default=9471)
    receiver.add_argument("--max-packets", type=bounded_int(1, 1000), default=100)
    receiver.add_argument("--idle-timeout", type=bounded_int(1, 300), default=30)
    receiver.add_argument("--output", type=Path, help="save observed probe IDs as JSON when the receiver exits")
    sender = commands.add_parser("probe", help="run a bounded delivery experiment")
    sender.add_argument("host")
    sender.add_argument("--family", choices=("auto", "ipv4", "ipv6"), default="auto",
                        help="address family; auto prefers IPv4 for hostnames")
    sender.add_argument("--port", type=bounded_int(1, 65535), default=9471)
    size_options = sender.add_mutually_exclusive_group()
    size_options.add_argument("--sizes", type=sizes_arg, help="comma-separated UDP payload sizes (default: 64,512,1200,1400)")
    size_options.add_argument("--sweep", type=sweep_arg, metavar="START:STOP:STEP",
                              help="inclusive size grid with at most 16 points; always includes STOP")
    sender.add_argument("--count", type=bounded_int(1, 10), default=3)
    sender.add_argument("--timeout", type=bounded_int(1, 5), default=1)
    sender.add_argument("--output", type=Path)
    sender.add_argument("--dont-fragment", action="store_true", help="Linux: prevent IPv4 or IPv6 fragmentation")
    combined = commands.add_parser("combine", help="combine two independently measured directions")
    combined.add_argument("a_to_b", type=Path, help="probe JSON from endpoint A to B")
    combined.add_argument("b_to_a", type=Path, help="probe JSON from endpoint B to A")
    combined.add_argument("--output", type=Path)
    correlated = commands.add_parser("correlate", help="match a probe report with receiver observations")
    correlated.add_argument("probe_report", type=Path)
    correlated.add_argument("receiver_report", type=Path)
    correlated.add_argument("--output", type=Path)
    shown = commands.add_parser("show", help="print a concise summary of a JSON report")
    shown.add_argument("report", type=Path)
    html_view = commands.add_parser("html", help="write a searchable local HTML view of a JSON report")
    html_view.add_argument("report", type=Path)
    html_view.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "receive":
            receive(args.bind, args.port, args.max_packets, args.idle_timeout, args.output, args.family)
        elif args.command == "probe":
            require_df_support(args.dont_fragment)
            sizes = args.sweep if args.sweep is not None else args.sizes
            report = probe(args.host, args.port, sizes if sizes is not None else [64, 512, 1200, 1400],
                           args.count, args.timeout, args.dont_fragment, args.family)
        elif args.command == "combine":
            require_distinct_output(args.output, args.a_to_b, args.b_to_a)
            a_to_b = json.loads(args.a_to_b.read_text(encoding="utf-8"))
            b_to_a = json.loads(args.b_to_a.read_text(encoding="utf-8"))
            report = combine_reports(a_to_b, b_to_a)
        elif args.command == "show":
            print(format_report(json.loads(args.report.read_text(encoding="utf-8"))))
        elif args.command == "html":
            require_distinct_output(args.output, args.report)
            from tunnelscope_view import render_report_html
            args.output.write_text(
                render_report_html(json.loads(args.report.read_text(encoding="utf-8"))),
                encoding="utf-8",
            )
            print(f"Wrote {args.output}")
        else:
            require_distinct_output(args.output, args.probe_report, args.receiver_report)
            probe_report = json.loads(args.probe_report.read_text(encoding="utf-8"))
            receiver_report = json.loads(args.receiver_report.read_text(encoding="utf-8"))
            report = correlate_reports(probe_report, receiver_report)
        if args.command not in ("receive", "show", "html"):
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

"""UDP probe and receiver implementation."""

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

from .icmp import drain_error_queue, enable_error_queue, require_icmp_support

MAGIC = b"TS01"
VERSION = "0.6.0.dev0"
HEADER = struct.Struct("!4s16sI")
ACK = b"TA01"
# Linux UAPI values, used when Python does not expose the constants.
IP_MTU_DISCOVER = getattr(socket, "IP_MTU_DISCOVER", 10)
IP_PMTUDISC_DO = getattr(socket, "IP_PMTUDISC_DO", 2)
IP_PMTUDISC_DONT = getattr(socket, "IP_PMTUDISC_DONT", 0)
IP_MTU = getattr(socket, "IP_MTU", 14)
IPV6_DONTFRAG = getattr(socket, "IPV6_DONTFRAG", 62)
IPV6_MTU = getattr(socket, "IPV6_MTU", 24)
SIOCGIFADDR = 0x8915
SIOCGIFMTU = 0x8921


from .reports import summarize_results, explain_evidence


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def require_df_support(dont_fragment):
    if dont_fragment and not sys.platform.startswith("linux"):
        raise ValueError("--dont-fragment currently requires Linux (including WSL2)")


def configure_fragmentation(sock, dont_fragment, allow_fragmentation=False):
    if dont_fragment and allow_fragmentation:
        raise ValueError("fragmentation modes are mutually exclusive")
    if dont_fragment:
        # Fail the experiment if the option cannot be enabled; never fall back.
        if sock.family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, IPV6_DONTFRAG, 1)
        else:
            sock.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO)
    elif allow_fragmentation:
        if sock.family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, IPV6_DONTFRAG, 0)
        else:
            sock.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DONT)


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


def probe(host, port, sizes, count, timeout, dont_fragment=False, family="auto",
          search_bounds=None, max_sizes=16, allow_fragmentation=False,
          observe_icmp=False):
    require_df_support(dont_fragment or allow_fragmentation)
    require_icmp_support(observe_icmp)
    if dont_fragment and allow_fragmentation:
        raise ValueError("fragmentation modes are mutually exclusive")
    if search_bounds is not None:
        if not dont_fragment:
            raise ValueError("size search requires Linux no-fragment mode")
        minimum, maximum = search_bounds
        if not 32 <= minimum < maximum <= 8192 or not 2 <= max_sizes <= 16:
            raise ValueError("search needs 32 <= MIN < MAX <= 8192 and 2..16 tested sizes")
        if max_sizes * count > 100 or max_sizes * count * timeout > 120:
            raise ValueError("search budget exceeds 100 probes or 120 seconds of timeout allowance")
        sizes = [minimum, maximum]
        from .search import assess_search
    else:
        sizes = list(sizes)
    started_at_utc = utc_now()
    run_id = secrets.token_bytes(8)
    address_family, destination = udp_address(host, port, family)
    address_key = "ipv6" if address_family == socket.AF_INET6 else "ipv4"
    results = []
    source = None
    size_index = 0
    search_summary = None
    while size_index < len(sizes):
        size = sizes[size_index]
        for attempt in range(1, count + 1):
            token = secrets.token_bytes(16)
            payload = HEADER.pack(MAGIC, token, size) + run_id + bytes(size - HEADER.size - len(run_id))
            result = {"payload_bytes": size, "attempt": attempt, "probe_id": token.hex()}
            # A new connected socket isolates replies from earlier attempts.
            with socket.socket(address_family, socket.SOCK_DGRAM) as sock:
                # Configuration failures are fatal, not delivery observations.
                configure_fragmentation(sock, dont_fragment, allow_fragmentation)
                if observe_icmp:
                    enable_error_queue(sock)
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
                if observe_icmp:
                    result["icmp_observation"] = drain_error_queue(
                        sock, HEADER.pack(MAGIC, token, size)
                    )
                    if result.get("status") == "packet_too_large":
                        events = result["icmp_observation"]["events"]
                        result["size_error_origin"] = (
                            "network_icmp_feedback" if any(
                                event.get("message") in ("fragmentation_needed", "packet_too_big")
                                and event.get("quoted_probe_match") is not False for event in events
                            ) else "local" if any(event.get("origin") == "local" for event in events)
                            else "unknown"
                        )
            results.append(result)
            time.sleep(0.05)
        size_index += 1
        if search_bounds is not None:
            next_size, search_summary = assess_search(
                minimum, maximum, summarize_results(sizes[:size_index], results), max_sizes
            )
            if next_size is not None:
                sizes.append(next_size)
    by_payload_size = summarize_results(sizes, results)
    summary = {"by_payload_size": by_payload_size}
    if observe_icmp:
        observations = [row["icmp_observation"] for row in results]
        events = [event for observation in observations for event in observation["events"]]
        size_feedback = [event for event in events
                         if event.get("message") in ("fragmentation_needed", "packet_too_big")
                         and event.get("quoted_probe_match") is not False]
        summary["icmp_feedback"] = {
            "observation_state": ("complete" if all(row["state"] == "completed" for row in observations)
                                  else "partial"),
            "size_feedback_events": len(size_feedback),
            "token_matched_size_feedback_events": sum(event.get("quoted_probe_match") is True
                                                      for event in size_feedback),
            "local_error_events": sum(event.get("origin") == "local" for event in events),
            "other_or_unparsed_events": len(events) - len(size_feedback)
                                        - sum(event.get("origin") == "local" for event in events),
        }
    if search_summary is not None:
        summary["search"] = search_summary
    return {
        "schema_version": 1,
        "kind": "probe",
        "run_id": run_id.hex(),
        "started_at_utc": started_at_utc,
        "finished_at_utc": utc_now(),
        "source": source,
        "target": {"host": host, address_key: destination[0], "port": port},
        "settings": {"payload_sizes": sizes, "count": count, "timeout_seconds": timeout,
                     "dont_fragment": dont_fragment, "observe_icmp": observe_icmp},
        "fragmentation_mode": "df" if dont_fragment else "permitted" if allow_fragmentation else "os_default",
        "fragmentation": (("disabled: Linux IPV6_DONTFRAG" if address_family == socket.AF_INET6 else "disabled: Linux IP_PMTUDISC_DO") if dont_fragment else
                          ("permitted: Linux IPV6_DONTFRAG=0" if address_family == socket.AF_INET6 else "permitted: Linux IP_PMTUDISC_DONT") if allow_fragmentation else
                          "OS default; fragmentation behavior is not controlled"),
        "interpretation": "Acknowledgement confirms delivery and a small reply. Timeout is inconclusive. packet_too_large records EMSGSIZE in DF mode; a kernel-reported MTU is current kernel knowledge, not an independently measured path MTU. ICMP error-queue observations are untrusted network feedback, not independent proof of the path or sender identity.",
        "summary": summary,
        "evidence": explain_evidence(by_payload_size, dont_fragment),
        "results": results,
    }


def compare_fragmentation(host, port, sizes, count, timeout, family="auto"):
    """Measure each configured size with DF and source fragmentation permitted."""
    require_df_support(True)
    sizes = list(sizes)
    if not 1 <= len(sizes) <= 16 or any(not 32 <= size <= 8192 for size in sizes):
        raise ValueError("comparison needs 1..16 payload sizes of 32..8192 bytes")
    if len(set(sizes)) != len(sizes):
        raise ValueError("comparison needs distinct payload sizes")
    if not 1 <= count <= 10 or not 1 <= timeout <= 5:
        raise ValueError("comparison count or timeout is outside CLI bounds")
    if 2 * len(sizes) * count > 100 or 2 * len(sizes) * count * timeout > 120:
        raise ValueError("comparison budget exceeds 100 probes or 120 seconds of timeout allowance")
    df = probe(host, port, sizes, count, timeout, True, family)
    permitted = probe(host, port, sizes, count, timeout, False, family,
                      allow_fragmentation=True)
    from .fragmentation import compare_fragmentation_reports
    return compare_fragmentation_reports(df, permitted)

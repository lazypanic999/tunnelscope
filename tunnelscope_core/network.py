"""UDP probe and receiver implementation."""

import argparse
from datetime import datetime, timezone
import errno
import ipaddress
import json
import os
import secrets
import socket
import struct
import sys
import time
from pathlib import Path

from .icmp import drain_error_queue, enable_error_queue, require_icmp_support
from ._version import VERSION

MAGIC = b"TS01"
HEADER = struct.Struct("!4s16sI")
ACK = b"TA01"
# v0.7: a probe asks for a same-sized reply with this marker after its run ID.
# Receivers without --sized-reply (and v0.6 receivers) keep sending ACK.
REPLY_REQUEST = b"SR01"
SIZED_ACK = b"TA02"
SIZED_REPLY_MIN_BYTES = HEADER.size + 8 + len(REPLY_REQUEST)
# Linux UAPI values, used when Python does not expose the constants.
IP_MTU_DISCOVER = getattr(socket, "IP_MTU_DISCOVER", 10)
IP_PMTUDISC_DO = getattr(socket, "IP_PMTUDISC_DO", 2)
IP_PMTUDISC_DONT = getattr(socket, "IP_PMTUDISC_DONT", 0)
IP_MTU = getattr(socket, "IP_MTU", 14)
IPV6_DONTFRAG = getattr(socket, "IPV6_DONTFRAG", 62)
IPV6_MTU = getattr(socket, "IPV6_MTU", 24)
# Winsock values (ws2ipdef.h); Python does not export IP_DONTFRAGMENT on Windows.
WINDOWS_IP_DONTFRAGMENT = 14
WINDOWS_IPV6_DONTFRAG = 14
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


def sized_reply_for(data):
    """Return a reply of the same length as the probe, or None if it was not requested."""
    if len(data) < SIZED_REPLY_MIN_BYTES or data[HEADER.size + 8:SIZED_REPLY_MIN_BYTES] != REPLY_REQUEST:
        return None
    _, token, size = HEADER.unpack_from(data)
    reply = HEADER.pack(SIZED_ACK, token, size) + data[HEADER.size:HEADER.size + 8]
    return reply + bytes(len(data) - len(reply))


def disable_reply_fragmentation(sock):
    """Make oversized sized replies fail instead of being fragmented; return how it was done."""
    if sys.platform.startswith("linux"):
        configure_fragmentation(sock, True)
        return ("disabled: Linux IPV6_DONTFRAG" if sock.family == socket.AF_INET6
                else "disabled: Linux IP_PMTUDISC_DO")
    if sys.platform == "win32":
        # Fail the receiver if the option cannot be set; never fall back.
        if sock.family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, WINDOWS_IPV6_DONTFRAG, 1)
            return "disabled: Windows IPV6_DONTFRAG"
        sock.setsockopt(socket.IPPROTO_IP, WINDOWS_IP_DONTFRAGMENT, 1)
        return "disabled: Windows IP_DONTFRAGMENT"
    raise ValueError("--sized-reply currently requires Linux (including WSL2) or Windows")


def receive(bind, port, max_packets, idle_timeout, output=None, family="auto", sized_reply=False):
    if sized_reply and not (sys.platform.startswith("linux") or sys.platform == "win32"):
        raise ValueError("--sized-reply currently requires Linux (including WSL2) or Windows")
    observations = []
    exit_reason = "max_packets"
    address_family, bind_address = udp_address(bind, port, family)
    if ipaddress.ip_address(bind_address[0]).is_unspecified:
        raise ValueError("receiver requires an explicit lab interface address; wildcard binds are disabled")
    address_key = "ipv6" if address_family == socket.AF_INET6 else "ipv4"
    with socket.socket(address_family, socket.SOCK_DGRAM) as sock:
        if address_family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        reply_fragmentation = None
        if sized_reply:
            # Oversized replies must fail visibly instead of being fragmented.
            reply_fragmentation = disable_reply_fragmentation(sock)
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
                # By default a fixed small acknowledgement does not echo the payload.
                # With --sized-reply, a requesting probe gets a reply of its own size,
                # never larger, so the receiver does not amplify traffic.
                reply = sized_reply_for(data) if sized_reply else None
                if reply is None:
                    reply = HEADER.pack(ACK, token, len(data))
                else:
                    observation["reply_kind"] = "sized"
                observation["reply_bytes"] = len(reply)
                try:
                    sock.sendto(reply, peer)
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
                local = sock.getsockname()
                receiver = {f"bind_{address_key}": local[0], "port": local[1]}
                if sock.family == socket.AF_INET6 and local[3]:
                    receiver["scope_id"] = local[3]
                if sized_reply:
                    receiver["sized_reply"] = True
                    receiver["reply_fragmentation"] = reply_fragmentation
                report = {
                    "schema_version": 1,
                    "kind": "receiver_observations",
                    "tunnelscope_version": VERSION,
                    "receiver": receiver,
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
            with open("/proc/net/if_inet6", "rb") as interfaces:
                for line in interfaces:
                    encoded, index, _, _, _, name = line.split()
                    if ipaddress.IPv6Address(int(encoded, 16)) == address and (not local[3] or int(index, 16) == local[3]):
                        source["interface"] = os.fsdecode(name)
                        break
        else:
            for _, name in socket.if_nameindex():
                request = struct.pack("256s", os.fsencode(name))
                try:
                    address = socket.inet_ntoa(fcntl.ioctl(sock.fileno(), SIOCGIFADDR, request)[20:24])
                except OSError:
                    continue
                if address == source["ipv4"]:
                    source["interface"] = name
                    break
        if "interface" in source:
            request = struct.pack("256s", os.fsencode(source["interface"]))
            try:
                source["interface_mtu_bytes"] = struct.unpack_from("I", fcntl.ioctl(sock.fileno(), SIOCGIFMTU, request), 16)[0]
            except OSError:
                pass
    except OSError:
        pass
    return source


def probe(host, port, sizes, count, timeout, dont_fragment=False, family="auto",
          search_bounds=None, max_sizes=16, allow_fragmentation=False,
          observe_icmp=False, sized_reply=False):
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
    if sized_reply and min(sizes) < SIZED_REPLY_MIN_BYTES:
        raise ValueError(f"--sized-reply needs payload sizes of at least {SIZED_REPLY_MIN_BYTES} bytes")
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
            payload = HEADER.pack(MAGIC, token, size) + run_id + (REPLY_REQUEST if sized_reply else b"")
            payload += bytes(size - len(payload))
            small_ack = HEADER.pack(ACK, token, size)
            sized_ack = sized_reply_for(payload) if sized_reply else None
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
                    result["send_attempted_at_utc"] = utc_now()
                    sock.send(payload)
                    while True:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise socket.timeout()
                        sock.settimeout(remaining)
                        reply = sock.recv(8193)
                        if reply == small_ack or (sized_ack is not None and reply == sized_ack):
                            result.update(status="acknowledged", rtt_ms=round((time.monotonic() - start) * 1000, 3),
                                          ack_received_at_utc=utc_now())
                            if sized_reply:
                                result.update(reply_bytes=len(reply), return_status=(
                                    "sized_reply_received" if reply == sized_ack else "ack_received"))
                            break
                    if observe_icmp:
                        result.update(drain_error_queue(sock))
                except socket.timeout:
                    result.update(status="timeout", return_status="no_reply")
                    if observe_icmp:
                        result.update(drain_error_queue(sock))
                except OSError as error:
                    result.update(socket_failure(error, sock, dont_fragment))
                    result["return_status"] = "send_error"
            results.append(result)
        if search_bounds is not None:
            search_summary = assess_search(sizes, results, max_sizes)
            if search_summary["next_size"] is None:
                break
            sizes.append(search_summary["next_size"])
        size_index += 1
    return {
        "schema_version": 1, "kind": "probe", "tunnelscope_version": VERSION,
        "run_id": run_id.hex(), "started_at_utc": started_at_utc, "finished_at_utc": utc_now(),
        "target": {address_key: destination[0], "port": destination[1]},
        "source": source or {},
        "settings": {"payload_sizes": sizes, "count": count, "timeout_seconds": timeout,
                     "dont_fragment": dont_fragment, "sized_reply": sized_reply},
        "fragmentation_mode": ("df" if dont_fragment else "permitted" if allow_fragmentation else "default"),
        "results": results,
        "summary": summarize_results(sizes, results),
        "search": search_summary,
        "interpretation": explain_evidence(results),
    }


def compare_fragmentation(host, port, sizes, count, timeout, family="auto",
                          observe_icmp=False, sized_reply=False):
    df = probe(host, port, sizes, count, timeout, dont_fragment=True, family=family,
               observe_icmp=observe_icmp, sized_reply=sized_reply)
    permitted = probe(host, port, sizes, count, timeout, allow_fragmentation=True, family=family,
                      observe_icmp=observe_icmp, sized_reply=sized_reply)
    from .fragmentation import compare_fragmentation_reports
    return compare_fragmentation_reports(df, permitted)

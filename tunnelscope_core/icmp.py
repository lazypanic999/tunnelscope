"""Optional Linux UDP error-queue observations without raw sockets."""

import errno
import socket
import struct
import sys


# Linux UAPI values are not consistently exposed by Python's socket module.
IP_RECVERR = getattr(socket, "IP_RECVERR", 11)
IPV6_RECVERR = getattr(socket, "IPV6_RECVERR", 25)
EXTENDED_ERROR = struct.Struct("=IBBBBII")
MAX_ERROR_QUEUE_ENTRIES = 8


def require_icmp_support(enabled):
    if enabled and (not sys.platform.startswith("linux") or
                    not hasattr(socket.socket, "recvmsg") or
                    not hasattr(socket, "MSG_ERRQUEUE") or
                    not hasattr(socket, "MSG_DONTWAIT") or
                    not hasattr(socket, "CMSG_SPACE")):
        raise ValueError("--observe-icmp requires Linux UDP error-queue support")


def enable_error_queue(sock):
    if sock.family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, IPV6_RECVERR, 1)
    else:
        sock.setsockopt(socket.IPPROTO_IP, IP_RECVERR, 1)


def _decode_event(data, ancillary, flags, family, expected_header):
    level, option = ((socket.IPPROTO_IPV6, IPV6_RECVERR) if family == socket.AF_INET6
                     else (socket.IPPROTO_IP, IP_RECVERR))
    for cmsg_level, cmsg_type, cmsg_data in ancillary:
        if cmsg_level != level or cmsg_type != option or len(cmsg_data) < EXTENDED_ERROR.size:
            continue
        error_number, origin, icmp_type, icmp_code, _, info, _ = EXTENDED_ERROR.unpack_from(cmsg_data)
        origin_name = {1: "local", 2: "icmpv4", 3: "icmpv6"}.get(origin, "unknown")
        is_ptb = ((family == socket.AF_INET and origin == 2 and icmp_type == 3 and icmp_code == 4) or
                  (family == socket.AF_INET6 and origin == 3 and icmp_type == 2 and icmp_code == 0))
        event = {
            "origin": origin_name,
            "errno": error_number,
            "message": ("fragmentation_needed" if family == socket.AF_INET else "packet_too_big")
                       if is_ptb else "other_icmp" if origin in (2, 3) else "local_error" if origin == 1 else "unknown_error",
            "quoted_probe_match": data.startswith(expected_header) if len(data) >= len(expected_header) else None,
        }
        if origin in (2, 3):
            event["icmp_type"] = icmp_type
            event["icmp_code"] = icmp_code
        if error_number == errno.EMSGSIZE and info:
            event["reported_mtu_bytes"] = info
        if flags & getattr(socket, "MSG_CTRUNC", 0):
            event["control_truncated"] = True
        return event
    return {"message": "unparsed_error_queue_entry", "quoted_probe_match": None,
            "control_truncated": bool(flags & getattr(socket, "MSG_CTRUNC", 0))}


def drain_error_queue(sock, expected_header):
    """Return bounded observations and whether reading completed cleanly."""
    events = []
    previous_timeout = sock.gettimeout()
    sock.setblocking(False)
    try:
        for _ in range(MAX_ERROR_QUEUE_ENTRIES):
            try:
                data, ancillary, flags, _ = sock.recvmsg(
                    8192, socket.CMSG_SPACE(128), socket.MSG_ERRQUEUE | socket.MSG_DONTWAIT
                )
            except OSError as error:
                if error.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    complete = all(event.get("message") != "unparsed_error_queue_entry"
                                   and not event.get("control_truncated") for event in events)
                    return {"state": "completed" if complete else "partial", "events": events}
                return {"state": "read_error", "events": events,
                        "errno": error.errno, "error": str(error)}
            events.append(_decode_event(data, ancillary, flags, sock.family, expected_header))
        return {"state": "limit_reached", "events": events}
    finally:
        sock.settimeout(previous_timeout)

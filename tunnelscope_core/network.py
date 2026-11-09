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
WSAEMSGSIZE = 10040
# Windows does not interrupt a blocking socket wait for Ctrl+C, so the receiver
# waits in short slices there and checks its own idle deadline.
WINDOWS_RECV_SLICE_SECONDS = 0.25
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
    try:
        resolved = socket.getaddrinfo(host, port, chosen, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    except socket.gaierror as error:
        wanted = "IPv6" if chosen == socket.AF_INET6 else "IPv4"
        hint = ""
        try:
            literal = ipaddress.ip_address(host.split("%")[0])
        except ValueError:
            literal = None
        if literal is not None and literal.version != (6 if chosen == socket.AF_INET6 else 4):
            hint = f"; {host} is an IPv{literal.version} address, so drop --family or use --family ipv{literal.version}"
        raise ValueError(f"cannot resolve {host!r} to an {wanted} address ({error.strerror}){hint}") from error
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


def live_line(observation):
    """One terminal line per accepted probe, written after its reply attempt."""
    source = observation.get("source_ipv4") or observation.get("source_ipv6")
    kind = "sized reply" if observation.get("reply_kind") == "sized" else "ACK"
    if observation.get("ack_send_status") == "sent":
        outcome = f"{kind} sent ({observation['reply_bytes']} bytes)"
    else:
        outcome = f"{kind} send failed (errno {observation.get('ack_send_errno')})"
    return (f"{observation['payload_bytes']:>5} bytes from {source}  run {observation['run_id'][:8]}  "
            f"probe {observation['probe_id'][:8]}  {outcome}")


def live_print(line):
    """Print a progress line; return False if stdout is gone so callers stop trying.

    A closed or broken stdout must never end a capture.
    """
    try:
        print(line, flush=True)
        return True
    except (OSError, ValueError):
        return False


def receive(bind, port, max_packets, idle_timeout, output=None, family="auto", sized_reply=False,
            live=False):
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
        sliced = sys.platform == "win32"
        sock.settimeout(idle_timeout)
        started_at_utc = utc_now()
        print(f"Listening on {sock.getsockname()[0]}:{sock.getsockname()[1]}", flush=True)
        if live and output is not None:
            live = live_print(f"Saving to {output} on exit; press Ctrl+C once to stop early.")
        try:
            received = 0
            idle_deadline = time.monotonic() + idle_timeout
            while received < max_packets:
                if sliced:
                    remaining = idle_deadline - time.monotonic()
                    if remaining <= 0:
                        exit_reason = "idle_timeout"
                        break
                    sock.settimeout(min(WINDOWS_RECV_SLICE_SECONDS, remaining))
                try:
                    data, peer = sock.recvfrom(8193)
                except socket.timeout:
                    if sliced:
                        continue  # the deadline check above decides
                    exit_reason = "idle_timeout"
                    break
                except ConnectionResetError:
                    # Windows reports an ICMP port unreachable for an earlier reply
                    # (for example a late ACK to a probe socket that already timed
                    # out) as WSAECONNRESET on the next receive. It is not a probe.
                    if sys.platform != "win32":
                        raise
                    continue
                except OSError as error:
                    # Windows fails a receive with WSAEMSGSIZE when a datagram is
                    # larger than the buffer, where Linux truncates it. Either way
                    # it is too large to be a probe; count it and keep listening.
                    if sys.platform != "win32" or getattr(error, "winerror", None) != WSAEMSGSIZE:
                        raise
                    received += 1
                    idle_deadline = time.monotonic() + idle_timeout
                    continue
                received += 1
                idle_deadline = time.monotonic() + idle_timeout
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
                if live:
                    live = live_print(live_line(observation))
        except KeyboardInterrupt:
            exit_reason = "interrupted"
            raise
        except OSError:
            exit_reason = "socket_error"
            raise
        finally:
            if output is not None:
                # A second Ctrl+C while saving must not lose the capture. Finish
                # the write, then let the interrupt through.
                interrupted_while_saving = False
                for _ in range(5):
                    try:
                        save_receiver_report(output, sock, address_key, sized_reply, reply_fragmentation,
                                             started_at_utc, exit_reason, observations)
                        if live:
                            count = len(observations)
                            live_print(f"Saved {output}: {count} probe{'' if count == 1 else 's'}; "
                                       f"exit: {exit_reason}")
                        break
                    except KeyboardInterrupt:
                        interrupted_while_saving = True
                if interrupted_while_saving:
                    raise KeyboardInterrupt


def save_receiver_report(output, sock, address_key, sized_reply, reply_fragmentation,
                         started_at_utc, exit_reason, observations):
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


def attempt_line(result, count, mode):
    """One progress line per sender attempt; the JSON report stays the record."""
    status = result.get("status")
    if status == "acknowledged":
        outcome = f"acknowledged in {result.get('rtt_ms')} ms"
    elif status == "packet_too_large":
        mtu = result.get("kernel_reported_mtu_bytes")
        outcome = "packet_too_large" + (f" (kernel MTU {mtu})" if mtu is not None else "")
    elif status == "socket_error":
        outcome = f"socket_error (errno {result.get('errno')})"
    else:
        outcome = str(status)
    return_status = {"sized_reply_received": "sized reply received", "small_ack_only": "small ACK only",
                     "no_reply": None}.get(result.get("return_status"))
    if return_status and status == "acknowledged":
        outcome += f", {return_status}"
    return (f"{result['payload_bytes']:>5} bytes  attempt {result['attempt']}/{count}  {mode:<10}  {outcome}")


def probe(host, port, sizes, count, timeout, dont_fragment=False, family="auto",
          search_bounds=None, max_sizes=16, allow_fragmentation=False,
          observe_icmp=False, sized_reply=False, progress=None):
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
                                    "sized_reply_received" if reply == sized_ack else "small_ack_only"))
                            break
                except socket.timeout:
                    result["status"] = "timeout"
                    if sized_reply:
                        result["return_status"] = "no_reply"
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
            if progress is not None:
                progress(attempt_line(result, count, "search" if search_bounds is not None else
                                      "DF" if dont_fragment else
                                      "permitted" if allow_fragmentation else "OS default"))
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
    # The return direction counts as tested only if the receiver demonstrably sent
    # same-sized replies and never fell back to the small acknowledgement.
    reverse_tested = (any(row.get("return_status") == "sized_reply_received" for row in results)
                      and not any(row.get("return_status") == "small_ack_only" for row in results))
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
        "tunnelscope_version": VERSION,
        "run_id": run_id.hex(),
        "started_at_utc": started_at_utc,
        "finished_at_utc": utc_now(),
        "source": source,
        "target": {"host": host, address_key: destination[0], "port": port},
        "settings": {"payload_sizes": sizes, "count": count, "timeout_seconds": timeout,
                     "dont_fragment": dont_fragment, "observe_icmp": observe_icmp,
                     **({"sized_reply": True} if sized_reply else {})},
        "fragmentation_mode": "df" if dont_fragment else "permitted" if allow_fragmentation else "os_default",
        "fragmentation": (("disabled: Linux IPV6_DONTFRAG" if address_family == socket.AF_INET6 else "disabled: Linux IP_PMTUDISC_DO") if dont_fragment else
                          ("permitted: Linux IPV6_DONTFRAG=0" if address_family == socket.AF_INET6 else "permitted: Linux IP_PMTUDISC_DONT") if allow_fragmentation else
                          "OS default; fragmentation behavior is not controlled"),
        "interpretation": ("Acknowledgement confirms delivery and a same-sized reply when return_status is "
                           "sized_reply_received; small_ack_only means the receiver sent only a small reply. "
                           if sized_reply else "Acknowledgement confirms delivery and a small reply. ") + "Timeout is inconclusive. packet_too_large records EMSGSIZE in DF mode; a kernel-reported MTU is current kernel knowledge, not an independently measured path MTU. ICMP error-queue observations are untrusted network feedback, not independent proof of the path or sender identity.",
        "summary": summary,
        "evidence": explain_evidence(by_payload_size, dont_fragment, reverse_tested),
        "results": results,
    }


def compare_fragmentation(host, port, sizes, count, timeout, family="auto",
                          observe_icmp=False, sized_reply=False, progress=None):
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
    df = probe(host, port, sizes, count, timeout, True, family,
               observe_icmp=observe_icmp, sized_reply=sized_reply, progress=progress)
    permitted = probe(host, port, sizes, count, timeout, False, family,
                      allow_fragmentation=True, observe_icmp=observe_icmp, sized_reply=sized_reply,
                      progress=progress)
    from .fragmentation import compare_fragmentation_reports
    return compare_fragmentation_reports(df, permitted)

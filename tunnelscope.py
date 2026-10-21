"""Small, bounded UDP delivery experiments. This is not an MTU detector yet."""

import argparse
import json
import secrets
import socket
import struct
import time
from pathlib import Path

MAGIC = b"TS01"
HEADER = struct.Struct("!4s16sI")
ACK = b"TA01"


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


def probe(host, port, sizes, count, timeout):
    address = socket.gethostbyname(host)
    results = []
    for size in sizes:
        for attempt in range(1, count + 1):
            token = secrets.token_bytes(16)
            payload = HEADER.pack(MAGIC, token, size) + bytes(size - HEADER.size)
            result = {"payload_bytes": size, "attempt": attempt}
            # A new connected socket isolates replies from earlier attempts.
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                try:
                    sock.connect((address, port))
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
                    result.update(status="socket_error", error=str(error))
            results.append(result)
            time.sleep(0.05)
    return {
        "schema_version": 1,
        "target": {"host": host, "ipv4": address, "port": port},
        "settings": {"payload_sizes": sizes, "count": count, "timeout_seconds": timeout},
        "fragmentation": "OS default; fragmentation is allowed",
        "interpretation": "Acknowledgement confirms delivery and a small reply. Timeout is inconclusive. This report does not determine path MTU.",
        "results": results,
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
    args = parser.parse_args()
    try:
        if args.command == "receive":
            receive(args.bind, args.port, args.max_packets, args.idle_timeout)
        else:
            report = probe(args.host, args.port, args.sizes, args.count, args.timeout)
            rendered = json.dumps(report, indent=2)
            if args.output:
                args.output.write_text(rendered + "\n", encoding="utf-8")
            print(rendered)
    except OSError as error:
        parser.exit(1, f"Error: {error}\n")
    except KeyboardInterrupt:
        parser.exit(130, "Stopped.\n")


if __name__ == "__main__":
    main()

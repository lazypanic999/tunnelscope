"""TunnelScope CLI and compatibility imports for existing scripts."""

import argparse
import json
from pathlib import Path
import socket
import sys

from tunnelscope_core.network import (
    ACK, HEADER, IP_MTU, IP_MTU_DISCOVER, IP_PMTUDISC_DO, IP_PMTUDISC_DONT, IPV6_DONTFRAG,
    IPV6_MTU, MAGIC, VERSION, compare_fragmentation, configure_fragmentation, probe, receive,
    require_df_support, socket_failure, source_snapshot, udp_address, utc_now,
)
from tunnelscope_core.reports import (
    combine_reports, correlate_reports, explain_evidence, format_report,
    summarize_results, text_table,
)


def require_distinct_output(output, *inputs):
    if output is not None and any(output.resolve() == source.resolve() for source in inputs):
        raise ValueError("--output must differ from the input report path")


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
    search = commands.add_parser("search", help="search a bounded observed payload-size interval (Linux no-fragment)")
    search.add_argument("host")
    search.add_argument("--family", choices=("auto", "ipv4", "ipv6"), default="auto")
    search.add_argument("--port", type=bounded_int(1, 65535), default=9471)
    search.add_argument("--min", type=bounded_int(32, 8192), required=True, dest="minimum")
    search.add_argument("--max", type=bounded_int(32, 8192), required=True, dest="maximum")
    search.add_argument("--max-sizes", type=bounded_int(2, 16), default=12)
    search.add_argument("--count", type=bounded_int(1, 10), default=3)
    search.add_argument("--timeout", type=bounded_int(1, 5), default=1)
    search.add_argument("--output", type=Path)
    comparison = commands.add_parser("compare-fragmentation", help="compare Linux DF and fragmentation-permitted probes")
    comparison.add_argument("host")
    comparison.add_argument("--family", choices=("auto", "ipv4", "ipv6"), default="auto")
    comparison.add_argument("--port", type=bounded_int(1, 65535), default=9471)
    comparison_sizes = comparison.add_mutually_exclusive_group()
    comparison_sizes.add_argument("--sizes", type=sizes_arg, help="comma-separated UDP payload sizes")
    comparison_sizes.add_argument("--sweep", type=sweep_arg, metavar="START:STOP:STEP")
    comparison.add_argument("--count", type=bounded_int(1, 10), default=5)
    comparison.add_argument("--timeout", type=bounded_int(1, 5), default=1)
    comparison.add_argument("--output", type=Path)
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
        elif args.command == "search":
            report = probe(args.host, args.port, None, args.count, args.timeout, True,
                           args.family, (args.minimum, args.maximum), args.max_sizes)
        elif args.command == "compare-fragmentation":
            sizes = args.sweep if args.sweep is not None else args.sizes
            report = compare_fragmentation(args.host, args.port,
                                           sizes if sizes is not None else [64, 1200, 1400],
                                           args.count, args.timeout, args.family)
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

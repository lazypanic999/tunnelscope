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
    version_details,
)
from tunnelscope_core.diagnose import correlate_diagnosis, diagnose
from tunnelscope_core.sanitize import sanitize_reports


def read_report(path):
    """Read JSON including BOM-marked PowerShell exports; keep errors contextual."""
    try:
        report = json.loads(path.read_bytes())
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid JSON report {path}: {error}") from error
    if not isinstance(report, dict):
        raise ValueError(f"expected a TunnelScope JSON object in {path}")
    return report


def require_distinct_output(output, *inputs):
    if output is None:
        return
    for source in inputs:
        if (output.resolve() == source.resolve()
                or (output.exists() and source.exists() and output.samefile(source))):
            raise ValueError("--output must differ from the input report path and file")


def require_output_target(output):
    """Reject unavailable report destinations before collection starts."""
    if output is None:
        return
    if not output.parent.is_dir():
        raise ValueError(f"output directory does not exist: {output.parent}")
    if output.is_dir():
        raise ValueError(f"output path names a directory: {output}")


def write_sanitized(inputs, output_dir, with_html, keep_timestamps):
    """Sanitize reports as one batch and write new files without touching the inputs."""
    if len(inputs) > 32:
        raise ValueError("sanitize accepts at most 32 reports per batch")
    if not output_dir.is_dir():
        raise ValueError(f"output directory does not exist: {output_dir}")
    resolved_inputs = {path.resolve() for path in inputs}
    if len(resolved_inputs) != len(inputs):
        raise ValueError("each input report may be given only once")
    targets = []
    for path in inputs:
        if path.suffix.lower() != ".json":
            raise ValueError(f"input must be a .json report: {path}")
        outputs = [output_dir / path.name] + ([output_dir / (path.stem + ".html")] if with_html else [])
        targets.append(outputs)
    flat = [target for outputs in targets for target in outputs]
    if len({target.resolve() for target in flat}) != len(flat):
        raise ValueError("input reports need distinct file names")
    for target in flat:
        if target.resolve() in resolved_inputs:
            raise ValueError("--output-dir must not contain the input reports")
        if target.exists():
            raise ValueError(f"refusing to overwrite existing file: {target}")
    reports = [read_report(path) for path in inputs]
    sanitized = sanitize_reports(reports, keep_timestamps)
    rendered = []
    if with_html:
        from tunnelscope_view import render_report_html
        rendered = [render_report_html(report) for report in sanitized]
    for index, (report, outputs) in enumerate(zip(sanitized, targets)):
        # Keep the no-overwrite guarantee even if a file appears after preflight.
        with outputs[0].open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(report, indent=2) + "\n")
        if with_html:
            with outputs[1].open("x", encoding="utf-8") as stream:
                stream.write(rendered[index])
        print("Wrote " + " and ".join(str(target) for target in outputs))
    summary = sanitized[0]["sanitization"]
    print(f"Replaced {summary['replaced_addresses']} addresses, {summary['replaced_interfaces']} interface names "
          f"and {summary['replaced_hostnames']} hostnames; timestamps {summary['timestamps'].split(';')[0]}.")
    print("Review the copies before sharing: free-text fields and file names are not guaranteed to be clean.")


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
    receiver.add_argument("--sized-reply", action="store_true",
                          help="Linux or Windows: answer probes that request it with a same-sized reply sent without fragmentation")
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
    sender.add_argument("--observe-icmp", action="store_true", help="Linux: record UDP error-queue ICMP feedback")
    sender.add_argument("--sized-reply", action="store_true",
                        help="ask a v0.7 receiver started with --sized-reply for same-sized replies")
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
    search.add_argument("--observe-icmp", action="store_true", help="Linux: record UDP error-queue ICMP feedback")
    search.add_argument("--sized-reply", action="store_true",
                        help="request same-sized replies; acknowledged then means both directions carried the size")
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
    comparison.add_argument("--observe-icmp", action="store_true", help="Linux: record UDP error-queue ICMP feedback")
    comparison.add_argument("--sized-reply", action="store_true", help="request same-sized replies in both runs")
    diagnosis_command = commands.add_parser("diagnose", help="run one bounded Linux sender-side diagnostic workflow")
    diagnosis_command.add_argument("host")
    diagnosis_command.add_argument("--family", choices=("auto", "ipv4", "ipv6"), default="auto")
    diagnosis_command.add_argument("--port", type=bounded_int(1, 65535), default=9471)
    diagnosis_command.add_argument("--min", type=bounded_int(32, 8192), required=True, dest="minimum")
    diagnosis_command.add_argument("--max", type=bounded_int(32, 8192), required=True, dest="maximum")
    diagnosis_command.add_argument("--max-sizes", type=bounded_int(2, 16), default=8)
    diagnosis_command.add_argument("--count", type=bounded_int(1, 10), default=2)
    diagnosis_command.add_argument("--timeout", type=bounded_int(1, 5), default=1)
    diagnosis_command.add_argument("--output", type=Path, required=True, help="new JSON report path")
    diagnosis_command.add_argument("--html", type=Path, help="new HTML report path (default: JSON stem with .html)")
    diagnosis_command.add_argument("--sized-reply", action="store_true",
                                   help="request same-sized replies in all three runs")
    combined = commands.add_parser("combine", help="combine two independently measured directions")
    combined.add_argument("a_to_b", type=Path, help="probe JSON from endpoint A to B")
    combined.add_argument("b_to_a", type=Path, help="probe JSON from endpoint B to A")
    combined.add_argument("--output", type=Path)
    correlated = commands.add_parser("correlate", help="match probe or diagnosis runs with receiver observations")
    correlated.add_argument("probe_report", type=Path)
    correlated.add_argument("receiver_report", type=Path)
    correlated.add_argument("--output", type=Path)
    correlated.add_argument("--html", type=Path, help="also write a local HTML view")
    shown = commands.add_parser("show", help="print a concise summary of a JSON report")
    shown.add_argument("report", type=Path)
    shown.add_argument("--format", choices=("text", "markdown"), default="text",
                       help="text table (default) or a bounded Markdown summary for issues")
    sanitized = commands.add_parser("sanitize", help="write copies of reports without addresses, interfaces or absolute times")
    sanitized.add_argument("reports", type=Path, nargs="+",
                           help="JSON reports sanitized together with one consistent mapping")
    sanitized.add_argument("--output-dir", type=Path, required=True,
                           help="existing directory for the sanitized copies (same file names)")
    sanitized.add_argument("--html", action="store_true", help="also write an HTML view next to each copy")
    sanitized.add_argument("--keep-timestamps", action="store_true", help="do not shift timestamps")
    html_view = commands.add_parser("html", help="write a searchable local HTML view of a JSON report")
    html_view.add_argument("report", type=Path)
    html_view.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command != "diagnose":
            require_output_target(getattr(args, "output", None))
        if args.command == "receive":
            receive(args.bind, args.port, args.max_packets, args.idle_timeout, args.output, args.family,
                    sized_reply=args.sized_reply)
        elif args.command == "probe":
            require_df_support(args.dont_fragment)
            sizes = args.sweep if args.sweep is not None else args.sizes
            report = probe(args.host, args.port, sizes if sizes is not None else [64, 512, 1200, 1400],
                           args.count, args.timeout, args.dont_fragment, args.family,
                           observe_icmp=args.observe_icmp, sized_reply=args.sized_reply)
        elif args.command == "search":
            report = probe(args.host, args.port, None, args.count, args.timeout, True,
                           args.family, (args.minimum, args.maximum), args.max_sizes,
                           observe_icmp=args.observe_icmp, sized_reply=args.sized_reply)
        elif args.command == "compare-fragmentation":
            sizes = args.sweep if args.sweep is not None else args.sizes
            report = compare_fragmentation(args.host, args.port,
                                           sizes if sizes is not None else [64, 1200, 1400],
                                           args.count, args.timeout, args.family,
                                           observe_icmp=args.observe_icmp, sized_reply=args.sized_reply)
        elif args.command == "diagnose":
            if args.output.suffix.lower() != ".json":
                raise ValueError("--output must name a .json file")
            html_path = args.html if args.html is not None else args.output.with_suffix(".html")
            if html_path.suffix.lower() != ".html" or args.output.resolve() == html_path.resolve():
                raise ValueError("diagnose needs distinct .json and .html output files")
            for path in (args.output, html_path):
                if path.exists():
                    raise ValueError(f"refusing to overwrite existing file: {path}")
                require_output_target(path)
            report = diagnose(args.host, args.port, args.minimum, args.maximum,
                              args.count, args.timeout, args.max_sizes, args.family,
                              sized_reply=args.sized_reply)
            from tunnelscope_view import render_report_html
            rendered_html = render_report_html(report)
            args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            html_path.write_text(rendered_html, encoding="utf-8")
            print(format_report(report))
            print(f"Wrote {args.output} and {html_path}")
        elif args.command == "combine":
            require_distinct_output(args.output, args.a_to_b, args.b_to_a)
            a_to_b = read_report(args.a_to_b)
            b_to_a = read_report(args.b_to_a)
            report = combine_reports(a_to_b, b_to_a)
        elif args.command == "sanitize":
            write_sanitized(args.reports, args.output_dir, args.html, args.keep_timestamps)
        elif args.command == "show":
            shown_report = read_report(args.report)
            if args.format == "markdown":
                from tunnelscope_core.markdown import render_report_markdown
                print(render_report_markdown(shown_report), end="")
            else:
                if isinstance(shown_report, dict) and isinstance(shown_report.get("sanitization"), dict):
                    timestamp_state = shown_report["sanitization"].get("timestamps", "unspecified")
                    print(f"Sanitized report: sanitization metadata present; timestamps: {timestamp_state}.")
                for label, value in version_details(shown_report):
                    print(f"{label}: {value}")
                print(format_report(shown_report))
        elif args.command == "html":
            require_distinct_output(args.output, args.report)
            from tunnelscope_view import render_report_html
            args.output.write_text(
                render_report_html(read_report(args.report)),
                encoding="utf-8",
            )
            print(f"Wrote {args.output}")
        else:
            require_distinct_output(args.output, args.probe_report, args.receiver_report)
            if args.html:
                if args.html.suffix.lower() != ".html":
                    raise ValueError("--html must name an .html file")
                require_distinct_output(args.html, args.probe_report, args.receiver_report)
                if args.output and args.html.resolve() == args.output.resolve():
                    raise ValueError("--html must differ from --output")
                if args.html.exists():
                    raise ValueError(f"refusing to overwrite existing file: {args.html}")
                require_output_target(args.html)
            probe_report = read_report(args.probe_report)
            receiver_report = read_report(args.receiver_report)
            report = (correlate_diagnosis(probe_report, receiver_report)
                      if isinstance(probe_report, dict) and probe_report.get("kind") == "diagnosis"
                      else correlate_reports(probe_report, receiver_report))
            if args.html:
                from tunnelscope_view import render_report_html
                html_content = render_report_html(report)
                args.html.write_text(html_content, encoding="utf-8")
        if args.command not in ("receive", "show", "html", "diagnose", "sanitize"):
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

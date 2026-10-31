"""Evidence summaries, correlation and terminal formatting."""

from math import sqrt


def no_ack_measurement(counts):
    """Describe missing ACKs among sent probes, without calling them packet loss."""
    acknowledged = counts.get("acknowledged", 0)
    timed_out = counts.get("timeout", 0)
    sent = acknowledged + timed_out
    if not sent:
        return {"sent_attempts": 0, "no_ack_count": 0,
                "no_ack_rate": None, "no_ack_wilson_95": None}
    rate = timed_out / sent
    z = 1.959963984540054
    z2 = z * z
    center = (rate + z2 / (2 * sent)) / (1 + z2 / sent)
    margin = z * sqrt(rate * (1 - rate) / sent + z2 / (4 * sent * sent)) / (1 + z2 / sent)
    return {"sent_attempts": sent, "no_ack_count": timed_out,
            "no_ack_rate": round(rate, 4),
            "no_ack_wilson_95": [round(max(0, center - margin), 4),
                                  round(min(1, center + margin), 4)]}


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
        summary.append({"payload_bytes": size, "status_counts": counts,
                        "no_ack_measurement": no_ack_measurement(counts),
                        "assessment": assessment})
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


def no_ack_text(measurement):
    if not isinstance(measurement, dict) or not measurement.get("sent_attempts"):
        return "-"
    interval = measurement.get("no_ack_wilson_95")
    if not isinstance(interval, list) or len(interval) != 2 or not all(
        isinstance(value, (int, float)) and not isinstance(value, bool)
        for value in (measurement.get("no_ack_count"), measurement.get("sent_attempts"),
                      measurement.get("no_ack_rate"), *interval)
    ):
        return "-"
    return (f"{measurement['no_ack_count']}/{measurement['sent_attempts']} "
            f"({measurement['no_ack_rate']:.0%}; 95% {interval[0]:.0%}-{interval[1]:.0%})")


def format_report(report):
    """Render existing JSON evidence as a compact terminal view."""
    if isinstance(report, dict) and isinstance(report.get("lab"), str):
        for key in ("correlation", "probe"):
            if isinstance(report.get(key), dict):
                return f"Lab: {report['lab']}\n" + format_report(report[key])
    if not isinstance(report, dict) or report.get("schema_version") != 1:
        raise ValueError("expected a schema_version 1 TunnelScope report")
    kind = report.get("kind", "probe")
    if kind == "diagnosis":
        runs = report.get("runs")
        comparison = runs.get("fragmentation_comparison") if isinstance(runs, dict) else None
        search = runs.get("size_search") if isinstance(runs, dict) else None
        if not isinstance(comparison, dict) or not isinstance(search, dict):
            raise ValueError("diagnosis needs comparison and search runs")
        consistency = report.get("consistency", {})
        summary = report.get("summary", {})
        search_summary = summary.get("search", {})
        if not all(isinstance(item, dict) for item in (consistency, summary, search_summary)):
            raise ValueError("invalid diagnosis summary")
        interval = search_summary.get("observed_interval_payload_bytes")
        interval_text = f"{interval[0]}..{interval[1]}" if isinstance(interval, list) and len(interval) == 2 else "none"
        return ("Diagnosis (single sender direction)\n" + format_report(comparison) +
                f"\nSearch: {search_summary.get('assessment', 'unknown')}; observed interval: {interval_text} UDP payload bytes; "
                f"attempts: {summary.get('attempts', '?')}; ICMP size feedback events: {summary.get('icmp_size_feedback_events', '?')}."
                f"\nTarget check: {consistency.get('search_target_check', 'unknown')}; "
                f"source check: {consistency.get('search_source_check', 'unknown')}."
                "\nRuns were sequential. This is not a two-way test or a proven path MTU.")
    if kind == "probe":
        summary = report.get("summary")
        rows = summary.get("by_payload_size") if isinstance(summary, dict) else None
        if not isinstance(rows, list):
            raise ValueError("probe report has no per-size summary")
        feedback = summary.get("icmp_feedback")
        ptb_by_size = {}
        if isinstance(feedback, dict):
            for result in report.get("results", []):
                if not isinstance(result, dict):
                    continue
                observation = result.get("icmp_observation")
                if isinstance(observation, dict) and isinstance(observation.get("events"), list):
                    ptb_by_size[result.get("payload_bytes")] = ptb_by_size.get(result.get("payload_bytes"), 0) + sum(
                        isinstance(event, dict) and event.get("message") in ("fragmentation_needed", "packet_too_big")
                        and event.get("quoted_probe_match") is not False
                        for event in observation["events"]
                    )
        values = []
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("status_counts"), dict):
                raise ValueError("invalid probe size summary")
            counts = row["status_counts"]
            measurement = row.get("no_ack_measurement") or no_ack_measurement(counts)
            value = [row.get("payload_bytes", "?"), counts.get("acknowledged", 0),
                     counts.get("packet_too_large", 0), counts.get("timeout", 0),
                     counts.get("socket_error", 0), no_ack_text(measurement)]
            if isinstance(feedback, dict):
                value.append(ptb_by_size.get(row.get("payload_bytes"), 0))
            value.append(row.get("assessment", "?"))
            values.append(value)
        search = summary.get("search")
        search_text = ""
        if isinstance(search, dict):
            interval = search.get("observed_interval_payload_bytes")
            bounds = f"{interval[0]}..{interval[1]} UDP payload bytes" if interval else "none"
            search_text = (f"\nSearch: {search.get('assessment', 'unknown')}; observed interval: {bounds}; "
                           f"tested {len(search.get('tested_payload_sizes', []))}/{search.get('max_tested_sizes', '?')} sizes.")
        feedback_text = ""
        if isinstance(feedback, dict):
            feedback_text = (f"\nICMP size feedback: {feedback.get('size_feedback_events', '?')} observed "
                             f"({feedback.get('token_matched_size_feedback_events', '?')} token matched); "
                             f"local errors: {feedback.get('local_error_events', '?')}; "
                             f"read: {feedback.get('observation_state', '?')}. "
                             "The legacy kernel_rejected_df_payload label covers local and ICMP-triggered EMSGSIZE.")
        headers = ["Bytes", "Ack", "Too large", "Timeout", "Error", "No ACK (95% CI)"]
        if isinstance(feedback, dict):
            headers.append("ICMP size")
        headers.append("Assessment")
        return ("Probe results (UDP payload bytes)\n" + text_table(headers, values) +
                search_text + feedback_text +
                "\nNo ACK is a sender timeout, not proven packet loss. ICMP feedback may be spoofed or absent; no feedback does not prove blocking.")
    if kind == "fragmentation_comparison":
        comparison = report.get("comparison")
        rows = comparison.get("by_payload_size") if isinstance(comparison, dict) else None
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ValueError("fragmentation comparison has no valid size summary")
        values = []
        for row in rows:
            df, allowed = row.get("df"), row.get("fragmentation_permitted")
            if not isinstance(df, dict) or not isinstance(allowed, dict):
                raise ValueError("fragmentation comparison has an invalid size row")
            values.append((row.get("payload_bytes", "?"), df.get("assessment", "?"),
                           no_ack_text(df.get("no_ack_measurement")),
                           allowed.get("assessment", "?"),
                           no_ack_text(allowed.get("no_ack_measurement"))))
        return (f"Fragmentation comparison; source check: {report.get('source_check', 'unknown')}\n" +
                text_table(["Bytes", "DF", "DF no ACK", "Permitted", "Permitted no ACK"], values) +
                "\nSource fragmentation was permitted in the second run, not observed on the path. Differences do not identify a cause.")
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

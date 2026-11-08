"""Shared observation tables for offline report renderers."""

from .reports import no_ack_text


def _records(value):
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise ValueError("report contains invalid result rows")
    return value


def _feedback_cell(row):
    observation = row.get("icmp_observation")
    if not isinstance(observation, dict):
        return "-"
    events = observation.get("events")
    if not isinstance(events, list):
        return "read unavailable"
    if not events:
        return "none observed" if observation.get("state") == "completed" else "read incomplete"
    labels = []
    for event in events:
        if not isinstance(event, dict):
            labels.append("unparsed")
            continue
        match = event.get("quoted_probe_match")
        association = "matched" if match is True else "socket only" if match is None else "mismatch"
        mtu = event.get("reported_mtu_bytes")
        labels.append(f"{event.get('message', 'unknown')} ({association}" +
                      (f", MTU {mtu}" if isinstance(mtu, int) else "") + ")")
    return "; ".join(labels)


def _table_data(report):
    kind = report.get("kind", "probe")
    if kind == "diagnosis":
        evidence = report.get("receiver_evidence")
        if isinstance(evidence, dict):
            correlations = evidence.get("correlations")
            if not isinstance(correlations, dict):
                raise ValueError("diagnosis has invalid receiver correlations")
            rows = []
            sized = False
            for name in ("df", "fragmentation_permitted", "size_search"):
                correlation = correlations.get(name)
                if not isinstance(correlation, dict):
                    raise ValueError("diagnosis is missing a receiver correlation")
                for row in _records(correlation.get("results")):
                    sized = sized or "return_evidence" in row
                    rows.append([name, row.get("payload_bytes"), row.get("sender_status"),
                                 "yes" if row.get("receiver_observed") else "no",
                                 row.get("evidence_case"), row.get("return_evidence"),
                                 row.get("probe_id"), row.get("send_attempted_at_utc"),
                                 row.get("receiver_received_at_utc"),
                                 row.get("sender_ack_received_at_utc")])
            if not sized:
                rows = [row[:5] + row[6:] for row in rows]
            return ["Run", "Bytes", "Sender status", "Receiver saw", "Evidence case",
                    *(["Return evidence"] if sized else []), "Probe ID",
                    "Send attempted (UTC)", "Receiver received (UTC)",
                    "Sender ACK received (UTC)"], rows
        runs = report.get("runs")
        comparison = runs.get("fragmentation_comparison") if isinstance(runs, dict) else None
        search = runs.get("size_search") if isinstance(runs, dict) else None
        if not isinstance(comparison, dict) or not isinstance(search, dict):
            raise ValueError("diagnosis needs comparison and search runs")
        _, compare_rows = _table_data(comparison)
        search_rows = _records(search.get("results"))
        rows = [["DF vs permitted", *row, ""] for row in compare_rows]
        rows.extend(["Size search", row.get("payload_bytes"), row.get("status"), "", "", ""]
                    for row in search_rows)
        return ["Run", "Bytes", "DF / search status", "DF no ACK", "Permitted", "Permitted no ACK"], rows
    if kind == "probe":
        headers = ["Bytes", "Attempt", "Status", "RTT ms", "Kernel MTU"]
        feedback_enabled = isinstance(report.get("summary"), dict) and isinstance(report["summary"].get("icmp_feedback"), dict)
        if feedback_enabled:
            headers.extend(("Size error origin", "ICMP feedback"))
        settings = report.get("settings")
        sized = isinstance(settings, dict) and settings.get("sized_reply") is True
        if sized:
            headers.extend(("Return", "Reply bytes"))
        return headers, [
            [row.get("payload_bytes"), row.get("attempt"), row.get("status"),
             row.get("rtt_ms"), row.get("kernel_reported_mtu_bytes"),
             *([row.get("size_error_origin"), _feedback_cell(row)] if feedback_enabled else []),
             *([row.get("return_status"), row.get("reply_bytes")] if sized else [])]
            for row in _records(report.get("results"))
        ]
    if kind == "receiver_observations":
        return ["Run ID", "Bytes", "Source", "ACK send", "Reply bytes"], [
            [row.get("run_id"), row.get("payload_bytes"),
             row.get("source_ipv4", row.get("source_ipv6")), row.get("ack_send_status"),
             row.get("reply_bytes")]
            for row in _records(report.get("observations"))
        ]
    if kind == "probe_receiver_correlation":
        rows = _records(report.get("results"))
        sized = any("return_evidence" in row for row in rows)
        return ["Bytes", "Sender status", "Receiver saw", "Evidence case",
                *(["Return evidence"] if sized else []), "ACK send", "Probe ID", "Direction",
                "Send attempted (UTC)", "Receiver received (UTC)", "Sender ACK received (UTC)"], [
            [row.get("payload_bytes"), row.get("sender_status"),
             "yes" if row.get("receiver_observed") else "no", row.get("evidence_case"),
             *([row.get("return_evidence")] if sized else []), row.get("ack_send_status"),
             row.get("probe_id"), row.get("direction"), row.get("send_attempted_at_utc"),
             row.get("receiver_received_at_utc"), row.get("sender_ack_received_at_utc")]
            for row in rows
        ]
    if kind == "bidirectional_comparison":
        comparison = report.get("comparison")
        if not isinstance(comparison, dict):
            raise ValueError("comparison report has no per-size summary")
        return ["Bytes", "A to B", "B to A"], [
            [row.get("payload_bytes"), row.get("a_to_b"), row.get("b_to_a")]
            for row in _records(comparison.get("by_payload_size"))
        ]
    if kind == "fragmentation_comparison":
        comparison = report.get("comparison")
        if not isinstance(comparison, dict):
            raise ValueError("fragmentation comparison has no per-size summary")
        rows = []
        for row in _records(comparison.get("by_payload_size")):
            df, allowed = row.get("df"), row.get("fragmentation_permitted")
            if not isinstance(df, dict) or not isinstance(allowed, dict):
                raise ValueError("invalid fragmentation comparison row")
            rows.append([row.get("payload_bytes"), df.get("assessment"),
                         no_ack_text(df.get("no_ack_measurement")), allowed.get("assessment"),
                         no_ack_text(allowed.get("no_ack_measurement"))])
        return ["Bytes", "DF", "DF no ACK", "Permitted", "Permitted no ACK"], rows
    return [], []


def _lab_data(report):
    cases = report.get("cases")
    if isinstance(cases, dict):
        directions = []
        for label, case in cases.items():
            if not isinstance(case, dict):
                raise ValueError("lab report has invalid case results")
            directions.append({**case, "direction": label})
    else:
        directions = _records(report.get("directions"))
    headers = ["Case" if isinstance(cases, dict) else "Direction", "Bytes", "Status", "Receiver saw"]
    rows = []
    sized = False
    for direction in directions:
        probe = direction.get("probe", direction)
        correlation = direction.get("correlation", {})
        if not isinstance(probe, dict) or not isinstance(correlation, dict):
            raise ValueError("lab report has invalid direction results")
        observed = {row.get("probe_id"): row
                    for row in _records(correlation.get("results", []))}
        for row in _records(probe.get("results")):
            joined = observed.get(row.get("probe_id"), {})
            seen = joined.get("receiver_observed")
            sized = sized or "return_status" in row or "return_evidence" in joined
            rows.append([direction.get("direction"), row.get("payload_bytes"),
                         row.get("status"), "yes" if seen else "no" if seen is False else None,
                         row.get("return_status"), joined.get("return_evidence"), joined.get("ack_send_status")])
    if sized:
        headers.extend(("Return", "Return evidence", "ACK send"))
    else:
        rows = [row[:4] for row in rows]
    return headers, rows


def report_table(report):
    """Return title, headers, rows and the report carrying display metadata."""
    if not isinstance(report, dict):
        raise ValueError("expected a TunnelScope JSON object")
    search_report = report
    if isinstance(report.get("lab"), str):
        title = f"Lab: {report['lab']}"
        if isinstance(report.get("directions"), list) or isinstance(report.get("cases"), dict):
            headers, rows = _lab_data(report)
        else:
            nested = report.get("correlation", report.get("probe"))
            if not isinstance(nested, dict):
                raise ValueError("lab report has no supported results")
            search_report = nested
            headers, rows = _table_data(nested)
    elif report.get("schema_version") == 1:
        kind = report.get("kind", "probe")
        if not isinstance(kind, str):
            raise ValueError("invalid report kind")
        title = kind.replace("_", " ").title()
        headers, rows = _table_data(report)
    else:
        raise ValueError("expected a schema_version 1 TunnelScope report")
    if not headers:
        raise ValueError("unsupported report kind")
    return title, headers, rows, search_report

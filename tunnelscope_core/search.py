"""Bounded adaptive size selection and conservative evidence assessment."""


def assess_search(minimum, maximum, by_size, max_sizes):
    """Return the next midpoint and an evidence summary for completed sizes."""
    tested = [row["payload_bytes"] for row in by_size]
    acknowledged = []
    too_large = []
    ambiguous = []
    for row in by_size:
        counts = row["status_counts"]
        statuses = [name for name, count in counts.items() if count]
        if statuses == ["acknowledged"]:
            acknowledged.append(row["payload_bytes"])
        elif statuses == ["packet_too_large"]:
            too_large.append(row["payload_bytes"])
        else:
            ambiguous.append(row["payload_bytes"])
    lower = max(acknowledged, default=None)
    upper = min(too_large, default=None)
    bracket = lower is not None and upper is not None and lower < upper
    summary = {
        "method": "bounded_binary_search",
        "requested_min_payload_bytes": minimum,
        "requested_max_payload_bytes": maximum,
        "max_tested_sizes": max_sizes,
        "tested_payload_sizes": tested,
        "largest_acknowledged_payload_bytes": lower,
        "smallest_packet_too_large_payload_bytes": upper,
        "ambiguous_payload_sizes": ambiguous,
        "observed_interval_payload_bytes": [lower, upper] if bracket else None,
    }
    if len(tested) < 2:
        assessment = "testing_endpoints"
    elif ambiguous or (lower is not None and upper is not None and lower >= upper):
        assessment = "inconclusive"
    elif not bracket:
        assessment = "no_explicit_bracket"
    elif upper - lower == 1:
        assessment = "adjacent_observed_bounds"
    elif len(tested) >= max_sizes:
        assessment = "budget_limited_interval"
    else:
        assessment = "searching"
    summary["assessment"] = assessment
    next_size = (lower + upper) // 2 if assessment == "searching" else None
    return next_size, summary

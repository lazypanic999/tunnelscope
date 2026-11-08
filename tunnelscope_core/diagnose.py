"""Bounded single-sender workflow using existing evidence-producing probes."""

from copy import deepcopy
from ._version import VERSION, declared_version

from .icmp import require_icmp_support
from .network import SIZED_REPLY_MIN_BYTES, compare_fragmentation, probe, require_df_support
from .reports import correlate_reports, is_hex_id


def build_diagnosis(comparison, search):
    """Bundle independent runs without claiming a root cause or reverse path."""
    if not isinstance(comparison, dict) or comparison.get("kind") != "fragmentation_comparison":
        raise ValueError("diagnosis needs a fragmentation comparison")
    if not isinstance(search, dict) or search.get("kind") != "probe":
        raise ValueError("diagnosis needs a size-search probe report")
    search_summary = search.get("summary")
    search_summary = search_summary.get("search") if isinstance(search_summary, dict) else None
    if not isinstance(search_summary, dict):
        raise ValueError("diagnosis needs a size-search summary")
    runs = comparison.get("runs")
    if not isinstance(runs, dict) or any(not isinstance(runs.get(mode), dict)
                                         for mode in ("df", "fragmentation_permitted")):
        raise ValueError("diagnosis needs both fragmentation runs")
    target_check = "matched" if comparison.get("target") == search.get("target") else "changed"
    df_source, search_source = runs["df"].get("source"), search.get("source")
    source_keys = ("ipv4", "ipv6", "interface")
    source_check = ("unavailable" if not isinstance(df_source, dict) or not isinstance(search_source, dict)
                    else "matched" if all(df_source.get(key) == search_source.get(key)
                                          for key in source_keys) else "changed")
    all_probes = [runs["df"], runs["fragmentation_permitted"], search]
    sized = [item.get("settings", {}).get("sized_reply") is True for item in all_probes]
    if any(sized) and not all(sized):
        raise ValueError("diagnosis runs disagree about sized replies")
    attempts = sum(len(item.get("results", [])) for item in all_probes)
    feedback = sum(item.get("summary", {}).get("icmp_feedback", {}).get("size_feedback_events", 0)
                   for item in all_probes)
    summary = {"attempts": attempts,
               "icmp_size_feedback_events": feedback,
               "search": search_summary}
    interpretation = ("One sender-to-target direction only. Runs are sequential and may be affected by route or PMTU-cache changes. "
                      "A small ACK does not prove same-sized reverse delivery. ")
    if all(sized):
        statuses = [row.get("return_status") for item in all_probes for row in item.get("results", [])
                    if isinstance(row, dict)]
        summary["return"] = {status: statuses.count(status)
                             for status in ("sized_reply_received", "small_ack_only", "no_reply")}
        interpretation = ("One sender with same-sized replies: an acknowledged attempt carried its size in both directions, "
                          "so the search interval reflects the smaller of the two directions. small_ack_only means the "
                          "receiver did not send same-sized replies. Runs are sequential and may be affected by route or "
                          "PMTU-cache changes. ")
    interpretation += ("Missing ACKs and absent ICMP are inconclusive; observed ICMP is untrusted feedback. "
                       "A reported interval is not an independently measured end-to-end path MTU.")
    return {
        "schema_version": 1,
        "kind": "diagnosis",
        "tunnelscope_version": VERSION,
        "input_versions": {"fragmentation_comparison": declared_version(comparison), "size_search": declared_version(search)},
        "scope": "single_sender_direction",
        "target": comparison.get("target"),
        "started_at_utc": runs["df"].get("started_at_utc"),
        "finished_at_utc": search.get("finished_at_utc"),
        "settings": {"compared_payload_sizes": comparison.get("settings", {}).get("payload_sizes"),
                     "requested_min_payload_bytes": search_summary.get("requested_min_payload_bytes"),
                     "requested_max_payload_bytes": search_summary.get("requested_max_payload_bytes"),
                     "count_per_size_per_run": comparison.get("settings", {}).get("count_per_mode"),
                     "timeout_seconds": runs["df"].get("settings", {}).get("timeout_seconds"),
                     "max_search_sizes": search_summary.get("max_tested_sizes"),
                     "run_order": ["df", "fragmentation_permitted", "size_search"],
                     "observe_icmp": True,
                     **({"sized_reply": True} if all(sized) else {})},
        "consistency": {"comparison_source_check": comparison.get("source_check"),
                        "search_target_check": target_check,
                        "search_source_check": source_check},
        "summary": summary,
        "interpretation": interpretation,
        "runs": {"fragmentation_comparison": comparison, "size_search": search},
    }


def diagnose(host, port, minimum, maximum, count=2, timeout=1,
             max_sizes=8, family="auto", sized_reply=False):
    """Run three bounded Linux experiments against an already controlled target."""
    require_df_support(True)
    require_icmp_support(True)
    if not 32 <= minimum < maximum <= 8192 or not 2 <= max_sizes <= 16:
        raise ValueError("diagnose needs 32 <= MIN < MAX <= 8192 and 2..16 search sizes")
    if not 1 <= count <= 10 or not 1 <= timeout <= 5:
        raise ValueError("diagnose count or timeout is outside CLI bounds")
    if sized_reply and minimum < SIZED_REPLY_MIN_BYTES:
        raise ValueError(f"--sized-reply needs --min of at least {SIZED_REPLY_MIN_BYTES} bytes")
    compared_sizes = list(dict.fromkeys((minimum, (minimum + maximum) // 2, maximum)))
    max_attempts = (2 * len(compared_sizes) + max_sizes) * count
    if max_attempts > 100 or max_attempts * timeout > 120:
        raise ValueError("diagnose budget exceeds 100 probes or 120 seconds of timeout allowance")
    comparison = compare_fragmentation(host, port, compared_sizes, count,
                                       timeout, family, observe_icmp=True, sized_reply=sized_reply)
    search = probe(host, port, None, count, timeout, True, family,
                   (minimum, maximum), max_sizes, observe_icmp=True, sized_reply=sized_reply)
    return build_diagnosis(comparison, search)


def correlate_diagnosis(diagnosis, receiver_report):
    """Join one receiver capture to each diagnosis run by its own run ID."""
    if not isinstance(diagnosis, dict) or diagnosis.get("schema_version") != 1 or diagnosis.get("kind") != "diagnosis":
        raise ValueError("expected a schema_version 1 diagnosis report")
    if (not isinstance(receiver_report, dict) or receiver_report.get("schema_version") != 1
            or receiver_report.get("kind") != "receiver_observations"
            or not isinstance(receiver_report.get("observations"), list)):
        raise ValueError("expected a schema_version 1 receiver observations report")
    if "receiver_evidence" in diagnosis:
        raise ValueError("diagnosis already contains receiver evidence")
    runs = diagnosis.get("runs")
    comparison = runs.get("fragmentation_comparison") if isinstance(runs, dict) else None
    nested = comparison.get("runs") if isinstance(comparison, dict) else None
    probes = {
        "df": nested.get("df") if isinstance(nested, dict) else None,
        "fragmentation_permitted": nested.get("fragmentation_permitted") if isinstance(nested, dict) else None,
        "size_search": runs.get("size_search") if isinstance(runs, dict) else None,
    }
    if any(not isinstance(probe, dict) or probe.get("kind") != "probe" or not isinstance(probe.get("results"), list)
           for probe in probes.values()):
        raise ValueError("diagnosis needs three probe runs")
    # Probe IDs become lookup keys before correlate_reports performs its full
    # row validation. Reject malformed JSON values here instead of hashing them.
    if any(not isinstance(row, dict) or not isinstance(row.get("probe_id"), str)
           for probe in probes.values() for row in probe["results"]):
        raise ValueError("diagnosis probe runs need valid probe IDs")
    run_ids = [probe.get("run_id") for probe in probes.values()]
    if any(not isinstance(value, str) or len(value) != 16 for value in run_ids) or len(set(run_ids)) != 3:
        raise ValueError("diagnosis needs three distinct run IDs")
    if not all(is_hex_id(value, 16) for value in run_ids):
        raise ValueError("diagnosis needs hexadecimal run IDs")
    observations = receiver_report["observations"]
    for row in observations:
        if not isinstance(row, dict) or not isinstance(row.get("run_id"), str):
            raise ValueError("receiver observations need run IDs for diagnosis")
        if len(row["run_id"]) != 16 or not isinstance(row.get("probe_id"), str) or len(row["probe_id"]) != 32 or not isinstance(row.get("payload_bytes"), int):
            raise ValueError("invalid receiver observation")
        if not is_hex_id(row["run_id"], 16) or not is_hex_id(row["probe_id"], 32):
            raise ValueError("invalid hexadecimal receiver identifier")
    if len({row["probe_id"] for row in observations}) != len(observations):
        raise ValueError("duplicate probe ID in receiver report")
    sent_run_by_probe = {row["probe_id"]: probe["run_id"]
                         for probe in probes.values() for row in probe["results"]}
    if any(row["probe_id"] in sent_run_by_probe and
           row["run_id"] != sent_run_by_probe[row["probe_id"]] for row in observations):
        raise ValueError("matching probe ID has a different run ID")
    known_ids = set(run_ids)
    matched_rows = [row for row in observations if row["run_id"] in known_ids]
    if observations and not matched_rows:
        raise ValueError("receiver report has no observations from this diagnosis")
    correlations = {}
    for name, probe in probes.items():
        scoped_receiver = {**receiver_report, "observations":
                           [row for row in matched_rows if row["run_id"] == probe["run_id"]]}
        correlations[name] = correlate_reports(probe, scoped_receiver)
    result = deepcopy(diagnosis)
    evidence_summary = {
        "receiver_observed": sum(item["summary"]["receiver_observed"] for item in correlations.values()),
        "sent_probes": sum(item["summary"]["sent_probes"] for item in correlations.values()),
        "unmatched_receiver_observations": sum(item["summary"]["unmatched_receiver_observations"] for item in correlations.values()),
        "unassigned_receiver_observations": len(observations) - len(matched_rows),
        "capture_exit_reason": receiver_report.get("exit_reason"),
    }
    for key in ("sized_reply_missing_after_arrival", "receiver_reply_send_failed", "receiver_reply_send_unverified"):
        if any(key in item["summary"] for item in correlations.values()):
            evidence_summary[key] = sum(item["summary"].get(key, 0) for item in correlations.values())
    result["receiver_evidence"] = {
        "tunnelscope_version": VERSION,
        "input_versions": {"diagnosis": declared_version(diagnosis), "receiver": declared_version(receiver_report)},
        "summary": evidence_summary,
        "interpretation": "A receiver observation confirms forward arrival. Missing observations remain inconclusive unless capture coverage is independently established. Receiver and sender clocks are not compared.",
        "correlations": correlations,
    }
    return result

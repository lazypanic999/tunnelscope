"""Bounded single-sender workflow using existing evidence-producing probes."""

from .icmp import require_icmp_support
from .network import compare_fragmentation, probe, require_df_support


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
    attempts = sum(len(item.get("results", [])) for item in all_probes)
    feedback = sum(item.get("summary", {}).get("icmp_feedback", {}).get("size_feedback_events", 0)
                   for item in all_probes)
    return {
        "schema_version": 1,
        "kind": "diagnosis",
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
                     "observe_icmp": True},
        "consistency": {"comparison_source_check": comparison.get("source_check"),
                        "search_target_check": target_check,
                        "search_source_check": source_check},
        "summary": {"attempts": attempts,
                    "icmp_size_feedback_events": feedback,
                    "search": search_summary},
        "interpretation": "One sender-to-target direction only. Runs are sequential and may be affected by route or PMTU-cache changes. A small ACK does not prove same-sized reverse delivery. Missing ACKs and absent ICMP are inconclusive; observed ICMP is untrusted feedback. A reported interval is not an independently measured end-to-end path MTU.",
        "runs": {"fragmentation_comparison": comparison, "size_search": search},
    }


def diagnose(host, port, minimum, maximum, count=2, timeout=1,
             max_sizes=8, family="auto"):
    """Run three bounded Linux experiments against an already controlled target."""
    require_df_support(True)
    require_icmp_support(True)
    if not 32 <= minimum < maximum <= 8192 or not 2 <= max_sizes <= 16:
        raise ValueError("diagnose needs 32 <= MIN < MAX <= 8192 and 2..16 search sizes")
    if not 1 <= count <= 10 or not 1 <= timeout <= 5:
        raise ValueError("diagnose count or timeout is outside CLI bounds")
    compared_sizes = list(dict.fromkeys((minimum, (minimum + maximum) // 2, maximum)))
    max_attempts = (2 * len(compared_sizes) + max_sizes) * count
    if max_attempts > 100 or max_attempts * timeout > 120:
        raise ValueError("diagnose budget exceeds 100 probes or 120 seconds of timeout allowance")
    comparison = compare_fragmentation(host, port, compared_sizes, count,
                                       timeout, family, observe_icmp=True)
    search = probe(host, port, None, count, timeout, True, family,
                   (minimum, maximum), max_sizes, observe_icmp=True)
    return build_diagnosis(comparison, search)

"""Conservative comparison of two fragmentation-mode experiments."""


def compare_fragmentation_reports(df_report, permitted_report):
    """Keep both runs and their observed outcomes, without a causal diagnosis."""
    for name, report, expected in (("df", df_report, True),
                                   ("fragmentation_permitted", permitted_report, False)):
        if not isinstance(report, dict) or report.get("schema_version") != 1 or report.get("kind") != "probe":
            raise ValueError(f"{name}: expected a schema_version 1 probe report")
        settings = report.get("settings")
        summary = report.get("summary")
        if not isinstance(settings, dict) or settings.get("dont_fragment") is not expected:
            raise ValueError(f"{name}: unexpected fragmentation setting")
        if not isinstance(summary, dict) or not isinstance(summary.get("by_payload_size"), list):
            raise ValueError(f"{name}: missing per-size summary")
    first, second = df_report["settings"], permitted_report["settings"]
    for key in ("payload_sizes", "count", "timeout_seconds"):
        if first.get(key) != second.get(key):
            raise ValueError(f"fragmentation runs have different {key}")
    if df_report.get("target") != permitted_report.get("target"):
        raise ValueError("fragmentation runs have different targets")
    df_source, allowed_source = df_report.get("source"), permitted_report.get("source")
    source_keys = ("ipv4", "ipv6", "interface")
    source_check = ("unavailable" if not isinstance(df_source, dict) or not isinstance(allowed_source, dict)
                    else "matched" if all(df_source.get(key) == allowed_source.get(key)
                                          for key in source_keys) else "changed")
    if permitted_report.get("fragmentation_mode") != "permitted":
        raise ValueError("second run did not explicitly permit fragmentation")
    df_rows = df_report["summary"]["by_payload_size"]
    allowed_rows = permitted_report["summary"]["by_payload_size"]
    if len(df_rows) != len(allowed_rows):
        raise ValueError("fragmentation runs have different size summaries")
    rows = []
    for df, allowed in zip(df_rows, allowed_rows):
        if df.get("payload_bytes") != allowed.get("payload_bytes"):
            raise ValueError("fragmentation runs have different size summaries")
        rows.append({"payload_bytes": df["payload_bytes"],
                     "df": {"assessment": df.get("assessment"),
                            "status_counts": df.get("status_counts"),
                            "no_ack_measurement": df.get("no_ack_measurement")},
                     "fragmentation_permitted": {
                         "assessment": allowed.get("assessment"),
                         "status_counts": allowed.get("status_counts"),
                         "no_ack_measurement": allowed.get("no_ack_measurement")},
                     "outcomes_differ": df.get("status_counts") != allowed.get("status_counts")})
    return {
        "schema_version": 1,
        "kind": "fragmentation_comparison",
        "target": df_report["target"],
        "source_check": source_check,
        "settings": {"payload_sizes": first["payload_sizes"], "count_per_mode": first["count"],
                     "timeout_seconds": first["timeout_seconds"], "run_order": ["df", "fragmentation_permitted"]},
        "interpretation": "Two sequential sender-side experiments. The second permits source fragmentation but does not prove fragments traversed the path. Different results suggest a useful follow-up, not a root cause. Timeouts are missing ACKs, not proven packet loss.",
        "comparison": {"by_payload_size": rows},
        "runs": {"df": df_report, "fragmentation_permitted": permitted_report},
    }

"""Runtime version and declared report provenance, without network imports."""

VERSION = "0.9.0.dev0"


def declared_version(report):
    """Return a producer's recorded claim; never infer a legacy version."""
    value = report.get("tunnelscope_version") if isinstance(report, dict) else None
    return value if isinstance(value, str) and value else None

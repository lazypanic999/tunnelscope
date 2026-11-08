"""Parse timezone-aware report timestamps consistently on Python 3.10+."""

from datetime import datetime
import re

TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})")


def parse_timestamp(value):
    """Return an aware datetime, or None for an unrecognized/invalid value."""
    if not isinstance(value, str) or not TIMESTAMP.fullmatch(value):
        return None
    # Python 3.10 accepts fractional seconds with three or six digits only.
    normalized = re.sub(r"\.(\d{1,6})(?=Z|[+-])",
                        lambda match: "." + match.group(1).ljust(6, "0"), value)
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None

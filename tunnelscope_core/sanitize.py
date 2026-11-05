"""Remove addresses, interface names, hostnames and absolute times from reports.

One ``Sanitizer`` instance maps values consistently across every report it
handles, so probe and receiver reports sanitized together can still be
combined or correlated. The mapping itself is never written to a report.
"""

import copy
from datetime import date, datetime, timedelta, timezone
import ipaddress
import re

from tunnelscope_core.network import VERSION

TIME_BASE = datetime(2000, 1, 1, tzinfo=timezone.utc)
KEPT_NETWORKS = tuple(ipaddress.ip_network(net) for net in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32",
))
IPV4_POOL = tuple(f"{prefix}.{host}" for prefix in ("192.0.2", "198.51.100", "203.0.113")
                  for host in range(1, 255))
KEPT_INTERFACES = {"lo"}
KEPT_NAMES = {"localhost"}
NAME_KEYS = {"host"}
INTERFACE_KEYS = {"interface"}

IPV4_TEXT = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)")
IPV6_TEXT = re.compile(r"(?<![\w:.%])[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*(?:%[\w.-]+)?")
DATETIME_TEXT = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:[+-]\d{2}:\d{2}|Z)$")
DATE_TEXT = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _kept(address):
    return (address.is_loopback or address.is_unspecified
            or any(address.version == net.version and address in net for net in KEPT_NETWORKS))


def _parse_ip(text):
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _walk_strings(value, visit, key=None):
    """Return a copy of ``value`` with ``visit(key, text)`` applied to every string."""
    if isinstance(value, dict):
        return {name: _walk_strings(item, visit, name) for name, item in value.items()}
    if isinstance(value, list):
        return [_walk_strings(item, visit, key) for item in value]
    if isinstance(value, str):
        return visit(key, value)
    return value


def _strings(value, key=None):
    if isinstance(value, dict):
        for name, item in value.items():
            yield from _strings(item, name)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item, key)
    elif isinstance(value, str):
        yield key, value


def require_report(report):
    if not isinstance(report, dict) or not (report.get("schema_version") == 1 or isinstance(report.get("lab"), str)):
        raise ValueError("expected a schema_version 1 TunnelScope report")
    if "sanitization" in report:
        raise ValueError("report is already sanitized")


class Sanitizer:
    """Consistent replacement state shared by one batch of reports."""

    def __init__(self, keep_timestamps=False):
        self.keep_timestamps = keep_timestamps
        self.addresses = {}
        self.interfaces = {}
        self.names = {}
        self.time_offset = None
        self._reserved = set()

    def prepare(self, reports):
        """Scan every report first so mappings and the time offset cover the batch."""
        earliest = None
        for report in reports:
            require_report(report)
            for key, text in _strings(report):
                for address in self._addresses_in(text):
                    if _kept(address):
                        self._reserved.add(str(address))
                if key in INTERFACE_KEYS and text not in KEPT_INTERFACES:
                    self.interfaces.setdefault(text, f"if-{len(self.interfaces) + 1}")
                if key in NAME_KEYS and text not in KEPT_NAMES and _parse_ip(text) is None:
                    self.names.setdefault(text, f"host-{len(self.names) + 1}.example")
                moment = self._moment(text)
                if moment is not None and (earliest is None or moment < earliest):
                    earliest = moment
        if earliest is not None and not self.keep_timestamps:
            self.time_offset = TIME_BASE - earliest

    def sanitize(self, report):
        require_report(report)
        result = _walk_strings(copy.deepcopy(report), self._visit)
        result["sanitization"] = self.summary()
        return result

    def summary(self):
        return {
            "tool": f"tunnelscope sanitize {VERSION}",
            "addresses": ("replaced with documentation addresses (RFC 5737, RFC 3849); "
                          "loopback, unspecified and documentation addresses kept"),
            "replaced_addresses": len(self.addresses),
            "interfaces": "replaced with if-N labels; loopback kept",
            "replaced_interfaces": len(self.interfaces),
            "hostnames": "host fields that are not addresses replaced with host-N.example",
            "replaced_hostnames": len(self.names),
            "timestamps": ("kept" if self.keep_timestamps or self.time_offset is None else
                           "shifted by one constant offset per batch; the earliest becomes "
                           + TIME_BASE.isoformat()),
            "retained": "payload sizes, outcomes, RTTs, probe and run IDs, ICMP event fields",
        }

    @staticmethod
    def _moment(text):
        if DATETIME_TEXT.match(text):
            # Python 3.10's fromisoformat does not accept a trailing "Z".
            return datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith("Z") else text)
        if DATE_TEXT.match(text):
            try:
                return datetime.combine(date.fromisoformat(text), datetime.min.time(), timezone.utc)
            except ValueError:
                return None
        return None

    @staticmethod
    def _addresses_in(text):
        for match in IPV6_TEXT.finditer(text):
            address = _parse_ip(match.group().split("%")[0].rstrip("."))
            if address is not None:
                yield address
        for match in IPV4_TEXT.finditer(text):
            address = _parse_ip(match.group())
            if address is not None:
                yield address

    def _replacement(self, address):
        if _kept(address):
            return str(address)
        original = str(address)
        if original not in self.addresses:
            if address.version == 6 and address.ipv4_mapped is not None:
                self.addresses[original] = "::ffff:" + self._replacement(address.ipv4_mapped)
                return self.addresses[original]
            pool = (IPV4_POOL if address.version == 4 else
                    (f"2001:db8::{index:x}" for index in range(1, 1 << 16)))
            used = set(self.addresses.values()) | self._reserved
            for candidate in pool:
                if candidate not in used:
                    self.addresses[original] = candidate
                    break
            else:
                raise ValueError("too many distinct addresses to sanitize in one batch")
        return self.addresses[original]

    def _replace_ipv6(self, match):
        token = match.group()
        trailing = "." if token.endswith(".") else ""
        body = token[:-1] if trailing else token
        text, _, scope = body.partition("%")
        address = _parse_ip(text)
        if address is None or address.version != 6:
            return token
        replaced = self._replacement(address)
        if scope:
            replaced += "%" + self.interfaces.get(scope, scope if scope in KEPT_INTERFACES else "if-scope")
        return replaced + trailing

    def _replace_ipv4(self, match):
        address = _parse_ip(match.group())
        return match.group() if address is None else self._replacement(address)

    def _visit(self, key, text):
        if key in INTERFACE_KEYS and text in self.interfaces:
            return self.interfaces[text]
        if key in NAME_KEYS and text in self.names:
            return self.names[text]
        moment = self._moment(text)
        if moment is not None:
            if self.time_offset is None:
                return text
            shifted = moment + self.time_offset
            if DATE_TEXT.match(text):
                return shifted.date().isoformat()
            timespec = "microseconds" if "." in text else "seconds"
            shifted = shifted.astimezone(moment.tzinfo).isoformat(timespec=timespec)
            return shifted[:-6] + "Z" if text.endswith("Z") else shifted
        text = IPV6_TEXT.sub(self._replace_ipv6, text)
        text = IPV4_TEXT.sub(self._replace_ipv4, text)
        for original, label in (*self.interfaces.items(), *self.names.items()):
            text = re.sub(rf"(?<![\w.-]){re.escape(original)}(?![\w-])", label, text)
        return text


def sanitize_reports(reports, keep_timestamps=False):
    """Sanitize a batch of reports with one shared mapping; inputs are not modified."""
    sanitizer = Sanitizer(keep_timestamps)
    sanitizer.prepare(reports)
    return [sanitizer.sanitize(report) for report in reports]

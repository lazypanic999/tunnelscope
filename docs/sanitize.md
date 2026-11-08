# Sanitize reports before sharing

`tunnelscope sanitize` writes copies of reports with network identifiers and
absolute times replaced, so that field evidence can be shared in issues and
validation records. It was added in v0.7.0. From a source checkout, run
`python tunnelscope.py sanitize ...`.

```sh
mkdir shared
tunnelscope sanitize probe.json receiver.json diagnosis.json --output-dir shared --html
```

Each input keeps its file name in the existing output directory. `--html`
also writes the offline view for each copy. The command never modifies an
input and refuses to overwrite an existing file. Up to 32 reports can be
sanitized in one batch.

## What changes

| Value | Replacement |
| --- | --- |
| IPv4 and IPv6 addresses, in any field or text | Documentation addresses: `192.0.2.x`, `198.51.100.x`, `203.0.113.x` ([RFC 5737](https://www.rfc-editor.org/rfc/rfc5737.html)) and `2001:db8::x` ([RFC 3849](https://www.rfc-editor.org/rfc/rfc3849.html)) |
| Interface names (`interface` fields, IPv6 scope IDs and the same names in text) | `if-1`, `if-2`, ... |
| `host` values that are not addresses | `host-1.example`, `host-2.example`, ... |
| Timestamps and dates | Shifted by one constant per batch; the earliest becomes `2000-01-01T00:00:00+00:00` |

Loopback and unspecified addresses, documentation addresses already in a
report, the `lo` interface and `localhost` stay unchanged. Payload sizes,
outcomes, RTTs, ports, probe and run IDs, kernel MTU values and ICMP event
fields stay unchanged because they carry the evidence.

Use `--keep-timestamps` when absolute times are not sensitive, for example to
compare them with an external packet capture.

## Sanitize related reports together

Replacements are consistent within one batch: the same original value always
gets the same placeholder, and time differences between files are preserved.
Reports sanitized together can still be joined:

```sh
tunnelscope correlate shared/probe.json shared/receiver.json --html shared/correlation.html
```

The joined result has the same per-probe evidence as joining the originals,
including `endpoint_check` and the target/bind address checks. Placeholders
from different batches are unrelated: `192.0.2.1` in two separate batches
may stand for two different hosts.

Interface and hostname labels avoid names already present in the input batch,
so the first interface is not necessarily `if-1`. An IPv6 scope ID gets a
consistent interface label even when no separate `interface` field names it;
different scope IDs keep different labels. Known names in free text are
replaced in one pass so a generated label is not renamed again.

## What the record says

Each copy gets a top-level `sanitization` object listing what kind of values
were replaced and how many distinct addresses, interfaces and hostnames were
mapped. The mapping itself is never written. `tunnelscope show` prints a
"Sanitized report" line first, and the HTML view shows a "Sanitized report"
section. A report that already has a `sanitization` object is refused.

## Review before sharing

The command replaces values it can recognize. It errs toward replacing:
a four-part version string such as a kernel release `6.6.87.2` is also a
valid IPv4 address, so it is replaced like one. Free text that names a site,
customer or device in another form, file names and anything added by hand
are not guaranteed to be clean. Read the copies before you publish them.
See [security boundaries](security-boundaries.md).

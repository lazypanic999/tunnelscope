# Report producer versions

This additive metadata is available in v0.9.0 and newer. The v0.8.2
collectors do not write it.

New probe and receiver reports record `tunnelscope_version`. A newly built
correlation, bidirectional comparison, fragmentation comparison or diagnosis
also records its producer version and `input_versions` for its immediate
inputs. For example, joining a versioned sender report with an older receiver
capture can produce:

```json
{
  "schema_version": 1,
  "kind": "probe_receiver_correlation",
  "tunnelscope_version": "0.9.1",
  "input_versions": {"probe": "0.9.0", "receiver": null}
}
```

This is a metadata excerpt, not a complete report. `null` means the input did
not record a valid string version; the current CLI version is never used as
a substitute. A version copied from another report is its declared claim,
not proof of the binary that ran. Existing report files remain readable and
keep `schema_version: 1`; packet and ACK formats are unchanged.

When a later `correlate` operation adds receiver evidence to an existing
diagnosis, the original top-level producer stays unchanged, including absence
on a legacy diagnosis. The new `receiver_evidence` object records the join
producer and its diagnosis/receiver input versions separately. This avoids
claiming that old measurements were collected by a newer tool.

Text, HTML and Markdown views display available producer details. An unknown
input is labeled `unknown (not recorded)`. For an unversioned standalone
legacy report, an absent producer means unknown; it is not inferred from its
filename, example label or schema number. HTML and Markdown escape these
values as untrusted report data. Markdown retains its output limits.

Batch sanitization preserves normal producer-version strings and the join
relationship while replacing identifiers. Sanitizer metadata describes the
sanitizing tool separately; it does not relabel the original measurement
producer. Version strings are useful in a field report but do not replace
the OS, Python version and exact command line requested by the
[field report guide](field-reports.md).

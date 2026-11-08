# Tracing retained lab evidence to a CI run

From v0.9.0, CI artifacts include `manifest.json` beside retained lab reports.
The delivery matrix, WireGuard workflow and OpenVPN workflow record:

- The workflow/run/attempt identifiers, event and repository.
- `tested_commit`: GitHub's `GITHUB_SHA`. On a pull request this can be the
  temporary merge commit actually tested.
- `source_commit`: the pull request's head SHA, or the tested commit for
  another event. These two roles are deliberately separate.
- Python implementation/version, operating system and kernel release.
- Each retained JSON file's relative path, byte count and SHA-256. Declared
  lab/kind/producer fields are copied when present; old versions are not
  inferred.

Hashes cover the exact stored bytes, including encoding and line endings.
The manifest excludes itself and does not change report files. Partially
written or failed JSON is still hashed and marked `json_state: invalid` so a
failed job's artifact can be inspected. A missing output directory produces
no manifest. The generator reads an explicit allowlist of CI variables; it
does not copy the environment or credentials.

Use the artifact attached to its Actions run and compare the JSON bytes to
its recorded hash. A manifest is declared provenance, not a signature or an
independent witness. Someone changing both a report and its manifest can
change the recorded hash. A passing controlled lab also remains separate
from independent operator field evidence.

To make the same inventory of local retained output:

```sh
python scripts/write_lab_manifest.py --directory output/my-lab
```

Outside GitHub Actions, CI fields are normally `null`; runtime and file hashes
still describe the local files. The manifest itself is not a TunnelScope
measurement report and is not an input to `show`, `correlate` or `sanitize`.

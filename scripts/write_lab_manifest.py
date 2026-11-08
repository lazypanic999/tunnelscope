"""Record lab artifact hashes and an explicit allowlist of CI provenance."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform


def build_manifest(directory):
    """Describe retained JSON bytes without changing or trusting their contents."""
    reports = []
    for path in sorted(directory.rglob("*.json")):
        if path == directory / "manifest.json" or not path.is_file():
            continue
        data = path.read_bytes()
        item = {"path": path.relative_to(directory).as_posix(), "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest()}
        try:
            report = json.loads(data)
        except (ValueError, UnicodeError):
            item["json_state"] = "invalid"
        else:
            item["json_state"] = "parsed"
            if isinstance(report, dict):
                for field in ("lab", "kind", "tunnelscope_version"):
                    if isinstance(report.get(field), str):
                        item[field] = report[field]
        reports.append(item)
    github = {name: os.environ.get(variable) for name, variable in (
        ("repository", "GITHUB_REPOSITORY"), ("workflow", "GITHUB_WORKFLOW"),
        ("run_id", "GITHUB_RUN_ID"), ("run_attempt", "GITHUB_RUN_ATTEMPT"),
        ("event", "GITHUB_EVENT_NAME"), ("tested_commit", "GITHUB_SHA"),
        ("source_commit", "TUNNELSCOPE_SOURCE_SHA"))}
    return {"manifest_version": 1,
            "interpretation": "Declared CI metadata and hashes of retained JSON; not a signature or independent field evidence.",
            "github": github,
            "runtime": {"python": platform.python_version(), "implementation": platform.python_implementation(),
                        "system": platform.system(), "release": platform.release()},
            "reports": reports}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    if not args.directory.exists():
        print("No lab artifact directory; no manifest written.")
        return
    if not args.directory.is_dir():
        parser.error("--directory must name a directory")
    manifest = build_manifest(args.directory)
    (args.directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Recorded provenance and SHA-256 for {len(manifest['reports'])} retained JSON files")


if __name__ == "__main__":
    main()

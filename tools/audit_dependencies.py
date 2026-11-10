"""Explicit online audit of public pinned package metadata; never sends project data."""

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--online", action="store_true", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or output.is_relative_to(ROOT):
        parser.error("Audit evidence needs a new file outside the public checkout")
    raw = output.with_name(output.stem + "-raw.json")
    if raw.exists() or not output.parent.is_dir():
        parser.error("Evidence parent must exist and raw output must be new")
    result = subprocess.run(
        [
            sys.executable,
            "-B",
            "-m",
            "pip_audit",
            "--disable-pip",
            "--no-deps",
            "-r",
            str(ROOT / "requirements-win-py314.lock"),
            "-f",
            "json",
            "-o",
            str(raw),
        ],
        capture_output=True,
        timeout=180,
    )
    if result.returncode not in (0, 1) or not raw.is_file():
        raise RuntimeError("Dependency audit unavailable; no clean result claimed")
    report = json.loads(raw.read_bytes())
    findings = [v for dep in report["dependencies"] for v in dep["vulns"]]
    evidence = {
        "checked_at": datetime.now(UTC).isoformat(),
        "lock_sha256": hashlib.sha256(
            (ROOT / "requirements-win-py314.lock").read_bytes()
        ).hexdigest(),
        "vulnerabilities": findings,
        "raw_path": str(raw),
        "raw_sha256": hashlib.sha256(raw.read_bytes()).hexdigest(),
        "source": "pip-audit public package metadata service",
    }
    output.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())

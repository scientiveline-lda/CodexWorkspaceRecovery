"""Pinned local Gitleaks scan of staged bytes and reachable Git history; no uploads."""

import argparse
import hashlib
import json
import subprocess
import tempfile
import urllib.request
import zipfile
from pathlib import Path

from publication_audit import public_files

ROOT = Path(__file__).resolve().parents[1]
VERSION = "8.30.1"
SHA256 = "d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e"
EXE_SHA256 = "17157e2ee8b76fc8b1d8bee607a250e34b8a8023c8bc81822d4b5ee4d78fcb7c"


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--download",
        action="store_true",
        help="Download pinned public scanner; never uploads repository contents",
    )
    args = p.parse_args()
    names = public_files(ROOT, index=True)
    target = ROOT / "artifacts/security-tools"
    exe = target / "gitleaks.exe"
    if not exe.exists() and args.download:
        target.mkdir(parents=True, exist_ok=True)
        url = f"https://github.com/gitleaks/gitleaks/releases/download/v{VERSION}/gitleaks_{VERSION}_windows_x64.zip"
        data = urllib.request.urlopen(url, timeout=60).read()
        if hashlib.sha256(data).hexdigest() != SHA256:
            raise RuntimeError("Scanner archive digest mismatch")
        import io

        with zipfile.ZipFile(io.BytesIO(data)) as z:
            exe.write_bytes(z.read("gitleaks.exe"))
    if not exe.exists() or hashlib.sha256(exe.read_bytes()).hexdigest() != EXE_SHA256:
        raise RuntimeError("Missing or untrusted scanner; provision with --download")
    with tempfile.TemporaryDirectory(prefix="cwm-public-scan-") as tmp:
        root = Path(tmp)
        snapshot = root / "index"
        snapshot.mkdir()
        for name in names:
            out = snapshot / name
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(subprocess.check_output(["git", "show", ":" + name], cwd=ROOT))

        def scan(mode, path, label):
            report = root / (label + ".json")
            command = [
                str(exe),
                mode,
                str(path),
                "--redact=100",
                "--no-banner",
                "--no-color",
                "--report-format",
                "json",
                "--report-path",
                str(report),
                "--ignore-gitleaks-allow",
            ]
            if mode == "git":
                command.extend(["--log-opts", "--all"])
            result = subprocess.run(command, capture_output=True, cwd=root)
            if result.returncode:
                findings = json.loads(report.read_text(encoding="utf-8")) if report.exists() else []
                print(
                    json.dumps(
                        {
                            "scope": label,
                            "status": "failed",
                            "findings": [
                                {
                                    "rule": f.get("RuleID"),
                                    "file": f.get("File"),
                                    "line": f.get("StartLine"),
                                }
                                for f in findings
                            ],
                        }
                    )
                )
                raise RuntimeError("Secret scan failed; sensitive match values are suppressed")

        scan("dir", snapshot, "staged-snapshot")
        commits = int(subprocess.check_output(["git", "rev-list", "--all", "--count"], cwd=ROOT))
        if commits:
            scan("git", ROOT, "reachable-history")
        print(
            json.dumps(
                {
                    "status": "passed",
                    "scanner": "gitleaks",
                    "version": VERSION,
                    "staged_files": len(names),
                    "reachable_commits": commits,
                }
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

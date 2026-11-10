"""Audit the exact Git index, without printing matched private content."""

import argparse
import json
import re
import subprocess
from pathlib import Path, PurePosixPath

PRIVATE_PARTS = {
    "private",
    "config",
    "local",
    "laboratory",
    "artifacts",
    "vendor",
    "dist",
    "build",
    ".venv",
    ".codex",
    ".aws",
    ".ssh",
    "evidence",
    "plans",
    "__pycache__",
}
PRIVATE_SUFFIXES = {
    ".clixml",
    ".vhdx",
    ".vmcx",
    ".iso",
    ".age",
    ".agekey",
    ".key",
    ".pem",
    ".pfx",
    ".p12",
    ".db",
    ".sqlite",
    ".jsonl",
    ".exe",
    ".dll",
    ".zip",
    ".whl",
    ".log",
    ".bundle",
    ".patch",
}
PATTERNS = {
    "personal-home-path": re.compile(
        rb"(?:[A-Za-z]:[\\/]+Users[\\/]+[A-Za-z0-9._-]+[\\/]|(?<![A-Za-z0-9_/])/(?:home|Users)/[A-Za-z0-9._-]+/)",
        re.I,
    ),
    "private-key-material": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "age-private-identity": re.compile(rb"AGE-SECRET-KEY-[A-Z0-9]{20,}"),
    "github-token": re.compile(rb"(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})"),
    "openai-token": re.compile(rb"sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{40,}"),
    "aws-access-key": re.compile(rb"(?:AKIA|ASIA)[A-Z0-9]{16}"),
}


def allowed_name(name):
    p = PurePosixPath(name)
    return (
        not p.is_absolute()
        and ".." not in p.parts
        and "\\" not in name
        and not any(x.lower() in PRIVATE_PARTS for x in p.parts)
        and p.suffix.lower() not in PRIVATE_SUFFIXES
        and not p.name.lower().startswith(".env")
    )


def audit_bytes(name, data):
    findings = []
    if not allowed_name(name):
        findings.append({"path": name, "rule": "private-file-class"})
    if len(data) > 2 * 1024 * 1024 or b"\x00" in data:
        findings.append({"path": name, "rule": "binary-or-oversized"})
    for rule, pattern in PATTERNS.items():
        for match in pattern.finditer(data):
            findings.append(
                {"path": name, "rule": rule, "line": data[: match.start()].count(b"\n") + 1}
            )
    return findings


def public_files(root, *, index=False):
    root = Path(root)

    def read(name):
        if index:
            return subprocess.check_output(["git", "show", ":" + name], cwd=root)
        p = root / name
        if p.is_symlink() or not p.is_file() or not p.resolve().is_relative_to(root.resolve()):
            raise ValueError("Unsafe or missing public file: " + name)
        return p.read_bytes()

    manifest = json.loads(read("packaging/public-files.json"))
    names = manifest["files"]
    if (
        manifest["schema_version"] != 1
        or len(names) != len(set(names))
        or not all(allowed_name(n) for n in names)
    ):
        raise ValueError("Invalid public-file allowlist")
    if index:
        entries = (
            subprocess.check_output(["git", "ls-files", "--stage", "-z"], cwd=root)
            .decode()
            .split("\0")
        )
        actual = []
        for entry in filter(None, entries):
            metadata, name = entry.split("\t", 1)
            mode, _, stage = metadata.split()
            if mode not in {"100644", "100755"} or stage != "0":
                raise ValueError("Unsafe index entry: " + name)
            actual.append(name)
        if set(actual) != set(names):
            raise ValueError(
                "Git index differs from public-file allowlist: "
                + repr(sorted(set(actual) ^ set(names)))
            )
    findings = []
    for name in names:
        findings.extend(audit_bytes(name, read(name)))
    if findings:
        raise ValueError(json.dumps({"findings": findings}))
    return names


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--working-tree",
        action="store_true",
        help="Validate declared files for packaging; default checks exact index",
    )
    args = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        names = public_files(root, index=not args.working_tree)
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        print(str(exc))
        return 1
    print(
        json.dumps(
            {
                "status": "passed",
                "files": len(names),
                "scope": "declared working files" if args.working_tree else "Git index",
                "note": "Also requires maintained secret scanning and human review",
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

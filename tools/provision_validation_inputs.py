"""Explicit network provisioning of hash-pinned validation inputs; never uploads data."""

import argparse
import hashlib
import json
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--download", action="store_true")
    a = p.parse_args()
    if not a.download:
        p.error("Network provisioning requires --download")
    lock = json.loads((ROOT / "packaging/runtime-lock.json").read_text(encoding="utf-8"))
    target = ROOT / "artifacts" / lock["file"]
    target.parent.mkdir(exist_ok=True)
    if not target.exists():
        data = urllib.request.urlopen(lock["url"], timeout=60).read()
        if hashlib.sha256(data).hexdigest() != lock["sha256"]:
            raise RuntimeError("Runtime archive digest mismatch")
        with target.open("xb") as f:
            f.write(data)
    with target.open("rb") as f:
        if hashlib.file_digest(f, "sha256").hexdigest() != lock["sha256"]:
            raise RuntimeError("Cached runtime digest mismatch")
    for notice in json.loads((ROOT / "packaging/notices-lock.json").read_text(encoding="utf-8")):
        target_notice = ROOT / "artifacts/notices" / notice["file"]
        target_notice.parent.mkdir(exist_ok=True)
        if not target_notice.exists():
            data = urllib.request.urlopen(notice["url"], timeout=30).read(100000)
            if hashlib.sha256(data).hexdigest() != notice["sha256"]:
                raise RuntimeError("Notice digest mismatch")
            target_notice.write_bytes(data)
        if hashlib.sha256(target_notice.read_bytes()).hexdigest() != notice["sha256"]:
            raise RuntimeError("Cached notice digest mismatch")
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "download",
            "--only-binary=:all:",
            "--require-hashes",
            "-r",
            str(ROOT / "requirements-win-py314.lock"),
            "--dest",
            str(ROOT / "artifacts/wheels"),
        ],
        check=True,
    )
    print("Pinned validation inputs provisioned; recovery phases require no downloads.")


if __name__ == "__main__":
    main()

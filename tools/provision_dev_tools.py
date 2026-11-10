"""Explicit development/CI provisioning from locked upstream archives. Never called by recovery."""

import argparse
import hashlib
import io
import json
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def provision():
    configs = {}
    for item in json.loads((ROOT / "packaging/toolchain-lock.json").read_text(encoding="utf-8")):
        with urllib.request.urlopen(item["url"], timeout=60) as response:
            data = response.read(100 * 1024 * 1024 + 1)
        if (
            len(data) > 100 * 1024 * 1024
            or hashlib.sha256(data).hexdigest() != item["archive_sha256"]
        ):
            raise RuntimeError("Locked development tool archive mismatch")
        folder = ROOT / "vendor" / item["name"]
        folder.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for info in z.infolist():
                leaf = Path(info.filename).name
                if leaf not in {"age.exe", "age-keygen.exe", "minisign.exe"}:
                    continue
                target = folder / leaf
                target.write_bytes(z.read(info))
                if leaf == item["name"] + ".exe" or leaf == "age-keygen.exe":
                    configs["age-keygen" if leaf == "age-keygen.exe" else item["name"]] = {
                        "path": str(target),
                        "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
                    }
    git_lock = json.loads((ROOT / "packaging/git-runtime-lock.json").read_text())
    with urllib.request.urlopen(git_lock["url"], timeout=60) as response:
        data = response.read(128 * 1024**2)
    if hashlib.sha256(data).hexdigest() != git_lock["archive_sha256"]:
        raise RuntimeError("Pinned Git archive mismatch")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for name, entry in git_lock["files"].items():
            content = archive.read(name)
            if hashlib.sha256(content).hexdigest() != entry["sha256"]:
                raise RuntimeError("Pinned Git member mismatch")
            target = ROOT / "vendor/git" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
    git_path = ROOT / "vendor/git/cmd/git.exe"
    configs["git"] = {"path": str(git_path), "sha256": git_lock["files"]["cmd/git.exe"]["sha256"]}
    (ROOT / "vendor/toolchain.json").write_text(json.dumps(configs, indent=2), encoding="utf-8")
    print(
        "Provisioned hash-pinned development crypto tools; build-time downloads only; recovery never downloads inputs"
    )


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--download", action="store_true", required=True)
    p.parse_args()
    provision()

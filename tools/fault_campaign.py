"""Real child termination on synthetic fixtures; no failpoints in production code."""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
import zipfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from cwm.archive import export
from cwm.capture import ReadGuard, capture
from cwm.restore import apply, plan, resume, verify_restore
from cwm.security import Toolchain, protect_directory
from tests.helpers import GIT, TOOLS, fixture, keys

CASES = [
    "acquisition",
    "archive-creation",
    "signing",
    "encryption",
    "verification",
    "extraction",
    "project-deployment",
    "before-publication",
    "after-publication",
]


def inventory(root):
    return {
        p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


def export_fixture(root, crypto, work="export"):
    return export(
        root / "capture",
        root / "archive.age",
        root / work,
        TOOLS,
        signing_key=crypto["signing_key"],
        key_id="fixture-signer",
        producer="cwm-fixture",
        scope="synthetic",
        recipients=crypto["recipients"],
        identity=crypto["identity"],
        trust=crypto["trust"],
        git_exe=GIT,
    )


def child(root, boundary):
    root = Path(root)
    crypto = {
        k: Path(v) if k not in ("recipients",) else v
        for k, v in json.loads((root / "crypto.json").read_text()).items()
    }

    def pause(*_):
        (root / "at-boundary.json").write_text(
            json.dumps({"boundary": boundary, "pid": os.getpid()})
        )
        while True:
            time.sleep(1)

    if boundary == "acquisition":
        original = ReadGuard.copy

        def copy(guard, target):
            original(guard, target)
            pause()

        with patch.object(ReadGuard, "copy", copy):
            capture(
                root / "source-home",
                root / "source-home",
                root / "capture",
                projects=[root / "project"],
                maintenance=True,
            )
        return
    if boundary in {"signing", "encryption", "verification", "archive-creation"}:
        import cwm_verify

        target, name = {
            "signing": (Toolchain, "sign"),
            "encryption": (Toolchain, "encrypt"),
            "verification": (cwm_verify, "verify"),
            "archive-creation": (zipfile.ZipFile, "write"),
        }[boundary]
        original = getattr(target, name)

        def stop(*args, **kwargs):
            result = original(*args, **kwargs) if boundary == "archive-creation" else None
            pause()
            return result

        with patch.object(target, name, stop):
            export_fixture(root, crypto)
        return
    if boundary == "extraction":
        import cwm_verify

        original = zipfile.ZipFile.open

        def open_member(z, *args, **kwargs):
            if (root / "planning/payload").exists():
                pause()
            return original(z, *args, **kwargs)

        with patch.object(zipfile.ZipFile, "open", open_member):
            plan(
                root / "archive.age",
                root / "destination",
                root / "planning",
                identity=crypto["identity"],
                trust=crypto["trust"],
                tools=TOOLS,
            )
        return
    import cwm.restore as restore

    if boundary == "project-deployment":
        original = restore.restore_project

        def deploy(*args):
            result = original(*args)
            pause()
            return result

        with patch.object(restore, "restore_project", deploy):
            apply(root / "planning/restore-plan.json", GIT)
    else:
        original = os.rename

        def rename(src, dst, *args, **kwargs):
            if Path(dst) == root / "destination":
                if boundary == "after-publication":
                    original(src, dst, *args, **kwargs)
                pause()
            return original(src, dst, *args, **kwargs)

        with patch.object(os, "rename", rename):
            apply(root / "planning/restore-plan.json", GIT)


def campaign(workspace):
    workspace = protect_directory(workspace)
    evidence = []
    for boundary in CASES:
        root = protect_directory(workspace / boundary)
        home, project, _ = fixture(root)
        crypto = keys(root)
        (root / "crypto.json").write_text(
            json.dumps({k: str(v) if isinstance(v, Path) else v for k, v in crypto.items()})
        )
        source_before = {"home": inventory(home), "project": inventory(project)}
        if boundary != "acquisition":
            capture(home, home, root / "capture", projects=[project], maintenance=True)
        if boundary in {
            "extraction",
            "project-deployment",
            "before-publication",
            "after-publication",
        }:
            export_fixture(root, crypto)
        if boundary in {"project-deployment", "before-publication", "after-publication"}:
            plan(
                root / "archive.age",
                root / "destination",
                root / "planning",
                identity=crypto["identity"],
                trust=crypto["trust"],
                tools=TOOLS,
            )
        log = (root / "child.log").open("wb")
        process = subprocess.Popen(
            [
                sys.executable,
                "-B",
                str(Path(__file__).resolve()),
                "--child",
                boundary,
                "--workspace",
                str(root),
            ],
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 120
            while not (root / "at-boundary.json").exists():
                if process.poll() is not None:
                    raise RuntimeError("Fault worker exited before barrier: " + boundary)
                if time.monotonic() > deadline:
                    raise RuntimeError("Fault barrier timeout: " + boundary)
                time.sleep(0.05)
            if os.name == "nt":
                subprocess.run(
                    [
                        str(Path(os.environ["SystemRoot"]) / "System32/taskkill.exe"),
                        "/PID",
                        str(process.pid),
                        "/T",
                        "/F",
                    ],
                    capture_output=True,
                    check=True,
                )
            else:
                process.kill()
            process.wait(timeout=20)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=20)
            log.close()
        if {"home": inventory(home), "project": inventory(project)} != source_before:
            raise RuntimeError("Source mutated in fault campaign")
        if boundary in {"acquisition", "archive-creation", "signing", "encryption", "verification"}:
            if (root / "archive.age").exists() or (root / "destination").exists():
                raise RuntimeError("Interrupted operation exposed a completed output")
            recovery = "safe_retained_incomplete_staging"
        elif boundary == "extraction":
            if (root / "destination").exists() or (root / "planning/restore-plan.json").exists():
                raise RuntimeError("Interrupted extraction created completed plan/destination")
            recovery = "safe_retained_incomplete_staging"
        else:
            result = resume(root / "planning/restore-plan.json", GIT)
            if (
                result["status"] not in {"already_applied", "portable_reconstructed"}
                or verify_restore(root / "planning/restore-plan.json", GIT)["status"] != "verified"
            ):
                raise RuntimeError("Killed restoration failed reconciliation")
            recovery = result["status"]
        evidence.append(
            {
                "boundary": boundary,
                "status": "passed",
                "actual_process_termination": True,
                "source_unchanged": True,
                "recovery": recovery,
            }
        )
        (workspace / "fault-results.json").write_text(json.dumps(evidence, indent=2))
    return evidence


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--child", choices=CASES)
    args = parser.parse_args()
    if args.child:
        child(args.workspace, args.child)
    else:
        print(json.dumps({"status": "passed", "cases": campaign(args.workspace)}))

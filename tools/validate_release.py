"""Local candidate-bound portable release gates. Never publishes."""

import argparse
import hashlib
import json
import subprocess
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from publication_audit import public_files

PHASES = ["baseline", "fixtures", "engineering", "faults", "package", "acceptance", "report"]
REQUIRED = PHASES[:-1]


def sha(path):
    with Path(path).open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def write(path, value):
    from cwm.util import write_json

    write_json(path, value, replace=Path(path).exists())


def fingerprint(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def candidate_state():
    files = {
        n: {"sha256": sha(ROOT / n), "size": (ROOT / n).stat().st_size} for n in public_files(ROOT)
    }
    return {"files": files, "sha256": fingerprint(files)}


def command(args, work, timeout=1800):
    result = subprocess.run(list(map(str, args)), cwd=ROOT, capture_output=True, timeout=timeout)
    (work / ("command-" + uuid.uuid4().hex[:8] + ".log")).write_bytes(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError("Validation failed; inspect protected logs")


def baseline(a, work):
    write(
        a.candidate,
        {
            "schema_version": 2,
            "source": candidate_state(),
            "python": sys.version,
            "contract": "portable-filesystem-v1",
        },
    )
    command([sys.executable, "-B", ROOT / "tools/publication_audit.py"], work)
    command([sys.executable, "-B", ROOT / "tools/secret_scan.py"], work)
    return {"status": "passed"}


def fixtures(a, work):
    command(
        [sys.executable, "-B", ROOT / "tools/test_report.py", "--output", work / "tests.json"], work
    )
    return {"status": "passed", "tests": read(work / "tests.json")["tests"]}


def engineering(a, work):
    args = [
        ROOT / ".quality/Scripts/python.exe",
        "-B",
        ROOT / "tools/engineering_gate.py",
        "--workspace",
        work / "quality",
    ]
    if a.dependency_audit:
        args += ["--dependency-audit", a.dependency_audit]
    command(args, work)
    return {"status": "passed"}


def faults(a, work):
    command(
        [sys.executable, "-B", ROOT / "tools/fault_campaign.py", "--workspace", work / "campaign"],
        work,
    )
    return {"status": "passed", "boundaries": 9}


def package(a, work):
    import tarfile
    import zipfile

    outputs = []
    canary = ROOT / "src/cwm/unreviewed_privacy_canary.py"
    text = ("CWM_PRIVACY_" + uuid.uuid4().hex).encode()
    if canary.exists():
        raise RuntimeError("Canary path already exists")
    try:
        for n in (1, 2):
            if n == 2:
                canary.write_bytes(text)
            dest = work / ("distribution-" + str(n))
            command(
                [sys.executable, "-B", ROOT / "packaging/build_windows.py", "--output", dest], work
            )
            outputs.append(dest)
        wheels = work / "wheels"
        wheels.mkdir()
        command(
            [
                sys.executable,
                "-m",
                "pip",
                "wheel",
                "--no-deps",
                "--no-build-isolation",
                "--no-cache-dir",
                "--wheel-dir",
                wheels,
                ".",
            ],
            work,
        )
        command(
            [
                sys.executable,
                "-c",
                "import setuptools.build_meta as b; b.build_sdist(" + repr(str(wheels)) + ")",
            ],
            work,
        )
        for wheel in wheels.glob("*.whl"):
            with zipfile.ZipFile(wheel) as archive:
                if any(
                    "canary" in name or text in archive.read(name) for name in archive.namelist()
                ):
                    raise RuntimeError("Python wheel leaked canary")
        for source in wheels.glob("*.tar.gz"):
            with tarfile.open(source) as archive:
                for member in archive.getmembers():
                    if member.isfile() and (
                        "canary" in member.name or text in archive.extractfile(member).read()
                    ):
                        raise RuntimeError("Python source package leaked canary")
    finally:
        if canary.exists() and canary.read_bytes() == text:
            canary.unlink()
    zips = [Path(str(p) + ".zip") for p in outputs]
    if sha(zips[0]) != sha(zips[1]):
        raise RuntimeError("Unsigned builds differ or unreviewed input leaked")
    source = read(a.candidate)["source"]["files"]
    actual = {
        p.relative_to(outputs[0] / "app").as_posix(): sha(p)
        for p in (outputs[0] / "app").rglob("*")
        if p.is_file()
        and (
            p.relative_to(outputs[0] / "app").as_posix().startswith("cwm/")
            or p.name == "cwm_verify.py"
        )
    }
    expected = {
        n.removeprefix("src/"): e["sha256"] for n, e in source.items() if n.startswith("src/")
    }
    if actual != expected:
        raise RuntimeError("Packaged application differs from frozen candidate")
    return {
        "status": "passed",
        "directory": str(outputs[0]),
        "zip": str(zips[0]),
        "zip_sha256": sha(zips[0]),
        "privacy_canaries_excluded": True,
        "python_distributions_checked": True,
        "package_sha256": fingerprint(
            {
                p.relative_to(outputs[0]).as_posix(): sha(p)
                for p in outputs[0].rglob("*")
                if p.is_file()
            }
        ),
    }


def acceptance(a, work):
    import zipfile

    pkg = read(a.workspace / "package.json")
    if pkg["status"] != "passed":
        raise RuntimeError("Passed package gate required")
    archive = Path(pkg["details"]["zip"])
    if sha(archive) != pkg["details"]["zip_sha256"]:
        raise RuntimeError("Distribution archive changed")
    with zipfile.ZipFile(archive) as z:
        for name in z.namelist():
            if not name.startswith("cwm/") or ".." in Path(name).parts or "\\" in name:
                raise RuntimeError("Unsafe distribution member")
        z.extractall(work / "extracted")
    command(
        [
            sys.executable,
            "-B",
            ROOT / "tools/end_to_end_drill.py",
            "--package",
            work / "extracted/cwm",
            "--workspace",
            work / "c",
        ],
        work,
        3600,
    )
    return {
        "status": "passed",
        "result": read(work / "c/acceptance.json"),
        "distribution_zip_sha256": sha(archive),
    }


def report(a, work):
    entries = {}
    state = candidate_state()
    candidate_hash = sha(a.candidate)
    for phase in REQUIRED:
        receipt = a.workspace / (phase + ".json")
        value = read(receipt) if receipt.exists() else {"status": "not_tested"}
        if value.get("status") == "passed":
            if (
                value.get("candidate_sha256") != candidate_hash
                or value.get("source_sha256") != state["sha256"]
            ):
                value = {"status": "failed", "reason": "Evidence belongs to another candidate"}
            else:
                root = Path(value.get("evidence_root", "")).resolve()
                for name, entry in value.get("evidence", {}).items():
                    file = (root / name).resolve()
                    if (
                        not root.is_relative_to(a.workspace.resolve())
                        or not file.is_relative_to(root)
                        or not file.is_file()
                        or sha(file) != entry["sha256"]
                    ):
                        value = {
                            "status": "failed",
                            "reason": "Recorded evidence missing or changed",
                        }
                        break
        entries[phase] = {k: value[k] for k in ["status", "reason"] if k in value}
    decision = "go" if all(v["status"] == "passed" for v in entries.values()) else "no-go"
    value = {
        "decision": decision,
        "contract": "portable-filesystem-v1",
        "candidate_sha256": candidate_hash,
        "source_sha256": state["sha256"],
        "gates": entries,
        "publication": "Not performed; company approval separate",
        "artifact_signature": "unsigned",
        "application_import": False,
    }
    write(a.workspace / "release-decision.json", value)
    (a.workspace / "release-decision.md").write_text(
        "# Portable technical decision: "
        + decision.upper()
        + "\n\n"
        + json.dumps(value, indent=2)
        + "\n",
        encoding="utf-8",
    )
    return value


def main():
    import tempfile
    from contextlib import nullcontext

    from cwm.security import protect_directory
    from cwm.util import kernel_lock, key

    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--phase", choices=PHASES, required=True)
    p.add_argument("--workspace", type=Path, required=True)
    p.add_argument("--candidate", type=Path, required=True)
    p.add_argument("--dependency-audit", type=Path)
    a = p.parse_args()
    a.workspace = a.workspace.resolve()
    if a.workspace.is_relative_to(ROOT) or ROOT.is_relative_to(a.workspace):
        p.error("Evidence must be outside source")
    if not a.workspace.exists():
        protect_directory(a.workspace)
    if (
        a.phase != "baseline"
        and read(a.candidate)["source"]["sha256"] != candidate_state()["sha256"]
    ):
        p.error("Candidate changed; freeze a new candidate")
    work = protect_directory(a.workspace / (a.phase + "-" + uuid.uuid4().hex[:8]))
    start = time.monotonic()
    try:
        lock_path = Path(tempfile.gettempdir()) / (
            "cwm-source-validation-" + key(str(ROOT)) + ".lock"
        )
        guard = kernel_lock(lock_path) if a.phase in ("package", "engineering") else nullcontext()
        with guard:
            details = globals()[a.phase](a, work)
        status = "passed" if a.phase != "report" or details["decision"] == "go" else "failed"
        reason = None
    except Exception as e:
        details = {}
        status = "failed"
        reason = type(e).__name__ + ": " + str(e)
    value = {
        "phase": a.phase,
        "status": status,
        "reason": reason,
        "details": details,
        "candidate_sha256": sha(a.candidate) if a.candidate.exists() else None,
        "source_sha256": candidate_state()["sha256"],
        "evidence_root": str(work),
        "evidence": {
            p.relative_to(work).as_posix(): {"sha256": sha(p), "size": p.stat().st_size}
            for p in work.rglob("*")
            if p.is_file()
        },
        "seconds": round(time.monotonic() - start, 3),
    }
    write(a.workspace / (a.phase + ".json"), value)
    print(json.dumps({k: value[k] for k in ["phase", "status", "reason", "seconds"]}))
    return 0 if status == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())

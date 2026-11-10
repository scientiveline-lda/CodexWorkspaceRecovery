"""Offline candidate builder. Requires pre-provisioned, hash-pinned inputs; does not sign releases."""

import argparse
import ast
import email
import hashlib
import json
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from publication_audit import public_files  # noqa: E402


def sha(p):
    with p.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def unpack(path, dest):
    with zipfile.ZipFile(path) as z:
        for i in z.infolist():
            if i.is_dir():
                continue
            parts = Path(i.filename.replace("\\", "/")).parts
            if any(x in ("..", "") for x in parts) or Path(i.filename).is_absolute():
                raise RuntimeError("Unsafe build input")
            out = dest.joinpath(*parts)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(z.read(i))


def build(output):
    approved = public_files(ROOT)
    output = Path(output).resolve()
    if output.exists():
        raise RuntimeError("Build output must not exist")
    output.mkdir(parents=True)
    runtime = output / "runtime"
    runtime.mkdir()
    app = output / "app"
    app.mkdir()
    lock = json.loads((ROOT / "packaging/runtime-lock.json").read_text(encoding="utf-8"))
    archive = ROOT / "artifacts" / lock["file"]
    if sha(archive) != lock["sha256"]:
        raise RuntimeError("Runtime digest mismatch")
    unpack(archive, runtime)
    pth = next(runtime.glob("python*._pth"))
    pth.write_text("python314.zip\n.\n../app\n", encoding="utf-8")
    version = ast.literal_eval(
        ast.parse((ROOT / "src/cwm/__init__.py").read_text(encoding="utf-8")).body[0].value
    )
    components = []
    for item in json.loads(
        (ROOT / "packaging/python-dependencies.lock.json").read_text(encoding="utf-8")
    ):
        if item["name"] == "setuptools":
            continue
        wheel = ROOT / "artifacts/wheels" / item["file"]
        if sha(wheel) != item["sha256"]:
            raise RuntimeError("Wheel digest mismatch")
        unpack(wheel, app)
        components.append(item)
    for name in approved:
        if name.startswith("src/"):
            dest = app / name.removeprefix("src/")
        elif name.startswith("docs/") or name in {"README.md", "LICENSE", "SECURITY.md"}:
            dest = output / name
        elif name in {
            "packaging/cwm.cmd",
            "packaging/cwm.ps1",
            "packaging/cwm-verify.cmd",
            "packaging/cwm-verify.ps1",
        }:
            dest = output / "bin" / Path(name).name
        else:
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, dest)
    config = json.loads((ROOT / "vendor/toolchain.json").read_text(encoding="utf-8"))
    portable = {}
    for name, spec in config.items():
        if name == "git":
            locked = json.loads((ROOT / "packaging/git-runtime-lock.json").read_text())
            source_root = ROOT / "vendor/git"
            actual = {
                p.relative_to(source_root).as_posix() for p in source_root.rglob("*") if p.is_file()
            }
            if actual != set(locked["files"]):
                raise RuntimeError("Git runtime membership mismatch")
            for member, entry in locked["files"].items():
                if sha(source_root / member) != entry["sha256"]:
                    raise RuntimeError("Git runtime digest mismatch")
            shutil.copytree(source_root, output / "vendor/git")
            portable[name] = {"path": "git/cmd/git.exe", "sha256": spec["sha256"]}
            continue
        source = Path(spec["path"])
        dest = output / "vendor" / name / source.name
        dest.parent.mkdir(parents=True, exist_ok=True)
        if sha(source) != spec["sha256"]:
            raise RuntimeError("Tool digest mismatch")
        shutil.copyfile(source, dest)
        portable[name] = {"path": name + "/" + source.name, "sha256": spec["sha256"]}
    (output / "vendor/toolchain.json").write_text(
        json.dumps(portable, indent=2, sort_keys=True), encoding="utf-8"
    )
    doctor = subprocess.run(
        [str(runtime / "python.exe"), "-B", "-m", "cwm", "doctor"], capture_output=True, check=True
    )
    result = json.loads(doctor.stdout)
    result.pop("operation_id", None)
    result["tools"] = {name: portable[name] for name in sorted(portable)}
    (output / "runtime-validation.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    # Reproducible unsigned artifacts: inputs, not wall-clock time, identify the SBOM.
    source_id = hashlib.sha256(
        json.dumps({n: sha(ROOT / n) for n in approved}, sort_keys=True).encode()
    ).hexdigest()
    notices = output / "third-party"
    notices.mkdir()
    shutil.copy2(runtime / "LICENSE.txt", notices / "CPython.txt")
    license_ids = {"rfc8785": "Apache-2.0"}
    for component in components:
        with zipfile.ZipFile(ROOT / "artifacts/wheels" / component["file"]) as wheel:
            metadata = email.message_from_bytes(
                wheel.read(next(n for n in wheel.namelist() if n.endswith(".dist-info/METADATA")))
            )
            license_ids[component["name"]] = metadata.get("License-Expression") or license_ids.get(
                component["name"], "NOASSERTION"
            )
            for name in wheel.namelist():
                if ".dist-info/" in name and (
                    "/licenses/" in name or name.endswith(("/LICENSE", "/COPYING"))
                ):
                    (notices / (component["name"] + "-" + Path(name).name + ".txt")).write_bytes(
                        wheel.read(name)
                    )
    for notice in json.loads((ROOT / "packaging/notices-lock.json").read_text(encoding="utf-8")):
        source = ROOT / "artifacts/notices" / notice["file"]
        if sha(source) != notice["sha256"]:
            raise RuntimeError("Third-party notice digest mismatch")
        shutil.copy2(source, notices / notice["file"])
        license_ids[notice["name"]] = notice["license"]
    license_ids["CPython"] = "Python-2.0"
    license_ids["Git-for-Windows"] = "GPL-2.0-only"
    (output / "THIRD_PARTY_NOTICES.txt").write_text(
        "Third-party license evidence is in third-party/ and runtime/LICENSE.txt.\n"
        "Organizational redistribution review remains required; this inventory is not legal approval.\n"
        + "".join(name + ": " + value + "\n" for name, value in sorted(license_ids.items())),
        encoding="utf-8",
    )
    sbom = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "CWM Windows recovery candidate",
        "documentNamespace": "https://github.com/scientiveline-lda/CodexWorkspaceRecovery/sbom/"
        + source_id,
        "creationInfo": {
            "creators": ["Tool: cwm-build-windows-" + version],
            "created": "2026-01-01T00:00:00Z",
        },
        "packages": [
            {
                "name": c["name"],
                "SPDXID": "SPDXRef-" + c["name"].replace("_", "-"),
                "versionInfo": c["version"],
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "checksums": [{"algorithm": "SHA256", "checksumValue": c["sha256"]}],
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": license_ids.get(c["name"], "NOASSERTION"),
                "copyrightText": "NOASSERTION",
            }
            for c in components
        ],
    }
    extra_components = [
        {
            "name": "Git-for-Windows",
            "version": locked["version"],
            "sha256": locked["archive_sha256"],
        },
        {"name": "CPython", "version": lock["version"], "sha256": lock["sha256"]},
        {"name": "age", "version": "1.3.2", "sha256": config["age"]["sha256"]},
        {"name": "minisign", "version": "0.12", "sha256": config["minisign"]["sha256"]},
    ]
    for component in extra_components:
        sbom["packages"].append(
            {
                "name": component["name"],
                "SPDXID": "SPDXRef-" + component["name"],
                "versionInfo": component["version"],
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "checksums": [{"algorithm": "SHA256", "checksumValue": component["sha256"]}],
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": license_ids.get(component["name"], "NOASSERTION"),
                "copyrightText": "NOASSERTION",
            }
        )
    (output / "sbom.spdx.json").write_text(json.dumps(sbom, indent=2), encoding="utf-8")
    inventory = {
        p.relative_to(output).as_posix(): sha(p) for p in sorted(output.rglob("*")) if p.is_file()
    }
    (output / "release-inventory.json").write_text(
        json.dumps(
            {
                "status": "unsigned_candidate",
                "technical_validation": "candidate; see exact candidate-bound report",
                "publication_approved": False,
                "files": inventory,
                "required_gates": [
                    "candidate-bound portable acceptance",
                    "privacy and redistribution review before publication",
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    zipped = output.parent / (output.name + ".zip")
    if zipped.exists():
        raise RuntimeError("Build ZIP exists")
    with zipfile.ZipFile(zipped, "x", compression=zipfile.ZIP_DEFLATED) as z:
        for p in sorted(output.rglob("*")):
            if p.is_file():
                info = zipfile.ZipInfo(
                    "cwm/" + p.relative_to(output).as_posix(), (2026, 1, 1, 0, 0, 0)
                )
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                with z.open(info, "w", force_zip64=True) as dst, p.open("rb") as src:
                    shutil.copyfileobj(src, dst, 1024 * 1024)
    return {
        "directory": str(output),
        "zip": str(zipped),
        "sha256": sha(zipped),
        "runtime": result,
        "status": "unsigned_candidate",
    }


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--output", required=True)
    a = p.parse_args()
    print(json.dumps(build(a.output), indent=2))

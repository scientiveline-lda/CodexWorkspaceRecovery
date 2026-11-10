"""Signed complete-inventory ZIP64 archives wrapped by age."""

from __future__ import annotations

import logging
import os
import uuid
import zipfile
from pathlib import Path
from typing import Any

from . import __version__
from .preservation import preserve
from .security import Toolchain, protect_directory
from .util import digest, load, now, require, safe_relative, within, write_json


def seal(
    payload: str | Path,
    output: str | Path,
    tools: Toolchain,
    *,
    signing_key: Any,
    key_id: str,
    producer: str,
    scope: str,
    recipients: list[str],
) -> tuple[Path, dict[str, Any]]:
    payload, output = (Path(payload), Path(output).absolute())
    require(not output.exists(), "conflict", "Archive output exists")
    require(not within(output, payload), "unsafe_path", "Archive output overlaps payload")
    files = {}
    for p in sorted(payload.rglob("*")):
        if p.is_file():
            name = safe_relative(p.relative_to(payload).as_posix())
            require(
                name not in ("manifest.json", "manifest.minisig"),
                "conflict",
                "Payload contains reserved control entries",
            )
            files[name] = {"sha256": digest(p), "size": p.stat().st_size}
    cap = load(payload / "inventory/capture.json")
    manifest = {
        "format": "CWMF",
        "version": "1.0",
        "draft": 3,
        "archive_id": uuid.uuid4().hex,
        "created_at": now(),
        "producer": producer,
        "scope": scope,
        "signing_key_id": key_id,
        "capture": cap["classification"],
        "payload": files,
        "features": [
            "sha256",
            "jcs-rfc8785",
            "minisign",
            "zip64",
            "portable-v1",
            "raw-rollouts-v1",
        ],
        "provenance": {
            "utility_version": __version__,
            "representation": "portable-filesystem",
            "encryption": "age; independent recipients; not threshold authorization",
        },
    }
    import jsonschema

    schema = load(Path(__file__).parent / "schemas/manifest.json")
    jsonschema.validate(manifest, schema)
    write_json(payload / "manifest.json", manifest)
    tools.sign(payload / "manifest.json", signing_key)
    os.rename(payload / "manifest.json.minisig", payload / "manifest.minisig")
    inner = payload.parent / "archive.zip.partial"
    with zipfile.ZipFile(inner, "x", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as z:
        for name in ["manifest.json", "manifest.minisig", *files]:
            z.write(
                payload / name,
                name,
                compress_type=zipfile.ZIP_STORED
                if name.startswith("objects/")
                else zipfile.ZIP_DEFLATED,
            )
    partial = output.with_name(output.name + ".partial")
    require(not partial.exists(), "conflict", "Archive partial output exists")
    try:
        tools.encrypt(inner, partial, recipients)
        return (partial, manifest)
    except Exception:
        if partial.exists():
            partial.unlink()
        raise


def export(
    snapshot: str | Path,
    output: str | Path,
    workspace: str | Path,
    toolchain: str | Path | dict[str, Any],
    *,
    signing_key: Any,
    key_id: str,
    producer: str,
    scope: str,
    recipients: list[str],
    identity: str | Path,
    trust: str | Path | dict[str, Any],
    selected: list[str] | None = None,
    archived: bool | None = None,
    since: str | None = None,
    until: str | None = None,
    git_exe: str | Path | None = None,
    profile: Any = "recovery",
    include_ignored: bool = False,
    include_supporting: bool = False,
) -> dict[str, Any]:
    from .util import blob_digest, canonical, exclusive_lock

    with exclusive_lock(Path(output).absolute().with_name(Path(output).name + ".cwm-lock")):
        require(not Path(output).exists(), "conflict", "Archive output already exists")
        from .util import require_space

        source_bytes = sum(item["size"] for item in load(Path(snapshot) / "capture.json")["files"])
        require_space(workspace, 12 * source_bytes)
        require_space(output, 2 * source_bytes)
        workspace = protect_directory(workspace)
        output = Path(output).absolute()
        require(
            output.parent.is_dir(),
            "missing_destination",
            "Archive destination directory must exist",
        )
        tools = Toolchain(toolchain)
        logging.getLogger("cwm.progress").info("Deriving portable evidence")
        report = preserve(
            snapshot,
            workspace / "payload",
            selected=selected,
            archived=archived,
            since=since,
            until=until,
            git_exe=git_exe,
            profile=profile,
            include_ignored=include_ignored,
            include_supporting=include_supporting,
        )
        logging.getLogger("cwm.progress").info("Signing and encrypting archive")
        partial, manifest = seal(
            workspace / "payload",
            output,
            tools,
            signing_key=signing_key,
            key_id=key_id,
            producer=producer,
            scope=scope,
            recipients=recipients,
        )
        import cwm_verify

        logging.getLogger("cwm.progress").info("Independently reopening encrypted archive")
        result = cwm_verify.verify(
            partial,
            identity,
            trust,
            toolchain,
            workspace / "independent-verification",
            extract_to=workspace / "verified-payload",
        )
        from .verification import semantic

        require(
            result["archive_id"] == manifest["archive_id"]
            and result["manifest_sha256"] == blob_digest(canonical(manifest)),
            "archive_changed",
            "Verified artifact differs from the archive being exported",
        )
        result["semantic"] = semantic(workspace / "verified-payload")
        require(not output.exists(), "conflict", "Archive destination appeared during verification")
        os.link(partial, output)
        partial.unlink()
        return {
            "archive_id": manifest["archive_id"],
            "archive": str(output),
            "sha256": digest(output),
            "verification": result,
            "preservation": report,
        }

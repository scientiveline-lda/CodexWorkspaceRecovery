"""New-directory-only restoration with deterministic plans and guarded rollback."""

from __future__ import annotations

import logging
import os
import shutil
import uuid
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any

from .projects import Git, compare, restore_project
from .security import protect_directory
from .util import (
    blob_digest,
    canonical,
    digest,
    kernel_lock,
    key,
    load,
    no_reparse_chain,
    now,
    require,
    within,
    write_json,
)
from .verification import semantic


def tree_hashes(root: str | Path) -> dict[str, str]:
    from .util import walk_files

    root = Path(root)
    result = {
        p.relative_to(root).as_posix(): digest(p)
        for p in walk_files(root)
        if p != root / ".cwm-operation.json"
    }
    result.update(
        {p.relative_to(root).as_posix() + "/": "directory" for p in root.rglob("*") if p.is_dir()}
    )
    return result


def safe_target(target: str | Path) -> Path:
    target = Path(target).absolute()
    no_reparse_chain(target)
    protected = [Path.home() / ".codex"]
    for n in ["CODEX_HOME", "CODEX_SQLITE_HOME"]:
        if os.environ.get(n):
            protected.append(Path(os.environ[n]))
    require(
        all(not within(target, p) and (not within(p, target)) for p in protected),
        "unsafe_destination",
        "Destination overlaps an active/default Codex home",
    )
    require(target.parent.is_dir(), "missing_destination", "Destination parent must exist")
    return target


def plan(
    archive: str | Path,
    target: str | Path,
    workspace: str | Path,
    *,
    identity: str | Path,
    trust: str | Path,
    tools: str | Path,
    mappings: dict[str, str] | None = None,
) -> dict[str, Any]:
    import cwm_verify

    target = safe_target(target)
    require(not target.exists(), "conflict", "Destination must be a new independent directory")
    require(
        not within(target, workspace) and not within(workspace, target),
        "unsafe_destination",
        "Planning workspace and destination overlap",
    )
    workspace = protect_directory(workspace)
    verification = cwm_verify.verify(
        archive, identity, trust, tools, workspace / "verify", extract_to=workspace / "payload"
    )
    payload = workspace / "payload"
    semantics = semantic(payload)
    manifest = load(payload / "manifest.json")
    source = load(payload / "inventory/source.json")
    for root in [source.get("codex_home"), source.get("sqlite_home")]:
        if root:
            require(
                not within(target, root) and (not within(root, target)),
                "unsafe_destination",
                "Destination overlaps captured source",
            )
    projects = load(payload / "inventory/projects.json")
    mappings = mappings or {p["source"]: str(target / "projects" / p["id"]) for p in projects}
    for p in projects:
        require(p["source"] in mappings, "mapping_required", "Project root mapping is missing")
        dst = Path(mappings[p["source"]]).absolute()
        require(
            within(dst, target / "projects") and dst != target / "projects",
            "unsafe_mapping",
            "First release mappings must remain in new recovery projects directory",
        )
    destinations = [Path(value).resolve() for value in mappings.values()]
    require(
        all(
            (
                not within(a, b) and (not within(b, a))
                for i, a in enumerate(destinations)
                for b in destinations[i + 1 :]
            )
        ),
        "unsafe_mapping",
        "Project mappings overlap",
    )
    plan = {
        "schema_version": "1",
        "archive": str(Path(archive).resolve()),
        "archive_sha256": digest(archive),
        "archive_id": manifest["archive_id"],
        "manifest_sha256": verification["manifest_sha256"],
        "target": str(target),
        "workspace": str(workspace),
        "identity_file": str(Path(identity).resolve()),
        "trust_policy": str(Path(trust).resolve()),
        "toolchain": str(Path(tools).resolve()),
        "toolchain_sha256": digest(tools),
        "trust_sha256": digest(trust),
        "mappings": mappings,
        "completeness": semantics["completeness"],
        "writes": ["evidence/", "projects/", ".cwm-operation.json"],
        "compatibility": {"status": "portable_filesystem", "application_import": False},
    }
    plan["plan_id"] = blob_digest(canonical(plan))
    write_json(workspace / "restore-plan.json", plan)
    return plan


def validate_plan(p: dict[str, Any]) -> None:
    value = dict(p)
    ident = value.pop("plan_id")
    require(blob_digest(canonical(value)) == ident, "plan_changed", "Restore plan was changed")
    require(
        digest(p["archive"]) == p["archive_sha256"],
        "archive_changed",
        "Archive changed after planning",
    )
    require(
        digest(p["trust_policy"]) == p["trust_sha256"]
        and digest(p["toolchain"]) == p["toolchain_sha256"],
        "plan_changed",
        "Trust/tool configuration changed after planning",
    )
    safe_target(p["target"])


def _apply(
    plan_path: str | Path, git_exe: str | Path, *, failpoint: str | None = None
) -> dict[str, Any]:
    import cwm_verify

    p = load(plan_path)
    validate_plan(p)
    target = Path(p["target"])
    work = Path(p["workspace"])
    if target.exists():
        existing = _verify_restore(plan_path, git_exe)
        require(
            existing["status"] == "verified",
            "conflict",
            "Existing recovery differs from authenticated state",
        )
        marker = (
            load(target / ".cwm-operation.json")
            if (target / ".cwm-operation.json").exists()
            else {}
        )
        require(
            marker.get("plan_id") == p["plan_id"] and marker.get("files") == tree_hashes(target),
            "conflict",
            "Existing destination differs; later work is preserved",
        )
        write_json(
            work / "operation.json",
            {
                "plan_id": p["plan_id"],
                "status": "verified",
                "target": str(target),
                "reconciled_after_interruption": True,
            },
            replace=(work / "operation.json").exists(),
        )
        return {
            "status": "already_applied",
            "target": str(target),
            "plan_id": p["plan_id"],
            "completeness": existing["completeness"],
        }
    fresh = work / ("apply-" + uuid.uuid4().hex)
    logging.getLogger("cwm.progress").info("Authenticating recovery archive")
    verified = cwm_verify.verify(
        p["archive"],
        p["identity_file"],
        p["trust_policy"],
        p["toolchain"],
        fresh,
        extract_to=fresh / "payload",
    )
    require(
        verified["archive_id"] == p["archive_id"]
        and verified["manifest_sha256"] == p["manifest_sha256"],
        "archive_changed",
        "Verified archive does not match the approved plan",
    )
    from .util import require_space

    require_space(target, 3 * verified["bytes"])
    payload = fresh / "payload"
    semantics = semantic(payload)
    for source in [
        load(payload / "inventory/source.json").get(k) for k in ("codex_home", "sqlite_home")
    ]:
        if source:
            require(
                not within(target, source) and (not within(source, target)),
                "unsafe_destination",
                "Destination overlaps source state",
            )
    stage = target.with_name(".cwm-stage-" + p["plan_id"][:16])
    journal = work / "operation.json"
    require(
        not stage.exists(),
        "recovery_required",
        "Interrupted staging exists; inspect the operation journal before recovery",
    )
    protect_directory(stage)
    write_json(stage / ".cwm-stage-owner.json", {"plan_id": p["plan_id"]})
    write_json(
        journal,
        {
            "plan_id": p["plan_id"],
            "status": "applying",
            "stage": str(stage),
            "target": str(target),
            "created_at": now(),
        },
        replace=journal.exists(),
    )
    try:
        logging.getLogger("cwm.progress").info(
            "Deploying evidence and selected projects into new staging"
        )
        shutil.copytree(payload, stage / "evidence")
        comparisons = []
        for project in load(payload / "inventory/projects.json"):
            dst = Path(p["mappings"][project["source"]])
            rel = dst.relative_to(target)
            comparisons.append(restore_project(project, payload, stage / rel, Git(git_exe)))
        require(
            failpoint != "after_projects",
            "injected_failure",
            "Synthetic fault injection after project restore",
        )
        require(
            all(c["status"] != "failed" for c in comparisons),
            "project_mismatch",
            "Restored project differs from snapshot",
        )
        report = {
            "status": "portable_reconstructed",
            "projects": comparisons,
            "archive_id": p["archive_id"],
            "plan_id": p["plan_id"],
            "completeness": semantics["completeness"],
            "limitations": [
                "Portable filesystem reconstruction; not application or account import"
            ],
        }
        write_json(stage / "recovery-report.json", report)
        files = tree_hashes(stage)
        write_json(
            work / "deployment-state.json",
            {"plan_id": p["plan_id"], "manifest_sha256": p["manifest_sha256"], "files": files},
            replace=(work / "deployment-state.json").exists(),
        )
        write_json(
            stage / ".cwm-operation.json",
            {
                "plan_id": p["plan_id"],
                "files": files,
                "status": "verified_portable",
                "created_at": now(),
            },
        )
        require(
            failpoint != "before_publish",
            "injected_failure",
            "Synthetic fault injection before publication",
        )
        no_reparse_chain(target.parent)
        os.rename(stage, target)
        require(
            failpoint != "after_publish",
            "injected_failure",
            "Synthetic fault injection after publication",
        )
        write_json(
            journal,
            {
                "plan_id": p["plan_id"],
                "status": "verified",
                "target": str(target),
                "stage": str(stage),
                "report": report,
            },
            replace=True,
        )
        return report
    except Exception:
        write_json(
            journal,
            {
                "plan_id": p["plan_id"],
                "status": "failed",
                "stage": str(stage),
                "target": str(target),
                "files": tree_hashes(stage),
            },
            replace=True,
        )
        raise


def _verify_restore(plan_path: str | Path, git_exe: str | Path) -> dict[str, Any]:
    import cwm_verify

    p = load(plan_path)
    validate_plan(p)
    target = Path(p["target"])
    fresh = Path(p["workspace"]) / ("recheck-" + uuid.uuid4().hex)
    verification = cwm_verify.verify(
        p["archive"],
        p["identity_file"],
        p["trust_policy"],
        p["toolchain"],
        fresh,
        extract_to=fresh / "payload",
    )
    require(
        verification["manifest_sha256"] == p["manifest_sha256"],
        "archive_changed",
        "Manifest changed",
    )
    payload = fresh / "payload"
    semantics = semantic(payload)
    baseline = load(Path(p["workspace"]) / "deployment-state.json")
    files_ok = (
        baseline.get("plan_id") == p["plan_id"]
        and baseline.get("manifest_sha256") == p["manifest_sha256"]
        and (baseline.get("files") == tree_hashes(target))
    )
    checks = [
        compare(pr, Path(p["mappings"][pr["source"]]), Git(git_exe))
        for pr in load(payload / "inventory/projects.json")
    ]
    return {
        "status": "verified"
        if files_ok and all(x["status"] != "failed" for x in checks)
        else "changed",
        "deployed_bytes_match": files_ok,
        "projects": checks,
        "completeness": semantics["completeness"],
        "representation": "portable-filesystem",
    }


def _rollback(plan_path: str | Path) -> dict[str, Any]:
    p = load(plan_path)
    validate_plan(p)
    target = Path(p["target"])
    work = Path(p["workspace"])
    if target.exists():
        marker = load(target / ".cwm-operation.json")
        require(
            marker.get("plan_id") == p["plan_id"] and marker.get("files") == tree_hashes(target),
            "rollback_conflict",
            "Destination changed; refusing to discard later work",
        )
        baseline = load(work / "deployment-state.json")
        require(
            baseline.get("plan_id") == p["plan_id"]
            and baseline.get("files") == tree_hashes(target),
            "rollback_conflict",
            "Destination differs from independently protected deployment state",
        )
        retained = target.with_name(target.name + ".rolled-back-" + p["plan_id"][:12])
        require(not retained.exists(), "conflict", "Rollback evidence destination exists")
        os.rename(target, retained)
        result = {
            "status": "rolled_back",
            "retained_evidence": str(retained),
            "plan_id": p["plan_id"],
        }
    else:
        j = load(work / "operation.json")
        stage = Path(j["stage"])
        require(
            stage == target.with_name(".cwm-stage-" + p["plan_id"][:16]),
            "journal_changed",
            "Unexpected journal stage",
        )
        require(
            load(stage / ".cwm-stage-owner.json").get("plan_id") == p["plan_id"],
            "journal_changed",
            "Staging ownership marker mismatch",
        )
        require(
            j.get("files") is None or j["files"] == tree_hashes(stage),
            "rollback_conflict",
            "Interrupted staging changed; preserve for manual recovery",
        )
        retained = stage.with_name(stage.name + ".abandoned")
        require(not retained.exists(), "conflict", "Abandoned evidence already exists")
        os.rename(stage, retained)
        result = {"status": "staging_abandoned", "retained_evidence": str(retained)}
    write_json(work / "operation.json", result, replace=True)
    return result


def _resume(plan_path: str | Path, git_exe: str | Path) -> dict[str, Any]:
    p = load(plan_path)
    j = load(Path(p["workspace"]) / "operation.json")
    if j.get("status") in ("failed", "applying") and (not Path(p["target"]).exists()):
        _rollback(plan_path)
    return _apply(plan_path, git_exe)


def operation_lock(plan_path: str | Path) -> AbstractContextManager[None]:
    p = load(plan_path)
    validate_plan(p)
    target = Path(p["target"])
    return kernel_lock(target.with_name(".cwm-operation-" + key(str(target)) + ".lock"))


def apply(
    plan_path: str | Path, git_exe: str | Path, *, failpoint: str | None = None
) -> dict[str, Any]:
    with operation_lock(plan_path):
        return _apply(plan_path, git_exe, failpoint=failpoint)


def verify_restore(plan_path: str | Path, git_exe: str | Path) -> dict[str, Any]:
    with operation_lock(plan_path):
        return _verify_restore(plan_path, git_exe)


def rollback(plan_path: str | Path) -> dict[str, Any]:
    with operation_lock(plan_path):
        return _rollback(plan_path)


def resume(plan_path: str | Path, git_exe: str | Path) -> dict[str, Any]:
    with operation_lock(plan_path):
        return _resume(plan_path, git_exe)

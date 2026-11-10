"""Deterministic portable export/import CLI. JSON stdout; safe diagnostics stderr."""

from __future__ import annotations

import argparse
import json
import logging
import sys
import uuid
from pathlib import Path
from typing import Any

import jsonschema

import cwm_verify

from . import __version__
from .util import RecoveryError, load, no_reparse_chain, require, within, write_json


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cwm",
        description="Encrypted portable Codex workspace export/import. No application or account activation.",
    )
    p.add_argument("--version", action="version", version="cwm " + __version__)
    sub = p.add_subparsers(dest="command", required=True)
    keys = sub.add_parser(
        "keys", help="Create local keys or a separate recovery-key copy."
    ).add_subparsers(dest="action", required=True)
    k = keys.add_parser(
        "init", help="Generate locally trusted signing/encryption keys; output must be new."
    )
    k.add_argument("--output", required=True)
    k = keys.add_parser(
        "export-recovery", help="Copy decryption/trust material, excluding signing private key."
    )
    k.add_argument("--keys", required=True)
    k.add_argument("--output", required=True)
    d = sub.add_parser(
        "discover", help="Inventory declared local sources; never opens source databases."
    )
    d.add_argument("--home")
    d.add_argument("--sqlite-home")
    d.add_argument("--output")
    e = sub.add_parser(
        "export", help="Acquire a closed workspace and publish a verified encrypted package."
    )
    e.add_argument("--home", required=True)
    e.add_argument("--sqlite-home")
    e.add_argument("--project", action="append", default=[])
    e.add_argument(
        "--source-closed",
        action="store_true",
        required=True,
        help="Confirm all writers are closed. This is not proof of atomicity.",
    )
    for name in ["output", "workspace", "keys"]:
        e.add_argument("--" + name, required=True)
    e.add_argument("--thread", action="append")
    e.add_argument("--archived", choices=["yes", "no"])
    e.add_argument("--since")
    e.add_argument("--until")
    e.add_argument("--profile", choices=["references", "recovery", "full"], default="recovery")
    e.add_argument("--include-supporting", action="store_true")
    e.add_argument("--include-ignored", action="store_true")
    v = sub.add_parser(
        "verify", help="Decrypt, authenticate and reconcile package content without deployment."
    )
    v.add_argument("archive")
    v.add_argument("--keys", required=True)
    v.add_argument("--workspace", required=True)
    imp = sub.add_parser(
        "import", help="Plan/apply/verify reconstruction into a new filesystem destination."
    ).add_subparsers(dest="action", required=True)
    plan = imp.add_parser("plan", help="Verify package and enumerate writes before deployment.")
    plan.add_argument("archive")
    for n in ["keys", "target", "workspace"]:
        plan.add_argument("--" + n, required=True)
    plan.add_argument(
        "--mappings",
        help="Optional JSON source-root to destination-root mapping inside target/projects",
    )
    for action in ["apply", "verify"]:
        a = imp.add_parser(action)
        a.add_argument("plan")
    rec = sub.add_parser(
        "recover", help="Resume interrupted deployment or retain rollback evidence."
    ).add_subparsers(dest="action", required=True)
    for action in ["resume", "rollback"]:
        a = rec.add_parser(action)
        a.add_argument("plan")
    cp = (
        sub.add_parser(
            "continuation", help="Copy historical continuation instructions; no model is invoked."
        )
        .add_subparsers(dest="action", required=True)
        .add_parser("build")
    )
    cp.add_argument("recovery")
    cp.add_argument("--project", required=True)
    cp.add_argument("--output", required=True)
    sub.add_parser(
        "doctor", help="Check embedded runtime and pinned bundled executables without downloads."
    )
    return p


def execute(a: argparse.Namespace) -> dict[str, Any]:
    from .keys import defaults, git_default, profile
    from .security import Toolchain, protect_directory

    if a.command == "keys":
        from .keys import export_recovery, initialize

        return initialize(a.output) if a.action == "init" else export_recovery(a.keys, a.output)
    if a.command == "doctor":
        import compression.zstd
        import sqlite3

        tools = Toolchain(defaults())
        b = b"runtime" * 100
        require(
            compression.zstd.decompress(compression.zstd.compress(b)) == b,
            "runtime_invalid",
            "Zstandard failed",
        )
        return {
            "status": "ready",
            "python": sys.version.split()[0],
            "sqlite": sqlite3.sqlite_version,
            "zstandard": "round_trip_verified",
            "tools": {n: str(tools.tool(n)) for n in ["age", "age-keygen", "minisign", "git"]},
            "representation": "portable-filesystem",
        }
    if a.command == "discover":
        from .discovery import discover

        result = discover(a.home, a.sqlite_home)
        if a.output:
            no_reparse_chain(a.output)
            require(
                not any(within(a.output, result[k]) for k in ["codex_home", "sqlite_home"]),
                "unsafe_destination",
                "Output overlaps source",
            )
            write_json(a.output, result)
        return result
    if a.command == "export":
        from .archive import export
        from .capture import capture
        from .discovery import locations
        from .keys import profile

        h, s, _ = locations(a.home, a.sqlite_home)
        require(
            all(
                not within(a.keys, root) and not within(root, a.keys)
                for root in [h, s, *map(Path, a.project)]
            ),
            "unsafe_source",
            "Recovery keys must remain outside all source roots",
        )
        roots = [h, s, *map(Path, a.project), Path(a.keys)]
        for dst in [a.workspace, a.output]:
            require(
                all(not within(dst, r) and not within(r, dst) for r in roots),
                "unsafe_destination",
                "Export paths overlap sources or keys",
            )
        require(
            not within(a.output, a.workspace) and not within(a.workspace, a.output),
            "unsafe_destination",
            "Archive output overlaps retained workspace",
        )
        require(not Path(a.output).exists(), "conflict", "Archive already exists")
        work = protect_directory(a.workspace)
        p = profile(a.keys, signing=True)
        capture(h, s, work / "capture", projects=a.project, maintenance=a.source_closed)
        return export(
            work / "capture",
            a.output,
            work / "export",
            defaults(),
            signing_key=p["signing_key"],
            key_id=p["key_id"],
            producer=p["producer"],
            scope=p["scope"],
            recipients=p["recipients"],
            identity=p["identity"],
            trust=p["trust"],
            selected=a.thread,
            archived=None if a.archived is None else a.archived == "yes",
            since=a.since,
            until=a.until,
            git_exe=git_default(),
            profile=a.profile,
            include_ignored=a.include_ignored,
            include_supporting=a.include_supporting,
        )
    if a.command == "verify":
        import cwm_verify

        from .verification import semantic

        p = profile(a.keys)
        require(
            not within(a.workspace, a.keys) and not within(a.keys, a.workspace),
            "unsafe_destination",
            "Verification workspace overlaps keys",
        )
        result = cwm_verify.verify(
            a.archive,
            p["identity"],
            p["trust"],
            defaults(),
            a.workspace,
            extract_to=Path(a.workspace) / "payload",
        )
        result["semantic"] = semantic(Path(a.workspace) / "payload")
        result["completeness"] = result["semantic"]["completeness"]
        return result
    if a.command == "import":
        from .restore import apply, plan, verify_restore

        if a.action == "plan":
            p = profile(a.keys)
            for dst in [a.target, a.workspace]:
                require(
                    not within(dst, a.keys) and not within(a.keys, dst),
                    "unsafe_destination",
                    "Recovery overlaps keys",
                )
            return plan(
                a.archive,
                a.target,
                a.workspace,
                identity=p["identity"],
                trust=p["trust"],
                tools=defaults(),
                mappings=load(a.mappings) if a.mappings else None,
            )
        return (
            apply(a.plan, git_default())
            if a.action == "apply"
            else verify_restore(a.plan, git_default())
        )
    if a.command == "recover":
        from .restore import resume, rollback

        return resume(a.plan, git_default()) if a.action == "resume" else rollback(a.plan)
    if a.command == "continuation":
        import shutil

        from .restore import safe_target
        from .util import check_path_budget, safe_relative, walk_files

        key = safe_relative(a.project)
        require("/" not in key, "invalid_project", "One project key required")
        src = Path(a.recovery) / "evidence/continuation" / key
        dst = safe_target(a.output)
        require(src.is_dir() and not dst.exists(), "conflict", "Source missing or output exists")
        require(
            not within(src, dst) and not within(dst, src), "unsafe_destination", "Paths overlap"
        )
        for f in walk_files(src):
            check_path_budget(dst / f.relative_to(src))
        shutil.copytree(src, dst)
        return {"status": "written", "semantic_inference": "none"}
    raise RecoveryError("command_invalid", "Unknown command")


def result_exit_code(result: dict[str, Any]) -> int:
    if result.get("status") in ("changed", "failed"):
        return 5 if result["status"] == "changed" else 2
    completeness = result.get("completeness", result.get("preservation", {}))
    return 4 if completeness.get("has_recovery_gaps") else 0


def main(argv: list[str] | None = None) -> int:
    a = parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="cwm: %(message)s")
    try:
        result = execute(a)
        result.setdefault("result_schema_version", "1")
        result.setdefault(
            "operation_id", result.get("plan_id", result.get("archive_id", uuid.uuid4().hex))
        )
        print(json.dumps(result, ensure_ascii=True, indent=2))
        return result_exit_code(result)
    except cwm_verify.VerificationError, jsonschema.ValidationError:
        print(
            json.dumps(
                {
                    "status": "failed",
                    "code": "verification_failed",
                    "message": "Package validation refused; no deployment was performed.",
                }
            ),
            file=sys.stderr,
        )
        return 2
    except RecoveryError as e:
        print(json.dumps({"status": "failed", "code": e.code, "message": str(e)}), file=sys.stderr)
        return 2
    except Exception as e:
        print(
            json.dumps(
                {
                    "status": "failed",
                    "code": type(e).__name__,
                    "message": "Operation failed; inspect protected staging and journal. No success is claimed.",
                }
            ),
            file=sys.stderr,
        )
        return 3

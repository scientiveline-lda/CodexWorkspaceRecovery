"""Git recovery from acquired copies; never runs Git against original projects."""

from __future__ import annotations

import os
import re
import shutil
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from . import __version__
from .util import RecoveryError, check_path_budget, digest, require, run, safe_relative


class Git:
    def __init__(self, executable: str | Path) -> None:
        self.exe = Path(executable).resolve()
        require(self.exe.is_file(), "tool_missing", "An explicit Git executable is required")

    def __call__(self, root: str | Path, *args: str, input: bytes | None = None) -> bytes:
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env.update(
            {
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_NO_LAZY_FETCH": "1",
                "GIT_OPTIONAL_LOCKS": "0",
                "GIT_LFS_SKIP_SMUDGE": "1",
            }
        )
        return run(
            [
                self.exe,
                "--no-optional-locks",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.hooksPath=" + os.devnull,
                "-c",
                "core.autocrlf=false",
                "-c",
                "core.longpaths=true",
                "-c",
                "protocol.allow=never",
                "-C",
                root,
                *args,
            ],
            env=env,
            input=input,
            timeout=600,
        )


def clean_url(value: str) -> str:
    if "://" in value:
        u = urlsplit(value)
        host = u.hostname or ""
        if ":" in host:
            host = "[" + host + "]"
        if u.port is not None:
            host += ":" + str(u.port)
        return urlunsplit((u.scheme, host, u.path, "", ""))
    if "@" in value:
        return value.split("@", 1)[-1]
    return value


def index_entries(git: Git, tree: Path) -> list[dict[str, Any]]:
    rows = []
    for record in git(tree, "ls-files", "--stage", "-z").split(b"\x00"):
        if not record:
            continue
        left, name = record.split(b"\t", 1)
        mode, oid, stage = left.decode().split()
        filename = name.decode("utf-8")
        safe_relative(filename)
        rows.append({"mode": mode, "oid": oid, "stage": int(stage), "path": filename})
    return rows


def prepare(
    snapshot: str | Path, layout: dict[str, Any], work: str | Path, git: Git
) -> tuple[Path, str | None]:
    acquired = Path(snapshot) / "acquired/projects" / layout["id"]
    tree = Path(work) / layout["id"]
    shutil.copytree(acquired / "tree", tree)
    if layout["linked"]:
        (tree / ".git").unlink()
        shutil.copytree(acquired / "common", tree / ".git")
        for name in [
            "HEAD",
            "index",
            "config.worktree",
            "ORIG_HEAD",
            "MERGE_HEAD",
            "MERGE_MSG",
            "AUTO_MERGE",
            "CHERRY_PICK_HEAD",
            "REVERT_HEAD",
        ]:
            p = acquired / "worktree_admin" / name
            if p.is_file():
                shutil.copyfile(p, tree / ".git" / name)
    dot = tree / ".git"
    if not dot.is_dir():
        require(
            not ((tree / "HEAD").is_file() and (tree / "objects").is_dir()),
            "git_unsupported",
            "Bare repository recovery is not supported",
        )
        return (tree, None)
    require(
        not (dot / "objects/info/alternates").exists(),
        "git_unsupported",
        "Git alternates require an explicit independent capture",
    )
    require(
        not list(dot.glob("sharedindex.*")),
        "git_unsupported",
        "Split indexes require a separately certified adapter",
    )
    require(
        not (dot / "shallow").exists(),
        "git_unsupported",
        "Shallow repository recovery is not certified",
    )
    require(
        not list((dot / "objects/pack").glob("*.promisor")),
        "git_unsupported",
        "Partial repositories require an independently complete object capture",
    )
    config = (
        (dot / "config").read_text(encoding="utf-8", errors="replace")
        if (dot / "config").exists()
        else ""
    )
    require(
        not re.search("(?:partialclone|promisor)\\s*=", config, re.I),
        "git_unsupported",
        "Partial repository recovery is not certified",
    )
    require(
        not (dot / "info/sparse-checkout").exists(),
        "git_unsupported",
        "Sparse checkout recovery is not supported",
    )
    require(
        not (dot / "modules").exists(),
        "git_unsupported",
        "Select submodules as separate projects; recursive administration is unsupported",
    )
    format_sha256 = bool(re.search("objectformat\\s*=\\s*sha256", config, re.I))
    safe = (
        "[core]\nrepositoryformatversion = "
        + ("1" if format_sha256 else "0")
        + "\nbare = false\nautocrlf = false\nfsmonitor = false\n"
    )
    if format_sha256:
        safe += "[extensions]\nobjectFormat = sha256\n"
    (dot / "config").write_text(safe, encoding="utf-8")
    if (dot / "config.worktree").exists():
        (dot / "config.worktree").unlink()
    return (tree, config)


def collect(
    snapshot: str | Path,
    layout: dict[str, Any],
    payload: str | Path,
    work: str | Path,
    git: Git,
    profile: Any = "recovery",
    include_ignored: bool = False,
) -> dict[str, Any]:
    tree, config = prepare(snapshot, layout, work, git)
    result = {
        "id": layout["id"],
        "source": layout["source"],
        "profile": profile,
        "files": [],
        "directories": sorted(
            d.relative_to(tree).as_posix()
            for d in tree.rglob("*")
            if d.is_dir()
            and ".git" not in d.relative_to(tree).parts
            and ".cwm-empty-hooks" not in d.relative_to(tree).parts
        ),
        "git": None,
        "limitations": [],
        "linked_worktree": layout["linked"],
        "transformation": {
            "adapter": "git-staging-v1",
            "version": __version__,
            "reason": "Sanitized operational Git configuration on staging copy only",
        },
    }
    if config is not None:
        index = index_entries(git, tree)
        try:
            head = git(tree, "rev-parse", "HEAD").decode().strip()
        except RecoveryError as exc:
            raise RecoveryError(
                "git_unsupported", "Project requires an available committed HEAD"
            ) from exc
        try:
            symbolic = git(tree, "symbolic-ref", "HEAD").decode().strip()
        except Exception:
            symbolic = None
        refs = [
            r.split(" ", 1)
            for r in git(tree, "for-each-ref", "--format=%(objectname) %(refname)")
            .decode()
            .splitlines()
        ]
        status = git(tree, "status", "--porcelain=v2", "-z", "--untracked-files=all").hex()
        flags = {}
        for r in git(tree, "ls-files", "-v", "-z").split(b"\x00"):
            if r:
                flags[r[2:].decode("utf-8")] = chr(r[0])
        sparse = (
            (tree / ".git/info/sparse-checkout").read_text(encoding="utf-8")
            if (tree / ".git/info/sparse-checkout").exists()
            else None
        )
        remotes = []
        if re.search("\\[remote\\s", config, re.IGNORECASE):
            try:
                values = git(
                    tree,
                    "config",
                    "--no-includes",
                    "--file",
                    "-",
                    "--null",
                    "--get-regexp",
                    "^remote\\..*\\.(url|pushurl)$",
                    input=config.encode(),
                )
                for value in values.split(b"\x00"):
                    if not value:
                        continue
                    field, url = value.split(b"\n", 1)
                    remote, kind = field.decode().removeprefix("remote.").rsplit(".", 1)
                    original = url.decode()
                    clean = clean_url(original)
                    remotes.append(
                        {
                            "name": remote,
                            "kind": kind,
                            "url": clean,
                            "credential_fields_removed_or_sanitized": clean != original,
                            "activation": "reference_only; review and reauthorize before configuring",
                        }
                    )
            except RecoveryError, ValueError, UnicodeDecodeError:
                result["limitations"].append(
                    "Remote reference configuration could not be parsed; original remains only in local acquisition evidence"
                )
        result["git"] = {
            "remotes": remotes,
            "sparse_patterns": sparse,
            "tool_sha256": digest(git.exe),
            "head": head,
            "symbolic_head": symbolic,
            "refs": refs,
            "index": index,
            "index_flags": flags,
            "status_porcelain_v2_hex": status,
            "object_format": "sha256" if len(head) == 64 else "sha1",
            "shallow": (tree / ".git/shallow").read_text().splitlines()
            if (tree / ".git/shallow").exists()
            else [],
            "in_progress": [
                p.name
                for p in (tree / ".git").iterdir()
                if p.name
                in ["MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "rebase-merge", "rebase-apply"]
            ],
            "original_config_preserved": False,
        }
        if profile != "references":
            git(tree, "update-ref", "refs/cwm-recovery/head", head)
            for oid in sorted({e["oid"] for e in index if e["mode"] != "160000"}):
                git(tree, "update-ref", "refs/cwm-recovery/index/" + oid, oid)
            bundle = Path(payload) / "portable/projects" / layout["id"] / "repository.bundle"
            bundle.parent.mkdir(parents=True, exist_ok=True)
            git(tree, "bundle", "create", str(bundle), "--all")
            git(tree, "bundle", "verify", str(bundle))
            result["git"]["bundle"] = bundle.relative_to(payload).as_posix()
        if result["git"]["in_progress"]:
            result["limitations"].append(
                "Operation metadata preserved as evidence; automatic merge/rebase continuation is not certified"
            )
        if any(e["mode"] == "160000" for e in index):
            result["limitations"].append(
                "Submodule Git object recovery requires separate project selection; working bytes are preserved when selected"
            )
        if result["git"]["shallow"]:
            result["limitations"].append("Shallow history is not a complete repository history")
    if profile == "references":
        result["limitations"].append("References profile does not restore working files")
        return result
    all_files = []
    for f in tree.rglob("*"):
        if (
            f.is_file()
            and ".git" not in f.relative_to(tree).parts
            and (".cwm-empty-hooks" not in f.relative_to(tree).parts)
        ):
            all_files.append(f)
    ignored = set()
    if result["git"]:
        ignored = {
            x.decode("utf-8")
            for x in git(
                tree, "ls-files", "--others", "--ignored", "--exclude-standard", "-z"
            ).split(b"\x00")
            if x
        }
    for f in sorted(all_files):
        rel = f.relative_to(tree).as_posix()
        safe_relative(rel)
        if rel in ignored and (not (include_ignored or profile == "full")):
            result["limitations"].append("Ignored file excluded: " + rel)
            continue
        if f.name.lower() in (
            "auth.json",
            "credentials",
            "credentials.json",
        ) or f.suffix.lower() in (".pfx", ".p12", ".key", ".agekey"):
            result["limitations"].append("Credential-like file excluded: " + rel)
            continue
        sha = digest(f)
        obj = Path(payload) / "objects/sha256" / sha
        obj.parent.mkdir(parents=True, exist_ok=True)
        if not obj.exists():
            shutil.copyfile(f, obj)
        result["files"].append(
            {"path": rel, "sha256": sha, "size": f.stat().st_size, "ignored": rel in ignored}
        )
    if (tree / ".git/lfs/objects").is_dir():
        result["git"]["lfs_objects"] = []
        for f in (tree / ".git/lfs/objects").rglob("*"):
            if f.is_file():
                sha = digest(f)
                obj = Path(payload) / "objects/sha256" / sha
                if not obj.exists():
                    shutil.copyfile(f, obj)
                result["git"]["lfs_objects"].append(
                    {"path": f.relative_to(tree / ".git/lfs/objects").as_posix(), "sha256": sha}
                )
    return result


def restore_project(
    project: dict[str, Any], payload: str | Path, target: str | Path, git: Git
) -> dict[str, Any]:
    target = Path(target)
    require(not target.exists(), "conflict", "Project restore target must be absent")
    for entry in project["files"]:
        check_path_budget(target / safe_relative(entry["path"]))
    for name in project["directories"]:
        check_path_budget(target / safe_relative(name))
    target.mkdir(parents=True)
    for name in project["directories"]:
        (target / safe_relative(name)).mkdir(parents=True, exist_ok=True)
    state = project.get("git")
    if state and state.get("bundle"):
        git(target, "init", "--object-format=" + state["object_format"])
        git(
            target,
            "-c",
            "protocol.file.allow=always",
            "fetch",
            "--update-head-ok",
            str(Path(payload) / state["bundle"]),
            "+refs/*:refs/*",
        )
        if state["symbolic_head"]:
            git(target, "symbolic-ref", "HEAD", state["symbolic_head"])
        else:
            git(target, "update-ref", "--no-deref", "HEAD", state["head"])
        lines = b""
        for e in state["index"]:
            lines += (
                e["mode"] + " " + e["oid"] + " " + str(e["stage"]) + "\t" + e["path"]
            ).encode() + b"\x00"
        git(target, "update-index", "-z", "--index-info", input=lines)
        if state.get("sparse_patterns") is not None:
            sparse = target / ".git/info/sparse-checkout"
            sparse.parent.mkdir(parents=True, exist_ok=True)
            sparse.write_text(state["sparse_patterns"], encoding="utf-8")
            git(target, "config", "core.sparseCheckout", "true")
        for name, flag in state["index_flags"].items():
            if flag.upper() == "S":
                git(target, "update-index", "--skip-worktree", "--", name)
            if flag.islower():
                git(target, "update-index", "--assume-unchanged", "--", name)
    for entry in project["files"]:
        p = target / safe_relative(entry["path"])
        p.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(Path(payload) / "objects/sha256" / entry["sha256"], p)
    if state:
        for o in state.get("lfs_objects", []):
            p = target / ".git/lfs/objects" / safe_relative(o["path"])
            p.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(Path(payload) / "objects/sha256" / o["sha256"], p)
    return compare(project, target, git)


def compare(project: dict[str, Any], target: str | Path, git: Git) -> dict[str, Any]:
    if project["profile"] == "references":
        return {
            "project_id": project["id"],
            "status": "references_only",
            "checks": [],
            "limitations": project["limitations"],
        }
    checks = []
    target = Path(target)
    dirs = {
        d.relative_to(target).as_posix()
        for d in target.rglob("*")
        if d.is_dir()
        and ".git" not in d.relative_to(target).parts
        and ".cwm-empty-hooks" not in d.relative_to(target).parts
    }
    checks.append({"kind": "directories", "ok": dirs == set(project["directories"])})
    for e in project["files"]:
        p = target / e["path"]
        checks.append(
            {"kind": "file", "path": e["path"], "ok": p.is_file() and digest(p) == e["sha256"]}
        )
    expected_files = {e["path"] for e in project["files"]}
    actual_files = {
        p.relative_to(target).as_posix()
        for p in target.rglob("*")
        if p.is_file()
        and ".git" not in p.relative_to(target).parts
        and (".cwm-empty-hooks" not in p.relative_to(target).parts)
    }
    checks.append(
        {
            "kind": "membership",
            "ok": actual_files == expected_files,
            "missing": sorted(expected_files - actual_files),
            "unexpected": sorted(actual_files - expected_files),
        }
    )
    state = project.get("git")
    if state and state.get("bundle"):
        checks.append(
            {
                "kind": "head",
                "ok": git(target, "rev-parse", "HEAD").decode().strip() == state["head"],
            }
        )
        checks.append({"kind": "index", "ok": index_entries(git, target) == state["index"]})
        actual_flags = {
            r[2:].decode("utf-8"): chr(r[0])
            for r in git(target, "ls-files", "-v", "-z").split(b"\x00")
            if r
        }
        checks.append({"kind": "index_flags", "ok": actual_flags == state["index_flags"]})
        actual_status = git(target, "status", "--porcelain=v2", "-z", "--untracked-files=all").hex()
        checks.append(
            {
                "kind": "status",
                "ok": actual_status == state["status_porcelain_v2_hex"],
                "gaps_may_explain_difference": bool(project["limitations"]),
            }
        )
        for oid, ref in state["refs"]:
            checks.append(
                {
                    "kind": "ref",
                    "ref": ref,
                    "ok": git(target, "rev-parse", ref).decode().strip() == oid,
                }
            )
    return {
        "project_id": project["id"],
        "status": "equivalent_selected_state"
        if all(c["ok"] for c in checks)
        else "equivalent_selected_bytes_with_gaps"
        if project["limitations"] and all(c["ok"] for c in checks if c["kind"] != "status")
        else "failed",
        "checks": checks,
        "limitations": project["limitations"],
    }


def recovery_dispositions(project: dict[str, Any]) -> dict[str, list[str]]:
    """Expected profile exclusions are distinct from unavailable required recovery state."""
    exclusions = [
        item for item in project["limitations"] if item.startswith("Ignored file excluded: ")
    ]
    gaps = [item for item in project["limitations"] if item not in exclusions]
    return {"selection_exclusions": exclusions, "recovery_gaps": gaps}

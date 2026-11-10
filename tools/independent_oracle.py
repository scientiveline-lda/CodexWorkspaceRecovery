"""Independent synthetic-fixture oracle; does not import the migration engine."""

import compression.zstd
import hashlib
import json
import os
import sqlite3
import subprocess
from contextlib import closing
from pathlib import Path


def sha(path):
    with Path(path).open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def json_file(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def tree(root):
    root = Path(root)
    return {
        p.relative_to(root).as_posix(): sha(p)
        for p in sorted(root.rglob("*"))
        if p.is_file() and ".git" not in p.relative_to(root).parts
    }


def git_state(root, git):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )

    def run(*args):
        return subprocess.check_output(
            [
                str(git),
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.autocrlf=false",
                "-c",
                "core.longpaths=true",
                "-c",
                "core.hooksPath=NUL",
                "--no-optional-locks",
                "-C",
                str(root),
                *args,
            ],
            env=env,
        )

    return {
        "head": run("rev-parse", "HEAD").hex(),
        "index": run("ls-files", "--stage", "-z").hex(),
        "flags": run("ls-files", "-v", "-z").hex(),
        "status": run("status", "--porcelain=v2", "-z", "--untracked-files=all").hex(),
        "refs": run("for-each-ref", "--format=%(objectname) %(refname)").decode().splitlines(),
    }


def expected(home, projects, git):
    home = Path(home)
    if not (home.parent / ".cwm-synthetic-fixture").is_file():
        raise ValueError("Oracle accepts explicitly marked synthetic fixtures only")
    sessions = {}
    for folder in ["sessions", "archived_sessions"]:
        for p in sorted((home / folder).rglob("*")):
            if not p.is_file():
                continue
            raw = p.read_bytes()
            expanded = compression.zstd.decompress(raw) if p.suffix == ".zst" else raw
            records = [json.loads(line) for line in expanded.splitlines()]
            ident = records[0]["payload"]["id"]
            sessions[ident] = {
                "sha256": hashlib.sha256(raw).hexdigest(),
                "records": records,
                "lines": expanded.splitlines(keepends=True),
                "archived": folder == "archived_sessions",
            }

    def logical(ident, end=None, seen=()):
        if ident in seen:
            raise ValueError("Fixture dependency cycle")
        records = sessions[ident]["records"]
        base = records[0]["payload"].get("history_base")
        result = logical(base["thread_id"], base["end_byte_offset"], (*seen, ident)) if base else []
        offset = 0
        for line, record in zip(sessions[ident]["lines"], records, strict=True):
            if end is not None and offset >= end:
                break
            result.append(
                {"source_thread_id": ident, "source_byte_offset": str(offset), "record": record}
            )
            offset += len(line)
        return result

    for ident, value in sessions.items():
        value["logical"] = logical(ident)
    for value in sessions.values():
        del value["lines"]
    databases = []
    for db in sorted(home.glob("*.sqlite")):
        with closing(sqlite3.connect(db.resolve().as_uri() + "?mode=ro", uri=True)) as c:
            c.row_factory = sqlite3.Row
            for table in ["threads", "projects", "project_roots"]:
                for row in c.execute('SELECT * FROM "' + table + '"'):
                    databases.append({"database": db.name, "table": table, "record": dict(row)})
    return {
        "sessions": sessions,
        "attachments": tree(home / "attachments"),
        "database_records": databases,
        "projects": [
            {
                "source": str(Path(p).resolve()),
                "files": tree(p),
                "directories": sorted(
                    d.relative_to(p).as_posix()
                    for d in Path(p).rglob("*")
                    if d.is_dir() and ".git" not in d.relative_to(p).parts
                ),
                "git": git_state(p, git) if (Path(p) / ".git").exists() else None,
            }
            for p in projects
        ],
    }


def verify(expected_state, payload, selected):
    payload = Path(payload)
    catalog = json_file(payload / "inventory/rollouts.json")["sessions"]
    expected_ids = set(selected)

    def ancestors(ident):
        base = expected_state["sessions"][ident]["records"][0]["payload"].get("history_base")
        if base and base["thread_id"] not in expected_ids:
            expected_ids.add(base["thread_id"])
            ancestors(base["thread_id"])

    for ident in selected:
        ancestors(ident)
    if {entry["id"] for entry in catalog} != expected_ids or len(catalog) != len(expected_ids):
        raise ValueError("Independent session membership mismatch")
    inventory = {s["id"]: s for s in json_file(payload / "inventory/sessions.json")}
    for entry in catalog:
        e = expected_state["sessions"][entry["id"]]
        if sha(payload / entry["object"]) != e["sha256"]:
            raise ValueError("Independent raw transcript digest mismatch")
        thread = payload / "portable/threads" / inventory[entry["id"]]["key"]
        events = [
            json.loads(line)["record"]
            for line in (thread / "events.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        logical_events = [
            {k: row[k] for k in ("source_thread_id", "source_byte_offset", "record")}
            for row in map(
                json.loads,
                (thread / "logical-events.jsonl").read_text(encoding="utf-8").splitlines(),
            )
        ]
        if events != e["records"] or logical_events != e["logical"]:
            raise ValueError("Independent event sequence mismatch")
    records = json_file(payload / "inventory/database-records.json")
    expected_rows = [
        row
        for row in expected_state["database_records"]
        if row["table"] != "threads" or row["record"]["id"] in expected_ids
    ]

    def normalized(rows):
        return sorted(json.dumps(row, sort_keys=True) for row in rows)

    if normalized(records) != normalized(expected_rows):
        raise ValueError("Independent database association mismatch")
    assets = json_file(payload / "inventory/assets.json")
    actual_assets = {a["source_path"]: a["sha256"] for a in assets if a["status"] == "present"}
    if actual_assets != expected_state["attachments"]:
        raise ValueError("Independent attachment omitted")
    for value in expected_state["attachments"].values():
        if sha(payload / "objects/sha256" / value) != value:
            raise ValueError("Independent attachment bytes mismatch")
    refs = json_file(payload / "inventory/asset-references.json")
    missing = sorted(row["source_reference"] for row in refs if row["status"] == "missing")
    if missing != sorted(expected_state.get("expected_missing_references", [])):
        raise ValueError("Independent missing-reference disposition mismatch")
    return {
        "status": "passed",
        "sessions": len(catalog),
        "checks": [
            "raw_bytes",
            "ordered_events",
            "logical_history",
            "database_associations",
            "attachment_bytes",
        ],
    }


def compare_project(expected_state, target, git, *, excluded=()):
    files = {k: v for k, v in expected_state["files"].items() if k not in excluded}
    if tree(target) != files:
        raise ValueError("Independent working file membership/bytes mismatch")
    dirs = sorted(
        d.relative_to(target).as_posix()
        for d in Path(target).rglob("*")
        if d.is_dir() and ".git" not in d.relative_to(target).parts
    )
    if dirs != expected_state["directories"]:
        raise ValueError("Independent directory membership mismatch")
    if expected_state["git"]:
        actual = git_state(target, git)
        for key in ["head", "index", "flags", "status"]:
            if actual[key] != expected_state["git"][key]:
                raise ValueError("Independent Git " + key + " mismatch")
        actual_refs = {line.split(" ", 1)[1]: line.split(" ", 1)[0] for line in actual["refs"]}
        for line in expected_state["git"]["refs"]:
            oid, ref = line.split(" ", 1)
            if actual_refs.get(ref) != oid:
                raise ValueError("Independent Git ref mismatch")
    return {
        "status": "passed",
        "checks": [
            "file_membership",
            "file_bytes",
            "head",
            "logical_index",
            "flags",
            "status",
            "refs",
        ],
    }

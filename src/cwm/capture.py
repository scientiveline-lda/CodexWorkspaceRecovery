"""Guarded acquisition. Only staging copies are opened by SQLite."""

from __future__ import annotations

import ctypes
import logging
import os
import shutil
import sqlite3
from collections.abc import Sequence
from contextlib import ExitStack, closing
from pathlib import Path
from typing import Any, BinaryIO

from .discovery import DENY_NAMES, KNOWN_DIRS, KNOWN_FILES, discover
from .security import protect_directory
from .util import (
    RecoveryError,
    blob_digest,
    canonical,
    check_path_budget,
    digest,
    key,
    now,
    reparse,
    require,
    walk_files,
    within,
    write_json,
)


class ReadGuard:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.file: BinaryIO | None = None

    def __enter__(self) -> ReadGuard:
        if os.name == "nt":
            import msvcrt

            k = ctypes.WinDLL("kernel32", use_last_error=True)
            k.CreateFileW.argtypes = [
                ctypes.c_wchar_p,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_void_p,
            ]
            k.CreateFileW.restype = ctypes.c_void_p
            handle = k.CreateFileW(str(self.path), 2147483648, 1, None, 3, 134217728, None)
            if handle == ctypes.c_void_p(-1).value:
                raise RecoveryError(
                    "source_busy", "Cannot acquire source read guard; close all source writers"
                )
            self.file = os.fdopen(msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY), "rb")
        else:
            self.file = self.path.open("rb")
        return self

    def copy(self, destination: str | Path) -> None:
        destination = Path(destination)
        if self.file is None:
            raise RecoveryError("capture_guard", "Source read guard is not open")
        destination.parent.mkdir(parents=True, exist_ok=True)
        self.file.seek(0)
        with destination.open("xb") as out:
            shutil.copyfileobj(self.file, out, 1024 * 1024)
            out.flush()
            os.fsync(out.fileno())

    def __exit__(self, *args: Any) -> None:
        if self.file:
            self.file.close()


def source_files(home: Path, sql: Path) -> tuple[list[tuple[Path, Path]], list[dict[str, Any]]]:
    out = []
    dispositions = []
    for label, base in [("home", home), ("sqlite", sql)]:
        if label == "sqlite" and sql == home:
            continue
        require(base.is_dir(), "missing_source", "Required source root does not exist")
        for p in sorted(base.iterdir()):
            if reparse(p):
                raise RecoveryError(
                    "unsupported_filesystem", "Reparse point in source state boundary"
                )
            relevant = (
                p.name in KNOWN_DIRS
                or p.name in KNOWN_FILES
                or ".sqlite" in p.name
                or p.name.endswith((".db", ".db-wal", ".db-journal", ".db-shm"))
                or (label == "home" and p.name.endswith(".config.toml"))
            )
            if p.name in DENY_NAMES:
                dispositions.append(
                    {
                        "root": label,
                        "name": p.name,
                        "status": "explicitly_excluded",
                        "reason": "Authentication or installation credential store",
                    }
                )
            elif relevant:
                if p.is_dir():
                    for f in walk_files(p):
                        out.append((f, Path("acquired") / label / f.relative_to(base)))
                else:
                    out.append((p, Path("acquired") / label / p.name))
            else:
                dispositions.append(
                    {
                        "root": label,
                        "name": p.name,
                        "status": "explicitly_excluded",
                        "reason": "Outside allowlisted state; not silently treated as preserved",
                    }
                )
    unique: dict[Path, tuple[Path, Path]] = {}
    for source, relative in out:
        unique.setdefault(source.resolve(), (source, relative))
    return (list(unique.values()), dispositions)


def git_layout(project: Path) -> tuple[Path | None, Path | None]:
    dot = project / ".git"
    if dot.is_dir():
        return (dot, dot)
    if dot.is_file():
        text = dot.read_text(encoding="utf-8").strip()
        require(text.startswith("gitdir: "), "git_layout", "Invalid worktree gitdir pointer")
        gd = (project / text[8:]).resolve()
        require(gd.is_dir(), "git_layout", "Worktree gitdir missing")
        common = (
            (gd / (gd / "commondir").read_text().strip()).resolve()
            if (gd / "commondir").exists()
            else gd
        )
        return (gd, common)
    return (None, None)


def inventory_pairs(pairs: list[tuple[Path, Path]]) -> list[dict[str, Any]]:
    return [
        {
            "source": str(p),
            "target": q.as_posix(),
            "size": p.stat().st_size,
            "mtime_ns": str(p.stat().st_mtime_ns),
        }
        for p, q in pairs
    ]


def capture(
    home: str | Path,
    sql: str | Path,
    output: str | Path,
    *,
    projects: Sequence[str | Path] = (),
    maintenance: bool = False,
) -> dict[str, Any]:
    home, sql, output = (Path(home).resolve(), Path(sql).resolve(), Path(output).absolute())
    require(
        maintenance,
        "maintenance_required",
        "Run capture from a separate maintenance terminal after closing source writers",
    )
    for src in [home, sql, *map(Path, projects)]:
        require(
            not within(output, src) and (not within(src, output)),
            "unsafe_path",
            "Capture destination overlaps source",
        )
    inventory = discover(home, sql)
    project_roots = [Path(p).resolve() for p in projects]
    require(
        all(
            not within(a, b) and not within(b, a)
            for i, a in enumerate(project_roots)
            for b in project_roots[i + 1 :]
        ),
        "unsafe_path",
        "Project roots overlap or repeat",
    )
    pairs, dispositions = source_files(home, sql)
    layouts: list[dict[str, Any]] = []
    for p in map(lambda x: Path(x).resolve(), projects):
        ident = key(str(p))
        gd, common = git_layout(p)
        for admin in (gd, common):
            if admin is not None:
                require(
                    not within(output, admin) and (not within(admin, output)),
                    "unsafe_path",
                    "Capture destination overlaps external Git administration",
                )
        require(
            not any(within(p, x) or within(x, p) for x in [home, sql]),
            "unsafe_path",
            "Project overlaps state root",
        )
        for f in walk_files(p):
            pairs.append((f, Path("acquired/projects") / ident / "tree" / f.relative_to(p)))
        if gd and common and (gd != p / ".git"):
            for f in walk_files(common):
                pairs.append(
                    (f, Path("acquired/projects") / ident / "common" / f.relative_to(common))
                )
            for f in walk_files(gd):
                pairs.append(
                    (f, Path("acquired/projects") / ident / "worktree_admin" / f.relative_to(gd))
                )
        layouts.append(
            {
                "directories": [d.relative_to(p).as_posix() for d in p.rglob("*") if d.is_dir()],
                "id": ident,
                "source": str(p),
                "gitdir": str(gd) if gd else None,
                "common": str(common) if common else None,
                "linked": bool(gd and gd != p / ".git"),
            }
        )
    aliases = []
    if os.name == "nt":
        short_path = ctypes.windll.kernel32.GetShortPathNameW
        short_path.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
        short_path.restype = ctypes.c_uint32
        for root in dict.fromkeys(
            [p for base in [home, sql, *project_roots] for p in [base, *base.parents]]
        ):
            buffer = ctypes.create_unicode_buffer(32768)
            if short_path(str(root), buffer, len(buffer)):
                aliases.append({"original": buffer.value, "canonical": str(root)})
                aliases.append(
                    {"original": str(root.parent / Path(buffer.value).name), "canonical": str(root)}
                )
    inventory["path_aliases"] = aliases
    for source, relative in pairs:
        check_path_budget(source)
        check_path_budget(output / relative)
    initial = inventory_pairs(pairs)
    require(len(pairs) <= 100000, "capture_limit", "Capture file limit exceeded")
    from .util import require_space

    require_space(output, 3 * sum((p.stat().st_size for p, q in pairs)))
    out = protect_directory(output)
    for layout in layouts:
        tree = out / "acquired/projects" / layout["id"] / "tree"
        tree.mkdir(parents=True, exist_ok=True)
        for name in layout["directories"]:
            check_path_budget(Path(layout["source"]) / name)
            check_path_budget(tree / name)
            (tree / name).mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {
        "schema_version": "1",
        "started_at": now(),
        "source": inventory,
        "projects": layouts,
        "dispositions": dispositions,
        "classification": "capture_failed",
        "files": [],
        "database_files": [],
        "findings": [],
    }
    write_json(out / "capture.json", report)
    try:
        with ExitStack() as stack:
            guards: dict[Path, ReadGuard] = {}
            for p, q in pairs:
                if p not in guards:
                    guards[p] = stack.enter_context(ReadGuard(p))
            before = inventory_pairs(pairs)
            require(
                before == initial,
                "source_changed",
                "Source changed before all capture guards were acquired",
            )
            logging.getLogger("cwm.progress").info("Acquiring %d source files", len(pairs))
            for p, q in pairs:
                guards[p].copy(out / q)
                report["files"].append(
                    {
                        "source": str(p),
                        "path": q.as_posix(),
                        "size": (out / q).stat().st_size,
                        "sha256": digest(out / q),
                    }
                )
            again, _ = source_files(home, sql)
            require(
                {str(p) for p, q in again}
                == {
                    str(p)
                    for p, q in pairs
                    if not str(q).startswith("acquired\\projects")
                    and (not q.as_posix().startswith("acquired/projects/"))
                },
                "source_changed",
                "State membership changed during acquisition",
            )
            for layout in layouts:
                require(
                    set(layout["directories"])
                    == {
                        d.relative_to(Path(layout["source"])).as_posix()
                        for d in Path(layout["source"]).rglob("*")
                        if d.is_dir()
                    },
                    "source_changed",
                    "Project directory membership changed",
                )
                roots = [(Path(layout.get("physical_source", layout["source"])), "tree")]
                if layout["linked"]:
                    roots += [
                        (Path(layout["common"]), "common"),
                        (Path(layout["gitdir"]), "worktree_admin"),
                    ]
                for root, part in roots:
                    prefix = "acquired/projects/" + layout["id"] + "/" + part + "/"
                    expected = {str(p) for p, q in pairs if q.as_posix().startswith(prefix)}
                    require(
                        expected == {str(p) for p in walk_files(root)},
                        "source_changed",
                        "Project or external Git administration membership changed",
                    )
            for item in report["files"]:
                require(
                    digest(Path(item["source"])) == item["sha256"],
                    "source_changed",
                    "Captured bytes differ from guarded source",
                )
            require(
                before == inventory_pairs(pairs),
                "source_changed",
                "Source changed during acquisition",
            )
            report["inventory_before"] = blob_digest(canonical(before))
            report["inventory_after"] = report["inventory_before"]
        logging.getLogger("cwm.progress").info("Recovering staged databases")
        database_candidates = []
        for item in report["files"]:
            acquired = Path(item["path"])
            original = Path(item["source"])
            state_namespace = acquired.parts[:2] in (("acquired", "home"), ("acquired", "sqlite"))
            state_location = original.parent in (home, sql) or within(original, home / "sqlite")
            if state_namespace and state_location:
                database_candidates.append(out / acquired)
        for db in database_candidates:
            if db.is_file() and db.suffix in (".sqlite", ".db"):
                working = out / "database_work" / key(str(db.relative_to(out)))
                working.mkdir(parents=True)
                dest = working / db.name
                shutil.copyfile(db, dest)
                for suffix in ["-wal", "-journal"]:
                    if Path(str(db) + suffix).exists():
                        shutil.copyfile(Path(str(db) + suffix), Path(str(dest) + suffix))
                try:
                    with closing(sqlite3.connect(dest)) as conn:
                        require(
                            conn.execute("PRAGMA integrity_check").fetchall() == [("ok",)],
                            "database_integrity",
                            "Staged database integrity failure",
                        )
                        final = out / "databases" / db.relative_to(out / "acquired")
                        final.parent.mkdir(parents=True, exist_ok=True)
                        with closing(sqlite3.connect(final)) as target:
                            conn.backup(target)
                            target.execute("PRAGMA journal_mode=DELETE")
                        require(
                            not conn.execute("PRAGMA foreign_key_check").fetchall(),
                            "database_integrity",
                            "Staged foreign-key failure",
                        )
                        report["database_files"].append(
                            {
                                "path": final.relative_to(out).as_posix(),
                                "sha256": digest(final),
                                "size": final.stat().st_size,
                            }
                        )
                except sqlite3.Error as e:
                    raise RecoveryError(
                        "database_integrity", "Staging database could not be recovered"
                    ) from e
        report["classification"] = (
            "guarded_validated" if os.name == "nt" else "best_effort_incomplete"
        )
        report["guards"] = (
            "Windows deny-write/delete read handles"
            if os.name == "nt"
            else "POSIX reads; no Windows consistency certification"
        )
        report["consistency_scope"] = {
            "existing_files": "deny-write/delete handles and byte comparison"
            if os.name == "nt"
            else "reads only",
            "membership": "before/after roots including external Git administration",
            "application_quiescence": "not_established",
            "limitations": [
                "No atomic transaction spans all stores; transient new/deleted files and hidden writers cannot be excluded"
            ],
        }
        report["ended_at"] = now()
        write_json(out / "capture.json", report, replace=True)
        return report
    except Exception:
        report["ended_at"] = now()
        report["findings"].append(
            {
                "code": "capture_incomplete",
                "detail": "Capture failed; acquired evidence retained in protected staging",
            }
        )
        write_json(out / "capture.json", report, replace=True)
        raise

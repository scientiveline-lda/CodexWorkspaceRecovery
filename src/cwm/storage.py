"""Versioned, bounded SQLite reader for recovered staging copies only."""

from __future__ import annotations

import base64
import re
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from .util import blob_digest, canonical, load, payload_json, require

MAX_RECORD = 32 * 1024**2
MAX_RECORDS_BYTES = 64 * 1024**2


def identifier(name: str) -> str:
    require(
        re.fullmatch("[A-Za-z_][A-Za-z0-9_]*", name), "schema_invalid", "Unsupported SQL identifier"
    )
    return '"' + name + '"'


def selected_records(
    databases: list[Path], selected: list[str]
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    spec = load(Path(__file__).parent / "schemas/storage-columns.json")
    records: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    total = 0
    project_ids: set[str] = set()
    selected_set = set(selected)
    for project_pass in (False, True):
        for database in databases:
            with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as connection:
                connection.row_factory = sqlite3.Row
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                if not project_pass:
                    for unknown in sorted(tables - set(spec["columns"])):
                        gaps.append(
                            {
                                "database": database.name,
                                "component": unknown,
                                "disposition": "local_acquisition_only",
                                "reason": "Uncertified table schema",
                            }
                        )
                for table in sorted(tables & set(spec["columns"])):
                    if (table in ("projects", "project_roots")) != project_pass:
                        continue
                    info = [
                        tuple(row)
                        for row in connection.execute(
                            "PRAGMA table_info(" + identifier(table) + ")"
                        )
                    ]
                    available = {row[1] for row in info}
                    columns = sorted(available & set(spec["columns"][table]))
                    unknown = sorted(available - set(columns))
                    if unknown:
                        gaps.append(
                            {
                                "database": database.name,
                                "component": table,
                                "columns": unknown,
                                "disposition": "local_acquisition_only",
                                "reason": "Unreviewed columns are not exported",
                            }
                        )
                    observations.append(
                        {
                            "database": database.name,
                            "table": table,
                            "schema_sha256": blob_digest(canonical(info)),
                            "columns": columns,
                            "status": "observed_allowlisted_columns; portable selected records only",
                        }
                    )
                    owner = (
                        "id"
                        if table in ("threads", "projects")
                        else "project_id"
                        if project_pass
                        else "thread_id"
                    )
                    if table == "thread_spawn_edges":
                        owner = "parent_thread_id"
                    if owner not in columns:
                        gaps.append(
                            {
                                "database": database.name,
                                "component": table,
                                "disposition": "local_acquisition_only",
                                "reason": "Missing ownership column",
                            }
                        )
                        continue
                    allowed = project_ids if project_pass else selected_set
                    if not allowed:
                        continue
                    ordered = sorted(allowed)
                    for offset in range(0, len(ordered), 400):
                        batch = ordered[offset : offset + 400]
                        where = identifier(owner) + " IN (" + ",".join("?" for _ in batch) + ")"
                        length_sql = " + ".join(
                            "coalesce(length(cast(" + identifier(c) + " as blob)),0)"
                            for c in columns
                        )
                        # Shipped table/column allowlists pass identifier(); all values are bound.
                        max_size = connection.execute(
                            "SELECT max("  # nosec B608
                            + length_sql
                            + ") FROM "
                            + identifier(table)
                            + " WHERE "
                            + where,
                            batch,
                        ).fetchone()[0]
                        require(
                            max_size is None or max_size <= MAX_RECORD,
                            "database_limit",
                            "Selected row exceeds supported size",
                        )
                        query = (
                            "SELECT "  # nosec B608
                            + ",".join(identifier(c) for c in columns)
                            + " FROM "
                            + identifier(table)
                            + " WHERE "
                            + where
                        )
                        for row in connection.execute(query, batch):
                            record = dict(row)
                            if (
                                table == "thread_spawn_edges"
                                and record.get("child_thread_id") not in selected_set
                            ):
                                continue
                            if table == "threads" and isinstance(record.get("project_id"), str):
                                project_ids.add(record["project_id"])
                            encoded = {
                                k: {"encoding": "base64", "value": base64.b64encode(v).decode()}
                                if isinstance(v, bytes)
                                else v
                                for k, v in record.items()
                            }
                            item = {"database": database.name, "table": table, "record": encoded}
                            total += len(payload_json(item))
                            require(
                                total <= MAX_RECORDS_BYTES,
                                "database_limit",
                                "Selected database controls exceed supported memory bound",
                            )
                            records.append(item)
    return (
        records,
        {
            "adapter": spec["adapter"],
            "observations": observations,
            "gaps": gaps,
            "limits": {"record_bytes": MAX_RECORD, "selected_total_bytes": MAX_RECORDS_BYTES},
            "source_policy": "Recovered staging copies only; no original database opens",
        },
    )

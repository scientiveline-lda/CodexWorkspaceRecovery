"""Bounded semantic admission after cryptographic verification.

Historical records stay extensible; paths and recovery control relationships do not.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from collections.abc import Iterator
from itertools import zip_longest
from pathlib import Path
from typing import Any, cast

from .assets import reconcile, references
from .models import Manifest
from .projects import recovery_dispositions
from .rollouts import records, text_content
from .util import digest, key, load, no_reparse_chain, payload_json, require, safe_relative


def member(payload: Path, manifest: Manifest, name: str) -> Path:
    """Resolve only a declared regular member inside the authenticated payload."""
    name = safe_relative(name)
    require(
        name in manifest["payload"], "undeclared_reference", "Reference is not an archive member"
    )
    path = payload / name
    no_reparse_chain(path)
    require(
        path.resolve().is_relative_to(payload.resolve()) and path.is_file(),
        "unsafe_reference",
        "Reference escapes verified payload",
    )
    entry = manifest["payload"][name]
    require(
        path.stat().st_size == entry["size"] and digest(path) == entry["sha256"],
        "payload_changed",
        "Verified payload member changed",
    )
    return path


def control(payload: Path, manifest: Manifest, name: str, kind: type) -> Any:
    path = member(payload, manifest, name)
    require(
        path.stat().st_size <= 64 * 1024**2,
        "control_limit",
        "Semantic control exceeds supported memory bound",
    )
    value = load(path)
    require(isinstance(value, kind), "control_invalid", "Invalid semantic control structure")
    return value


def project_file(name: str) -> str:
    name = safe_relative(name)
    require(
        not any(part.casefold() == ".git" for part in name.split("/")),
        "unsafe_project",
        "Ordinary project entries cannot deploy Git administration",
    )
    return name


def validate_projects(payload: Path, manifest: Manifest, projects: list[Any]) -> None:
    ids, sources = (set(), set())
    for project in projects:
        require(isinstance(project, dict), "project_invalid", "Invalid project record")
        ident, source = (project.get("id"), project.get("source"))
        require(
            isinstance(source, str)
            and ident == key(source)
            and (ident not in ids)
            and (source not in sources),
            "project_invalid",
            "Project identity is invalid or duplicated",
        )
        ids.add(ident)
        sources.add(source)
        require(
            project.get("profile") in ("references", "recovery", "full")
            and isinstance(project.get("files"), list)
            and isinstance(project.get("limitations"), list),
            "project_invalid",
            "Invalid project recovery profile",
        )
        paths = set()
        for entry in project["files"]:
            name = project_file(entry["path"])
            folded = unicodedata.normalize("NFKC", name).casefold()
            require(folded not in paths, "project_invalid", "Duplicate project destination")
            paths.add(folded)
            sha = entry["sha256"]
            require(
                isinstance(sha, str) and re.fullmatch("[a-f0-9]{64}", sha),
                "project_invalid",
                "Invalid project object digest",
            )
            obj = member(payload, manifest, "objects/sha256/" + sha)
            require(
                digest(obj) == sha and obj.stat().st_size == entry["size"],
                "project_invalid",
                "Project bytes differ from recovery inventory",
            )
        require(
            isinstance(project.get("directories"), list),
            "project_invalid",
            "Directory inventory missing",
        )
        names = [project_file(d) for d in project["directories"]]
        require(len(names) == len(set(names)), "project_invalid", "Duplicate directory")
        files = {entry["path"] for entry in project["files"]}

        def normalize(value: str) -> str:
            return unicodedata.normalize("NFKC", value).casefold()

        require(
            len({normalize(n) for n in names}) == len(names),
            "project_invalid",
            "Directory case/Unicode collision",
        )
        require(
            not ({normalize(n) for n in names} & {normalize(f) for f in files}),
            "project_invalid",
            "File/directory case collision",
        )
        require(
            all(
                "/".join(n.split("/")[:i]) in set(names)
                for n in set(names) | files
                for i in range(1, len(n.split("/")))
            ),
            "project_invalid",
            "Missing parent directory inventory",
        )
        require(not (set(names) & files), "project_invalid", "File/directory collision")
        directory_set = set(names)
        require(
            all(
                "/".join(n.split("/")[:i]) not in files
                for n in directory_set | files
                for i in range(1, len(n.split("/")))
            ),
            "project_invalid",
            "File ancestor collision",
        )
        state = project.get("git")
        if state:
            require(isinstance(state, dict), "project_invalid", "Invalid Git control")
            if state.get("bundle"):
                require(
                    state["bundle"] == "portable/projects/" + ident + "/repository.bundle",
                    "unsafe_project",
                    "Git bundle must belong to its project",
                )
                member(payload, manifest, state["bundle"])
            for entry in state.get("index", []):
                project_file(entry["path"])
                require(
                    entry["mode"] in ("100644", "100755", "120000", "160000")
                    and type(entry["stage"]) is int
                    and (0 <= entry["stage"] <= 3)
                    and re.fullmatch("[a-f0-9]{40}|[a-f0-9]{64}", entry["oid"]),
                    "project_invalid",
                    "Invalid Git index entry",
                )
            for name in state.get("index_flags", {}):
                project_file(name)
            for obj in state.get("lfs_objects", []):
                safe_relative(obj["path"])
                require(
                    re.fullmatch("[a-f0-9]{64}", obj["sha256"]),
                    "project_invalid",
                    "Invalid LFS digest",
                )
                member(payload, manifest, "objects/sha256/" + obj["sha256"])


def reconcile_history(
    payload: Path, manifest: Manifest, sessions: list[Any], catalog: dict[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    require(
        isinstance(catalog.get("sessions"), list), "session_mismatch", "Invalid rollout catalog"
    )
    expected = {s["id"]: s for s in sessions}
    entries = catalog["sessions"]
    actual_ids = [entry["id"] for entry in entries]
    require(
        len(actual_ids) == len(set(actual_ids))
        and set(actual_ids) == set(expected)
        and (len(expected) == len(sessions)),
        "session_mismatch",
        "Catalog/inventory membership or uniqueness differs",
    )
    inv: dict[str, dict[str, Any]] = {}
    for entry in entries:
        ident = entry["id"]
        e = expected[ident]
        require(e["key"] == key(ident), "session_mismatch", "Invalid derived session key")
        original = safe_relative(entry["original_path"])
        require(
            original.startswith(("sessions/", "archived_sessions/")),
            "session_mismatch",
            "Invalid rollout namespace",
        )
        require(
            entry["object"] == "objects/sha256/" + e["raw_sha256"],
            "history_mismatch",
            "Raw object does not match session digest",
        )
        source = member(payload, manifest, entry["object"])
        metadata = control(
            payload, manifest, "portable/threads/" + e["key"] + "/metadata.json", dict
        )
        require(
            {k: v for k, v in metadata.items() if k != "metadata"} == e,
            "session_mismatch",
            "Per-session and global inventories differ",
        )
        require(digest(source) == e["raw_sha256"], "history_mismatch", "Raw history digest differs")
        count, meta = (0, None)
        counts: dict[str, int] = {}
        for _, _, record in records(source, compressed=original.endswith(".zst")):
            if count == 0:
                require(
                    record.get("type") == "session_meta",
                    "history_invalid",
                    "Missing session header",
                )
                meta = record.get("payload")
            count += 1
            kind = record.get("type", "unknown")
            counts[kind] = counts.get(kind, 0) + 1
        require(
            isinstance(meta, dict)
            and meta.get("id") == ident
            and (meta == metadata["metadata"])
            and (count == e["record_count"])
            and (counts == e["record_types"]),
            "history_mismatch",
            "Raw history and metadata inventory differ",
        )
        inv[ident] = {"path": source, "compressed": original.endswith(".zst"), "metadata": meta}

    def logical(
        ident: str, end: int | None = None, ancestors: tuple[str, ...] = ()
    ) -> Iterator[tuple[str, int, dict[str, Any]]]:
        require(
            ident in inv and ident not in ancestors and (len(ancestors) < 128),
            "history_invalid",
            "Missing, cyclic or excessive ancestry",
        )
        info = inv[ident]
        base = info["metadata"].get("history_base")
        if base:
            require(
                isinstance(base, dict)
                and type(base.get("end_byte_offset")) is int
                and (type(base.get("end_ordinal_exclusive")) is int)
                and (base["end_byte_offset"] >= 0)
                and (base["end_ordinal_exclusive"] >= 0),
                "history_invalid",
                "Invalid ancestor boundary",
            )
            inherited = 0
            for row in logical(base["thread_id"], base["end_byte_offset"], (*ancestors, ident)):
                inherited += 1
                yield row
            require(
                inherited == base["end_ordinal_exclusive"],
                "history_invalid",
                "Ordinal and byte history boundaries disagree",
            )
        boundary = end == 0 or end is None
        for offset, line, record in records(info["path"], compressed=info["compressed"]):
            if end is not None and offset >= end:
                break
            require(
                end is None or offset + len(line) <= end,
                "history_invalid",
                "Ancestor cutoff splits a record",
            )
            if offset + len(line) == end:
                boundary = True
            yield (ident, offset, record)
        require(boundary, "history_invalid", "Ancestor cutoff exceeds available history")

    checks = []
    sentinel = object()
    for ident, e in expected.items():
        prefix = "portable/threads/" + e["key"] + "/"
        original_events = member(payload, manifest, prefix + "events.jsonl")
        raw_readable = member(payload, manifest, prefix + "transcript.md")
        raw_md = hashlib.sha256()
        raw_md.update(
            ("# Preserved conversation evidence\n\nOriginal identifier: " + ident + "\n\n").encode()
        )
        base = inv[ident]["metadata"].get("history_base")
        if base:
            raw_md.update(
                (
                    "Inherited history: "
                    + base["thread_id"]
                    + "; see its preserved transcript and exact boundary metadata.\n\n"
                ).encode()
            )
        raw_stream = records(inv[ident]["path"], compressed=inv[ident]["compressed"])
        stored_stream = (row for _, _, row in records(original_events))
        for ordinal, (raw_row, stored_row) in enumerate(
            zip_longest(raw_stream, stored_stream, fillvalue=sentinel)
        ):
            require(
                isinstance(raw_row, tuple) and isinstance(stored_row, dict),
                "history_mismatch",
                "Raw event view omits or adds records",
            )
            if not isinstance(raw_row, tuple):
                from .util import RecoveryError

                raise RecoveryError("history_mismatch", "Invalid raw view")
            offset, line, record = raw_row
            expected_row = {
                "ordinal": ordinal,
                "byte_offset": str(offset),
                "byte_length": len(line),
                "record": record,
            }
            require(
                payload_json(stored_row) == payload_json(expected_row),
                "history_mismatch",
                "Raw event view differs",
            )
            kind = record.get("type", "unknown")
            body = record.get("payload")
            role = body.get("role", body.get("type", "")) if isinstance(body, dict) else ""
            raw_md.update((f"## Record {ordinal}: {kind} {role}\n\n").encode())
            text = text_content(body)
            if kind in ("session_meta", "turn_context", "world_state", "token_usage_record"):
                text = "[Structured execution metadata preserved in events.jsonl]\n\n"
            elif text:
                text = "\n".join("> " + row for row in text.splitlines()) + "\n\n"
            else:
                text = "[Structured or opaque content preserved in events.jsonl]\n\n"
            raw_md.update(text.encode())
        require(
            digest(raw_readable) == raw_md.hexdigest(),
            "history_mismatch",
            "Raw readable view differs",
        )
        events = member(payload, manifest, prefix + "logical-events.jsonl")
        readable = member(payload, manifest, prefix + "logical-transcript.md")
        md = hashlib.sha256()
        md.update(
            b"# Combined historical evidence\n\nInherited raw records respect their preserved byte boundaries. This is not the exact current model context.\n\n"
        )
        count = 0
        actual = (record for _, _, record in records(events))
        for number, pair in enumerate(zip_longest(logical(ident), actual, fillvalue=sentinel)):
            logical_row, stored = pair
            if not isinstance(logical_row, tuple) or not isinstance(stored, dict):
                from .util import RecoveryError

                raise RecoveryError(
                    "history_mismatch", "Logical history has omitted or extra events"
                )
            origin, offset, record = logical_row
            row = {
                "derived_position": number,
                "source_thread_id": origin,
                "source_byte_offset": str(offset),
                "record": record,
            }
            require(
                payload_json(stored) == payload_json(row),
                "history_mismatch",
                "Logical event order/content/provenance differs",
            )
            text = text_content(record.get("payload"))
            if text:
                md.update(
                    (
                        "## "
                        + origin
                        + " @ "
                        + str(offset)
                        + "\n\n"
                        + "\n".join(("> " + line for line in text.splitlines()))
                        + "\n\n"
                    ).encode()
                )
            count += 1
        require(
            count == e["logical_record_count"] and digest(readable) == md.hexdigest(),
            "history_mismatch",
            "Logical history count/readable view differs",
        )
        checks.append(
            {"kind": "session", "id": ident, "logical_records": count, "status": "verified"}
        )
    return (checks, inv)


def semantic(payload: Path | str) -> dict[str, Any]:
    payload = Path(payload)
    no_reparse_chain(payload)
    require(
        (payload / "manifest.json").is_file(),
        "control_invalid",
        "Authenticated manifest is required",
    )
    raw_manifest = load(payload / "manifest.json")
    import jsonschema

    jsonschema.validate(raw_manifest, load(Path(__file__).parent / "schemas/manifest.json"))
    manifest = cast(Manifest, raw_manifest)
    require(
        isinstance(manifest.get("payload"), dict), "control_invalid", "Missing payload inventory"
    )
    catalog = control(payload, manifest, "inventory/rollouts.json", dict)
    sessions = control(payload, manifest, "inventory/sessions.json", list)
    projects = control(payload, manifest, "inventory/projects.json", list)
    validate_projects(payload, manifest, projects)
    checks, histories = reconcile_history(payload, manifest, sessions, catalog)
    assets = control(payload, manifest, "inventory/assets.json", list)
    for asset in assets:
        require(
            asset.get("status") in ("present", "embedded", "external", "missing", "excluded"),
            "attachment_invalid",
            "Unknown attachment disposition",
        )
        if asset["status"] == "present":
            sha = asset["sha256"]
            require(
                isinstance(sha, str) and re.fullmatch("[a-f0-9]{64}", sha),
                "attachment_invalid",
                "Invalid attachment digest",
            )
            require(
                digest(member(payload, manifest, "objects/sha256/" + sha)) == sha,
                "attachment_mismatch",
                "Attachment content mismatch",
            )
    stored_references = control(payload, manifest, "inventory/asset-references.json", list)
    database_records = control(payload, manifest, "inventory/database-records.json", list)
    source = control(payload, manifest, "inventory/source.json", dict)
    require(
        isinstance(source.get("codex_home"), str),
        "control_invalid",
        "Source home reference is missing",
    )
    aliases = source.get("path_aliases", [])
    require(
        isinstance(aliases, list)
        and len(aliases) <= 1024
        and all(
            isinstance(row, dict)
            and all(
                isinstance(row.get(field), str) and 0 < len(row[field]) <= 2048
                for field in ("original", "canonical")
            )
            for row in aliases
        ),
        "control_invalid",
        "Invalid or excessive source aliases",
    )
    expected_references = references(histories, list(histories), database_records)
    reconcile(
        expected_references, assets, source["codex_home"], projects, source.get("path_aliases", [])
    )
    require(
        payload_json(expected_references) == payload_json(stored_references),
        "attachment_mismatch",
        "Attachment reference inventory differs from verified history and available bytes",
    )
    completeness = control(payload, manifest, "reports/completeness.json", dict)
    require(
        completeness.get("sessions") == len(sessions)
        and completeness.get("projects") == len(projects)
        and (completeness.get("assets") == len(assets)),
        "control_invalid",
        "Completeness counts differ from inventories",
    )
    declared = completeness["has_recovery_gaps"]
    gaps = (
        any(row.get("status") != "preserved" for row in completeness.get("project_coverage", []))
        or any(row["status"] not in ("present", "embedded") for row in assets + expected_references)
        or any(recovery_dispositions(project)["recovery_gaps"] for project in projects)
        or bool(completeness.get("storage_gaps"))
    )
    completeness = {
        **completeness,
        "declared_has_recovery_gaps": declared,
        "has_recovery_gaps": gaps,
        "assessment": "semantic-admission-v2",
        "scope": "selected_state_equivalence; not whole-machine or account recovery",
    }
    security = control(payload, manifest, "reports/security.json", dict)
    require(
        isinstance(security.get("findings"), list)
        and isinstance(security.get("limitations"), list),
        "control_invalid",
        "Invalid security control",
    )
    return {
        "status": "verified_preserved_evidence",
        "sessions": checks,
        "representation": "portable-filesystem",
        "completeness": completeness,
    }

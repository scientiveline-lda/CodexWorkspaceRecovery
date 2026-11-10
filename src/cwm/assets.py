"""Inventory typed asset references without crawling arbitrary transcript text or URLs."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from typing import Any

from .rollouts import records

ASSET_TYPES = {
    "input_image",
    "input_file",
    "image",
    "localImage",
    "file",
    "audio",
    "input_audio",
    "video",
}


def typed_refs(value: Any) -> Iterator[str]:
    if isinstance(value, dict):
        if value.get("type") in ASSET_TYPES:
            for k in ("image_url", "url", "path", "file_id", "audio_url", "filename"):
                ref = value.get(k)
                if isinstance(ref, str):
                    yield ref
                elif isinstance(ref, dict) and isinstance(ref.get("url"), str):
                    yield ref["url"]
        for v in value.values():
            yield from typed_refs(v)
    elif isinstance(value, list):
        for v in value:
            yield from typed_refs(v)


def references(
    inv: dict[str, dict[str, Any]], chosen: list[str], db_records: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    result = []
    seen = set()

    def add(tid: str | None, ref: str) -> None:
        token = (tid, ref)
        if token in seen:
            return
        seen.add(token)
        if ref.startswith("data:"):
            result.append(
                {
                    "thread_id": tid,
                    "reference_sha256": hashlib.sha256(ref.encode()).hexdigest(),
                    "status": "embedded",
                    "reason": "Exact inline content remains in raw rollout",
                }
            )
        else:
            result.append({"thread_id": tid, "source_reference": ref, "status": "unresolved"})

    for tid in chosen:
        for _, _, record in records(inv[tid]["path"], compressed=inv[tid].get("compressed")):
            for ref in typed_refs(record):
                add(tid, ref)
    for e in db_records:
        if e["table"] != "thread_attachments":
            continue
        row = e["record"]
        payload = row.get("payload")
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except ValueError:
                payload = {}
        for ref in typed_refs(payload):
            add(row.get("thread_id"), ref)
        if isinstance(payload, dict):
            for k in ("path", "url", "file_id"):
                if isinstance(payload.get(k), str):
                    add(row.get("thread_id"), payload[k])
    return result


def mapped_path(value: str, aliases: list[dict[str, str]]) -> str:
    result = value.replace("\\", "/")
    ordered = sorted(aliases, key=lambda row: len(row["original"]), reverse=True)
    for _ in range(128):
        changed = False
        for alias in ordered:
            prefix = alias["original"].replace("\\", "/").rstrip("/")
            if result.casefold() == prefix.casefold() or result.casefold().startswith(
                prefix.casefold() + "/"
            ):
                replacement = (
                    alias["canonical"].replace("\\", "/").rstrip("/") + result[len(prefix) :]
                )
                if replacement != result:
                    result = replacement
                    changed = True
                    break
        if not changed:
            break

    return result


def managed_path(
    ref: str, source_home: str, aliases: list[dict[str, str]] | None = None
) -> str | None:
    value = mapped_path(ref, aliases or [])
    prefix = source_home.replace("\\", "/").rstrip("/") + "/attachments/"
    if value.casefold().startswith(prefix.casefold()):
        return value[len(prefix) :]
    if value.startswith("attachments/"):
        return value[len("attachments/") :]
    return None


def reconcile(
    refs: list[dict[str, Any]],
    assets: list[dict[str, Any]],
    source_home: str,
    projects: list[dict[str, Any]],
    aliases: list[dict[str, str]] | None = None,
) -> list[dict[str, Any]]:
    managed = {a.get("source_path"): a for a in assets if a.get("status") == "present"}
    for ref in refs:
        if ref["status"] == "embedded":
            continue
        value = ref["source_reference"]
        relative = managed_path(value, source_home, aliases)
        if relative in managed:
            ref.update(
                {
                    "status": "present",
                    "sha256": managed[relative]["sha256"],
                    "source_path": relative,
                }
            )
            continue
        found = False
        for project in projects:
            prefix = project["source"].replace("\\", "/").rstrip("/") + "/"
            normalized = mapped_path(value, aliases or [])
            if normalized.casefold().startswith(prefix.casefold()):
                name = normalized[len(prefix) :]
                matching = [f for f in project["files"] if f["path"] == name]
                if matching:
                    ref.update(
                        {
                            "status": "present",
                            "sha256": matching[0]["sha256"],
                            "project_id": project["id"],
                        }
                    )
                    found = True
                    break
        if found:
            continue
        external = value.startswith(
            ("http:", "https:", "file-", "project-file:", "library-file:", "plugin:")
        )
        ref.update(
            {
                "status": "external" if external else "missing",
                "reason": "No automatic retrieval; referenced bytes were not present in the selected captured assets",
            }
        )
    return refs

"""Streaming raw preservation, dependency closure and loss-aware readable views."""

from __future__ import annotations

import compression.zstd
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .util import RecoveryError, digest, key, loads, payload_json, require

MAX_LINE = 32 * 1024 * 1024
MAX_EXPANDED = 4 * 1024 * 1024 * 1024


def records(
    path: str | Path, *, compressed: bool | None = None
) -> Iterator[tuple[int, bytes, dict[str, Any]]]:
    total = 0
    offset = 0
    opener = (
        compression.zstd.open
        if (Path(path).suffix == ".zst" if compressed is None else compressed)
        else open
    )
    try:
        with opener(path, "rb") as f:
            while line := f.readline(MAX_LINE + 1):
                require(len(line) <= MAX_LINE, "rollout_limit", "Rollout line exceeds safety limit")
                total += len(line)
                require(
                    total <= MAX_EXPANDED, "rollout_limit", "Expanded rollout exceeds safety limit"
                )
                require(
                    line.endswith(b"\n"), "rollout_truncated", "Incomplete final rollout record"
                )
                r = loads(line)
                require(isinstance(r, dict), "rollout_invalid", "Rollout record must be an object")
                yield (offset, line, r)
                offset += len(line)
    except (OSError, ValueError, EOFError, compression.zstd.ZstdError) as e:
        if isinstance(e, RecoveryError):
            raise
        raise RecoveryError("rollout_invalid", "Rollout cannot be decoded") from e


def inventory(snapshot: str | Path) -> dict[str, dict[str, Any]]:
    out = {}
    for folder in ["sessions", "archived_sessions"]:
        root = Path(snapshot) / "acquired/home" / folder
        if not root.exists():
            continue
        for p in sorted(root.rglob("*")):
            if not p.is_file():
                continue
            first = next(records(p), None)
            require(
                first is not None and first[2].get("type") == "session_meta",
                "rollout_invalid",
                "Missing initial session metadata",
            )
            if first is None:
                raise RecoveryError("rollout_invalid", "Empty session")
            meta = first[2].get("payload", {})
            ident = meta.get("id")
            require(
                isinstance(ident, str) and ident, "rollout_invalid", "Missing thread identifier"
            )
            require(
                ident not in out,
                "duplicate_session",
                "Multiple rollouts share an identity; resolve before export",
            )
            out[ident] = {
                "id": ident,
                "key": key(ident),
                "path": str(p),
                "relative_path": p.relative_to(Path(snapshot) / "acquired/home").as_posix(),
                "sha256": digest(p),
                "archived": folder == "archived_sessions",
                "metadata": meta,
            }
    return out


def closure(inv: dict[str, dict[str, Any]], selected: list[str]) -> list[str]:
    visiting: set[str] = set()
    done = set()
    result = []

    def visit(ident: str) -> None:
        require(ident in inv, "missing_history", "Referenced ancestor/session is unavailable")
        require(ident not in visiting, "history_cycle", "History dependency cycle")
        if ident in done:
            return
        require(len(visiting) < 128, "history_invalid", "History ancestry exceeds supported depth")
        visiting.add(ident)
        base = inv[ident]["metadata"].get("history_base")
        if base:
            require(
                isinstance(base, dict) and isinstance(base.get("thread_id"), str),
                "history_invalid",
                "Invalid history base",
            )
            visit(base["thread_id"])
            end = base.get("end_byte_offset")
            ordinal = base.get("end_ordinal_exclusive")
            require(
                type(end) is int and type(ordinal) is int and (end >= 0) and (ordinal >= 0),
                "history_invalid",
                "Invalid history boundary",
            )
            ancestor = inv[base["thread_id"]]
            offsets = {0}
            count = 0
            for off, line, _ in records(ancestor["path"]):
                offsets.add(off + len(line))
                count += 1
            require(
                end in offsets, "history_invalid", "History byte boundary is not a record boundary"
            )
            require(
                sum(1 for _ in logical_records(inv, base["thread_id"], end=end)) == ordinal,
                "history_invalid",
                "Ordinal and byte history boundaries disagree",
            )
        visiting.remove(ident)
        done.add(ident)
        result.append(ident)

    for ident in selected:
        visit(ident)
    return result


def text_content(payload: Any) -> str:
    if not isinstance(payload, dict):
        return ""
    chunks = []
    if isinstance(payload.get("content"), list):
        for c in payload["content"]:
            if isinstance(c, dict) and isinstance(c.get("text"), str):
                chunks.append(c["text"])
            elif isinstance(c, dict):
                chunks.append("[Non-text item: " + str(c.get("type", "unknown")) + "]")
    for k in ["message", "output", "arguments"]:
        if isinstance(payload.get(k), str):
            chunks.append(payload[k])
    return "\n".join(chunks)


def render(inv: dict[str, dict[str, Any]], ident: str, output: str | Path) -> dict[str, Any]:
    info = inv[ident]
    out = Path(output)
    out.mkdir(parents=True, exist_ok=False)
    counts: dict[str, int] = {}
    n = 0
    offset_end = 0
    with (
        (out / "events.jsonl").open("xb") as events,
        (out / "transcript.md").open("w", encoding="utf-8", newline="\n") as md,
    ):
        md.write("# Preserved conversation evidence\n\nOriginal identifier: " + ident + "\n\n")
        base = info["metadata"].get("history_base")
        if base:
            md.write(
                "Inherited history: "
                + base["thread_id"]
                + "; see its preserved transcript and exact boundary metadata.\n\n"
            )
        for offset, line, r in records(info["path"]):
            t = r.get("type", "unknown")
            counts[t] = counts.get(t, 0) + 1
            events.write(
                payload_json(
                    {
                        "ordinal": n,
                        "byte_offset": str(offset),
                        "byte_length": len(line),
                        "record": r,
                    }
                )
                + b"\n"
            )
            p = r.get("payload")
            text = text_content(p)
            role = p.get("role", p.get("type", "")) if isinstance(p, dict) else ""
            md.write(f"## Record {n}: {t} {role}\n\n")
            if t in ("session_meta", "turn_context", "world_state", "token_usage_record"):
                md.write("[Structured execution metadata preserved in events.jsonl]\n\n")
            elif text:
                md.write("\n".join("> " + x for x in text.splitlines()) + "\n\n")
            else:
                md.write("[Structured or opaque content preserved in events.jsonl]\n\n")
            n += 1
            offset_end = offset + len(line)
    return {
        "id": ident,
        "key": info["key"],
        "archived": info["archived"],
        "metadata": info["metadata"],
        "raw_sha256": info["sha256"],
        "record_count": n,
        "record_types": counts,
        "expanded_bytes": str(offset_end),
        "history_status": "reference_preserved"
        if info["metadata"].get("history_base")
        else "local_records_preserved",
    }


def logical_records(
    inv: dict[str, dict[str, Any]],
    ident: str,
    stack: set[str] | None = None,
    end: int | None = None,
) -> Iterator[tuple[str, int, dict[str, Any]]]:
    stack = set() if stack is None else stack
    require(ident not in stack, "history_cycle", "History dependency cycle")
    stack = stack | {ident}
    base = inv[ident]["metadata"].get("history_base")
    if base:
        yield from logical_records(inv, base["thread_id"], stack, base["end_byte_offset"])
    for off, line, record in records(inv[ident]["path"]):
        if end is not None and off >= end:
            break
        yield (ident, off, record)


def render_logical(inv: dict[str, dict[str, Any]], ident: str, out: Any) -> int:
    count = 0
    with (
        (Path(out) / "logical-events.jsonl").open("xb") as events,
        (Path(out) / "logical-transcript.md").open("w", encoding="utf-8", newline="\n") as md,
    ):
        md.write(
            "# Combined historical evidence\n\nInherited raw records respect their preserved byte boundaries. This is not the exact current model context.\n\n"
        )
        for origin, offset, record in logical_records(inv, ident):
            events.write(
                payload_json(
                    {
                        "derived_position": count,
                        "source_thread_id": origin,
                        "source_byte_offset": str(offset),
                        "record": record,
                    }
                )
                + b"\n"
            )
            text = text_content(record.get("payload"))
            if text:
                md.write(
                    "## "
                    + origin
                    + " @ "
                    + str(offset)
                    + "\n\n"
                    + "\n".join("> " + line for line in text.splitlines())
                    + "\n\n"
                )
            count += 1
    return count

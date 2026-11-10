"""Inert supporting evidence; never installs source trust or executable configuration."""

from __future__ import annotations

import shutil
import tomllib
from pathlib import Path
from typing import Any

from .util import digest, load, loads, write_payload


def preserve_configuration(
    snapshot: str | Path,
    payload: str | Path,
    chosen: list[str],
    full: bool,
    *,
    include_supporting: bool = False,
) -> dict[str, Any]:
    home = Path(snapshot) / "acquired/home"
    payload = Path(payload)
    base = payload / "portable/configuration"
    base.mkdir(parents=True)
    report: dict[str, Any] = {"activation": "inert evidence only", "included": [], "excluded": []}
    config = home / "config.toml"
    if config.exists():
        c = tomllib.loads(config.read_text(encoding="utf-8"))
        allowed = {
            "model",
            "model_provider",
            "model_reasoning_effort",
            "model_reasoning_summary",
            "model_verbosity",
            "history",
            "project_doc_max_bytes",
            "project_doc_fallback_filenames",
        }
        safe = {k: v for k, v in c.items() if k in allowed}
        write_payload(base / "user-config-reviewed.json", safe)
        report["included"].append("reviewed user preferences")
        report["excluded"].append(
            {
                "component": "user_config_keys",
                "keys": sorted(set(c) - allowed),
                "reason": "Credential-bearing, executable, trust or unreviewed settings are not copied blindly",
            }
        )
    agents = home / "AGENTS.md"
    if agents.exists():
        shutil.copyfile(agents, base / "AGENTS.md")
        report["included"].append("AGENTS.md")
    for n, idkey in [("history.jsonl", "session_id"), ("session_index.jsonl", "id")]:
        p = home / n
        if p.exists():
            with p.open(encoding="utf-8") as stream:
                rows = [loads(line) for line in stream if line.strip()]
            write_payload(
                base / (n + ".selected.json"), [row for row in rows if row.get(idkey) in chosen]
            )
    g = home / ".codex-global-state.json"
    if g.exists():
        state = load(g)
        safe = {}
        for k in [
            "thread-project-assignments",
            "thread-workspace-root-hints",
            "thread-writable-roots",
        ]:
            value = state.get(k)
            if isinstance(value, dict):
                safe[k] = {tid: v for tid, v in value.items() if tid in chosen}
        pids = {
            v.get("projectId")
            for v in safe.get("thread-project-assignments", {}).values()
            if isinstance(v, dict)
        }
        value = state.get("local-projects", {})
        if isinstance(value, dict):
            safe["local-projects"] = {i: v for i, v in value.items() if i in pids}
        write_payload(base / "desktop-associations-reviewed.json", safe)
        report["excluded"].append(
            {
                "component": "desktop_global_state",
                "reason": "Browser, account renderer, enrollment and unreviewed UI state excluded",
            }
        )
    for directory in ["skills", "rules", "plans"]:
        source = home / directory
        if not source.exists():
            continue
        if not (full or include_supporting):
            report["excluded"].append(
                {
                    "component": directory,
                    "reason": "Shared global supporting material not automatically included in selective exports",
                }
            )
            continue
        for f in source.rglob("*"):
            if not f.is_file():
                continue
            rel = f.relative_to(source)
            if ".system" in rel.parts:
                item = {
                    "component": directory + "/.system",
                    "reason": "Bundled system material must be reinstalled from its authenticated distribution",
                }
                if item not in report["excluded"]:
                    report["excluded"].append(item)
                continue
            if f.name.lower() == "auth.json" or f.suffix.lower() in (
                ".pfx",
                ".p12",
                ".key",
                ".agekey",
            ):
                report["excluded"].append(
                    {
                        "component": directory + "/" + rel.as_posix(),
                        "reason": "Credential-like material excluded",
                    }
                )
                continue
            dest = base / directory / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(f, dest)
            report["included"].append(
                {"path": dest.relative_to(payload).as_posix(), "sha256": digest(f)}
            )
    write_payload(base / "coverage.json", report)
    return report

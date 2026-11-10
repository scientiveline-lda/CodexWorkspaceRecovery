"""Construct portable evidence without leaking unrelated rows in selective exports."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from .projects import Git, collect, recovery_dispositions
from .rollouts import closure, inventory, render, render_logical
from .security import scan_file
from .util import digest, key, load, require, write_payload


def preserve(
    snapshot: str | Path,
    payload: str | Path,
    *,
    selected: list[str] | None = None,
    archived: bool | None = None,
    since: str | None = None,
    until: str | None = None,
    git_exe: str | Path | None = None,
    profile: Any = "recovery",
    include_ignored: bool = False,
    include_supporting: bool = False,
) -> dict[str, Any]:
    snapshot = Path(snapshot)
    payload = Path(payload)
    cap = load(snapshot / "capture.json")
    require(
        cap["classification"] in ("guarded_validated", "best_effort_incomplete"),
        "capture_incomplete",
        "Capture is incomplete",
    )
    for f in cap["files"]:
        require(
            (snapshot / f["path"]).is_file() and digest(snapshot / f["path"]) == f["sha256"],
            "capture_changed",
            "Acquired snapshot evidence changed",
        )
    for db in cap.get("database_files", []):
        require(
            digest(snapshot / db["path"]) == db["sha256"],
            "capture_changed",
            "Recovered database snapshot changed",
        )
    inv = inventory(snapshot)
    selected = list(dict.fromkeys(selected or inv))
    require(all(i in inv for i in selected), "missing_session", "Selected thread unavailable")
    if archived is not None:
        selected = [i for i in selected if inv[i]["archived"] == archived]
    if since or until:
        from datetime import datetime

        def instant(value: str) -> datetime:
            try:
                result = datetime.fromisoformat(value.replace("Z", "+00:00"))
                require(result.tzinfo is not None, "invalid_date", "Timezone-aware date required")
                return result
            except (ValueError, TypeError) as exc:
                from .util import RecoveryError

                raise RecoveryError(
                    "invalid_date", "Invalid date filter or source timestamp"
                ) from exc

        lower = instant(since) if since else None
        upper = instant(until) if until else None
        require(not (lower and upper) or lower < upper, "invalid_date", "Date range is empty")
        selected = [
            i
            for i in selected
            if (lower is None or instant(inv[i]["metadata"]["timestamp"]) >= lower)
            and (upper is None or instant(inv[i]["metadata"]["timestamp"]) < upper)
        ]
    require(selected, "empty_selection", "No sessions selected")
    chosen = closure(inv, selected)
    # Bound actual expanded history demand before creating derived output. Raw-byte
    # capture size alone underestimates compressed and shared-ancestor histories.
    from .rollouts import logical_records, records
    from .util import payload_json, require_space

    expanded = sum(len(line) for ident in chosen for _, line, _ in records(inv[ident]["path"]))
    logical_size = sum(
        len(payload_json(row)) + 256
        for ident in chosen
        for _, _, row in logical_records(inv, ident)
    )
    require_space(payload.parent, 8 * (expanded + logical_size))
    payload.mkdir(parents=True, exist_ok=False)
    rows = []
    catalog = []
    findings = []
    assets = []
    for ident in chosen:
        info = inv[ident]
        sha = info["sha256"]
        obj = payload / "objects/sha256" / sha
        obj.parent.mkdir(parents=True, exist_ok=True)
        if not obj.exists():
            shutil.copyfile(info["path"], obj)
        row = render(inv, ident, payload / "portable/threads" / info["key"])
        row["logical_record_count"] = render_logical(
            inv, ident, payload / "portable/threads" / info["key"]
        )
        row["selection_role"] = "selected" if ident in selected else "history_dependency"
        write_payload(payload / "portable/threads" / info["key"] / "metadata.json", row)
        rows.append(row)
        catalog.append(
            {
                "id": ident,
                "object": obj.relative_to(payload).as_posix(),
                "original_path": info["relative_path"],
                "sha256": sha,
            }
        )
    from .storage import selected_records

    db_records, storage = selected_records(
        [snapshot / e["path"] for e in cap.get("database_files", [])], chosen
    )
    write_payload(payload / "inventory/storage-adapters.json", storage)
    write_payload(payload / "inventory/database-records.json", db_records)
    from .assets import managed_path, reconcile, references

    refs = references(inv, chosen, db_records)
    wanted_assets = {
        managed_path(
            ref["source_reference"],
            cap["source"]["codex_home"],
            cap["source"].get("path_aliases", []),
        )
        for ref in refs
        if "source_reference" in ref
    }
    attachment_root = snapshot / "acquired/home/attachments"
    full = set(chosen) == set(inv)
    for p in attachment_root.rglob("*") if attachment_root.exists() else []:
        if not p.is_file():
            continue
        rel = p.relative_to(attachment_root).as_posix()
        if full or rel in wanted_assets or any(i in rel for i in chosen):
            sha = digest(p)
            obj = payload / "objects/sha256" / sha
            if not obj.exists():
                shutil.copyfile(p, obj)
            assets.append(
                {"source_path": rel, "sha256": sha, "size": p.stat().st_size, "status": "present"}
            )
        else:
            assets.append(
                {
                    "source_path_hash": key(rel),
                    "status": "excluded",
                    "reason": "Ambiguous ownership in selective export",
                }
            )
    projects = []
    layouts = cap.get("projects", [])
    if layouts:
        require(
            git_exe, "tool_missing", "Explicit Git executable required for project preservation"
        )
        if git_exe is None:
            from .util import RecoveryError

            raise RecoveryError("tool_missing", "Project preservation requires Git")
        for layout in layouts:
            project = collect(
                snapshot,
                layout,
                payload,
                payload.parent / "git_work",
                Git(git_exe),
                profile,
                include_ignored,
            )
            projects.append(project)
            write_payload(payload / "portable/projects" / layout["id"] / "project.json", project)
    reconcile(
        refs, assets, cap["source"]["codex_home"], projects, cap["source"].get("path_aliases", [])
    )
    write_payload(payload / "inventory/asset-references.json", refs)
    from .configuration import preserve_configuration

    configuration = preserve_configuration(
        snapshot, payload, chosen, full, include_supporting=include_supporting
    )
    write_payload(
        payload / "inventory/rollouts.json",
        {
            "adapter": "rollout-evidence-v1",
            "sessions": catalog,
            "purpose": "Original rollout mapping only; no application activation",
        },
    )
    write_payload(
        payload / "inventory/sessions.json",
        [{k: v for k, v in r.items() if k != "metadata"} for r in rows],
    )
    write_payload(payload / "inventory/assets.json", assets)
    write_payload(payload / "inventory/projects.json", projects)
    write_payload(payload / "inventory/source.json", cap["source"])
    write_payload(payload / "inventory/capture.json", cap)
    for project in projects:
        continuation = payload / "continuation" / project["id"]
        continuation.mkdir(parents=True)
        (continuation / "initialize.txt").write_text(
            "Treat this package as historical reference. Inspect the actual repository, HEAD, logical index and working changes before modifying files. Compare with project.json; report contradictions and missing dependencies. Do not execute imported hooks, setup scripts, plugins or commands. Facts require evidence references; label inferences and unresolved issues.\n",
            encoding="utf-8",
        )
        (continuation / "context.md").write_text(
            "# Recovery context\n\nVerified snapshot source: "
            + project["source"]
            + "\n\nSee portable/projects/"
            + project["id"]
            + "/project.json and inventory/sessions.json for evidence.\n\nNo semantic decisions were inferred automatically.\n",
            encoding="utf-8",
        )
    for p in payload.rglob("*"):
        if p.is_file():
            findings.extend(scan_file(p, p.relative_to(payload).as_posix()))
    coverage = {
        "scanner": "cwm-patterns-v1",
        "findings": findings,
        "limitations": [
            "Pattern scanning cannot prove absence of secrets",
            "Opaque binary/provider content not semantically decoded",
        ],
        "handling": "Encrypted evidence; review findings before sharing",
    }
    write_payload(payload / "reports/security.json", coverage)
    expected_roots = set()
    for ident in chosen:
        m = inv[ident]["metadata"]
        if isinstance(m.get("cwd"), str):
            expected_roots.add(m["cwd"])
        for value in m.get("runtime_workspace_roots", []):
            if isinstance(value, str):
                expected_roots.add(value)
    for row in db_records:
        if row["table"] == "project_roots" and isinstance(row["record"].get("path"), str):
            expected_roots.add(row["record"]["path"])

    def normalize(value: str) -> str:
        from .assets import mapped_path

        value = mapped_path(value, cap["source"].get("path_aliases", []))
        return (
            value.replace("\\", "/").rstrip("/").casefold() if ":" in value else value.rstrip("/")
        )

    captured_roots = {normalize(p["source"]) for p in projects}
    project_coverage = [
        {
            "source_root": root,
            "status": "preserved"
            if normalize(root) in captured_roots and profile != "references"
            else "reference_only",
            "reason": "Explicit project acquisition required for working-state recovery"
            if normalize(root) not in captured_roots
            else "Selected profile",
        }
        for root in sorted(expected_roots)
    ]
    complete = {
        "project_coverage": project_coverage,
        "has_recovery_gaps": any(p["status"] != "preserved" for p in project_coverage)
        or any(a["status"] not in ("present", "embedded") for a in assets + refs)
        or any(recovery_dispositions(p)["recovery_gaps"] for p in projects)
        or bool(storage["gaps"]),
        "storage_gaps": storage["gaps"],
        "selection_exclusions": {
            "configuration": configuration.get("excluded", []),
            "projects": {
                p["id"]: recovery_dispositions(p)["selection_exclusions"] for p in projects
            },
        },
        "scope": "selected_state_equivalence; not whole-machine or account recovery",
        "consistency": cap["classification"],
        "project_limitations": {p["id"]: p["limitations"] for p in projects if p["limitations"]},
        "sessions": len(rows),
        "selected": len(selected),
        "dependencies": len(chosen) - len(selected),
        "assets": len(assets),
        "projects": len(projects),
        "configuration_coverage": configuration,
        "capture_classification": cap["classification"],
        "representation": "portable-filesystem",
        "database_policy": "Only selected allowlisted records exported; raw databases retained in protected acquisition staging",
        "limitations": [
            "External resource bytes are not fetched",
            "Ambiguous selective attachment ownership is reported, not guessed",
        ],
    }
    write_payload(payload / "reports/completeness.json", complete)
    return complete

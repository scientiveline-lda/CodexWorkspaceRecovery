"""Read-only coverage discovery. No auth reads and no database opens."""

from __future__ import annotations

import os
import shutil
import tomllib
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .models import SourceCoverage
from .util import digest, now

KNOWN_DIRS = {
    "sessions",
    "archived_sessions",
    "attachments",
    "sqlite",
    "memories",
    "skills",
    "rules",
    "plans",
}
KNOWN_FILES = {
    "config.toml",
    "AGENTS.md",
    ".codex-global-state.json",
    "session_index.jsonl",
    "history.jsonl",
}
DENY_NAMES = {"auth.json", "cap_sid", "installation_id"}


def locations(
    home: str | Path | None = None, sqlite_home: str | Path | None = None
) -> tuple[Path, Path, dict[str, Any]]:
    h = Path(home or os.environ.get("CODEX_HOME") or Path.home() / ".codex").expanduser().resolve()
    config = {}
    if (h / "config.toml").is_file():
        config = tomllib.loads((h / "config.toml").read_text(encoding="utf-8"))
    configured = config.get("sqlite_home")
    sql = (
        Path(sqlite_home or configured or os.environ.get("CODEX_SQLITE_HOME") or h)
        .expanduser()
        .resolve()
    )
    return (
        h,
        sql,
        {
            "explicit_sqlite_home": sqlite_home is not None,
            "config_sqlite_home": configured is not None,
            "effective_config_top_keys": sorted(config),
            "limitation": "Launch-specific -c overrides and IDE/remote environment must be declared separately",
        },
    )


def installation(path: str | Path, surface: str) -> dict[str, Any] | None:
    p = Path(path)
    if not p.is_file():
        return None
    out = {"surface": surface, "path": str(p.resolve()), "sha256": digest(p)}
    out["version"] = "not executed; file identity only"
    return out


def discover(
    home: str | Path | None = None, sqlite_home: str | Path | None = None
) -> dict[str, Any]:
    h, sql, origins = locations(home, sqlite_home)
    coverage = []
    for surface, source_root in [("codex_home", h), ("sqlite_home", sql)]:
        coverage.append(
            asdict(
                SourceCoverage(
                    surface,
                    str(source_root),
                    "discovered_supported" if source_root.is_dir() else "inaccessible",
                    "Declared local boundary",
                )
            )
        )
    candidates = []
    runtime = os.environ.get("CODEX_APP_RUNTIME_CLI_PATH")
    if runtime:
        candidates.append((runtime, "desktop_engine"))
    cli = shutil.which("codex.exe") or shutil.which("codex.ps1") or shutil.which("codex")
    if cli:
        candidates.append((cli, "cli"))
    for editor in [".vscode", ".vscode-insiders", ".cursor"]:
        base = Path.home() / editor / "extensions"
        if base.exists():
            for ext in base.glob("openai.chatgpt-*"):
                for b in ext.glob("bin/windows-*/codex.exe"):
                    candidates.append((str(b), "ide_engine"))
    local = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData/Local")))
    for base in [
        local / "OpenAI/Codex/bin",
        local / "Programs/OpenAI/Codex/bin",
        h / "packages/standalone",
    ]:
        if base.is_dir():
            for binary in list(base.rglob("codex.exe"))[:100]:
                candidates.append((str(binary), "standalone_or_desktop_engine"))
    npm = (
        Path(os.environ.get("APPDATA", str(Path.home() / "AppData/Roaming")))
        / "npm/node_modules/@openai"
    )
    if npm.is_dir():
        for binary in list(npm.rglob("codex.exe"))[:100]:
            candidates.append((str(binary), "npm_engine"))
    engines = []
    for executable_path, surface_name in dict.fromkeys(candidates):
        item = installation(executable_path, surface_name)
        if item:
            engines.append(item)
    for surface, reason in [
        ("other_profiles", "Separate authorization and profile inventory required"),
        ("wsl", "Report-only; no distribution is started"),
        ("remote", "Remote homes require a separate host capture"),
        ("cloud", "No verified general history migration contract"),
    ]:
        coverage.append(asdict(SourceCoverage(surface, None, "not_examined", reason)))
    profiles = Path(os.environ.get("SystemDrive", "C:") + "/Users")
    try:
        for profile in profiles.iterdir():
            if not profile.is_dir() or profile.resolve() == Path.home().resolve():
                continue
            try:
                candidate = profile / ".codex"
                if candidate.is_dir():
                    coverage.append(
                        asdict(
                            SourceCoverage(
                                "additional_profile",
                                str(candidate),
                                "not_examined",
                                "Detected; separate authorized capture required",
                            )
                        )
                    )
            except PermissionError:
                coverage.append(
                    asdict(
                        SourceCoverage(
                            "additional_profile",
                            str(profile),
                            "inaccessible",
                            "Profile access denied",
                        )
                    )
                )
    except OSError:
        coverage.append(
            asdict(
                SourceCoverage(
                    "profile_inventory", str(profiles), "inaccessible", "Cannot enumerate profiles"
                )
            )
        )
    files = []
    for root in dict.fromkeys([h, sql]):
        if root.exists():
            for p in sorted(root.iterdir()):
                if p.is_file():
                    files.append(
                        {
                            "name": p.name,
                            "bytes": p.stat().st_size,
                            "root": str(root),
                            "credential_store": p.name in DENY_NAMES,
                        }
                    )
    return {
        "schema_version": "1",
        "created_at": now(),
        "codex_home": str(h),
        "sqlite_home": str(sql),
        "configuration_origins": origins,
        "installations": engines,
        "coverage": coverage,
        "top_level_inventory": files,
        "identity": {"status": "unknown", "reason": "Authentication stores are never read"},
    }

"""Operator-owned recovery material. No external authority or implicit archive trust."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path
from typing import Any

from .security import Toolchain, protect_directory
from .util import digest, load, require, run, within, write_json


def defaults() -> Path:
    package = Path(sys.executable).resolve().parent.parent
    config = package / "vendor/toolchain.json"
    if config.is_file():
        return config
    # Explicit development layout; packaged runtime never falls back here.
    root = Path(__file__).resolve().parents[2]
    config = root / "vendor/toolchain.json"
    require(
        config.is_file(),
        "tool_missing",
        "Packaged toolchain is missing; reinstall the complete distribution",
    )
    return config


def git_default() -> Path:
    tools = Toolchain(defaults())
    return tools.tool("git")


def profile(root: str | Path, *, signing: bool = False) -> dict[str, Any]:
    root = Path(root).resolve()
    p = load(root / "profile.json")
    require(p.get("schema_version") == 1, "key_profile", "Unsupported recovery key profile")
    for name in ["identity.agekey", "trust.json"] + (["signing.key"] if signing else []):
        require((root / name).is_file(), "key_missing", "Recovery key material is incomplete")
    return {
        **p,
        "identity": root / "identity.agekey",
        "trust": root / "trust.json",
        "signing_key": root / "signing.key",
    }


def initialize(output: str | Path) -> dict[str, Any]:
    root = protect_directory(output)
    tools = Toolchain(defaults())
    run([tools.tool("age-keygen"), "-o", root / "identity.agekey"])
    recipient = run([tools.tool("age-keygen"), "-y", root / "identity.agekey"]).decode().strip()
    run(
        [tools.tool("minisign"), "-G", "-W", "-s", root / "signing.key", "-p", root / "signing.pub"]
    )
    pub = (root / "signing.pub").read_text().splitlines()[-1]
    ident = digest(root / "signing.pub")[:32]
    write_json(
        root / "profile.json",
        {
            "schema_version": 1,
            "key_id": ident,
            "producer": "local-operator",
            "scope": "portable-workspace",
            "recipients": [recipient],
        },
    )
    write_json(
        root / "trust.json",
        {
            "schema_version": "1",
            "issued_at": "2020-01-01T00:00:00Z",
            "expires_at": "2099-01-01T00:00:00Z",
            "keys": [
                {
                    "id": ident,
                    "status": "trusted",
                    "public_key": pub,
                    "producers": ["local-operator"],
                    "scopes": ["portable-workspace"],
                }
            ],
        },
    )
    return {
        "status": "created",
        "keys": str(root),
        "signer_fingerprint": ident,
        "warning": "Back up recovery keys separately. Local private keys are ACL-protected, not passphrase-encrypted.",
    }


def export_recovery(keys: str | Path, output: str | Path) -> dict[str, Any]:
    profile(keys)
    require(
        not within(output, keys) and not within(keys, output),
        "unsafe_path",
        "Key directories overlap",
    )
    target = protect_directory(output)
    for name in ["profile.json", "identity.agekey", "trust.json"]:
        shutil.copyfile(Path(keys) / name, target / name)
    return {
        "status": "created",
        "keys": str(target),
        "signing_private_key_included": False,
        "warning": "Contains a private decryption key; never share alongside the archive or publish.",
    }

"""Pinned external cryptography, protected staging and transparent secret findings."""

from __future__ import annotations

import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from .util import RecoveryError, as_record, digest, load, no_reparse_chain, now, require, run


class Toolchain:
    def __init__(self, config: str | Path | dict[str, Any]) -> None:
        self.base = Path(config).resolve().parent if isinstance(config, (str, Path)) else None
        self.config: dict[str, Any] = as_record(
            load(config) if isinstance(config, (str, Path)) else config
        )

    def tool(self, name: str) -> Path:
        spec = self.config.get(name, {})
        p = Path(spec.get("path", ""))
        if not p.is_absolute():
            require(
                self.base is not None,
                "tool_missing",
                "Relative tool path requires an explicit configuration file",
            )
            from .util import safe_relative

            if self.base is None:
                raise RecoveryError("tool_missing", "Relative executable has no configuration root")
            p = self.base / safe_relative(p.as_posix())
        require(p.is_file(), "tool_missing", f"Explicit {name} executable is required")
        no_reparse_chain(p)
        require(
            digest(p) == spec.get("sha256"), "tool_integrity", f"{name} executable hash mismatch"
        )
        return p

    def sign(self, manifest: str | Path, secret_key: str | Path) -> None:
        run(
            [
                self.tool("minisign"),
                "-S",
                "-s",
                Path(secret_key).resolve(),
                "-m",
                manifest,
                "-x",
                str(manifest) + ".minisig",
                "-t",
                "CWMF 1.0 manifest",
            ]
        )

    def verify(self, manifest: str | Path, signature: str | Path, public_key: str) -> None:
        run([self.tool("minisign"), "-V", "-P", public_key, "-m", manifest, "-x", signature])

    def encrypt(self, source: str | Path, output: str | Path, recipients: list[str]) -> None:
        require(
            len(set(recipients)) >= 1, "key_policy", "At least one native age recipient is required"
        )
        argv: list[str | Path] = [self.tool("age"), "--encrypt"]
        for r in recipients:
            require(r.startswith("age1"), "key_policy", "Use explicit native age public recipients")
            argv += ["-r", r]
        run([*argv, "-o", output, source], timeout=3600)

    def decrypt(self, source: str | Path, output: str | Path, identity: str | Path) -> None:
        run(
            [self.tool("age"), "--decrypt", "-i", Path(identity).resolve(), "-o", output, source],
            timeout=3600,
        )


def system_executable(name: str) -> Path:
    """Resolve Windows security tools through the OS, never the current directory/PATH."""
    require(
        name in ("whoami.exe", "icacls.exe", "powershell.exe"),
        "tool_policy",
        "Unapproved system tool",
    )
    import ctypes

    buffer = ctypes.create_unicode_buffer(32768)
    require(
        ctypes.windll.kernel32.GetSystemDirectoryW(buffer, len(buffer)) > 0,
        "tool_missing",
        "Windows system directory unavailable",
    )
    base = Path(buffer.value)
    return base / ("WindowsPowerShell/v1.0/powershell.exe" if name == "powershell.exe" else name)


def system_environment() -> dict[str, str]:
    """Exclude user/other-edition PowerShell modules from security diagnostics."""
    env = os.environ.copy()
    env["PSModulePath"] = str(system_executable("powershell.exe").parent / "Modules")
    return env


def protect_directory(path: str | Path) -> Path:
    path = Path(path).absolute()
    no_reparse_chain(path)
    path.mkdir(mode=448, parents=False, exist_ok=False)
    if os.name == "nt":
        sid = (
            run([system_executable("whoami.exe"), "/user", "/fo", "csv", "/nh"])
            .decode(errors="replace")
            .split(",")[-1]
            .strip()
            .strip('"')
        )
        require(sid.startswith("S-1-"), "acl_failed", "Cannot establish current Windows SID")
        run(
            [
                system_executable("icacls.exe"),
                path,
                "/inheritance:r",
                "/grant:r",
                f"*{sid}:(OI)(CI)F",
                "*S-1-5-18:(OI)(CI)F",
            ]
        )
        env = system_environment()
        env["CWM_ACL_PATH"] = str(path)
        env["CWM_ACL_SID"] = sid
        script = "$ErrorActionPreference='Stop'; $d=[Security.AccessControl.DirectorySecurity]::new(); $d.SetAccessRuleProtection($true,$false); foreach($sid in @($env:CWM_ACL_SID,'S-1-5-18')){$r=[Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'); $d.AddAccessRule($r)}; [IO.Directory]::SetAccessControl($env:CWM_ACL_PATH,$d); $a=[IO.Directory]::GetAccessControl($env:CWM_ACL_PATH); if(-not $a.AreAccessRulesProtected){throw 'ACL inheritance'}; $rules=$a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]); foreach($r in $rules){if($r.AccessControlType -ne 'Allow' -or $r.IdentityReference.Value -notin @($env:CWM_ACL_SID,'S-1-5-18')){throw 'Unexpected access rule'}}; if($rules.Count -ne 2){throw 'Missing access rules'}; 'protected'"
        require(
            run(
                [
                    system_executable("powershell.exe"),
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    script,
                ],
                env=env,
            ).strip()
            == b"protected",
            "acl_failed",
            "Directory effective ACL is not restricted to the operator and SYSTEM",
        )
    else:
        path.chmod(448)
    return path


def trusted_key(policy: str | Path | dict[str, Any], key_id: str, producer: str, scope: str) -> str:
    p = load(policy) if isinstance(policy, (str, Path)) else policy
    require(p.get("schema_version") == "1", "trust_failed", "Unsupported trust policy")
    try:
        start = datetime.fromisoformat(p["issued_at"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(p["expires_at"].replace("Z", "+00:00"))
        current = datetime.fromisoformat(now().replace("Z", "+00:00"))
        valid = start.tzinfo is not None and end.tzinfo is not None and (start <= current <= end)
    except KeyError, AttributeError, TypeError, ValueError:
        valid = False
    require(valid, "trust_failed", "Trust policy is not currently valid")
    matches = [k for k in p.get("keys", []) if k.get("id") == key_id]
    require(len(matches) == 1, "trust_failed", "Unknown or ambiguous signing key")
    k = matches[0]
    require(k.get("status") == "trusted", "trust_failed", "Revoked or untrusted signing key")
    require(
        producer in k.get("producers", []) and scope in k.get("scopes", []),
        "trust_failed",
        "Signer is not authorized for producer and scope",
    )
    public = k["public_key"]
    if not isinstance(public, str):
        raise RecoveryError("trust_failed", "Signing public key must be text")
    return public


RULES = [
    ("age_private_identity", "critical", re.compile(rb"AGE-SECRET-KEY-[A-Z0-9]{20,}")),
    ("private_key", "critical", re.compile(b"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")),
    ("openai_key", "high", re.compile(b"\\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}")),
    ("bearer", "high", re.compile(b"(?i)\\bbearer\\s+[A-Za-z0-9._~+/-]{20,}")),
    (
        "credential_assignment",
        "suspected",
        re.compile(
            b'(?i)(?:api[_-]?key|access[_-]?token|password|client[_-]?secret)\\s*[=:]\\s*["\\x27]?[A-Za-z0-9_./+~=-]{8,}'
        ),
    ),
]


def scan_file(path: str | Path, logical_name: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    tail = b""
    with Path(path).open("rb") as f:
        while data := f.read(1024 * 1024):
            chunk = tail + data
            for rule, severity, pattern in RULES:
                if pattern.search(chunk) and (not any(x["rule"] == rule for x in findings)):
                    findings.append(
                        {
                            "path": logical_name,
                            "rule": rule,
                            "severity": severity,
                            "disposition": "unresolved",
                        }
                    )
            tail = chunk[-4096:]
    return findings

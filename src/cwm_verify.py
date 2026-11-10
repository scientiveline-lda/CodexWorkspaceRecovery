"""Independent bounded verifier. No imports from restoration or acquisition adapters."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import unicodedata
import zipfile
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn

import jsonschema
import rfc8785

MAX_ARCHIVE = 100 * 1024**3
MAX_MEMBER = 16 * 1024**3
MAX_ENTRIES = 200000
MAX_CONTROL = 4 * 1024**2


class VerificationError(Exception):
    pass


def check(ok: Any, message: str) -> None:
    if not ok:
        raise VerificationError(message)


def pairs(items: Any) -> dict[str, Any]:
    d = {}
    for k, v in items:
        check(k not in d, "Duplicate JSON property")
        d[k] = v
    return d


def decode(raw: bytes | str) -> Any:

    def reject(v: Any) -> NoReturn:
        raise VerificationError("Invalid numeric constant")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=reject)


def hashfile(p: str | Path) -> str:
    with Path(p).open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def safe(name: str) -> str:
    check(isinstance(name, str) and 0 < len(name) <= 2048, "Invalid path")
    check(
        "\\" not in name and "\x00" not in name and (not name.startswith("/")), "Nonportable member"
    )
    ps = PurePosixPath(name).parts
    check("/".join(ps) == name, "Noncanonical path")
    for p in ps:
        check(
            p not in (".", "..")
            and (not p.endswith((".", " ")))
            and (not re.search('[<>:"|?*\\x00-\\x1f]', p)),
            "Unsafe path",
        )
        stem = p.split(".")[0].upper()
        check(
            stem not in {"CON", "PRN", "AUX", "NUL"} and (not re.fullmatch("(COM|LPT)[1-9]", stem)),
            "Reserved name",
        )
    return name


def record(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(k, str) for k in value):
        raise VerificationError("Expected string-keyed control object")
    return value


def read_tools(value: Any) -> dict[str, Any]:
    if not isinstance(value, (str, Path)):
        return record(value)
    base = Path(value).resolve().parent
    config = decode(Path(value).read_bytes())
    for spec in config.values():
        p = Path(spec["path"])
        if not p.is_absolute():
            spec["path"] = str(base / safe(p.as_posix()))
    return record(config)


def tool(config: dict[str, Any], name: str) -> str:
    s = config.get(name, {})
    p = Path(s.get("path", ""))
    check(p.is_absolute() and p.is_file(), "Explicit pinned executable required")
    for q in [p, *p.parents]:
        if q.exists():
            check(
                not q.is_symlink() and (not getattr(q.lstat(), "st_file_attributes", 0) & 1024),
                "Reparse tool path",
            )
    check(hashfile(p) == s.get("sha256"), "Executable hash mismatch")
    return str(p)


def command(argv: Sequence[str | Path], timeout: int = 3600) -> bytes:
    try:
        r = subprocess.run(argv, capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise VerificationError("Cryptographic tool failed") from e
    check(r.returncode == 0, "Cryptographic verification failed")
    return r.stdout


def system_tool(name: str) -> str:
    import ctypes

    check(name in ("powershell.exe", "icacls.exe", "whoami.exe"), "Unsupported system tool")
    buffer = ctypes.create_unicode_buffer(32768)
    check(
        ctypes.windll.kernel32.GetSystemDirectoryW(buffer, len(buffer)) > 0,
        "System directory unavailable",
    )
    base = Path(buffer.value)
    return str(
        base / ("WindowsPowerShell/v1.0/powershell.exe" if name == "powershell.exe" else name)
    )


def directory_bounds(path: Path) -> None:
    """Bound classic and ZIP64 central-directory allocation before ZipFile parses it."""
    import struct

    size = path.stat().st_size
    with path.open("rb") as stream:
        start = max(0, size - 65557)
        stream.seek(start)
        tail = stream.read(65557)
        off = tail.rfind(b"PK\x05\x06")
        check(off >= 0 and len(tail) - off >= 22, "Missing ZIP end record")
        end = struct.unpack_from("<4s4H2LH", tail, off)
        check(off + 22 + end[7] == len(tail), "Trailing or malformed ZIP data")
        check(end[1] == 0 and end[2] == 0 and end[3] == end[4], "Split ZIP unsupported")
        count, length, location = end[4], end[5], end[6]
        boundary = start + off
        if count == 65535 or length == 0xFFFFFFFF or location == 0xFFFFFFFF:
            check(boundary >= 20, "Missing ZIP64 locator")
            stream.seek(boundary - 20)
            loc = struct.unpack("<4sLQL", stream.read(20))
            check(loc[0] == b"PK\x06\x07" and loc[1] == 0 and loc[3] == 1, "Invalid ZIP64 locator")
            check(0 <= loc[2] <= boundary - 76, "ZIP64 end offset")
            stream.seek(loc[2])
            record = struct.unpack("<4sQ2H2L4Q", stream.read(56))
            check(
                record[0] == b"PK\x06\x06"
                and record[1] == 44
                and record[4] == 0
                and record[5] == 0
                and record[6] == record[7],
                "Unsupported ZIP64 end record",
            )
            check(loc[2] + 56 == boundary - 20, "ZIP64 record mismatch")
            count, length, location = record[7], record[8], record[9]
            boundary = loc[2]
        check(
            count <= MAX_ENTRIES and length <= 32 * 1024**2,
            "Central directory exceeds memory bound",
        )
        check(
            0 <= location <= boundary and location + length == boundary,
            "Central directory outside archive",
        )


def verify_zip(
    path: str | Path,
    trust: str | Path | dict[str, Any],
    tools: str | Path | dict[str, Any],
    work: str | Path,
    *,
    extract_to: str | Path | None = None,
) -> dict[str, Any]:
    trust = decode(Path(trust).read_bytes()) if isinstance(trust, (str, Path)) else trust
    tools = read_tools(tools)
    work = Path(work)
    work.mkdir(parents=True, exist_ok=False)
    check(Path(path).stat().st_size <= MAX_ARCHIVE, "Archive size limit")
    directory_bounds(Path(path))
    with zipfile.ZipFile(path) as z:
        infos = z.infolist()
        check(len(infos) <= MAX_ENTRIES, "Entry count limit")
        seen = set()
        normalized = set()
        total = 0
        for i in infos:
            safe(i.filename)
            check(i.filename not in seen, "Duplicate member")
            seen.add(i.filename)
            norm = unicodedata.normalize("NFKC", i.filename).casefold()
            check(norm not in normalized, "Case/Unicode member collision")
            normalized.add(norm)
            mode = i.external_attr >> 16
            check(
                not i.is_dir()
                and (not stat.S_ISLNK(mode))
                and (stat.S_IFMT(mode) in (0, stat.S_IFREG)),
                "Non-regular ZIP member",
            )
            check(not i.flag_bits & 1, "Nested ZIP encryption unsupported")
            check(0 <= i.file_size <= MAX_MEMBER, "Member size limit")
            check(i.file_size <= max(1, i.compress_size) * 1000, "Compression ratio limit")
            total += i.file_size
            check(total <= MAX_ARCHIVE, "Expanded archive size limit")
        check({"manifest.json", "manifest.minisig"} <= seen, "Missing control data")
        for n in ["manifest.json", "manifest.minisig"]:
            check(z.getinfo(n).file_size <= MAX_CONTROL, "Control data limit")
        raw = z.read("manifest.json")
        m = decode(raw)
        check(raw == rfc8785.dumps(m), "Manifest is not RFC8785 canonical")
        schema = decode((Path(__file__).parent / "cwm/schemas/manifest.json").read_bytes())
        jsonschema.validate(m, schema)
        now = datetime.now(UTC)
        check(trust.get("schema_version") == "1", "Unsupported trust policy")
        start = datetime.fromisoformat(trust["issued_at"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(trust["expires_at"].replace("Z", "+00:00"))
        check(
            start.tzinfo is not None and end.tzinfo is not None and (start <= now <= end),
            "Trust policy expired or not yet valid",
        )
        ks = [k for k in trust["keys"] if k["id"] == m["signing_key_id"]]
        check(len(ks) == 1 and ks[0]["status"] == "trusted", "Unknown/revoked signer")
        k = ks[0]
        check(
            m["producer"] in k["producers"] and m["scope"] in k["scopes"], "Signer scope mismatch"
        )
        (work / "manifest.json").write_bytes(raw)
        (work / "manifest.minisig").write_bytes(z.read("manifest.minisig"))
        command(
            [
                tool(tools, "minisign"),
                "-V",
                "-P",
                k["public_key"],
                "-m",
                str(work / "manifest.json"),
                "-x",
                str(work / "manifest.minisig"),
            ]
        )
        check(
            seen == set(m["payload"]) | {"manifest.json", "manifest.minisig"},
            "Undeclared or missing payload",
        )
        for name, e in m["payload"].items():
            safe(name)
            check(set(e) == {"sha256", "size"}, "Invalid entry descriptor")
            check(z.getinfo(name).file_size == e["size"], "Size mismatch")
            h = hashlib.sha256()
            actual = 0
            with z.open(name) as f:
                while b := f.read(1024**2):
                    actual += len(b)
                    check(actual <= e["size"], "Expanded member exceeds descriptor")
                    h.update(b)
            check(actual == e["size"] and h.hexdigest() == e["sha256"], "Content hash mismatch")
        if extract_to is not None:
            target = Path(extract_to)
            check(not target.exists(), "Extraction target exists")
            for p in [target.parent, *target.parent.parents]:
                if p.exists():
                    check(
                        not p.is_symlink()
                        and (not getattr(p.lstat(), "st_file_attributes", 0) & 1024),
                        "Reparse destination",
                    )
            import shutil

            existing = target.parent
            while not existing.exists():
                existing = existing.parent
            check(
                shutil.disk_usage(existing).free >= total + 2 * 1024**3,
                "Insufficient extraction capacity with safety reserve",
            )
            for name in ["manifest.json", "manifest.minisig", *m["payload"]]:
                check(
                    os.name != "nt" or len(str((target / safe(name)).absolute())) < 248,
                    "Windows path exceeds certified budget; choose a shorter recovery root",
                )
            target.mkdir(parents=True)
            for name in ["manifest.json", "manifest.minisig", *m["payload"]]:
                p = target / safe(name)
                p.parent.mkdir(parents=True, exist_ok=True)
                with z.open(name) as src, p.open("xb") as dst:
                    while b := src.read(1024**2):
                        dst.write(b)
        return {
            "status": "verified",
            "archive_id": m["archive_id"],
            "manifest_sha256": hashlib.sha256(raw).hexdigest(),
            "objects": len(m["payload"]),
            "bytes": total,
            "signing_key_id": m["signing_key_id"],
            "trust_policy_issued_at": trust["issued_at"],
            "semantic_completeness": "not_established_by_cryptographic_verifier",
        }


def verify(
    archive: str | Path,
    identity: str | Path,
    trust: str | Path | dict[str, Any],
    tools: str | Path | dict[str, Any],
    workspace: str | Path,
    *,
    extract_to: str | Path | None = None,
) -> dict[str, Any]:
    config = read_tools(tools)
    workspace = Path(workspace)
    check(not workspace.exists(), "Verification workspace exists")
    for ancestor in [workspace.parent, *workspace.parent.parents]:
        if ancestor.exists():
            check(
                not ancestor.is_symlink()
                and (not getattr(ancestor.lstat(), "st_file_attributes", 0) & 1024),
                "Reparse verification path",
            )
    workspace.mkdir(mode=448)
    if os.name == "nt":
        sid = (
            command([system_tool("whoami.exe"), "/user", "/fo", "csv", "/nh"])
            .decode()
            .split(",")[-1]
            .strip()
            .strip('"')
        )
        check(sid.startswith("S-1-"), "Cannot establish ACL identity")
        command(
            [
                system_tool("icacls.exe"),
                str(workspace),
                "/inheritance:r",
                "/grant:r",
                f"*{sid}:(OI)(CI)F",
                "*S-1-5-18:(OI)(CI)F",
            ]
        )
        acl_env = os.environ.copy()
        acl_env["CWM_ACL_PATH"], acl_env["CWM_ACL_SID"] = (str(workspace), sid)
        acl_script = "$ErrorActionPreference='Stop'; $d=[Security.AccessControl.DirectorySecurity]::new(); $d.SetAccessRuleProtection($true,$false); foreach($sid in @($env:CWM_ACL_SID,'S-1-5-18')){$r=[Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'); $d.AddAccessRule($r)}; [IO.Directory]::SetAccessControl($env:CWM_ACL_PATH,$d); $a=[IO.Directory]::GetAccessControl($env:CWM_ACL_PATH); if(-not $a.AreAccessRulesProtected){throw 'ACL inheritance'}; $rules=$a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]); foreach($r in $rules){if($r.AccessControlType -ne 'Allow' -or $r.IdentityReference.Value -notin @($env:CWM_ACL_SID,'S-1-5-18')){throw 'Unexpected ACL'}}; if($rules.Count -ne 2){throw 'Missing ACL'}; 'protected'"
        result = subprocess.run(
            [
                system_tool("powershell.exe"),
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                acl_script,
            ],
            env=acl_env,
            capture_output=True,
            timeout=30,
        )
        check(
            result.returncode == 0 and result.stdout.strip() == b"protected",
            "Effective staging ACL is not protected",
        )
    import shutil

    archive = Path(archive).resolve()
    check(
        shutil.disk_usage(workspace).free >= archive.stat().st_size + 2 * 1024**3,
        "Insufficient staging capacity with safety reserve",
    )
    check(archive.stat().st_size <= MAX_ARCHIVE, "Ciphertext size limit")
    inner = workspace / "archive.zip"
    command(
        [
            tool(config, "age"),
            "--decrypt",
            "-i",
            str(Path(identity).resolve()),
            "-o",
            str(inner),
            str(archive),
        ]
    )
    return verify_zip(inner, trust, config, workspace / "controls", extract_to=extract_to)


def main() -> int:
    p = argparse.ArgumentParser(
        prog="cwm-verify",
        description="Independent encrypted package integrity verifier; does not deploy projects",
    )
    p.add_argument("archive")
    p.add_argument("--keys", required=True)
    p.add_argument("--workspace", required=True)
    a = p.parse_args()
    try:
        root = Path(a.keys).resolve()
        # Independently resolve packaged tools; never import application adapters.
        package = Path(__file__).resolve().parent.parent
        tools = package / "vendor/toolchain.json"
        if not tools.is_file():
            tools = Path(__file__).resolve().parent.parent / "vendor/toolchain.json"
        print(
            json.dumps(
                verify(
                    a.archive, root / "identity.agekey", root / "trust.json", tools, a.workspace
                ),
                indent=2,
            )
        )
        return 0
    except Exception as e:
        print(
            json.dumps(
                {
                    "status": "failed",
                    "error_type": type(e).__name__,
                    "message": "Verification failed; no restoration performed",
                }
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

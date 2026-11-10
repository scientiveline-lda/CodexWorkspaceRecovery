"""Strict data and filesystem primitives. Never follows source reparse points."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import uuid
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn

import rfc8785


class RecoveryError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def require(condition: Any, code: str, message: str) -> None:
    if not condition:
        raise RecoveryError(code, message)


def now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out = {}
    for k, v in pairs:
        require(k not in out, "invalid_json", "Duplicate JSON property")
        out[k] = v
    return out


def loads(data: bytes | str) -> Any:

    def bad(_: Any) -> NoReturn:
        raise RecoveryError("invalid_json", "Non-finite JSON number")

    return json.loads(data, object_pairs_hook=unique_pairs, parse_constant=bad)


def load(path: str | Path) -> Any:
    return loads(Path(path).read_bytes())


def canonical(value: Any) -> bytes:
    try:
        return rfc8785.dumps(value)
    except (ValueError, TypeError) as e:
        raise RecoveryError("invalid_json", "Value cannot be represented canonically") from e


def digest(path: str | Path) -> str:
    with Path(path).open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def blob_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def key(value: Any) -> str:
    return blob_digest(str(value).encode())[:32]


def atomic_bytes(path: str | Path, data: bytes, *, replace: bool = False) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    require(replace or not path.exists(), "conflict", "Output already exists")
    temp = path.with_name("." + path.name + "." + uuid.uuid4().hex + ".partial")
    try:
        with temp.open("xb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if replace:
            os.replace(temp, path)
        else:
            os.link(temp, path)
            temp.unlink()
    finally:
        if temp.exists():
            temp.unlink()


def write_json(path: str | Path, value: Any, *, replace: bool = False) -> None:
    atomic_bytes(path, canonical(value), replace=replace)


def safe_relative(name: str) -> str:
    require(isinstance(name, str) and 0 < len(name) <= 2048, "unsafe_path", "Invalid member name")
    require(
        "\\" not in name and "\x00" not in name and (not name.startswith("/")),
        "unsafe_path",
        "Nonportable member path",
    )
    parts = PurePosixPath(name).parts
    require("/".join(parts) == name, "unsafe_path", "Noncanonical member path")
    for part in parts:
        require(
            part not in (".", "..") and (not part.endswith((".", " "))),
            "unsafe_path",
            "Unsafe path component",
        )
        require(
            not re.search('[<>:"|?*\\x00-\\x1f]', part), "unsafe_path", "Unsupported path character"
        )
        stem = part.split(".")[0].upper()
        require(
            stem not in {"CON", "PRN", "AUX", "NUL"} and (not re.fullmatch("(COM|LPT)[1-9]", stem)),
            "unsafe_path",
            "Reserved filename",
        )
    return name


def check_path_budget(path: str | Path) -> None:
    require(
        os.name != "nt" or len(str(Path(path).absolute())) < 248,
        "unsupported_filesystem",
        "Windows path exceeds the certified budget; use a shorter recovery root",
    )


def reparse(path: str | Path) -> bool:
    s = Path(path).lstat()
    return stat.S_ISLNK(s.st_mode) or bool(getattr(s, "st_file_attributes", 0) & 1024)


def within(path: str | Path, root: str | Path) -> bool:
    p, r = (Path(path).resolve(), Path(root).resolve())
    return p == r or r in p.parents


def no_reparse_chain(path: str | Path) -> None:
    p = Path(path).absolute()
    for a in [p, *p.parents]:
        if a.exists():
            require(not reparse(a), "unsafe_path", "Reparse point in destination path")


def walk_files(root: str | Path) -> Iterator[Path]:
    root = Path(root)
    require(root.is_dir() and (not reparse(root)), "unsafe_path", "Invalid source root")
    for base, dirs, files in os.walk(root, followlinks=False):
        for d in dirs:
            require(
                not reparse(Path(base) / d),
                "unsupported_filesystem",
                "Source contains a reparse directory",
            )
        for n in files:
            p = Path(base) / n
            require(not reparse(p), "unsupported_filesystem", "Source contains a link/reparse file")
            yield p


def run(
    argv: Sequence[str | Path],
    *,
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int = 120,
    input: bytes | None = None,
) -> bytes:
    try:
        p = subprocess.run(
            [str(a) for a in argv],
            cwd=cwd,
            env=env,
            input=input,
            capture_output=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        raise RecoveryError("tool_failed", "External tool unavailable or timed out") from e
    require(p.returncode == 0, "tool_failed", "External tool failed; sensitive stderr suppressed")
    return p.stdout


def payload_json(value: Any) -> bytes:
    """Historical payloads retain exact large integers; only control manifests use JCS."""
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def write_payload(path: str | Path, value: Any) -> None:
    atomic_bytes(path, payload_json(value))


@contextmanager
def exclusive_lock(path: str | Path) -> Iterator[None]:
    path = Path(path)
    no_reparse_chain(path.parent)
    try:
        handle = path.open("xb")
    except FileExistsError as e:
        raise RecoveryError(
            "operation_locked", "Output is locked by another or interrupted operation"
        ) from e
    try:
        handle.write(canonical({"pid": os.getpid(), "created_at": now()}))
        handle.flush()
        os.fsync(handle.fileno())
        yield
    finally:
        handle.close()
        path.unlink()


def require_space(
    path: str | Path, required_bytes: int, *, reserve_bytes: int = 2 * 1024**3
) -> None:
    import shutil

    path = Path(path).absolute()
    while not path.exists():
        path = path.parent
    require(
        shutil.disk_usage(path).free >= required_bytes + reserve_bytes,
        "insufficient_space",
        "Insufficient free space including the 2 GiB safety reserve",
    )


@contextmanager
def kernel_lock(path: str | Path) -> Iterator[None]:
    """Kernel-released operation lock; retained inode avoids stale-lock deletion races.

    Windows handles are exclusive. A killed owner releases the lock automatically.
    The small lock file is retained outside the recovery target as coordination state.
    """
    path = Path(path)
    no_reparse_chain(path)
    if os.name == "nt":
        import ctypes
        import msvcrt

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        kernel.CreateFileW.restype = ctypes.c_void_p
        handle = kernel.CreateFileW(str(path.absolute()), 1073741824, 0, None, 4, 128, None)
        require(
            handle != ctypes.c_void_p(-1).value,
            "operation_locked",
            "Another operation holds the recovery lock",
        )
        with os.fdopen(msvcrt.open_osfhandle(handle, os.O_WRONLY | os.O_BINARY), "wb") as stream:
            stream.write(canonical({"pid": os.getpid(), "created_at": now()}))
            stream.flush()
            yield
    else:
        raise RecoveryError("unsupported_platform", "Recovery kernel locks are Windows-only")


def as_record(value: Any) -> dict[str, Any]:
    """Narrow a dynamically decoded control object after checking its key domain."""
    if not isinstance(value, dict) or not all(isinstance(k, str) for k in value):
        raise RecoveryError("control_invalid", "Expected a string-keyed control object")
    return value

import json
import os
import sqlite3
import subprocess
from contextlib import closing
from pathlib import Path

from cwm.util import write_json

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "vendor/toolchain.json"
GIT = Path("C:\\Program Files\\Git\\cmd\\git.exe")


def rollout(
    home,
    ident="11111111-1111-4111-8111-111111111111",
    *,
    base=None,
    compressed=False,
    archived=False,
    text="Historical architecture decision: retain raw evidence.",
):
    import compression.zstd

    folder = home / ("archived_sessions" if archived else "sessions")
    folder.mkdir(parents=True, exist_ok=True)
    meta = {
        "id": ident,
        "session_id": ident,
        "timestamp": "2026-11-06T00:00:00Z",
        "cwd": str(home.parent / "project"),
        "originator": "cwm-synthetic-fixture",
        "cli_version": "synthetic",
        "source": "cli",
        "model_provider": "cwm_lab",
        "history_mode": "paginated",
    }
    if base:
        meta["history_base"] = base
    records = [
        {"timestamp": "2026-11-06T00:00:00Z", "type": "session_meta", "payload": meta},
        {
            "timestamp": "2026-11-06T00:00:01Z",
            "type": "response_item",
            "payload": {
                "type": "message",
                "role": "user",
                "content": [{"type": "input_text", "text": text}],
            },
        },
    ]
    data = b"".join(json.dumps(r).encode() + b"\n" for r in records)
    p = folder / (ident + ".jsonl" + (".zst" if compressed else ""))
    p.write_bytes(compression.zstd.compress(data) if compressed else data)
    return (p, data)


def fixture(parent, *, project=True):
    (parent / ".cwm-synthetic-fixture").write_text(
        "Synthetic disposable fixture only", encoding="utf-8"
    )
    home = parent / "source-home"
    home.mkdir()
    ident = "11111111-1111-4111-8111-111111111111"
    rollout(home, ident)
    (home / "attachments" / ident).mkdir(parents=True)
    (home / "attachments" / ident / "diagram.txt").write_text("Synthetic attachment")
    (home / "auth.json").write_text('{"access_token":"NEVER_COPY_FIXTURE"}')
    with closing(sqlite3.connect(home / "state_5.sqlite")) as c:
        c.executescript(
            "CREATE TABLE threads(id TEXT, project_id TEXT, title TEXT); CREATE TABLE projects(id TEXT,name TEXT); CREATE TABLE project_roots(project_id TEXT,path TEXT);"
        )
        c.execute("INSERT INTO threads VALUES(?,?,?)", (ident, "p1", "Synthetic thread"))
        c.execute("INSERT INTO projects VALUES(?,?)", ("p1", "Synthetic project"))
        c.execute("INSERT INTO project_roots VALUES(?,?)", ("p1", str(parent / "project")))
        c.commit()
    p = parent / "project"
    if project:
        p.mkdir()
        git(p, "init")
        git(p, "config", "user.email", "fixture@example.invalid")
        git(p, "config", "user.name", "Fixture")
        (p / "tracked.txt").write_bytes(b"base\n")
        (p / ".gitignore").write_text("ignored.txt\n")
        git(p, "add", ".")
        git(p, "commit", "-m", "Synthetic baseline")
        (p / "tracked.txt").write_bytes(b"staged\n")
        git(p, "add", "tracked.txt")
        (p / "tracked.txt").write_bytes(b"unstaged\n")
        (p / "untracked.bin").write_bytes(bytes(range(256)))
        (p / "ignored.txt").write_text("Local ignored fixture")
        (p / "AGENTS.md").write_text("Synthetic project instruction; do not execute imports.")
    return (home, p, ident)


def git(p, *args):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_OPTIONAL_LOCKS": "0",
        }
    )
    r = subprocess.run(
        [
            str(GIT),
            "--no-optional-locks",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=NUL",
            "-c",
            "core.autocrlf=false",
            "-c",
            "core.longpaths=true",
            "-c",
            "init.defaultBranch=main",
            "-C",
            str(p),
            *args,
        ],
        capture_output=True,
        env=env,
    )
    if r.returncode:
        raise RuntimeError(r.stderr.decode(errors="replace"))
    return r.stdout


def keys(parent):
    t = json.loads(TOOLS.read_text())
    agekey = Path(t["age"]["path"]).with_name("age-keygen.exe")
    recipients = []
    for n in ["operator", "recovery"]:
        secret = parent / (n + ".agekey")
        subprocess.run([str(agekey), "-o", str(secret)], check=True, capture_output=True)
        pub = (
            subprocess.run([str(agekey), "-y", str(secret)], check=True, capture_output=True)
            .stdout.decode()
            .strip()
        )
        recipients.append(pub)
    secret = parent / "signing.key"
    public = parent / "signing.pub"
    subprocess.run(
        [t["minisign"]["path"], "-G", "-W", "-s", str(secret), "-p", str(public)],
        check=True,
        capture_output=True,
    )
    pub = public.read_text().splitlines()[-1]
    trust = {
        "schema_version": "1",
        "issued_at": "2020-01-01T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "keys": [
            {
                "id": "fixture-signer",
                "status": "trusted",
                "public_key": pub,
                "producers": ["cwm-fixture"],
                "scopes": ["synthetic"],
            }
        ],
    }
    write_json(parent / "trust.json", trust)
    import shutil

    shutil.copyfile(parent / "operator.agekey", parent / "identity.agekey")
    write_json(
        parent / "profile.json",
        {
            "schema_version": 1,
            "key_id": "fixture-signer",
            "producer": "cwm-fixture",
            "scope": "synthetic",
            "recipients": recipients,
        },
    )
    return {
        "recipients": recipients,
        "identity": parent / "operator.agekey",
        "signing_key": secret,
        "trust": parent / "trust.json",
        "tools": TOOLS,
    }

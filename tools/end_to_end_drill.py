"""Packaged public CLI round trips with an independent pre-export synthetic oracle."""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import independent_oracle as oracle
from performance_metrics import Sampler

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tests.helpers import fixture, rollout


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--package", type=Path, required=True)
    p.add_argument("--workspace", type=Path, required=True)
    a = p.parse_args()
    package = a.package.resolve()
    work = a.workspace.resolve()
    if work.exists() or work.is_relative_to(ROOT) or ROOT.is_relative_to(work):
        raise ValueError("New independent evidence root required")
    work.mkdir()
    calls = []
    runs = []
    runtime = package / "runtime/python.exe"
    git = package / "vendor/git/cmd/git.exe"
    # Every normal public operation runs under a Python network-denial audit hook.
    # This is process-level denial, not an OS firewall certification.
    wrapper = """import sys,runpy,pathlib,os
package=pathlib.Path(sys.executable).resolve().parent.parent
system=pathlib.Path(os.environ['SystemRoot']).resolve()
def audit(event,args):
 if event.startswith(('socket.','urllib.','http.client.')): raise RuntimeError('Network use forbidden during recovery')
 if event=='subprocess.Popen':
  command=args[0]
  if command is None:
   import ctypes
   count=ctypes.c_int()
   parse=ctypes.windll.shell32.CommandLineToArgvW
   parse.argtypes=[ctypes.c_wchar_p,ctypes.POINTER(ctypes.c_int)]
   parse.restype=ctypes.POINTER(ctypes.c_wchar_p)
   values=parse(args[1],ctypes.byref(count))
   if not values or count.value==0:raise RuntimeError('Cannot establish child executable')
   command=values[0]
   ctypes.windll.kernel32.LocalFree.argtypes=[ctypes.c_void_p]
   ctypes.windll.kernel32.LocalFree(values)
  executable=pathlib.Path(command).resolve()
  if not executable.is_relative_to(package) and not executable.is_relative_to(system): raise RuntimeError('External developer tool forbidden')
sys.addaudithook(audit)
sys.argv=[sys.argv[1],*sys.argv[2:]]
try: runpy.run_module('cwm_verify' if sys.argv[0]=='cwm-verify' else 'cwm',run_name='__main__')
finally:
 for name,module in list(sys.modules.items()):
  if name.split('.')[0] in {'cwm','cwm_verify','jsonschema','rfc8785','attrs','attr','referencing','rpds'}:
   file=getattr(module,'__file__',None)
   if file and not pathlib.Path(file).resolve().is_relative_to(package/'app'):raise RuntimeError('Host import detected')
"""
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("PYTHON", "GIT_", "CODEX_", "CWM_"))
    }
    env["PATH"] = str(Path(os.environ["SystemRoot"]) / "System32")
    env["PYTHONNOUSERSITE"] = "1"

    default_code = 0

    def cli(*args, code=None, module="cwm"):
        expected_code = default_code if code is None else code
        start = time.monotonic()
        result = subprocess.run(
            [str(runtime), "-I", "-B", "-c", wrapper, module, *map(str, args)],
            cwd=work,
            env=env,
            capture_output=True,
            timeout=1800,
        )
        index = len(calls)
        (work / (str(index) + ".log")).write_bytes(result.stdout + result.stderr)
        value = json.loads(result.stdout) if result.stdout else {}
        calls.append(
            {
                "command": list(map(str, args[:2])),
                "exit_code": result.returncode,
                "seconds": round(time.monotonic() - start, 3),
            }
        )
        if result.returncode != expected_code:
            raise RuntimeError("Packaged CLI unexpected outcome at call " + str(index))
        return value

    sampler = Sampler(work, interval=2.0)
    sampler.__enter__()
    cli("doctor")
    # CMD and PowerShell entry points are checked independently of the audit wrapper.
    for launcher in ["cwm.cmd", "cwm-verify.cmd"]:
        if launcher == "cwm.cmd":
            args = [str(package / "bin" / launcher), "--help"]
        else:
            args = [str(package / "bin" / launcher), "--help"]
        result = subprocess.run(
            [str(Path(os.environ["SystemRoot"]) / "System32/cmd.exe"), "/d", "/c", *args],
            cwd=work,
            env=env,
            capture_output=True,
        )
        if result.returncode:
            raise RuntimeError("CMD launcher failed")
    cli("keys", "init", "--output", work / "keys")
    cli("keys", "export-recovery", "--keys", work / "keys", "--output", work / "recovery-keys")
    if (work / "recovery-keys/signing.key").exists():
        raise RuntimeError("Signing private key leaked")
    for number in range(3):
        start = time.monotonic()
        root = work / str(number)
        root.mkdir()
        home, project, ident = fixture(root)
        (project / "empty-directory/nested").mkdir(parents=True)
        (project / "empty-file").write_bytes(b"")
        (project / "opaque.db").write_bytes(b"Opaque project database-named bytes")
        (home / "attachments" / ident / "opaque.db").write_bytes(
            b"Opaque attachment database-named bytes"
        )
        (project / "Unicode-\u03bb.txt").write_text("Synthetic Unicode \u03bb", encoding="utf-8")
        # These data are independent of the application archive/restore implementation.
        if number == 0:
            with (project / "scale.bin").open("wb") as f:
                for _ in range(128):
                    f.write(os.urandom(1024**2))
            for n in range(1, 685):
                rollout(
                    home,
                    f"{n:08x}-2222-4222-8222-{n:012x}",
                    compressed=n % 2 == 0,
                    archived=n % 3 == 0,
                )
        rows = [
            json.loads(line)
            for line in next((home / "sessions").glob("*.jsonl")).read_text().splitlines()
        ]
        rows[-1]["payload"]["content"].append(
            {"type": "input_file", "path": str(home / "attachments" / ident / "diagram.txt")}
        )
        next((home / "sessions").glob("*.jsonl")).write_text(
            "".join(json.dumps(row) + "\n" for row in rows)
        )
        default_code = 4 if number == 2 else 0
        if number == 2:
            path = next((home / "sessions").glob("*.jsonl"))
            extra = [json.loads(line) for line in path.read_text().splitlines()]
            extra[-1]["payload"]["content"].append(
                {"type": "input_file", "path": str(home / "attachments/missing.bin")}
            )
            path.write_text("".join(json.dumps(row) + "\n" for row in extra))
        expected = oracle.expected(home, [project], git)
        expected["expected_missing_references"] = (
            [str(home / "attachments/missing.bin")] if number == 2 else []
        )
        (root / "expected.json").write_text(json.dumps(expected), encoding="utf-8")

        def all_bytes(base):
            return {
                p.relative_to(base).as_posix(): oracle.sha(p)
                for p in base.rglob("*")
                if p.is_file()
            }

        source = {"home": all_bytes(home), "project": all_bytes(project)}
        sentinel = root / "unrelated"
        sentinel.mkdir()
        (sentinel / "retain.txt").write_text("Unrelated state")
        cli(
            "export",
            "--home",
            home,
            "--project",
            project,
            "--source-closed",
            "--keys",
            work / "keys",
            "--workspace",
            root / "e",
            "--output",
            root / "archive.age",
            *(["--thread", ident, "--thread", ident] if number == 1 else []),
        )
        cli(
            str(root / "archive.age"),
            "--keys",
            work / "recovery-keys",
            "--workspace",
            root / "independent",
            module="cwm-verify",
            code=0,
        )
        bad = bytearray((root / "archive.age").read_bytes())
        bad[len(bad) // 2] ^= 1
        (root / "corrupt.age").write_bytes(bad)
        cli(
            "verify",
            root / "corrupt.age",
            "--keys",
            work / "recovery-keys",
            "--workspace",
            root / "bad",
            code=2,
        )
        cli(
            "verify",
            root / "archive.age",
            "--keys",
            work / "recovery-keys",
            "--workspace",
            root / "v",
        )
        planned = cli(
            "import",
            "plan",
            root / "archive.age",
            "--keys",
            work / "recovery-keys",
            "--target",
            root / "destination",
            "--workspace",
            root / "p",
        )
        plan = root / "p/restore-plan.json"
        cli("import", "apply", plan)
        cli("import", "verify", plan)
        oracle.verify(expected, root / "destination/evidence", list(expected["sessions"]))
        for state in expected["projects"]:
            oracle.compare_project(
                state, planned["mappings"][state["source"]], git, excluded=["ignored.txt"]
            )
        # Deliberate omissions and substitutions must be detected by the external oracle.
        dst = Path(next(iter(planned["mappings"].values())))
        victim = dst / "empty-file"
        victim.unlink()
        try:
            oracle.compare_project(expected["projects"][0], dst, git, excluded=["ignored.txt"])
        except ValueError:
            pass
        else:
            raise RuntimeError("Oracle accepted omission")
        victim.write_bytes(b"substitution")
        try:
            oracle.compare_project(expected["projects"][0], dst, git, excluded=["ignored.txt"])
        except ValueError:
            pass
        else:
            raise RuntimeError("Oracle accepted substitution")
        victim.write_bytes(b"")
        cli("import", "apply", plan)
        cli(
            "import",
            "plan",
            root / "archive.age",
            "--keys",
            work / "recovery-keys",
            "--target",
            root / "destination",
            "--workspace",
            root / "collision",
            code=2,
        )
        (root / "destination/later-work.txt").write_text("Later work")
        cli("import", "verify", plan, code=5)
        cli("recover", "rollback", plan, code=2)
        if (root / "destination/later-work.txt").read_text() != "Later work":
            raise RuntimeError("Later work lost")
        (root / "destination/later-work.txt").unlink()
        cli("recover", "rollback", plan, code=0)
        if source != {"home": all_bytes(home), "project": all_bytes(project)} or oracle.tree(
            sentinel
        ) != {"retain.txt": hashlib.sha256(b"Unrelated state").hexdigest()}:
            raise RuntimeError("Source/unrelated mutation")
        runs.append(
            {
                "status": "passed",
                "sessions": len(expected["sessions"]),
                "seconds": round(time.monotonic() - start, 3),
                "archive_sha256": oracle.sha(root / "archive.age"),
                "source_unchanged": True,
                "content_result": "with_explicit_missing_attachment"
                if number == 2
                else "complete_selected_content",
                "independent_comparison": "passed",
                "omission_substitution_detection": "passed",
            }
        )
        (work / "acceptance.json").write_text(
            json.dumps(
                {
                    "status": "passed" if len(runs) == 3 else "running",
                    "runs": runs,
                    "calls": calls,
                    "network_denial": "Python audit hook; package/system subprocess allowlist",
                    "clean_os_certification": False,
                },
                indent=2,
            )
        )
    sampler.__exit__()
    report = json.loads((work / "acceptance.json").read_text())
    report["metrics"] = sampler.values
    (work / "acceptance.json").write_text(json.dumps(report, indent=2))
    print(json.dumps({"status": "passed", "runs": runs, "public_cli_calls": len(calls)}))


if __name__ == "__main__":
    main()

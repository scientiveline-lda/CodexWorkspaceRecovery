"""Candidate-content quality checks. Never commits, uploads evidence or publishes."""

import argparse
import ast
import hashlib
import importlib.metadata
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def architecture() -> dict[str, Any]:
    issues = []
    graph = {}
    for path in (ROOT / "src").rglob("*.py"):
        module = ".".join(path.relative_to(ROOT / "src").with_suffix("").parts)
        edges = set()
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
                if node.level:
                    edges.add("cwm." + (node.module or ""))
            else:
                continue
            if any(name.split(".")[0] in ("tests", "tools", "packaging") for name in names):
                issues.append(module + ": forbidden development dependency")
            if module == "cwm_verify" and any(
                name == "cwm" or name.startswith("cwm.") for name in names
            ):
                issues.append("Standalone verifier imports application adapter")
        graph[module] = sorted(edges)

    def visit(node: str, stack: tuple[str, ...]) -> None:
        if node in stack:
            issues.append("Dependency cycle: " + " -> ".join((*stack, node)))
            return
        for child in graph.get(node, []):
            visit(child, (*stack, node))

    for module_name in graph:
        visit(module_name, ())
    return {"status": "failed" if issues else "passed", "issues": issues, "graph": graph}


def run(workspace: Path, dependency_audit: Path | None = None) -> dict[str, Any]:
    from cwm.security import protect_directory
    from cwm.util import no_reparse_chain

    workspace = workspace.resolve()
    if workspace.is_relative_to(ROOT) or ROOT.is_relative_to(workspace):
        raise ValueError("Engineering evidence must be outside source")
    no_reparse_chain(workspace)
    protect_directory(workspace)
    results = {"architecture": architecture()}
    commands = {
        "lint": ["ruff", "check", "--no-cache", "src", "tests", "tools", "packaging", "setup.py"],
        "format": [
            "ruff",
            "format",
            "--check",
            "--no-cache",
            "src",
            "tests",
            "tools",
            "packaging",
            "setup.py",
        ],
        "types": [
            "mypy",
            "--strict",
            "--cache-dir",
            str(workspace / "type-cache"),
            "src",
            "tools/engineering_gate.py",
            "tools/docs_check.py",
            "tools/mutation_check.py",
        ],
        "security": [
            "bandit",
            "-r",
            "src",
            "-f",
            "json",
            "-o",
            str(workspace / "bandit.json"),
            "-q",
        ],
        "docs": ["mkdocs", "build", "--strict", "--site-dir", str(workspace / "site")],
        "documentation_contracts": ["tools/docs_check.py"],
        "coverage": [
            "coverage",
            "run",
            "--branch",
            "--source=src",
            "tools/test_report.py",
            "--output",
            str(workspace / "tests.json"),
        ],
        "coverage_report": ["coverage", "json", "-o", str(workspace / "coverage.json")],
        "mutations": ["tools/mutation_check.py", "--workspace", str(workspace / "mutations")],
    }
    env = os.environ.copy()
    env["COVERAGE_FILE"] = str(workspace / ".coverage")
    for name, args in commands.items():
        try:
            command = (
                [sys.executable, "-B", *args]
                if args[0].endswith(".py")
                else [sys.executable, "-B", "-m", *args]
            )
            child = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, timeout=1800)
            (workspace / (name + ".log")).write_bytes(child.stdout + child.stderr)
            status = "passed" if child.returncode == 0 else "failed"
            if name == "security" and (workspace / "bandit.json").exists():
                report = json.loads((workspace / "bandit.json").read_bytes())
                status = (
                    "failed"
                    if report["errors"]
                    or any(f["issue_severity"] in ("MEDIUM", "HIGH") for f in report["results"])
                    else "passed"
                )
            results[name] = {"status": status, "exit_code": child.returncode}
        except (OSError, subprocess.TimeoutExpired) as exc:
            results[name] = {"status": "blocked", "reason": type(exc).__name__}
    if dependency_audit:
        audit = json.loads(dependency_audit.read_bytes())
        fresh = datetime.now(UTC) - datetime.fromisoformat(audit["checked_at"])
        expected = sha(ROOT / "requirements-win-py314.lock")
        raw_path = Path(audit.get("raw_path", ""))
        if not raw_path.is_file() or sha(raw_path) != audit.get("raw_sha256"):
            raise ValueError("Dependency scanner raw evidence missing or changed")
        raw = json.loads(raw_path.read_bytes())
        actual_findings = [finding for dep in raw["dependencies"] for finding in dep["vulns"]]
        if actual_findings != audit.get("vulnerabilities"):
            raise ValueError("Dependency summary differs from scanner evidence")
        (workspace / "dependency-audit-raw.json").write_bytes(raw_path.read_bytes())
        (workspace / "dependency-audit.json").write_bytes(dependency_audit.read_bytes())
        results["dependencies"] = {
            "status": "passed"
            if audit.get("lock_sha256") == expected
            and 0 <= fresh.total_seconds() <= 7 * 86400
            and not audit.get("vulnerabilities")
            else "failed",
            "evidence_sha256": sha(dependency_audit),
        }
    else:
        results["dependencies"] = {
            "status": "blocked",
            "reason": "Fresh lock-bound vulnerability evidence required",
        }
    matrix = json.loads((ROOT / "tests/safety-invariants.json").read_bytes())["invariants"]
    tested = (
        json.loads((workspace / "tests.json").read_bytes())
        if (workspace / "tests.json").exists()
        else {}
    )
    passed_cases = {case["test"] for case in tested.get("cases", []) if case["status"] == "passed"}
    missing = {
        name: sorted(set(cases) - passed_cases)
        for name, cases in matrix.items()
        if set(cases) - passed_cases
    }
    results["critical_path_review"] = {
        "status": "passed" if not missing and (workspace / "coverage.json").is_file() else "failed",
        "missing_outcomes": missing,
        "basis": "Explicit safety outcomes, branch evidence and required tests; final human review separate",
    }
    value = {
        "status": "passed" if all(x["status"] == "passed" for x in results.values()) else "failed",
        "checked_at": datetime.now(UTC).isoformat(),
        "checks": results,
        "source": {
            str(p.relative_to(ROOT)): sha(p)
            for p in sorted((ROOT / "src").rglob("*"))
            if p.is_file() and p.suffix in (".py", ".json")
        },
        "tools": {
            name: importlib.metadata.version(name)
            for name in ("ruff", "mypy", "bandit", "coverage", "mkdocs", "pip-audit")
        },
    }
    (workspace / "engineering.json").write_text(json.dumps(value, indent=2), encoding="utf-8")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--dependency-audit", type=Path)
    args = parser.parse_args()
    report = run(args.workspace, args.dependency_audit)
    print(json.dumps({"status": report["status"], "checks": report["checks"]}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())

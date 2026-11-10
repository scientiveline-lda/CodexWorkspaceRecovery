"""Focused safety mutations in disposable application copies; never edits checkout."""

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MUTATIONS = [
    (
        "trust_expiry",
        "cwm/security.py",
        "start <= current <= end",
        "True",
        "tests.test_closure.PolicyTests.test_offset_expiry_is_compared_as_instant",
    ),
    (
        "project_containment",
        "cwm/verification.py",
        'part.casefold() == ".git"',
        "False",
        "tests.test_closure.ClosureTests.test_signed_git_administration_file_rejected",
    ),
    (
        "gap_exit",
        "cwm/cli.py",
        'return 4 if completeness.get("has_recovery_gaps") else 0',
        "return 0",
        "tests.test_closure.PolicyTests.test_result_exit_contract",
    ),
    (
        "rollback_baseline",
        "cwm/restore.py",
        'and baseline.get("files") == tree_hashes(target)',
        "and True",
        "tests.test_closure.ClosureTests.test_changed_metadata_and_forged_marker_do_not_redefine_baseline",
    ),
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    args = parser.parse_args()
    root = args.workspace.resolve()
    if root.exists() or root.is_relative_to(ROOT) or ROOT.is_relative_to(root):
        raise ValueError("Mutations require a new private directory outside checkout")
    from cwm.security import protect_directory

    protect_directory(root)
    outcomes = []
    for ident, module, before, after, test in MUTATIONS:
        source = root / ident
        shutil.copytree(ROOT / "src", source, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        path = source / module
        text = path.read_text(encoding="utf-8")
        if before not in text:
            raise ValueError("Mutation anchor stale: " + ident)
        # Rollback's final occurrence is separate from verification's condition.
        index = text.rfind(before) if ident == "rollback_baseline" else text.index(before)
        path.write_text(text[:index] + text[index:].replace(before, after, 1), encoding="utf-8")
        script = "import sys,unittest;sys.path.insert(0,sys.argv[1]);sys.path.insert(1,sys.argv[2]);import cwm;assert cwm.__file__.startswith(sys.argv[1]);s=unittest.defaultTestLoader.loadTestsFromName(sys.argv[3]);r=unittest.TextTestRunner().run(s);sys.exit(0 if r.wasSuccessful() else 1)"
        child = subprocess.run(
            [sys.executable, "-B", "-c", script, str(source), str(ROOT), test],
            cwd=root,
            capture_output=True,
            timeout=180,
        )
        (root / (ident + ".log")).write_bytes(child.stdout + child.stderr)
        # An import/setup error is not evidence that the intended assertion killed a mutation.
        text_output = (child.stdout + child.stderr).decode(errors="replace")
        killed = child.returncode == 1 and "FAIL:" in text_output and "ERROR:" not in text_output
        outcomes.append(
            {"mutation": ident, "test": test, "status": "passed" if killed else "failed"}
        )
    report = {
        "status": "passed" if all(x["status"] == "passed" for x in outcomes) else "failed",
        "outcomes": outcomes,
    }
    (root / "mutations.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())

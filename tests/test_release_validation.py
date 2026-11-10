import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cwm.capture import ReadGuard, capture
from cwm.preservation import preserve
from cwm.projects import Git, compare, restore_project
from cwm.util import RecoveryError
from tests.helpers import GIT, fixture, git

ROOT = Path(__file__).resolve().parents[1]


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / (name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


class ReleaseValidationTests(unittest.TestCase):
    def test_release_runner_rejects_skips_and_unexpected_success(self):
        runner = module("test_report")

        class Skipped(unittest.TestCase):
            @unittest.skip("synthetic missing dependency")
            def test_skip(self):
                pass

        suite = unittest.defaultTestLoader.loadTestsFromTestCase(Skipped)
        ids = runner.test_ids(suite)
        result = unittest.TextTestRunner(stream=io.StringIO()).run(suite)
        self.assertFalse(runner.release_success(result, ids, ids))
        result.skipped = []
        result.unexpectedSuccesses = ["synthetic"]
        self.assertFalse(runner.release_success(result, ids, ids))
        self.assertFalse(runner.release_success(result, ids + ["missing"], ids))

    def test_capture_detects_added_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home, _, _ = fixture(root, project=False)
            original = ReadGuard.copy

            def changed(guard, destination):
                original(guard, destination)
                (home / "sessions/created-during-capture.jsonl").write_text("synthetic")

            with patch.object(ReadGuard, "copy", changed), self.assertRaises(RecoveryError):
                capture(home, home, root / "capture", maintenance=True)
            report = json.loads((root / "capture/capture.json").read_text())
            self.assertEqual(report["classification"], "capture_failed")

    def test_independent_oracle_detects_omission_and_substitution(self):
        oracle = module("independent_oracle")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home, project, ident = fixture(root)
            expected = oracle.expected(home, [project], GIT)
            capture(home, home, root / "capture", projects=[project], maintenance=True)
            preserve(root / "capture", root / "payload", git_exe=GIT)
            payload = root / "payload"
            self.assertEqual(oracle.verify(expected, payload, [ident])["status"], "passed")
            state = json.loads((payload / "inventory/projects.json").read_text())[0]
            restore_project(state, payload, root / "destination", Git(GIT))
            oracle.compare_project(
                expected["projects"][0], root / "destination", GIT, excluded=["ignored.txt"]
            )
            (root / "destination/unexpected.txt").write_text("synthetic omission canary")
            with self.assertRaises(ValueError):
                oracle.compare_project(
                    expected["projects"][0], root / "destination", GIT, excluded=["ignored.txt"]
                )
            self.assertEqual(compare(state, root / "destination", Git(GIT))["status"], "failed")
            catalog = payload / "inventory/rollouts.json"
            original = catalog.read_bytes()
            catalog.write_text('{"sessions":[]}')
            with self.assertRaises(ValueError):
                oracle.verify(expected, payload, [ident])
            catalog.write_bytes(original)
            session = json.loads(catalog.read_text())["sessions"][0]
            (payload / session["object"]).write_bytes(b"substituted")
            with self.assertRaises(ValueError):
                oracle.verify(expected, payload, [ident])

    def test_split_index_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home, project, _ = fixture(root)
            git(project, "update-index", "--split-index")
            capture(home, home, root / "capture", projects=[project], maintenance=True)
            with self.assertRaises(RecoveryError):
                preserve(root / "capture", root / "payload", git_exe=GIT)

    def test_cli_rejects_unknown_filter(self):
        import subprocess
        import sys

        result = subprocess.run(
            [sys.executable, "-B", "-m", "cwm", "export", "--unknown-filter"], capture_output=True
        )
        self.assertNotEqual(result.returncode, 0)

    def test_cli_doctor_subprocess(self):
        import subprocess
        import sys

        result = subprocess.run(
            [sys.executable, "-B", "-m", "cwm", "doctor"], capture_output=True, check=True
        )
        self.assertEqual(json.loads(result.stdout)["zstandard"], "round_trip_verified")

    def test_external_git_admin_overlap_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home, project, _ = fixture(root)
            linked = root / "linked"
            git(project, "worktree", "add", str(linked), "-b", "linked")
            from cwm.capture import git_layout

            admin, _ = git_layout(linked)
            output = admin / "capture-must-not-exist"
            with self.assertRaises(RecoveryError):
                capture(home, home, output, projects=[linked], maintenance=True)
            self.assertFalse(output.exists())

    def test_plain_db_is_captured(self):
        import sqlite3
        from contextlib import closing

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home, _, _ = fixture(root, project=False)
            with closing(sqlite3.connect(home / "additional.db")) as db:
                db.execute("CREATE TABLE synthetic(value TEXT)")
                db.commit()
            report = capture(home, home, root / "capture", maintenance=True)
            self.assertTrue(
                any(e["path"].endswith("additional.db") for e in report["database_files"])
            )

    def test_semantic_duplicate_catalog_refused(self):
        from cwm.verification import semantic

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home, _, _ = fixture(root, project=False)
            capture(home, home, root / "capture", maintenance=True)
            preserve(root / "capture", root / "payload")
            p = root / "payload/inventory/rollouts.json"
            value = json.loads(p.read_text())
            value["sessions"].append(value["sessions"][0])
            p.write_text(json.dumps(value))
            with self.assertRaises(RecoveryError):
                semantic(root / "payload")

    @unittest.skipUnless(__import__("os").name == "nt", "Windows process metrics")
    def test_performance_sampler_reads_current_process(self):
        metrics = module("performance_metrics")
        memory, missing = metrics.working_set_tree()
        self.assertGreater(memory, 0)
        self.assertIsInstance(missing, list)

    @unittest.skipUnless(__import__("os").name == "nt", "Windows path budget")
    def test_windows_long_path_is_explicitly_refused(self):
        from cwm.util import check_path_budget

        with self.assertRaises(RecoveryError) as error:
            check_path_budget(Path("C:/") / ("long/" * 60) / "file.txt")
        self.assertEqual(error.exception.code, "unsupported_filesystem")

    def test_report_rejects_tampered_evidence(self):
        from types import SimpleNamespace

        validator = module("validate_release")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "baseline-evidence"
            evidence.mkdir()
            record = evidence / "record.txt"
            record.write_text("original synthetic evidence")
            candidate = root / "candidate.json"
            candidate.write_text('{"source":{"sha256":"synthetic-source"}}')
            phase = {
                "status": "passed",
                "candidate_sha256": validator.sha(candidate),
                "source_sha256": "synthetic-source",
                "evidence_root": str(evidence),
                "evidence": {"record.txt": {"sha256": validator.sha(record)}},
            }
            (root / "baseline.json").write_text(json.dumps(phase))
            record.write_text("modified synthetic evidence")
            args = SimpleNamespace(workspace=root, candidate=candidate)
            with patch.object(
                validator, "candidate_state", return_value={"sha256": "synthetic-source"}
            ):
                result = validator.report(args, root)
            self.assertEqual(result["gates"]["baseline"]["status"], "failed")
            self.assertEqual(
                result["gates"]["baseline"]["reason"], "Recorded evidence missing or changed"
            )
            self.assertEqual(result["decision"], "no-go")

    def test_nested_sqlite_home_is_not_duplicated(self):
        import shutil

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home, _, _ = fixture(root, project=False)
            sqlite_home = home / "sqlite"
            sqlite_home.mkdir()
            shutil.move(str(home / "state_5.sqlite"), str(sqlite_home / "state_5.sqlite"))
            report = capture(home, sqlite_home, root / "capture", maintenance=True)
            self.assertEqual(len(report["database_files"]), 1)
            self.assertEqual(len({e["source"] for e in report["files"]}), len(report["files"]))

    def test_independent_oracle_handles_compressed_ancestor_closure(self):
        from tests.helpers import rollout

        oracle = module("independent_oracle")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home, project, parent = fixture(root)
            original_path = next((home / "sessions").glob("*.jsonl"))
            boundary = original_path.stat().st_size
            original_path.write_bytes(
                original_path.read_bytes()
                + b'{"type":"future_event","payload":{"message":"excluded from child"}}\n'
            )
            child = "22222222-2222-4222-8222-222222222222"
            rollout(
                home,
                child,
                compressed=True,
                archived=True,
                base={"thread_id": parent, "end_byte_offset": boundary, "end_ordinal_exclusive": 2},
            )
            expected = oracle.expected(home, [project], GIT)
            capture(home, home, root / "capture", projects=[project], maintenance=True)
            preserve(root / "capture", root / "payload", git_exe=GIT)
            self.assertEqual(
                oracle.verify(expected, root / "payload", [parent, child])["status"], "passed"
            )
            self.assertEqual(len(expected["sessions"][child]["logical"]), 4)

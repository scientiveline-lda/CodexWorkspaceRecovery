"""Regression evidence for the production-readiness audit findings; synthetic only."""

import contextlib
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from cwm.archive import export
from cwm.capture import capture
from cwm.cli import main
from cwm.restore import apply, plan, rollback, tree_hashes, verify_restore
from cwm.security import Toolchain, trusted_key
from cwm.util import RecoveryError, digest, kernel_lock, load, write_json
from tests.helpers import GIT, TOOLS, fixture, keys


class PolicyTests(unittest.TestCase):
    def test_offset_expiry_is_compared_as_instant(self):
        policy = {
            "schema_version": "1",
            "issued_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-11-09T23:00:00+14:00",
            "keys": [
                {
                    "id": "key",
                    "status": "trusted",
                    "public_key": "synthetic-public",
                    "producers": ["producer"],
                    "scopes": ["scope"],
                }
            ],
        }
        with (
            patch("cwm.security.now", return_value="2026-11-09T12:00:00Z"),
            self.assertRaises(RecoveryError),
        ):
            trusted_key(policy, "key", "producer", "scope")

    def test_malformed_and_naive_dates_fail_closed(self):
        for expiry in ("not-a-date", "2027-01-01T00:00:00", None):
            with self.subTest(expiry=expiry), self.assertRaises(RecoveryError):
                trusted_key(
                    {
                        "schema_version": "1",
                        "issued_at": "2020-01-01T00:00:00Z",
                        "expires_at": expiry,
                    },
                    "key",
                    "producer",
                    "scope",
                )

    def test_result_exit_contract(self):
        for result, expected in [
            ({"status": "changed"}, 5),
            ({"status": "verified", "completeness": {"has_recovery_gaps": True}}, 4),
            ({"status": "verified"}, 0),
        ]:
            with (
                patch("cwm.cli.execute", return_value=result),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(main(["doctor"]), expected)

    def test_kernel_lock_refuses_concurrent_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "operation.lock"
            with kernel_lock(path), self.assertRaises(RecoveryError):
                with kernel_lock(path):
                    self.fail("Concurrent owner entered")
            with kernel_lock(path):
                pass

    def test_continuation_refuses_recursive_destination(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "evidence/continuation/project"
            source.mkdir(parents=True)
            (source / "context.md").write_text("Synthetic context")
            with (
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                code = main(
                    [
                        "continuation",
                        "build",
                        str(root),
                        "--project",
                        "project",
                        "--output",
                        str(source / "nested"),
                    ]
                )
            self.assertEqual(code, 2)
            self.assertFalse((source / "nested").exists())


class ClosureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.base = Path(cls.temporary.name)
        (cls.base / "keys").mkdir()
        cls.crypto = keys(cls.base / "keys")
        home, project, ident = fixture(cls.base)
        rollout_path = next((home / "sessions").glob("*.jsonl"))
        rows = [json.loads(line) for line in rollout_path.read_text().splitlines()]
        rows[1]["payload"]["content"].append(
            {"type": "input_file", "path": str(home / "attachments" / ident / "diagram.txt")}
        )
        rollout_path.write_text("".join(json.dumps(row) + "\n" for row in rows))
        capture(home, home, cls.base / "capture", projects=[project], maintenance=True)
        cls.result = export(
            cls.base / "capture",
            cls.base / "archive.age",
            cls.base / "export",
            TOOLS,
            signing_key=cls.crypto["signing_key"],
            key_id="fixture-signer",
            producer="cwm-fixture",
            scope="synthetic",
            recipients=cls.crypto["recipients"],
            identity=cls.crypto["identity"],
            trust=cls.crypto["trust"],
            git_exe=GIT,
        )

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=self.base)
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def planned(self, archive=None):
        return plan(
            archive or self.base / "archive.age",
            self.root / "destination",
            self.root / "plan",
            identity=self.crypto["identity"],
            trust=self.crypto["trust"],
            tools=TOOLS,
        )

    def changed_archive(self, change):
        payload = self.root / "payload"
        shutil.copytree(self.base / "export/verified-payload", payload)
        change(payload)
        manifest = load(payload / "manifest.json")
        manifest["payload"] = {
            p.relative_to(payload).as_posix(): {"sha256": digest(p), "size": p.stat().st_size}
            for p in payload.rglob("*")
            if p.is_file() and p.name not in ("manifest.json", "manifest.minisig")
        }
        write_json(payload / "manifest.json", manifest, replace=True)
        tools = Toolchain(TOOLS)
        tools.sign(payload / "manifest.json", self.crypto["signing_key"])
        (payload / "manifest.json.minisig").replace(payload / "manifest.minisig")
        inner = self.root / "changed.zip"
        with zipfile.ZipFile(inner, "x") as archive:
            for p in payload.rglob("*"):
                if p.is_file():
                    archive.write(p, p.relative_to(payload).as_posix())
        encrypted = self.root / "changed.age"
        tools.encrypt(inner, encrypted, self.crypto["recipients"])
        return encrypted

    def test_signed_logical_substitution_rejected_before_deployment(self):

        def change(payload):
            p = next((payload / "portable/threads").glob("*/logical-events.jsonl"))
            rows = [json.loads(line) for line in p.read_text().splitlines()]
            rows[-1]["record"]["payload"]["content"][0]["text"] = "Synthetic substitution"
            p.write_text("".join(json.dumps(row) + "\n" for row in rows))

        with self.assertRaises(RecoveryError):
            self.planned(self.changed_archive(change))
        self.assertFalse((self.root / "destination").exists())

    def test_signed_raw_readable_substitution_rejected(self):
        def change(payload):
            next((payload / "portable/threads").glob("*/transcript.md")).write_text(
                "Substituted raw view"
            )

        with self.assertRaises(RecoveryError):
            self.planned(self.changed_archive(change))

    def test_signed_raw_event_substitution_rejected(self):
        def change(payload):
            target = next((payload / "portable/threads").glob("*/events.jsonl"))
            rows = [json.loads(line) for line in target.read_text().splitlines()]
            rows[-1]["record"] = {"type": "substitution"}
            target.write_text("".join(json.dumps(row) + "\n" for row in rows))

        with self.assertRaises(RecoveryError):
            self.planned(self.changed_archive(change))

    def test_signed_git_administration_file_rejected(self):

        def change(payload):
            p = payload / "inventory/projects.json"
            projects = load(p)
            projects[0]["files"][0]["path"] = ".git/config"
            projects[0]["directories"].append(
                ".git"
            )  # coherent attack, not a missing-parent rejection
            write_json(p, projects, replace=True)

        with self.assertRaises(RecoveryError):
            self.planned(self.changed_archive(change))

    def test_signed_missing_attachment_relationship_rejected(self):

        def change(payload):
            write_json(payload / "inventory/asset-references.json", [], replace=True)

        with self.assertRaises(RecoveryError):
            self.planned(self.changed_archive(change))

    def test_intentional_profile_exclusions_are_separate_from_required_gaps(self):
        from cwm.projects import recovery_dispositions

        dispositions = recovery_dispositions(
            {
                "limitations": [
                    "Ignored file excluded: cache.bin",
                    "Credential-like file excluded: recovery.key",
                ]
            }
        )
        self.assertEqual(dispositions["selection_exclusions"], ["Ignored file excluded: cache.bin"])
        self.assertEqual(
            dispositions["recovery_gaps"], ["Credential-like file excluded: recovery.key"]
        )

    def test_signed_bundle_escape_rejected(self):

        def change(payload):
            p = payload / "inventory/projects.json"
            projects = load(p)
            projects[0]["git"]["bundle"] = "../outside.bundle"
            write_json(p, projects, replace=True)

        with self.assertRaises(RecoveryError):
            self.planned(self.changed_archive(change))

    def test_signed_catalog_escape_rejected(self):

        def change(payload):
            p = payload / "inventory/rollouts.json"
            catalog = load(p)
            catalog["sessions"][0]["object"] = "../outside.jsonl"
            write_json(p, catalog, replace=True)

        with self.assertRaises(RecoveryError):
            self.planned(self.changed_archive(change))

    def test_readable_substitution_rejected(self):

        def change(payload):
            next((payload / "portable/threads").glob("*/logical-transcript.md")).write_text(
                "Wrong history"
            )

        with self.assertRaises(RecoveryError):
            self.planned(self.changed_archive(change))

    def test_guarded_complete_content_keeps_atomicity_limitation(self):
        report = self.result["preservation"]
        self.assertFalse(report["has_recovery_gaps"])
        cap = load(self.base / "export/payload/inventory/capture.json")
        self.assertEqual(cap["consistency_scope"]["application_quiescence"], "not_established")
        self.assertTrue(all(row["status"] == "preserved" for row in report["project_coverage"]))
        self.assertTrue(report["project_limitations"])
        self.assertEqual(report["consistency"], "guarded_validated")

    def test_changed_metadata_and_forged_marker_do_not_redefine_baseline(self):
        self.planned()
        path = self.root / "plan/restore-plan.json"
        apply(path, GIT)
        target = self.root / "destination"
        (target / "evidence/inventory/projects.json").write_text("[]")
        marker = load(target / ".cwm-operation.json")
        marker["files"] = tree_hashes(target)
        write_json(target / ".cwm-operation.json", marker, replace=True)
        self.assertEqual(verify_restore(path, GIT)["status"], "changed")
        with self.assertRaises(RecoveryError):
            rollback(path)

    def test_actual_cli_complete_alias_recovery_returns_zero(self):
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                "-m",
                "cwm",
                "verify",
                str(self.base / "archive.age"),
                "--keys",
                str(Path(str(self.crypto["identity"])).parent),
                "--workspace",
                str(self.root / "verify"),
            ],
            capture_output=True,
            timeout=120,
        )
        self.assertEqual(result.returncode, 0)
        self.assertFalse(json.loads(result.stdout)["completeness"]["has_recovery_gaps"])

    def test_actual_cli_mismatch_returns_five(self):
        self.planned()
        path = self.root / "plan/restore-plan.json"
        apply(path, GIT)
        (self.root / "destination/new-work.txt").write_text("Later work")
        result = subprocess.run(
            [sys.executable, "-B", "-m", "cwm", "import", "verify", str(path)],
            capture_output=True,
            timeout=120,
        )
        self.assertEqual(result.returncode, 5)
        self.assertEqual(json.loads(result.stdout)["status"], "changed")


class StorageTests(unittest.TestCase):
    def test_unknown_database_column_is_not_exported(self):
        import sqlite3
        from contextlib import closing

        from cwm.preservation import preserve

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home, _, _ = fixture(root, project=False)
            with closing(sqlite3.connect(home / "state_5.sqlite")) as db:
                db.execute("ALTER TABLE threads ADD COLUMN unfamiliar_secret TEXT")
                db.execute("UPDATE threads SET unfamiliar_secret=?", ("SYNTHETIC_UNKNOWN_COLUMN",))
                db.commit()
            capture(home, home, root / "capture", maintenance=True)
            preserve(root / "capture", root / "payload")
            records = (root / "payload/inventory/database-records.json").read_text()
            self.assertNotIn("SYNTHETIC_UNKNOWN_COLUMN", records)
            adapters = load(root / "payload/inventory/storage-adapters.json")
            self.assertTrue(
                any("unfamiliar_secret" in row.get("columns", []) for row in adapters["gaps"])
            )

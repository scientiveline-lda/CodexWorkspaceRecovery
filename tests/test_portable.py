"""Revised product-contract safety requirements. Synthetic source only."""

import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import cwm_verify
from cwm.capture import capture
from cwm.preservation import preserve
from cwm.projects import Git, compare, restore_project
from cwm.rollouts import closure, inventory
from cwm.util import RecoveryError
from tests.helpers import GIT, fixture, rollout


class PortableTests(unittest.TestCase):
    def test_empty_directory_and_file_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = Path(tmp)
            h, p, _ = fixture(r)
            (p / "empty/nested").mkdir(parents=True)
            (p / "zero").write_bytes(b"")
            capture(h, h, r / "c", projects=[p], maintenance=True)
            preserve(r / "c", r / "payload", git_exe=GIT)
            project = json.loads((r / "payload/inventory/projects.json").read_text())[0]
            restore_project(project, r / "payload", r / "out", Git(GIT))
            self.assertTrue((r / "out/empty/nested").is_dir())
            self.assertEqual((r / "out/zero").read_bytes(), b"")
            (r / "out/extra-empty").mkdir()
            self.assertEqual(compare(project, r / "out", Git(GIT))["status"], "failed")

    def test_source_closure_is_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = Path(tmp)
            h, _, _ = fixture(r, project=False)
            with self.assertRaises(RecoveryError):
                capture(h, h, r / "out")
            self.assertFalse((r / "out").exists())

    def test_history_ordinal_disagreement_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = Path(tmp)
            h, _, ident = fixture(r, project=False)
            original = next((h / "sessions").glob("*"))
            rollout(
                h,
                "child",
                base={
                    "thread_id": ident,
                    "end_byte_offset": original.stat().st_size,
                    "end_ordinal_exclusive": 999,
                },
            )
            capture(h, h, r / "c", maintenance=True)
            with self.assertRaises(RecoveryError):
                closure(inventory(r / "c"), ["child"])

    def test_invalid_date_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = Path(tmp)
            h, _, _ = fixture(r, project=False)
            capture(h, h, r / "c", maintenance=True)
            with self.assertRaises(RecoveryError):
                preserve(r / "c", r / "payload", since="not-a-date")

    def test_sparse_repository_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = Path(tmp)
            h, p, _ = fixture(r)
            (p / ".git/info/sparse-checkout").write_text("tracked.txt")
            capture(h, h, r / "c", projects=[p], maintenance=True)
            with self.assertRaises(RecoveryError):
                preserve(r / "c", r / "payload", git_exe=GIT)

    def test_zip64_oversized_directory_refused_before_parser(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "bad.zip"
            record = struct.pack(
                "<4sQ2H2L4Q", b"PK\x06\x06", 44, 45, 45, 0, 0, 1, 1, 64 * 1024**2, 0
            )
            locator = struct.pack("<4sLQL", b"PK\x06\x07", 0, 0, 1)
            end = struct.pack(
                "<4s4H2LH", b"PK\x05\x06", 0, 0, 65535, 65535, 0xFFFFFFFF, 0xFFFFFFFF, 0
            )
            p.write_bytes(record + locator + end)
            with self.assertRaises(cwm_verify.VerificationError):
                cwm_verify.directory_bounds(p)

    def test_missing_packaged_tool_fails_closed(self):
        from cwm.security import Toolchain

        with self.assertRaises(RecoveryError):
            Toolchain({}).tool("age")

    def test_single_recipient_is_supported(self):
        from cwm.security import Toolchain

        with (
            patch.object(Toolchain, "tool", return_value=Path("age.exe")),
            patch("cwm.security.run") as run,
        ):
            Toolchain({}).encrypt("in", "out", ["age1synthetic"])
            self.assertTrue(run.called)

    def test_verifier_refusal_is_exit_two(self):
        import contextlib
        import io

        from cwm.cli import main

        with (
            patch("cwm.cli.execute", side_effect=cwm_verify.VerificationError("synthetic")),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(main(["doctor"]), 2)

    def test_actual_missing_attachment_remains_a_gap(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = Path(tmp)
            h, project, _ = fixture(r)
            file = next((h / "sessions").glob("*.jsonl"))
            rows = [json.loads(line) for line in file.read_text().splitlines()]
            rows[-1]["payload"]["content"].append(
                {"type": "input_file", "path": str(h / "attachments/missing.bin")}
            )
            file.write_text("".join(json.dumps(row) + "\n" for row in rows))
            capture(h, h, r / "c", projects=[project], maintenance=True)
            report = preserve(r / "c", r / "payload", git_exe=GIT)
            self.assertTrue(report["has_recovery_gaps"])
            refs = json.loads((r / "payload/inventory/asset-references.json").read_text())
            self.assertTrue(any(ref["status"] == "missing" for ref in refs))

    def test_archive_controlled_hook_directory_never_executes(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = Path(tmp)
            h, project, _ = fixture(r)
            hooks = project / ".cwm-empty-hooks"
            hooks.mkdir()
            marker = r / "hook-executed"
            (hooks / "reference-transaction").write_text(
                '#!/bin/sh\nprintf unsafe > "' + marker.as_posix() + '"\n'
            )
            capture(h, h, r / "c", projects=[project], maintenance=True)
            preserve(r / "c", r / "payload", git_exe=GIT)
            self.assertFalse(marker.exists())
            self.assertEqual(
                (hooks / "reference-transaction").read_text().splitlines()[0], "#!/bin/sh"
            )

    def test_key_profile_inside_source_is_refused_before_writes(self):
        import contextlib
        import io

        from cwm.cli import main

        with tempfile.TemporaryDirectory() as tmp:
            r = Path(tmp)
            home, project, _ = fixture(r)
            keys = project / "recovery-keys"
            keys.mkdir()
            (keys / "identity.agekey").write_text("Synthetic private identity canary")
            with contextlib.redirect_stderr(io.StringIO()):
                code = main(
                    [
                        "export",
                        "--home",
                        str(home),
                        "--project",
                        str(project),
                        "--keys",
                        str(keys),
                        "--source-closed",
                        "--workspace",
                        str(r / "work"),
                        "--output",
                        str(r / "archive.age"),
                    ]
                )
            self.assertEqual(code, 2)
            self.assertFalse((r / "work").exists())
            self.assertFalse((r / "archive.age").exists())
            self.assertEqual(
                (keys / "identity.agekey").read_text(), "Synthetic private identity canary"
            )

    def test_other_age_identity_excluded_with_explicit_gap(self):
        import hashlib

        with tempfile.TemporaryDirectory() as tmp:
            r = Path(tmp)
            home, project, _ = fixture(r)
            secret = b"Synthetic other private age identity canary"
            (project / "other.agekey").write_bytes(secret)
            capture(home, home, r / "c", projects=[project], maintenance=True)
            report = preserve(r / "c", r / "payload", git_exe=GIT)
            self.assertTrue(report["has_recovery_gaps"])
            self.assertFalse(
                (r / "payload/objects/sha256" / hashlib.sha256(secret).hexdigest()).exists()
            )
            self.assertTrue(
                any(
                    "Credential-like file excluded: other.agekey" in value
                    for values in report["project_limitations"].values()
                    for value in values
                )
            )

    def test_project_db_extension_is_opaque_file_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = Path(tmp)
            home, project, _ = fixture(r)
            data = b"Not a SQLite database; ordinary project bytes"
            (project / "opaque.db").write_bytes(data)
            report = capture(home, home, r / "c", projects=[project], maintenance=True)
            self.assertEqual(len(report["database_files"]), 1)
            preserve(r / "c", r / "payload", git_exe=GIT)
            state = json.loads((r / "payload/inventory/projects.json").read_text())[0]
            restore_project(state, r / "payload", r / "out", Git(GIT))
            self.assertEqual((r / "out/opaque.db").read_bytes(), data)

    def test_attachment_db_extension_not_opened_as_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = Path(tmp)
            home, _, ident = fixture(r, project=False)
            data = b"Opaque attachment with db extension"
            (home / "attachments" / ident / "opaque.db").write_bytes(data)
            report = capture(home, home, r / "c", maintenance=True)
            self.assertEqual(len(report["database_files"]), 1)
            preserve(r / "c", r / "payload")
            assets = json.loads((r / "payload/inventory/assets.json").read_text())
            import hashlib

            self.assertTrue(
                any(a.get("sha256") == hashlib.sha256(data).hexdigest() for a in assets)
            )

    def test_repeated_thread_selection_has_unique_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = Path(tmp)
            home, project, ident = fixture(r)
            capture(home, home, r / "c", projects=[project], maintenance=True)
            report = preserve(r / "c", r / "payload", git_exe=GIT, selected=[ident, ident])
            self.assertEqual(report["selected"], 1)
            self.assertEqual(report["sessions"], 1)
            self.assertEqual(report["dependencies"], 0)
            self.assertEqual(
                len(json.loads((r / "payload/inventory/sessions.json").read_text())), 1
            )

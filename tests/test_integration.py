import tempfile
import unittest
import zipfile
from contextlib import closing
from pathlib import Path

import cwm_verify
from cwm.archive import export
from cwm.capture import capture
from cwm.preservation import preserve
from cwm.restore import apply, plan, rollback, verify_restore
from cwm.util import RecoveryError, load, write_json
from tests.helpers import GIT, TOOLS, fixture, git, keys


@unittest.skipUnless(
    TOOLS.exists(), "Explicitly provision vendor/toolchain.json to run real crypto integration"
)
class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.crypto = keys(self.root)
        self.h, self.project, self.ident = fixture(self.root)
        capture(self.h, self.h, self.root / "snapshot", projects=[self.project], maintenance=True)

    def tearDown(self):
        self.temp.cleanup()

    def export(self):
        return export(
            self.root / "snapshot",
            self.root / "backup.age",
            self.root / "export",
            TOOLS,
            signing_key=self.crypto["signing_key"],
            key_id="fixture-signer",
            producer="cwm-fixture",
            scope="synthetic",
            recipients=self.crypto["recipients"],
            identity=self.crypto["identity"],
            trust=self.crypto["trust"],
            git_exe=GIT,
        )

    def test_encrypted_signed_project_roundtrip_idempotence_and_rollback(self):
        result = self.export()
        self.assertEqual(result["verification"]["status"], "verified")
        self.assertNotIn(b"Historical architecture", (self.root / "backup.age").read_bytes())
        p = plan(
            self.root / "backup.age",
            self.root / "destination",
            self.root / "plan",
            identity=self.crypto["identity"],
            trust=self.crypto["trust"],
            tools=TOOLS,
        )
        report = apply(self.root / "plan/restore-plan.json", GIT)
        self.assertEqual(report["status"], "portable_reconstructed")
        self.assertEqual(
            verify_restore(self.root / "plan/restore-plan.json", GIT)["status"], "verified"
        )
        self.assertEqual(
            apply(self.root / "plan/restore-plan.json", GIT)["status"], "already_applied"
        )
        dst = Path(p["mappings"][str(self.project.resolve())])
        self.assertEqual((dst / "tracked.txt").read_bytes(), b"unstaged\n")
        self.assertEqual(git(dst, "show", ":tracked.txt"), b"staged\n")
        self.assertFalse((dst / "ignored.txt").exists())
        self.assertEqual(rollback(self.root / "plan/restore-plan.json")["status"], "rolled_back")
        self.assertFalse((self.root / "destination").exists())

    def test_changed_destination_is_preserved(self):
        self.export()
        plan(
            self.root / "backup.age",
            self.root / "destination",
            self.root / "plan",
            identity=self.crypto["identity"],
            trust=self.crypto["trust"],
            tools=TOOLS,
        )
        apply(self.root / "plan/restore-plan.json", GIT)
        (self.root / "destination/new-work.txt").write_text("later work")
        with self.assertRaises(RecoveryError):
            rollback(self.root / "plan/restore-plan.json")
        self.assertTrue((self.root / "destination/new-work.txt").exists())

    def test_ciphertext_tampering_rejected(self):
        self.export()
        p = self.root / "backup.age"
        data = bytearray(p.read_bytes())
        data[-20] ^= 1
        p.write_bytes(data)
        with self.assertRaises(cwm_verify.VerificationError):
            cwm_verify.verify(
                p, self.crypto["identity"], self.crypto["trust"], TOOLS, self.root / "verify"
            )

    def test_revoked_signer_rejected(self):
        self.export()
        trust = load(self.crypto["trust"])
        trust["keys"][0]["status"] = "revoked"
        write_json(self.root / "revoked.json", trust)
        with self.assertRaises(cwm_verify.VerificationError):
            cwm_verify.verify(
                self.root / "backup.age",
                self.crypto["identity"],
                self.root / "revoked.json",
                TOOLS,
                self.root / "verify",
            )

    def test_each_recipient_independently_decrypts(self):
        self.export()
        r = cwm_verify.verify(
            self.root / "backup.age",
            self.root / "recovery.agekey",
            self.crypto["trust"],
            TOOLS,
            self.root / "verify",
        )
        self.assertEqual(r["status"], "verified")

    def test_traversal_member_rejected_before_extraction(self):
        self.export()
        z = self.root / "export/archive.zip.partial"
        with zipfile.ZipFile(z, "a") as f:
            f.writestr("../escape.txt", "malicious")
        with self.assertRaises(cwm_verify.VerificationError):
            cwm_verify.verify_zip(z, self.crypto["trust"], TOOLS, self.root / "verify")
        self.assertFalse((self.root / "escape.txt").exists())

    def test_undeclared_member_rejected(self):
        self.export()
        z = self.root / "export/archive.zip.partial"
        with zipfile.ZipFile(z, "a") as f:
            f.writestr("unexpected.txt", "malicious")
        with self.assertRaises(cwm_verify.VerificationError):
            cwm_verify.verify_zip(z, self.crypto["trust"], TOOLS, self.root / "verify")

    def test_selective_export_omits_unrelated_database_rows(self):
        import sqlite3

        with closing(sqlite3.connect(self.h / "state_5.sqlite")) as c:
            c.execute(
                "insert into threads values (?,?,?)",
                ("unselected", "p2", "PRIVATE_UNSELECTED_TEXT"),
            )
            c.commit()
        capture(self.h, self.h, self.root / "selective-snapshot", maintenance=True)
        preserve(
            self.root / "selective-snapshot",
            self.root / "payload",
            selected=[self.ident],
            git_exe=GIT,
        )
        self.assertNotIn(
            "PRIVATE_UNSELECTED_TEXT",
            (self.root / "payload/inventory/database-records.json").read_text(),
        )

    def test_archive_replacement_invalidates_plan(self):
        self.export()
        plan(
            self.root / "backup.age",
            self.root / "destination",
            self.root / "plan",
            identity=self.crypto["identity"],
            trust=self.crypto["trust"],
            tools=TOOLS,
        )
        with (self.root / "backup.age").open("ab") as f:
            f.write(b"changed")
        with self.assertRaises(RecoveryError):
            apply(self.root / "plan/restore-plan.json", GIT)


if __name__ == "__main__":
    unittest.main()

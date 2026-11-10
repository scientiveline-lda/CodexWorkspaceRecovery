import tempfile
import unittest
import zipfile
from pathlib import Path

import cwm_verify
from cwm.archive import export
from cwm.capture import capture
from cwm.restore import apply, plan, resume
from cwm.security import Toolchain
from cwm.util import RecoveryError, load, write_json
from tests.helpers import GIT, TOOLS, fixture, keys


@unittest.skipUnless(TOOLS.exists(), "Explicit crypto toolchain needed")
class AdversarialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.crypto = keys(cls.root)
        h, p, i = fixture(cls.root, project=False)
        capture(h, h, cls.root / "capture", maintenance=True)
        export(
            cls.root / "capture",
            cls.root / "backup.age",
            cls.root / "export",
            TOOLS,
            signing_key=cls.crypto["signing_key"],
            key_id="fixture-signer",
            producer="cwm-fixture",
            scope="synthetic",
            recipients=cls.crypto["recipients"],
            identity=cls.crypto["identity"],
            trust=cls.crypto["trust"],
        )
        cls.serial = 0

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def work(self):
        type(self).serial += 1
        return self.root / ("case-" + str(self.serial))

    def modified_zip(self, change):
        output = self.work().with_suffix(".zip")
        with (
            zipfile.ZipFile(self.root / "export/archive.zip.partial") as source,
            zipfile.ZipFile(output, "x") as dest,
        ):
            for i in source.infolist():
                dest.writestr(i, change(i.filename, source.read(i)))
        return output

    def test_valid_archive_swap_after_preflight_is_rejected(self):
        import shutil
        from unittest.mock import patch

        import cwm.restore as recovery

        manifest = load(self.root / "export/payload/manifest.json")
        manifest["archive_id"] = "f" * 32
        controls = self.work()
        controls.mkdir()
        write_json(controls / "manifest.json", manifest)
        tools = Toolchain(TOOLS)
        tools.sign(controls / "manifest.json", self.crypto["signing_key"])
        changed = self.modified_zip(
            lambda n, b: (
                (controls / "manifest.json").read_bytes()
                if n == "manifest.json"
                else (controls / "manifest.json.minisig").read_bytes()
                if n == "manifest.minisig"
                else b
            )
        )
        replacement = self.work().with_suffix(".age")
        tools.encrypt(changed, replacement, self.crypto["recipients"])
        archive = self.work().with_suffix(".age")
        shutil.copyfile(self.root / "backup.age", archive)
        work = self.work()
        target = self.work()
        plan(
            archive,
            target,
            work,
            identity=self.crypto["identity"],
            trust=self.crypto["trust"],
            tools=TOOLS,
        )
        original = recovery.validate_plan

        def swap_after_validation(value):
            original(value)
            archive.write_bytes(replacement.read_bytes())

        with (
            patch.object(recovery, "validate_plan", side_effect=swap_after_validation),
            self.assertRaises(RecoveryError),
        ):
            apply(work / "restore-plan.json", GIT)
        self.assertFalse(target.exists())

    def test_payload_substitution(self):
        path = self.modified_zip(lambda n, b: b + b"bad" if n == "inventory/sessions.json" else b)
        with self.assertRaises(cwm_verify.VerificationError):
            cwm_verify.verify_zip(path, self.crypto["trust"], TOOLS, self.work())

    def test_invalid_signature(self):
        path = self.modified_zip(
            lambda n, b: b.replace(b"R", b"S", 1) if n == "manifest.minisig" else b
        )
        with self.assertRaises(cwm_verify.VerificationError):
            cwm_verify.verify_zip(path, self.crypto["trust"], TOOLS, self.work())

    def test_noncanonical_manifest(self):
        path = self.modified_zip(lambda n, b: b + b"\n" if n == "manifest.json" else b)
        with self.assertRaises(cwm_verify.VerificationError):
            cwm_verify.verify_zip(path, self.crypto["trust"], TOOLS, self.work())

    def test_unknown_signer(self):
        trust = load(self.crypto["trust"])
        trust["keys"] = []
        with self.assertRaises(cwm_verify.VerificationError):
            cwm_verify.verify_zip(
                self.root / "export/archive.zip.partial", trust, TOOLS, self.work()
            )

    def test_expired_trust(self):
        trust = load(self.crypto["trust"])
        trust["expires_at"] = "2020-01-02T00:00:00Z"
        with self.assertRaises(cwm_verify.VerificationError):
            cwm_verify.verify_zip(
                self.root / "export/archive.zip.partial", trust, TOOLS, self.work()
            )

    def test_wrong_scope(self):
        trust = load(self.crypto["trust"])
        trust["keys"][0]["scopes"] = ["different"]
        with self.assertRaises(cwm_verify.VerificationError):
            cwm_verify.verify_zip(
                self.root / "export/archive.zip.partial", trust, TOOLS, self.work()
            )

    def test_source_snapshot_tampering(self):
        from cwm.preservation import preserve

        p = (
            self.root
            / "capture/acquired/home/sessions"
            / "11111111-1111-4111-8111-111111111111.jsonl"
        )
        original = p.read_bytes()
        p.write_bytes(original + b"\n")
        try:
            with self.assertRaises(RecoveryError):
                preserve(self.root / "capture", self.work())
        finally:
            p.write_bytes(original)

    def test_interrupted_apply_resumes_without_discarding_staging(self):
        work = self.work()
        target = self.work()
        plan(
            self.root / "backup.age",
            target,
            work,
            identity=self.crypto["identity"],
            trust=self.crypto["trust"],
            tools=TOOLS,
        )
        with self.assertRaises(RecoveryError):
            apply(work / "restore-plan.json", GIT, failpoint="before_publish")
        self.assertEqual(
            resume(work / "restore-plan.json", GIT)["status"], "portable_reconstructed"
        )
        self.assertTrue(list(target.parent.glob(".cwm-stage-*.abandoned")))

    def test_crash_after_publish_reconciles(self):
        work = self.work()
        target = self.work()
        plan(
            self.root / "backup.age",
            target,
            work,
            identity=self.crypto["identity"],
            trust=self.crypto["trust"],
            tools=TOOLS,
        )
        with self.assertRaises(RecoveryError):
            apply(work / "restore-plan.json", GIT, failpoint="after_publish")
        self.assertEqual(resume(work / "restore-plan.json", GIT)["status"], "already_applied")
        self.assertEqual(load(work / "operation.json")["status"], "verified")


if __name__ == "__main__":
    unittest.main()

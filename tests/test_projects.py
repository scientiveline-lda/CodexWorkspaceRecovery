import subprocess
import tempfile
import unittest
from pathlib import Path

from cwm.capture import capture
from cwm.projects import Git, collect, restore_project
from tests.helpers import GIT, fixture, git


class ProjectTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.home, self.project, self.ident = fixture(self.root)

    def tearDown(self):
        self.temp.cleanup()

    def roundtrip(self, source=None, profile="recovery"):
        source = source or self.project
        cap = capture(
            self.home, self.home, self.root / "capture", projects=[source], maintenance=True
        )
        payload = self.root / "payload"
        payload.mkdir()
        p = collect(
            self.root / "capture",
            cap["projects"][0],
            payload,
            self.root / "work",
            Git(GIT),
            profile,
        )
        report = restore_project(p, payload, self.root / "destination", Git(GIT))
        self.assertNotEqual(report["status"], "failed", report)
        return (p, report)

    def test_staged_unstaged_untracked_binary(self):
        p, report = self.roundtrip()
        self.assertEqual((self.root / "destination/untracked.bin").read_bytes(), bytes(range(256)))
        self.assertEqual(git(self.root / "destination", "show", ":tracked.txt"), b"staged\n")

    def test_full_profile_preserves_ignored_file(self):
        self.roundtrip(profile="full")
        self.assertEqual(
            (self.root / "destination/ignored.txt").read_text(), "Local ignored fixture"
        )

    def test_detached_head(self):
        git(self.project, "checkout", "--detach", "HEAD")
        p, _ = self.roundtrip()
        self.assertIsNone(p["git"]["symbolic_head"])
        result = subprocess.run(
            [str(GIT), "-C", str(self.root / "destination"), "symbolic-ref", "HEAD"],
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_conflicted_index(self):
        oid = git(self.project, "rev-parse", "HEAD:tracked.txt").decode().strip()
        source = (
            "0 "
            + "0" * 40
            + "\ttracked.txt\n"
            + "".join("100644 " + oid + " " + str(i) + "\ttracked.txt\n" for i in [1, 2, 3])
        )
        subprocess.run(
            [str(GIT), "-C", str(self.project), "update-index", "--index-info"],
            input=source.encode(),
            check=True,
            capture_output=True,
        )
        p, _ = self.roundtrip()
        self.assertEqual(
            [x["stage"] for x in p["git"]["index"] if x["path"] == "tracked.txt"], [1, 2, 3]
        )

    def test_assume_unchanged_flag(self):
        git(self.project, "update-index", "--assume-unchanged", "tracked.txt")
        p, _ = self.roundtrip()
        self.assertTrue(p["git"]["index_flags"]["tracked.txt"].islower())

    def test_linked_worktree(self):
        linked = self.root / "linked"
        git(self.project, "worktree", "add", "-b", "fixture-linked", str(linked), "HEAD")
        (linked / "tracked.txt").write_bytes(b"linked modification\n")
        p, _ = self.roundtrip(linked)
        self.assertTrue(p["linked_worktree"])
        self.assertTrue((self.root / "destination/.git").is_dir())

    def test_remote_references_preserved_without_credentials(self):
        git(
            self.project,
            "remote",
            "add",
            "origin",
            "https://user:FAKE_SECRET@example.invalid:8443/company/repo.git?token=FAKE_SECRET",
        )
        project, _ = self.roundtrip()
        remote = project["git"]["remotes"][0]
        self.assertEqual(remote["url"], "https://example.invalid:8443/company/repo.git")
        self.assertTrue(remote["credential_fields_removed_or_sanitized"])
        self.assertNotIn("FAKE_SECRET", str(project))

    def test_local_refs_preserved(self):
        git(self.project, "branch", "local-only")
        git(self.project, "tag", "fixture-tag")
        p, _ = self.roundtrip()
        refs = {x[1] for x in p["git"]["refs"]}
        self.assertIn("refs/heads/local-only", refs)
        self.assertIn("refs/tags/fixture-tag", refs)

    def test_missing_alternates_are_refused(self):
        from cwm.util import RecoveryError

        alternates = self.project / ".git/objects/info/alternates"
        alternates.write_text(str(self.root / "missing-objects"))
        with self.assertRaises(RecoveryError):
            self.roundtrip()


if __name__ == "__main__":
    unittest.main()

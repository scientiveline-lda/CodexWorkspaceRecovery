import json
import os
import sqlite3
import subprocess
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from cwm.capture import capture
from cwm.discovery import locations
from cwm.rollouts import closure, inventory, records
from cwm.security import Toolchain, scan_file
from cwm.util import *
from tests.helpers import fixture, rollout


class CoreTests(unittest.TestCase):
    def test_output_lock_refuses_concurrent_writer(self):
        from cwm.util import exclusive_lock

        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "operation.lock"
            with exclusive_lock(p):
                with self.assertRaises(RecoveryError):
                    with exclusive_lock(p):
                        pass
            self.assertFalse(p.exists())

    def test_capacity_preflight_refuses_without_writing(self):
        from collections import namedtuple
        from unittest.mock import patch

        from cwm.util import require_space

        usage = namedtuple("usage", "total used free")(100, 99, 1)
        with tempfile.TemporaryDirectory() as d, patch("shutil.disk_usage", return_value=usage):
            with self.assertRaises(RecoveryError):
                require_space(Path(d) / "never-created", 1)
            self.assertFalse((Path(d) / "never-created").exists())

    def test_duplicate_json(self):
        with self.assertRaises(RecoveryError):
            loads('{"a":1,"a":2}')

    def test_nonfinite(self):
        for v in ["NaN", "Infinity", "-Infinity"]:
            with self.assertRaises(RecoveryError):
                loads('{"a":' + v + "}")

    def test_jcs_unicode_and_numbers(self):
        self.assertEqual(canonical({"b": 1.0, "a": "\u20ac"}), b'{"a":"\xe2\x82\xac","b":1}')

    def test_large_integer_rejected(self):
        with self.assertRaises(RecoveryError):
            canonical({"a": 2**60})

    def test_unsafe_paths(self):
        for n in [
            "../escape",
            "a/../x",
            "/absolute",
            "C:/x",
            "a\\b",
            "a//b",
            "x/CON.txt",
            "x/trailing.",
            "x/a:b",
            "x/../y",
            "NUL",
            "a\x00b",
        ]:
            with self.subTest(n=n), self.assertRaises(RecoveryError):
                safe_relative(n)

    def test_atomic_publication_conflict(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x"
            atomic_bytes(p, b"original")
            with self.assertRaises(RecoveryError):
                atomic_bytes(p, b"replacement")
            self.assertEqual(p.read_bytes(), b"original")

    def test_secret_findings_do_not_contain_secret(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x"
            secret = "sk-proj-" + "x" * 40
            p.write_text(secret)
            r = scan_file(p, "fixture")
            self.assertTrue(r)
            self.assertNotIn(secret, json.dumps(r))

    def test_location_precedence(self):
        with tempfile.TemporaryDirectory() as d:
            h = Path(d)
            (h / "config.toml").write_text(
                'sqlite_home = "' + str(h / "sql").replace("\\", "\\\\") + '"'
            )
            _, sql, _ = locations(h)
            self.assertEqual(sql, (h / "sql").resolve())
            _, sql, _ = locations(h, h / "explicit")
            self.assertEqual(sql, (h / "explicit").resolve())

    def test_rollout_unknown_events_preserved(self):
        with tempfile.TemporaryDirectory() as d:
            p, _ = rollout(Path(d))
            p.write_bytes(p.read_bytes() + b'{"type":"future","payload":{"opaque":42}}\n')
            self.assertEqual(list(records(p))[-1][2]["type"], "future")

    def test_compressed_rollout(self):
        with tempfile.TemporaryDirectory() as d:
            p, data = rollout(Path(d), compressed=True)
            self.assertEqual(len(list(records(p))), 2)

    def test_partial_rollout_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p, _ = rollout(Path(d))
            p.write_bytes(p.read_bytes()[:-1])
            with self.assertRaises(RecoveryError):
                list(records(p))

    def test_dependency_closure(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            h = root / "acquired/home"
            h.mkdir(parents=True)
            ident = "11111111-1111-4111-8111-111111111111"
            p, data = rollout(h, ident, compressed=True)
            child = "22222222-2222-4222-8222-222222222222"
            rollout(
                h,
                child,
                base={"thread_id": ident, "end_byte_offset": len(data), "end_ordinal_exclusive": 2},
            )
            self.assertEqual(closure(inventory(root), [child]), [ident, child])

    def test_missing_dependency_blocks(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            h = root / "acquired/home"
            h.mkdir(parents=True)
            rollout(
                h, base={"thread_id": "missing", "end_byte_offset": 0, "end_ordinal_exclusive": 0}
            )
            with self.assertRaises(RecoveryError):
                closure(inventory(root), list(inventory(root)))

    def test_bad_boundary_blocks(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            h = root / "acquired/home"
            h.mkdir(parents=True)
            p, data = rollout(h)
            child = "22222222-2222-4222-8222-222222222222"
            rollout(
                h,
                child,
                base={
                    "thread_id": "11111111-1111-4111-8111-111111111111",
                    "end_byte_offset": 1,
                    "end_ordinal_exclusive": 1,
                },
            )
            with self.assertRaises(RecoveryError):
                closure(inventory(root), [child])

    def test_capture_no_source_mutation_or_auth_copy(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            h, p, i = fixture(root, project=False)
            before = {str(f): digest(f) for f in h.rglob("*") if f.is_file()}
            report = capture(h, h, root / "snapshot", maintenance=True)
            self.assertEqual(before, {str(f): digest(f) for f in h.rglob("*") if f.is_file()})
            self.assertFalse((root / "snapshot/acquired/home/auth.json").exists())
            self.assertEqual(
                report["classification"],
                "guarded_validated" if os.name == "nt" else "best_effort_incomplete",
            )

    def test_live_database_writer_blocks_windows_capture(self):
        if os.name != "nt":
            self.skipTest("Windows handle sharing")
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            h, p, i = fixture(root, project=False)
            c = sqlite3.connect(h / "state_5.sqlite")
            c.execute("BEGIN IMMEDIATE")
            try:
                with self.assertRaises(RecoveryError):
                    capture(h, h, root / "snapshot", maintenance=True)
            finally:
                c.rollback()
                c.close()

    def test_capture_requires_maintenance(self):
        with tempfile.TemporaryDirectory() as d:
            h, p, i = fixture(Path(d), project=False)
            with self.assertRaises(RecoveryError):
                capture(h, h, Path(d) / "s")

    def test_capture_overlap_blocks(self):
        with tempfile.TemporaryDirectory() as d:
            h, p, i = fixture(Path(d), project=False)
            with self.assertRaises(RecoveryError):
                capture(h, h, h / "s", maintenance=True)

    def test_wal_recovered_on_staging_only(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            h, p, i = fixture(root, project=False)
            db = h / "wal.sqlite"
            code = (
                "import sqlite3,os; c=sqlite3.connect("
                + repr(str(db))
                + '); c.execute("pragma journal_mode=wal"); c.execute("create table evidence(value text)"); c.execute("insert into evidence values (\'committed WAL\')"); c.commit(); os._exit(0)'
            )
            subprocess.run([os.sys.executable, "-c", code], check=True)
            before = {f.name: digest(f) for f in h.glob("wal.sqlite*")}
            capture(h, h, root / "snapshot", maintenance=True)
            self.assertEqual(before, {f.name: digest(f) for f in h.glob("wal.sqlite*")})
            with closing(sqlite3.connect(root / "snapshot/databases/home/wal.sqlite")) as c:
                self.assertEqual(
                    c.execute("select value from evidence").fetchone()[0], "committed WAL"
                )

    def test_credential_tools_not_path_resolved(self):
        with self.assertRaises(RecoveryError):
            Toolchain({"age": {"path": "age.exe", "sha256": "x"}}).tool("age")


if __name__ == "__main__":
    unittest.main()

import compression.zstd
import json
import tempfile
import unittest
from pathlib import Path

from cwm.configuration import preserve_configuration
from cwm.rollouts import closure, inventory, records, render_logical
from cwm.util import RecoveryError, load, write_payload
from tests.helpers import rollout


class AdditionalTests(unittest.TestCase):
    def test_missing_typed_asset_is_explicit(self):
        from cwm.assets import reconcile

        refs = [
            {
                "thread_id": "fixture",
                "source_reference": "C:/old/missing-image.png",
                "status": "unresolved",
            }
        ]
        result = reconcile(refs, [], "C:/old/.codex", [])
        self.assertEqual(result[0]["status"], "missing")

    def test_embedded_assets_are_not_duplicated(self):
        from cwm.assets import typed_refs

        self.assertEqual(
            list(typed_refs({"type": "input_image", "image_url": "data:fixture"})), ["data:fixture"]
        )

    def test_payload_preserves_large_integers(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.json"
            write_payload(p, {"historical_integer": 2**70})
            self.assertEqual(load(p)["historical_integer"], 2**70)

    def test_archived_compressed_inventory(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            home = root / "acquired/home"
            home.mkdir(parents=True)
            rollout(home, compressed=True, archived=True)
            values = list(inventory(root).values())
            self.assertEqual(len(values), 1)
            self.assertTrue(values[0]["archived"])

    def test_combined_history_respects_prefix(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            home = root / "acquired/home"
            home.mkdir(parents=True)
            parent = "11111111-1111-4111-8111-111111111111"
            child = "22222222-2222-4222-8222-222222222222"
            p, data = rollout(home, parent, text="INCLUDED_PREFIX")
            p.write_bytes(
                data
                + b'{"type":"response_item","payload":{"type":"message","role":"user","content":[{"text":"EXCLUDED_FUTURE"}]}}\n'
            )
            rollout(
                home,
                child,
                base={
                    "thread_id": parent,
                    "end_byte_offset": len(data),
                    "end_ordinal_exclusive": 2,
                },
                text="CHILD_TEXT",
            )
            inv = inventory(root)
            closure(inv, [child])
            out = root / "out"
            out.mkdir()
            render_logical(inv, child, out)
            text = (out / "logical-transcript.md").read_text()
            self.assertIn("INCLUDED_PREFIX", text)
            self.assertIn("CHILD_TEXT", text)
            self.assertNotIn("EXCLUDED_FUTURE", text)

    def test_configuration_is_reviewed_and_inert(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            home = root / "snapshot/acquired/home"
            home.mkdir(parents=True)
            (home / "config.toml").write_text(
                'model="example"\n[mcp_servers.secret]\ncommand="never-run"\n'
            )
            (home / "AGENTS.md").write_text("Preserve this instruction as evidence")
            report = preserve_configuration(root / "snapshot", root / "payload", [], True)
            data = load(root / "payload/portable/configuration/user-config-reviewed.json")
            self.assertEqual(data, {"model": "example"})
            self.assertNotIn("never-run", json.dumps(report))
            self.assertEqual(report["activation"], "inert evidence only")

    def test_concatenated_zstandard_frames(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.zst"
            p.write_bytes(
                compression.zstd.compress(b'{"type":"one"}\n')
                + compression.zstd.compress(b'{"type":"two"}\n')
            )
            self.assertEqual([r[2]["type"] for r in records(p)], ["one", "two"])

    def test_truncated_zstandard_frame(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.zst"
            data = compression.zstd.compress(
                b'{"type":"record","payload":"' + b"x" * 100000 + b'"}\n'
            )
            p.write_bytes(data[:-5])
            with self.assertRaises(RecoveryError):
                list(records(p))


if __name__ == "__main__":
    unittest.main()

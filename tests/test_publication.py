"""Publication boundary tests use synthetic sensitive-looking canaries only."""

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "publication_audit", ROOT / "tools/publication_audit.py"
)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class PublicationTests(unittest.TestCase):
    def test_forbidden_files(self):
        for name in [
            "docs/evidence/report.md",
            "laboratory/key.txt",
            "config/local.json",
            "data.sqlite",
            "key.pem",
            "../escape.md",
        ]:
            self.assertFalse(audit.allowed_name(name), name)

    def test_detects_secret_without_echoing_value(self):
        token = "ghp_" + "a" * 36
        findings = audit.audit_bytes("README.md", token.encode())
        self.assertTrue(findings)
        self.assertNotIn(token, json.dumps(findings))

    def test_build_allowlist_excludes_unreviewed_documents(self):
        names = audit.public_files(ROOT)
        self.assertNotIn("docs/plans/private.md", names)
        source = (ROOT / "packaging/build_windows.py").read_text(encoding="utf-8")
        self.assertNotIn('shutil.copytree(ROOT / "docs"', source)
        self.assertIn("public_files", source)

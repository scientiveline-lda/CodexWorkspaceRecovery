"""Publication boundary tests use synthetic sensitive-looking canaries only."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from tools.docs_check import check_document

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

    def test_documentation_checks_picture_sources_and_anchors(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            page = root / "README.md"
            for name in ["dark.svg", "light.svg"]:
                (root / name).write_text('<svg xmlns="http://www.w3.org/2000/svg"/>')
            valid = (
                "# Demo\n[Workflow](#demo)\n<picture>"
                '<source srcset="dark.svg 1x, light.svg 2x">'
                '<img src="light.svg" alt="Demo"></picture>\n'
            )
            page.write_text(valid, encoding="utf-8")
            check_document(page, root)
            for broken in [
                valid.replace("dark.svg", "missing.svg"),
                valid.replace('src="light.svg"', 'src="missing.svg"'),
                valid.replace("#demo)", "#missing)"),
                valid.replace("dark.svg", "../outside.svg"),
            ]:
                with self.subTest(markup=broken):
                    page.write_text(broken, encoding="utf-8")
                    with self.assertRaises(ValueError):
                        check_document(page, root)

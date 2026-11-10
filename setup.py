"""Setuptools content boundary: only explicitly reviewed application inputs ship."""

import json
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py
from setuptools.command.sdist import sdist

ROOT = Path(__file__).resolve().parent
ALLOWED = set(json.loads((ROOT / "packaging/public-files.json").read_text())["files"])


def allowed(path):
    try:
        return Path(path).resolve().relative_to(ROOT).as_posix() in ALLOWED
    except ValueError:
        return False


class ReviewedBuild(build_py):
    def find_package_modules(self, package, package_dir):
        return [
            entry
            for entry in super().find_package_modules(package, package_dir)
            if allowed(entry[2])
        ]

    def run(self):
        super().run()
        for path in Path(self.build_lib).rglob("*"):
            if (
                path.is_file()
                and "src/" + path.relative_to(self.build_lib).as_posix() not in ALLOWED
            ):
                raise RuntimeError("Unreviewed/stale build output; use a fresh build directory")

    def find_data_files(self, package, src_dir):
        return [path for path in super().find_data_files(package, src_dir) if allowed(path)]


class ReviewedSource(sdist):
    def make_release_tree(self, base_dir, files):
        # Setuptools' modern sdist obtains its file list from egg_info rather than
        # invoking legacy get_file_list(). Enforce the boundary at actual copying.
        metadata = [
            name for name in files if name.startswith("src/codex_workspace_recovery.egg-info/")
        ]
        reviewed = sorted(ALLOWED | set(metadata))
        super().make_release_tree(base_dir, reviewed)
        sources = Path(base_dir) / "src/codex_workspace_recovery.egg-info/SOURCES.txt"
        if sources.exists():
            content = (
                "\n".join(name for name in sources.read_text().splitlines() if name in reviewed)
                + "\n"
            )
            # Break any setuptools hard link before replacing generated metadata.
            sources.unlink()
            sources.write_text(content, encoding="utf-8")


setup(cmdclass={"build_py": ReviewedBuild, "sdist": ReviewedSource})

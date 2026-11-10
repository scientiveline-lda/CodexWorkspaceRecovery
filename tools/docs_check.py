"""Check local documentation links and generated command-reference parity."""

import argparse
import re
from pathlib import Path

from cwm.cli import parser

ROOT = Path(__file__).resolve().parents[1]


def reference() -> str:
    lines = [
        "# CLI reference\n",
        "Generated from the command parser. JSON results use stdout; errors and progress use stderr.\n",
    ]

    def walk(command: argparse.ArgumentParser) -> None:
        lines.append("## " + command.prog + "\n\n```text\n" + command.format_help() + "```\n")
        for action in command._actions:
            if isinstance(action, argparse._SubParsersAction):
                for child in action.choices.values():
                    walk(child)

    walk(parser())
    return "\n".join(lines)


def main() -> int:
    expected = reference()
    if (ROOT / "docs/cli-reference.md").read_text(encoding="utf-8") != expected:
        raise ValueError("CLI reference is stale")
    for path in [*ROOT.glob("*.md"), *(ROOT / "docs").glob("*.md")]:
        text = path.read_text(encoding="utf-8")
        if text.count("```") % 2:
            raise ValueError("Unclosed documentation fence: " + path.name)
        for target in re.findall(r"\]\(([^)]+)\)", text):
            if "://" in target or target.startswith("#"):
                continue
            if not (path.parent / target.split("#")[0]).is_file():
                raise ValueError("Broken documentation link: " + path.name)
    print("CLI reference and local documentation links match")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

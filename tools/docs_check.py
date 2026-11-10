"""Check local documentation links and generated command-reference parity."""

import argparse
import re
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

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


class ImageReferences(HTMLParser):
    """Collect local image variants that Markdown link matching cannot see."""

    def __init__(self) -> None:
        super().__init__()
        self.targets: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag not in {"img", "source"}:
            return
        for name, value in attrs:
            if name == "src" and value:
                self.targets.append(value)
            elif name == "srcset" and value:
                self.targets.extend(
                    part.strip().split()[0] for part in value.split(",") if part.strip()
                )


def heading_anchors(text: str) -> set[str]:
    anchors: set[str] = set()
    for heading in re.findall(r"^#{1,6} +(.+)$", text, re.M):
        heading = re.sub(r"\[([^]]+)\]\([^)]+\)", r"\1", heading)
        slug = re.sub(r"[^\w -]", "", heading.lower()).replace(" ", "-")
        anchor = slug
        number = 0
        while anchor in anchors:
            number += 1
            anchor = slug + "-" + str(number)
        anchors.add(anchor)
    return anchors


def check_document(path: Path, root: Path = ROOT) -> None:
    text = path.read_text(encoding="utf-8")
    if text.count("```") % 2:
        raise ValueError("Unclosed documentation fence: " + path.name)
    markup = re.sub(r"```.*?```", "", text, flags=re.S)
    images = ImageReferences()
    images.feed(markup)
    references = re.findall(r"\]\(([^)]+)\)", markup) + images.targets
    for reference in references:
        target = urlsplit(reference)
        if target.scheme in {"https", "http", "mailto"}:
            continue
        local = (path.parent / unquote(target.path)).resolve() if target.path else path.resolve()
        if target.scheme or not local.is_relative_to(root.resolve()) or not local.is_file():
            raise ValueError("Broken or unsafe documentation reference: " + path.name)
        if target.fragment and local.suffix == ".md":
            source = re.sub(r"```.*?```", "", local.read_text(encoding="utf-8"), flags=re.S)
            if unquote(target.fragment) not in heading_anchors(source):
                raise ValueError("Broken documentation anchor: " + path.name)


def main() -> int:
    expected = reference()
    if (ROOT / "docs/cli-reference.md").read_text(encoding="utf-8") != expected:
        raise ValueError("CLI reference is stale")
    for path in [*ROOT.glob("*.md"), *(ROOT / "docs").rglob("*.md")]:
        check_document(path)
    print("CLI reference, Markdown/HTML images, local links and anchors match")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

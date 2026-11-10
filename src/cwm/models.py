from dataclasses import dataclass
from typing import Literal, TypedDict

CoverageStatus = Literal[
    "captured",
    "discovered_supported",
    "discovered_unsupported",
    "inaccessible",
    "not_examined",
    "explicitly_excluded",
]


@dataclass
class SourceCoverage:
    surface: str
    location: str | None
    status: CoverageStatus
    reason: str


class FileEntry(TypedDict):
    sha256: str
    size: int


class Manifest(TypedDict):
    format: str
    version: str
    draft: int
    archive_id: str
    payload: dict[str, FileEntry]
    capture: str

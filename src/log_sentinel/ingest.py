"""Walk a directory of sample logs and parse them into Events."""

from __future__ import annotations

from pathlib import Path

from log_sentinel.models import Event
from log_sentinel.parsers import guess_parser, parse_file

SKIP_NAMES = {"readme.md", "readme.txt", ".gitkeep"}
SKIP_SUFFIXES = {".md", ".txt", ".json", ".yaml", ".yml"}


def collect_log_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    if not target.is_dir():
        raise FileNotFoundError(f"path not found: {target}")
    files: list[Path] = []
    for path in sorted(target.rglob("*")):
        if not path.is_file():
            continue
        if path.name.lower() in SKIP_NAMES:
            continue
        if path.suffix.lower() in SKIP_SUFFIXES and guess_parser(path) is None:
            continue
        if guess_parser(path) is None:
            continue
        files.append(path)
    return files


def ingest(target: Path) -> tuple[list[Event], dict[str, int]]:
    """Parse all recognized logs under target.

    Returns (events, counts_by_source_type).
    """
    events: list[Event] = []
    counts: dict[str, int] = {}
    for path in collect_log_files(target):
        parsed = parse_file(path)
        events.extend(parsed)
        if parsed:
            kind = parsed[0].source_type
            counts[kind] = counts.get(kind, 0) + len(parsed)
    events.sort(key=lambda e: e.timestamp)
    return events, counts

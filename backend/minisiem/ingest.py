"""Collector: read raw lines, parse them, and store normalized events."""

import hashlib
import sqlite3
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .models import EVENT_FIELDS
from .parsers import ParseContext, get_parser

_INSERT = (
    f"INSERT OR IGNORE INTO events (fingerprint, ingested_at, {', '.join(EVENT_FIELDS)}) "
    f"VALUES (?, ?, {', '.join('?' for _ in EVENT_FIELDS)})"
)


@dataclass
class IngestResult:
    source_type: str
    lines: int = 0
    parsed: int = 0
    inserted: int = 0
    duplicates: int = 0
    unparsed: int = 0
    unparsed_samples: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def _fingerprint(source_type: str, raw: str, occurrence: int) -> str:
    return hashlib.sha256(f"{source_type}\x00{occurrence}\x00{raw}".encode()).hexdigest()


def ingest_lines(
    conn: sqlite3.Connection,
    lines: Iterable[str],
    source_type: str,
    ctx: ParseContext | None = None,
) -> IngestResult:
    parser = get_parser(source_type)
    ctx = ctx or ParseContext()
    result = IngestResult(source_type=source_type)
    seen: Counter[str] = Counter()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    rows = []

    for line in lines:
        line = line.rstrip("\r\n")
        if not line.strip():
            continue
        result.lines += 1
        event = parser.parse_line(line, ctx)
        if event is None:
            result.unparsed += 1
            if len(result.unparsed_samples) < 5:
                result.unparsed_samples.append(line[:300])
            continue
        result.parsed += 1
        # Same raw line seen N times in one upload -> N distinct events, but
        # uploading the same file twice -> no new events.
        seen[line] += 1
        data = event.to_dict()
        rows.append((_fingerprint(source_type, line, seen[line]), now, *(data[f] for f in EVENT_FIELDS)))

    before = conn.total_changes
    conn.executemany(_INSERT, rows)
    conn.commit()
    result.inserted = conn.total_changes - before
    result.duplicates = result.parsed - result.inserted
    return result


def ingest_file(conn: sqlite3.Connection, path: Path, source_type: str, ctx: ParseContext | None = None):
    with open(path, encoding="utf-8", errors="replace") as fh:
        return ingest_lines(conn, fh, source_type, ctx)

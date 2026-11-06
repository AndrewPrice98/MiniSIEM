"""Seeding for the hosted demo.

Serverless hosts (e.g. Vercel) give each instance a fresh, writable /tmp and nothing
else that persists. On cold start, the instance builds its own database from the
example logs, so every visitor sees a fully populated dashboard. Anything uploaded
afterwards lives only as long as that instance.
"""

import json
import logging

from . import config, db
from .detection import run_detection
from .ingest import ingest_file
from .parsers import ParseContext

log = logging.getLogger("minisiem.demo")


def seed_examples(conn) -> int:
    """Ingest every file in samples/examples/manifest.json and run detection. Returns alert count."""
    manifest = json.loads((config.EXAMPLES_DIR / "manifest.json").read_text(encoding="utf-8"))
    for entry in manifest:
        ctx = ParseContext.build(year=entry.get("year"), host=entry.get("host"))
        ingest_file(conn, config.EXAMPLES_DIR / entry["file"], entry["source_type"], ctx)
    return run_detection(conn)["new_alerts"]


def ensure_seeded() -> None:
    """Create and seed the database if this instance doesn't have one yet."""
    conn = db.connect()
    try:
        if conn.execute("SELECT 1 FROM events LIMIT 1").fetchone():
            return
        alerts = seed_examples(conn)
        log.info("Seeded demo database at %s with %d alerts", config.db_path(), alerts)
    finally:
        conn.close()

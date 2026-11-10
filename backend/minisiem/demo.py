"""Seeding for the hosted demo.

Serverless hosts (e.g. Vercel) give each instance a fresh, writable /tmp and nothing
else that persists. On cold start, the instance builds its own database from the
example logs, so every visitor sees a fully populated dashboard. Anything uploaded
afterwards lives only as long as that instance.
"""

import json
import logging
from datetime import datetime, timedelta, timezone

from . import config, db
from .detection import run_detection
from .models import parse_utc_string
from .ingest import ingest_file
from .parsers import ParseContext

log = logging.getLogger("minisiem.demo")

REPLAY_HOST = "demo-live"


def shift_events(conn, offset: timedelta) -> None:
    """Move every event's timestamp by `offset` (fingerprints don't include timestamps)."""
    modifier = f"{int(offset.total_seconds()):+d} seconds"
    conn.execute("UPDATE events SET timestamp = strftime('%Y-%m-%dT%H:%M:%SZ', timestamp, ?)", (modifier,))
    conn.commit()


def seed_examples(conn, now: datetime | None = None) -> int:
    """Ingest the manifest, shift the whole dataset so its newest event lands at now - 5 min,
    then run detection. Returns the new alert count."""
    now = now or datetime.now(timezone.utc)
    manifest = json.loads((config.EXAMPLES_DIR / "manifest.json").read_text(encoding="utf-8"))
    for entry in manifest:
        ctx = ParseContext.build(year=entry.get("year"), host=entry.get("host"))
        ingest_file(conn, config.EXAMPLES_DIR / entry["file"], entry["source_type"], ctx)
    newest = conn.execute("SELECT MAX(timestamp) FROM events").fetchone()[0]
    if newest:
        target = now - timedelta(minutes=5)
        shift_events(conn, target - parse_utc_string(newest))
    return run_detection(conn, skip_host=REPLAY_HOST)["new_alerts"]


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

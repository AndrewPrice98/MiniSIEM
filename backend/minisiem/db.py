"""SQLite storage for events and alerts."""

import sqlite3
from pathlib import Path

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY,
    fingerprint     TEXT NOT NULL UNIQUE,
    timestamp       TEXT NOT NULL,
    source_type     TEXT NOT NULL,
    host            TEXT,
    source_ip       TEXT,
    destination_ip  TEXT,
    user_name       TEXT,
    group_name      TEXT,
    event_category  TEXT,
    event_action    TEXT,
    event_outcome   TEXT,
    process         TEXT,
    message         TEXT,
    http_method     TEXT,
    url_path        TEXT,
    http_status     INTEGER,
    user_agent      TEXT,
    raw             TEXT NOT NULL,
    ingested_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts        ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source    ON events(source_type, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_user      ON events(user_name);
CREATE INDEX IF NOT EXISTS idx_events_host      ON events(host);

CREATE TABLE IF NOT EXISTS alerts (
    id                INTEGER PRIMARY KEY,
    fingerprint       TEXT NOT NULL UNIQUE,
    rule_id           TEXT NOT NULL,
    rule_title        TEXT NOT NULL,
    severity          TEXT NOT NULL,
    attack_technique  TEXT,
    attack_name       TEXT,
    attack_tactics    TEXT,
    host              TEXT,
    source_ip         TEXT,
    user_name         TEXT,
    summary           TEXT NOT NULL,
    first_seen        TEXT NOT NULL,
    last_seen         TEXT NOT NULL,
    event_count       INTEGER NOT NULL,
    status            TEXT NOT NULL DEFAULT 'new',
    created_at        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_last_seen ON alerts(last_seen);
CREATE INDEX IF NOT EXISTS idx_alerts_rule      ON alerts(rule_id);

CREATE TABLE IF NOT EXISTS alert_events (
    alert_id  INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    event_id  INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    PRIMARY KEY (alert_id, event_id)
);
CREATE INDEX IF NOT EXISTS idx_alert_events_event ON alert_events(event_id);
"""


def connect(path: Path | None = None) -> sqlite3.Connection:
    """Open the database, creating it and its schema if needed."""
    path = Path(path or config.db_path())
    path.parent.mkdir(parents=True, exist_ok=True)
    # FastAPI may run a dependency and its endpoint on different worker
    # threads; each request still gets its own connection.
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.executescript(SCHEMA)
    return conn


def reset(path: Path | None = None) -> None:
    """Delete all events and alerts."""
    conn = connect(path)
    try:
        conn.executescript("DELETE FROM alert_events; DELETE FROM alerts; DELETE FROM events;")
        conn.commit()
    finally:
        conn.close()

from datetime import datetime, timezone

from minisiem import db
from minisiem.demo import ensure_seeded, seed_examples


def test_ensure_seeded_populates_once(db_file):
    ensure_seeded()
    conn = db.connect(db_file)
    try:
        events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        alerts = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE host IS NULL OR host != 'demo-live'").fetchone()[0]
    finally:
        conn.close()
    assert events > 20_000 and alerts == 60

    ensure_seeded()  # a warm instance must not re-seed or duplicate
    conn = db.connect(db_file)
    try:
        assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == events
    finally:
        conn.close()


def test_seed_ends_at_present_and_keeps_60_alerts(db_file):
    now = datetime(2027, 3, 15, 12, 0, tzinfo=timezone.utc)
    conn = db.connect(db_file)
    try:
        seed_examples(conn, now=now)
        newest = conn.execute("SELECT MAX(timestamp) FROM events").fetchone()[0]
        assert newest == "2027-03-15T11:55:00Z"
        assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 60
        # first/last seen moved with the events
        assert conn.execute("SELECT MAX(last_seen) FROM alerts").fetchone()[0] <= newest
    finally:
        conn.close()

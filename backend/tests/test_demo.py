from minisiem import db
from minisiem.demo import ensure_seeded


def test_ensure_seeded_populates_once(db_file):
    ensure_seeded()
    conn = db.connect(db_file)
    try:
        events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    finally:
        conn.close()
    assert events > 20_000 and alerts == 60

    ensure_seeded()  # a warm instance must not re-seed or duplicate
    conn = db.connect(db_file)
    try:
        assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == events
    finally:
        conn.close()

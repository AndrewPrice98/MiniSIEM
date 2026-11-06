from minisiem import config
from minisiem.ingest import ingest_file

LINES = [
    "Nov  1 03:12:09 h sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2",
    "Nov  1 03:12:09 h sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2",  # legit repeat
    "",
    "this line is garbage",
]


def test_ingest_counts_and_stores(load, conn):
    r = load("auth", LINES)
    assert (r.lines, r.parsed, r.inserted, r.unparsed) == (3, 2, 2, 1)
    assert r.unparsed_samples == ["this line is garbage"]
    row = conn.execute("SELECT * FROM events").fetchone()
    assert row["raw"] == LINES[0] and row["timestamp"] == "2026-11-01T03:12:09Z"


def test_reingesting_same_lines_is_idempotent(load, conn):
    load("auth", LINES)
    r = load("auth", LINES)
    assert (r.inserted, r.duplicates) == (0, 2)
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 2


def test_sample_files_parse_cleanly(conn):
    for name, source in (("auth.log", "auth"), ("access.log", "web")):
        r = ingest_file(conn, config.SAMPLES_DIR / name, source)
        assert r.inserted > 100
        assert r.unparsed == 1  # each sample contains exactly one deliberately broken line

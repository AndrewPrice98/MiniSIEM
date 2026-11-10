import threading
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from minisiem import db
from minisiem.demo import REPLAY_HOST, catch_up, retime_line, seed_examples

NOW = datetime(2027, 3, 15, 12, 0, tzinfo=timezone.utc)


def count_replay(conn) -> int:
    return conn.execute("SELECT COUNT(*) FROM events WHERE host = ?", (REPLAY_HOST,)).fetchone()[0]


def test_retime_auth_line_sets_time_and_host():
    out = retime_line("auth", "Nov  1 03:12:09 web01 sshd[811]: Failed password for root from 1.2.3.4 port 22 ssh2",
                      datetime(2027, 3, 15, 3, 12, 9, tzinfo=timezone.utc), "demo-live")
    assert out.startswith("Mar 15 03:12:09 demo-live sshd[811]:")


def test_retime_auth_iso_line_sets_time_and_host():
    # samples/auth.log uses RFC 3339 headers
    out = retime_line("auth", "2026-11-01T03:12:09.201185+00:00 srv-bastion sshd[4075]: Accepted publickey",
                      datetime(2027, 3, 5, 3, 12, 9, tzinfo=timezone.utc), "demo-live")
    assert out.startswith("2027-03-05T03:12:09")
    assert " demo-live sshd[4075]: Accepted publickey" in out


def test_retime_auth_bsd_line_pads_single_digit_day():
    out = retime_line("auth", "Nov 11 03:12:09 web01 sshd[811]: x",
                      datetime(2027, 3, 5, 3, 12, 9, tzinfo=timezone.utc), "demo-live")
    assert out == "Mar  5 03:12:09 demo-live sshd[811]: x"


def test_retime_web_line():
    out = retime_line("web", '1.2.3.4 - - [01/Nov/2026:03:12:09 +0000] "GET / HTTP/1.1" 200 5 "-" "x"',
                      datetime(2027, 3, 15, 3, 12, 9, tzinfo=timezone.utc), "demo-live")
    assert "[15/Mar/2027:03:12:09 +0000]" in out


def test_first_catch_up_fills_last_24_hours_only(conn):
    n = catch_up(conn, NOW, throttle_seconds=0)
    lo, hi = conn.execute("SELECT MIN(timestamp), MAX(timestamp) FROM events WHERE host='demo-live'").fetchone()
    assert n > 0 and lo > "2027-03-14T12:00:00Z" and hi <= "2027-03-15T12:00:00Z"
    assert n == count_replay(conn)


def test_catch_up_adds_only_newly_due_events(conn):
    catch_up(conn, NOW, throttle_seconds=0)
    before = count_replay(conn)
    assert catch_up(conn, NOW, throttle_seconds=0) == 0            # nothing new is due
    added = catch_up(conn, NOW + timedelta(hours=6), throttle_seconds=0)
    assert count_replay(conn) == before + added
    assert catch_up(conn, NOW + timedelta(days=3), throttle_seconds=0) > 0   # days later still works


def test_catch_up_after_long_idle_only_fills_last_24_hours(conn):
    catch_up(conn, NOW, throttle_seconds=0)
    before = count_replay(conn)
    later = NOW + timedelta(days=10)
    added = catch_up(conn, later, throttle_seconds=0)
    # exactly one day's worth (the last 24 hours), nothing from the idle gap
    assert added == before
    gap = conn.execute(
        "SELECT COUNT(*) FROM events WHERE host='demo-live' AND timestamp > ? AND timestamp <= ?",
        ("2027-03-15T12:00:00Z", "2027-03-24T12:00:00Z"),
    ).fetchone()[0]
    assert gap == 0


def test_throttle_skips_recent_runs(conn):
    catch_up(conn, NOW, throttle_seconds=0)
    assert catch_up(conn, NOW + timedelta(hours=6), throttle_seconds=3600) == 0


def test_replay_raises_alerts_without_touching_base_alerts(conn):
    seed_examples(conn, now=NOW)
    catch_up(conn, NOW, throttle_seconds=0)
    assert conn.execute("SELECT COUNT(*) FROM alerts WHERE host='demo-live'").fetchone()[0] > 0
    assert conn.execute("SELECT COUNT(*) FROM alerts WHERE host IS NULL OR host!='demo-live'").fetchone()[0] == 60


def test_concurrent_catch_up_does_not_duplicate(db_file, tmp_path):
    single = db.connect(tmp_path / "single.db")
    try:
        expected = catch_up(single, NOW, throttle_seconds=0)
    finally:
        single.close()
    assert expected > 0

    db.connect(db_file).close()  # create the schema up front, as a cold start does
    barrier = threading.Barrier(2)
    errors: list[BaseException] = []

    def worker():
        conn = db.connect(db_file)
        try:
            barrier.wait()
            catch_up(conn, NOW, throttle_seconds=0)
        except BaseException as exc:  # noqa: BLE001 - reported below
            errors.append(exc)
        finally:
            conn.close()

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    conn = db.connect(db_file)
    try:
        assert count_replay(conn) == expected
    finally:
        conn.close()


def test_read_request_catches_up_in_demo_mode(db_file, monkeypatch):
    monkeypatch.setenv("MINISIEM_DEMO", "true")
    import minisiem.demo as demo
    monkeypatch.setattr(demo, "_last_run", None)
    r = TestClient(app_()).get("/api/events")
    assert r.status_code == 200
    conn = db.connect(db_file)
    try:
        assert count_replay(conn) > 0
    finally:
        conn.close()


def test_failed_catch_up_never_fails_a_read(db_file, monkeypatch):
    monkeypatch.setenv("MINISIEM_DEMO", "true")
    import minisiem.demo as demo

    def boom(*args, **kwargs):
        raise RuntimeError("database is locked")

    monkeypatch.setattr(demo, "catch_up", boom)
    assert TestClient(app_()).get("/api/events").status_code == 200


def app_():
    from minisiem.api import app
    return app

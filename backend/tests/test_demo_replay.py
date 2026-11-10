import threading
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

import pytest

from minisiem import db
from minisiem.demo import (ATTACK_END, ATTACK_START, REPLAY_HOST, _replay_lines, _replay_streams,
                           catch_up, retime_line, seed_examples)
from minisiem.parsers import ParseContext, get_parser

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


# The intrusion's attacker addresses (scripts/generate_attack.py).
ATTACKER_IPS = ("192.0.2.77", "203.0.113.45", "198.51.100.23")


@pytest.mark.parametrize("when", [
    datetime(2027, 3, 5, 0, 0, 1, tzinfo=timezone.utc),
    datetime(2027, 12, 31, 23, 59, 59, tzinfo=timezone.utc),
])
def test_every_cached_replay_line_retimes_and_parses_back(when):
    # A sample line catch_up can't retime would make every catch-up raise.
    lines = _replay_lines()
    assert len(lines) > 1000
    ctx = ParseContext.build(year=when.year, host=REPLAY_HOST)
    expected = when.strftime("%Y-%m-%dT%H:%M:%SZ")
    for _, source_type, line in lines:
        event = get_parser(source_type).parse_line(retime_line(source_type, line, when, REPLAY_HOST), ctx)
        assert event is not None and event.timestamp == expected and event.host == REPLAY_HOST, line


def test_attack_segment_holds_the_whole_intrusion():
    daily, hourly = _replay_streams()
    assert ATTACK_END - ATTACK_START < 3600           # one cycle fits in an hour
    assert len(daily) + len(hourly) == len(_replay_lines())
    assert all(0 <= offset <= ATTACK_END - ATTACK_START for offset, _, _ in hourly)
    assert not [line for _, _, line in daily if any(ip in line for ip in ATTACKER_IPS)]
    assert sum(any(ip in line for ip in ATTACKER_IPS) for _, _, line in hourly) > 100


def test_first_catch_up_fills_last_24_hours_only(conn):
    n = catch_up(conn, NOW, throttle_seconds=0)
    lo, hi = conn.execute("SELECT MIN(timestamp), MAX(timestamp) FROM events WHERE host='demo-live'").fetchone()
    assert n > 0 and lo > "2027-03-14T12:00:00Z" and hi <= "2027-03-15T12:00:00Z"
    assert n == count_replay(conn)
    # every hourly cycle and the daily background are distinct events (no fingerprint clashes)
    daily, hourly = _replay_streams()
    assert n == len(daily) + 24 * len(hourly)


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


def test_attack_alerts_arrive_every_hour_of_an_afternoon_visit(conn):
    start = datetime(2027, 3, 15, 15, 0, tzinfo=timezone.utc)
    catch_up(conn, start, throttle_seconds=0)       # cold start: backfill the last 24 hours
    now = start
    while now < start + timedelta(hours=6):       # a visitor polling every 10 minutes
        now += timedelta(minutes=10)
        catch_up(conn, now, throttle_seconds=0)
    rows = conn.execute(
        "SELECT rule_id, first_seen FROM alerts WHERE host = ? AND rule_id != 'MSIEM-006' "
        "AND first_seen > ? ORDER BY first_seen",
        (REPLAY_HOST, "2027-03-15T15:00:00Z"),
    ).fetchall()
    for hour in range(15, 21):
        in_hour = {r[0] for r in rows if r[1].startswith(f"2027-03-15T{hour:02d}:")}
        # every hour brings the brute force, the compromise and the persistence steps
        assert {"MSIEM-001", "MSIEM-002", "MSIEM-003", "MSIEM-004", "MSIEM-005", "MSIEM-008"} <= in_hour, hour
    # the scan opens each cycle at the top of the hour
    scans = [r[1] for r in rows if r[0] == "MSIEM-007"]
    assert scans == [f"2027-03-15T{h:02d}:00:00Z" for h in range(16, 21)]


def test_hourly_and_daily_replay_stay_idempotent(conn):
    catch_up(conn, NOW, throttle_seconds=0)
    for minutes in (7, 7, 61, 61, 125):
        catch_up(conn, NOW + timedelta(minutes=minutes), throttle_seconds=0)
    stepped = count_replay(conn)
    alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

    other = db.connect(conn.execute("PRAGMA database_list").fetchone()[2] + ".jump.db")
    try:
        catch_up(other, NOW, throttle_seconds=0)
        catch_up(other, NOW + timedelta(minutes=125), throttle_seconds=0)
        # stepping in small increments or one jump inserts exactly the same events and alerts
        assert count_replay(other) == stepped
        assert other.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == alerts
    finally:
        other.close()


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

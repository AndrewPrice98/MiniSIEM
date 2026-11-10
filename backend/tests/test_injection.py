import sqlite3

import pytest
from fastapi.testclient import TestClient

from minisiem import config
from minisiem.api import app

from .conftest import TEST_PASSWORD, TEST_USER

HOSTILE = ["'", "%", "_", "\\", "\" OR 1=1 --", "'; DROP TABLE events; --", "x" * 10_000]


@pytest.fixture
def client(db_file):
    """Logged-in admin client over a DB seeded from the sample logs (demo mode off)."""
    c = TestClient(app)
    r = c.post("/api/auth/login", json={"username": TEST_USER, "password": TEST_PASSWORD})
    assert r.status_code == 200, r.text
    for name, source, host in (("auth.log", "auth", "srv-bastion"), ("access.log", "web", "web01")):
        with open(config.SAMPLES_DIR / name, "rb") as fh:
            r = c.post("/api/ingest", data={"source_type": source, "host": host},
                       files={"file": (name, fh, "text/plain")})
        assert r.status_code == 200, r.text
    return c


@pytest.fixture
def db_still_has_tables(db_file):
    def check():
        c = sqlite3.connect(db_file)
        try:
            names = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            n_events = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        finally:
            c.close()
        return {"events", "alerts"} <= names and n_events > 0
    return check


@pytest.mark.parametrize("value", HOSTILE)
@pytest.mark.parametrize("path, param", [
    ("/api/alerts", "q"), ("/api/events", "q"),
    ("/api/alerts", "host"), ("/api/events", "user_name"), ("/api/events", "source_type"),
])
def test_hostile_filter_values_are_literal(client, db_still_has_tables, path, param, value):
    r = client.get(path, params={param: value})
    assert r.status_code in (200, 422)  # 422 only for over-length q
    if r.status_code == 422:
        assert param == "q" and len(value) > 200
    assert db_still_has_tables()


def test_percent_and_underscore_match_literally(client, load):
    load("auth", [
        "2026-11-02T10:00:00+00:00 srv1 sshd[1]: Failed password for invalid user 50%_off from 10.9.9.9 port 22 ssh2",
        "2026-11-02T10:00:01+00:00 srv1 sshd[1]: Failed password for invalid user 50xxoff from 10.9.9.9 port 22 ssh2",
    ])
    r = client.get("/api/events", params={"q": "50%_off"})
    assert r.status_code == 200
    assert r.json()["total"] == 1
    assert "50%_off" in r.json()["items"][0]["raw"]


@pytest.mark.parametrize("sort", ["timestamp; DROP TABLE alerts", "1", "severity desc"])
def test_unknown_sort_rejected(client, sort):
    assert client.get("/api/alerts", params={"sort": sort}).status_code == 400


def test_severity_list_with_quotes(client):
    r = client.get("/api/alerts", params=[("severity", "high' OR '1'='1")])
    assert r.json()["total"] == 0


def test_alerts_q_over_length_rejected(client):
    assert client.get("/api/alerts", params={"q": "x" * 201}).status_code == 422

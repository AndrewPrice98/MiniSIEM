import pytest
from fastapi.testclient import TestClient

from minisiem.api import app

from .test_auth import login


@pytest.fixture
def demo_env(monkeypatch, db_file):
    monkeypatch.setenv("MINISIEM_DEMO", "true")


def _write(client, path):
    if path == "/api/ingest":
        return client.post(
            path,
            files={"file": ("auth.log", b"Nov  9 10:00:00 host sshd[1]: test\n", "text/plain")},
            data={"source_type": "auth"},
        )
    return client.post(path)


def test_guest_reads_without_login(demo_env):
    c = TestClient(app)
    assert c.get("/api/auth/me").json() == {"username": "guest", "guest": True}
    assert c.get("/api/alerts").status_code == 200


def test_guest_works_even_without_admin_configured(demo_env, monkeypatch):
    monkeypatch.delenv("MINISIEM_ADMIN_PASSWORD_HASH")
    assert TestClient(app).get("/api/stats").status_code == 200


@pytest.mark.parametrize("path", ["/api/detect", "/api/ingest"])
def test_guest_cannot_write(demo_env, path):
    assert _write(TestClient(app), path).status_code == 403


def test_admin_still_writes_in_demo(demo_env):
    c = TestClient(app)
    login(c)
    assert c.get("/api/auth/me").json() == {"username": "admin", "guest": False}
    assert c.post("/api/detect").status_code == 200


def test_guest_can_be_disabled(demo_env, monkeypatch):
    monkeypatch.setenv("MINISIEM_GUEST", "false")
    assert TestClient(app).get("/api/alerts").status_code == 401


def test_health_reports_guest(demo_env):
    assert TestClient(app).get("/api/health").json()["guest"] is True


def test_no_guest_outside_demo(db_file):
    c = TestClient(app)
    assert c.get("/api/alerts").status_code == 401
    assert c.get("/api/health").json()["guest"] is False

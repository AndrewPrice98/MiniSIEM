from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi.testclient import TestClient

from minisiem import auth
from minisiem.api import app

from .conftest import TEST_PASSWORD, TEST_USER

PROTECTED = [
    ("get", "/api/auth/me"),
    ("get", "/api/alerts"),
    ("get", "/api/alerts/1"),
    ("get", "/api/events"),
    ("get", "/api/events/facets"),
    ("get", "/api/stats"),
    ("get", "/api/rules"),
    ("post", "/api/detect"),
    ("post", "/api/ingest"),
]


@pytest.fixture
def anon(db_file):
    return TestClient(app)


def login(client, username=TEST_USER, password=TEST_PASSWORD, **kw):
    return client.post("/api/auth/login", json={"username": username, "password": password}, **kw)


# -- password hashing ------------------------------------------------------------------------

def test_password_hash_roundtrip_and_salting():
    h1, h2 = auth.hash_password("s3cret-pass", 1000), auth.hash_password("s3cret-pass", 1000)
    assert h1 != h2  # random salt
    assert auth.verify_password("s3cret-pass", h1)
    assert not auth.verify_password("wrong", h1)
    assert "s3cret-pass" not in h1


@pytest.mark.parametrize("bad", ["", "plaintext", "md5:1:a:b", "pbkdf2_sha256:x:y:z"])
def test_malformed_hashes_never_verify(bad):
    assert not auth.verify_password("anything", bad)


# -- access control ----------------------------------------------------------------------------

@pytest.mark.parametrize("method, path", PROTECTED)
def test_protected_endpoints_require_login(anon, method, path):
    r = getattr(anon, method)(path)
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"


def test_health_is_public_and_reports_auth_state(anon):
    body = anon.get("/api/health").json()
    assert body["status"] == "ok" and body["auth_configured"] is True


def test_login_sets_hardened_cookie_and_grants_access(anon):
    r = login(anon)
    assert r.status_code == 200 and r.json()["username"] == TEST_USER
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie and "path=/api" in cookie
    assert anon.get("/api/auth/me").json() == {"username": TEST_USER, "guest": False}
    assert anon.get("/api/stats").status_code == 200


def test_cookie_is_secure_by_default(anon, monkeypatch):
    monkeypatch.delenv("MINISIEM_COOKIE_SECURE")
    assert "secure" in login(anon).headers["set-cookie"].lower()


def test_bearer_token_works_without_cookie(anon):
    token = login(TestClient(app)).json()["token"]
    r = anon.get("/api/alerts", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200


@pytest.mark.parametrize("username, password", [
    (TEST_USER, "wrong password"),
    ("root", TEST_PASSWORD),
    ("ADMIN", TEST_PASSWORD),
])
def test_bad_credentials_are_rejected_with_one_message(anon, username, password):
    r = login(anon, username, password)
    assert r.status_code == 401
    assert r.json()["detail"] == "Invalid username or password"
    assert "set-cookie" not in r.headers


def test_login_validates_input(anon):
    assert anon.post("/api/auth/login", json={"username": "", "password": "x"}).status_code == 422
    assert anon.post("/api/auth/login", json={"username": "a" * 500, "password": "x"}).status_code == 422


def test_logout_clears_cookie(anon):
    login(anon)
    anon.post("/api/auth/logout")
    assert anon.get("/api/auth/me").status_code == 401


# -- tokens ------------------------------------------------------------------------------------

def _token(secret="test-secret-" + "x" * 40, **claims):
    now = datetime.now(timezone.utc)
    payload = {"sub": TEST_USER, "iat": now, "exp": now + timedelta(hours=1), **claims}
    return jwt.encode(payload, secret, algorithm="HS256")


@pytest.mark.parametrize("token", [
    _token(exp=datetime.now(timezone.utc) - timedelta(seconds=5)),  # expired
    _token(secret="a-different-secret-" + "y" * 40),  # forged signature
    _token(sub="someone-else"),  # not the admin
    "not.a.jwt",
    jwt.encode({"sub": TEST_USER, "exp": 9999999999, "iat": 0}, key=None, algorithm="none"),  # unsigned
])
def test_invalid_tokens_are_rejected(anon, token):
    assert anon.get("/api/alerts", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_rotating_secret_invalidates_sessions(anon, monkeypatch):
    login(anon)
    monkeypatch.setenv("MINISIEM_SECRET_KEY", "rotated-secret-" + "z" * 40)
    assert anon.get("/api/auth/me").status_code == 401


# -- brute-force protection ----------------------------------------------------------------------

def test_failed_logins_are_rate_limited(anon):
    for _ in range(5):
        assert login(anon, password="nope").status_code == 401
    r = login(anon)  # even the right password is refused while locked out
    assert r.status_code == 429 and int(r.headers["retry-after"]) > 0


def test_successful_login_resets_failure_count(anon):
    for _ in range(4):
        login(anon, password="nope")
    assert login(anon).status_code == 200
    for _ in range(4):
        login(anon, password="nope")
    assert login(anon).status_code == 200


def test_forwarded_ip_only_trusted_when_configured(anon, monkeypatch):
    spoof = {"X-Forwarded-For": "1.2.3.4"}
    for i in range(5):
        login(anon, password="nope", headers={"X-Forwarded-For": f"9.9.9.{i}"})
    # Not trusting the header: all five failures counted against the real client.
    assert login(anon, headers=spoof).status_code == 429
    auth.limiter.reset()
    monkeypatch.setenv("MINISIEM_TRUST_PROXY", "true")
    for _ in range(5):
        login(anon, password="nope", headers=spoof)
    assert login(anon, headers=spoof).status_code == 429
    assert login(anon, headers={"X-Forwarded-For": "5.6.7.8"}).status_code == 200


# -- fail closed ----------------------------------------------------------------------------------

@pytest.mark.parametrize("var, value", [
    ("MINISIEM_ADMIN_PASSWORD_HASH", ""),
    ("MINISIEM_SECRET_KEY", ""),
    ("MINISIEM_SECRET_KEY", "too-short"),
])
def test_unconfigured_auth_fails_closed(anon, monkeypatch, var, value):
    monkeypatch.setenv(var, value)
    assert login(anon).status_code == 503
    assert anon.get("/api/alerts").status_code == 503
    assert anon.get("/api/health").json()["auth_configured"] is False

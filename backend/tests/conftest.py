import pytest

from minisiem import db, demo
from minisiem.auth import hash_password, limiter
from minisiem.detection import load_rules
from minisiem.ingest import ingest_lines
from minisiem.parsers import ParseContext


TEST_USER = "admin"
TEST_PASSWORD = "correct horse battery staple"
# Few iterations keep the suite fast; production hashes use auth.DEFAULT_ITERATIONS.
TEST_HASH = hash_password(TEST_PASSWORD, iterations=1_000)


@pytest.fixture(autouse=True)
def auth_env(monkeypatch):
    """Known admin credentials for every test, regardless of any local backend/.env."""
    monkeypatch.setenv("MINISIEM_ADMIN_USER", TEST_USER)
    monkeypatch.setenv("MINISIEM_ADMIN_PASSWORD_HASH", TEST_HASH)
    monkeypatch.setenv("MINISIEM_SECRET_KEY", "test-secret-" + "x" * 40)
    monkeypatch.setenv("MINISIEM_COOKIE_SECURE", "false")  # TestClient talks plain http
    monkeypatch.setenv("MINISIEM_TRUST_PROXY", "false")
    limiter.reset()
    yield
    limiter.reset()


@pytest.fixture(autouse=True)
def reset_demo_replay(monkeypatch):
    """Each test starts with the replay throttle cleared, so a catch-up in one test can't
    make another test's catch-up a silent no-op. The parsed-line cache (_replay_cache) is
    read-only data from samples/ and is kept for speed."""
    monkeypatch.setattr(demo, "_last_run", None)


@pytest.fixture
def db_file(tmp_path, monkeypatch):
    path = tmp_path / "test.db"
    monkeypatch.setenv("MINISIEM_DB", str(path))
    return path


@pytest.fixture
def conn(db_file):
    c = db.connect(db_file)
    yield c
    c.close()


@pytest.fixture(scope="session")
def rules():
    return {r.id: r for r in load_rules()}


@pytest.fixture
def ctx():
    return ParseContext.build(year=2026, host="testhost")


@pytest.fixture
def load(conn, ctx):
    """Ingest lines into the test DB: load('auth', [...])."""
    def _load(source_type, lines):
        return ingest_lines(conn, lines, source_type, ctx)
    return _load

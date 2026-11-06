import pytest

from minisiem import db
from minisiem.detection import load_rules
from minisiem.ingest import ingest_lines
from minisiem.parsers import ParseContext


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

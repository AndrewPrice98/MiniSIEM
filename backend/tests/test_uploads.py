import pytest
from fastapi.testclient import TestClient

from minisiem import config
from minisiem.api import app
from minisiem.uploads import UploadError, decode_log_upload

from .test_auth import login


@pytest.fixture
def admin_client(db_file):
    c = TestClient(app)
    assert login(c).status_code == 200
    return c


def test_bom_and_crlf_accepted():
    assert decode_log_upload(b"\xef\xbb\xbfa\r\nb\r\n") == ["a", "b"]


def test_nul_rejected():
    with pytest.raises(UploadError) as e:
        decode_log_upload(b"a\x00b")
    assert e.value.status == 415


def test_invalid_utf8_rejected():
    with pytest.raises(UploadError) as e:
        decode_log_upload(b"\xff\xfe\xfa")
    assert e.value.status == 415


def test_long_line_rejected_with_line_number():
    with pytest.raises(UploadError) as e:
        decode_log_upload(b"ok\n" + b"x" * 9000)
    assert e.value.status == 413 and "Line 2" in str(e.value)


def test_crlf_bom_upload_matches_clean_upload(admin_client, tmp_path, monkeypatch):
    raw = (config.SAMPLES_DIR / "auth.log").read_bytes()
    messy = b"\xef\xbb\xbf" + raw.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")

    def upload(content):
        r = admin_client.post("/api/ingest", data={"source_type": "auth"},
                              files={"file": ("auth.log", content)})
        assert r.status_code == 200, r.text
        return r.json()["ingest"]["inserted"]

    clean = upload(raw)
    monkeypatch.setenv("MINISIEM_DB", str(tmp_path / "second.db"))
    assert upload(messy) == clean > 100


def test_endpoint_maps_errors(admin_client):
    post = lambda c: admin_client.post("/api/ingest", data={"source_type": "auth"},
                                       files={"file": ("a.log", c)})
    assert post(b"\xff\xfe\xfa").status_code == 415
    r = post(b"x" * 9000)
    assert r.status_code == 413 and "Line 1" in r.text

import pytest
from fastapi.testclient import TestClient

from minisiem import config
from minisiem.api import app


@pytest.fixture
def client(db_file):
    return TestClient(app)


@pytest.fixture
def loaded(client):
    for name, source, host in (("auth.log", "auth", "srv-bastion"), ("access.log", "web", "web01")):
        with open(config.SAMPLES_DIR / name, "rb") as fh:
            r = client.post("/api/ingest", data={"source_type": source, "host": host},
                            files={"file": (name, fh, "text/plain")})
        assert r.status_code == 200, r.text
    return client


def test_health(client):
    assert client.get("/api/health").json()["status"] == "ok"


def test_ingest_returns_counts_and_runs_detection(client):
    with open(config.SAMPLES_DIR / "auth.log", "rb") as fh:
        body = client.post("/api/ingest", data={"source_type": "auth"},
                           files={"file": ("auth.log", fh)}).json()
    assert body["ingest"]["inserted"] > 100
    assert body["detection"]["new_alerts"] > 0


def test_ingest_rejects_unknown_source_bad_type_binary_and_large(client, monkeypatch):
    def post(name, content, source="auth"):
        return client.post("/api/ingest", data={"source_type": source}, files={"file": (name, content)})

    assert post("a.log", b"x", source="windows").status_code == 400
    assert post("evil.exe", b"x").status_code == 415
    assert post("a.log", b"abc\x00def").status_code == 415
    assert post("auth.log.1", b"Nov  1 00:00:00 h sshd[1]: x").status_code == 200
    monkeypatch.setenv("MINISIEM_MAX_UPLOAD_MB", "0")
    assert post("a.log", b"x").status_code == 413


def test_alerts_list_filter_and_sort(loaded):
    body = loaded.get("/api/alerts", params={"limit": 100}).json()
    assert body["total"] == 15
    crit = loaded.get("/api/alerts", params={"severity": "critical"}).json()
    assert crit["total"] == 1 and crit["items"][0]["rule_id"] == "MSIEM-002"
    multi = loaded.get("/api/alerts", params=[("severity", "critical"), ("severity", "high")]).json()
    assert {a["severity"] for a in multi["items"]} == {"critical", "high"}
    by_sev = loaded.get("/api/alerts", params={"sort": "severity", "order": "desc"}).json()
    assert by_sev["items"][0]["severity"] == "critical"
    assert isinstance(by_sev["items"][0]["attack_tactics"], list)
    assert loaded.get("/api/alerts", params={"sort": "id; DROP TABLE alerts"}).status_code == 400


def test_alert_detail_includes_events_and_rule(loaded):
    alert = loaded.get("/api/alerts", params={"rule_id": "MSIEM-002"}).json()["items"][0]
    detail = loaded.get(f"/api/alerts/{alert['id']}").json()
    assert len(detail["events"]) == detail["event_count"] == 8
    assert all(e["raw"] for e in detail["events"])
    assert detail["rule"]["attack_technique"] == "T1078"
    assert loaded.get("/api/alerts/999999").status_code == 404


def test_events_search(loaded):
    body = loaded.get("/api/events", params={"source_ip": "198.51.100.23"}).json()
    assert body["total"] >= 8
    kw = loaded.get("/api/events", params={"q": "svc-backup"}).json()
    assert kw["total"] >= 3 and all("svc-backup" in e["raw"] for e in kw["items"])
    # LIKE wildcards in input are matched literally, not as wildcards.
    # As a wildcard, "s%d" would match almost every line; literally it matches none.
    assert loaded.get("/api/events", params={"q": "s%d"}).json()["total"] == 0
    ranged = loaded.get("/api/events", params={"start": "2026-11-01T03:00:00Z",
                                               "end": "2026-11-01T03:30:00Z"}).json()
    assert all("2026-11-01T03:00:00Z" <= e["timestamp"] <= "2026-11-01T03:30:00Z" for e in ranged["items"])
    assert loaded.get("/api/events", params={"start": "yesterday"}).status_code == 400
    assert loaded.get("/api/events", params={"limit": 10_000}).status_code == 422


def test_stats(loaded):
    s = loaded.get("/api/stats").json()
    assert s["total_alerts"] == 15
    assert s["alerts_by_severity"]["critical"] == 1
    assert s["bucket"] == "hour" and len(s["timeline"]) == 24
    assert sum(b["events"] for b in s["timeline"]) == s["total_events"]
    assert s["top_source_ips"][0]["value"] == "192.0.2.77"
    assert s["top_targeted_users"][0]["value"] in ("root", "deploy")


def test_rules_include_alert_counts(loaded):
    rules = loaded.get("/api/rules").json()
    assert len(rules) == 8
    assert all(r["alert_count"] > 0 for r in rules)


def test_detect_endpoint_is_idempotent(loaded):
    assert loaded.post("/api/detect").json()["new_alerts"] == 0

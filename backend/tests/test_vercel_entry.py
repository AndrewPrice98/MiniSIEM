"""Smoke test for the Vercel entry point (api/index.py)."""

import importlib.util
import sys

from fastapi.testclient import TestClient

from minisiem import config

ENTRY = config.REPO_DIR / "api" / "index.py"
PATH_AT_IMPORT = list(sys.path)


def test_vercel_entry_serves_seeded_demo_to_guests(tmp_path, monkeypatch):
    monkeypatch.setenv("MINISIEM_DB", str(tmp_path / "vercel.db"))
    # Hosted-demo defaults: let api/index.py set these itself. setenv first so monkeypatch
    # records each variable's original state (delenv alone records nothing for an unset
    # variable), which removes whatever the entry point sets once the test ends.
    for name in ("MINISIEM_DEMO", "MINISIEM_GUEST", "MINISIEM_TRUST_PROXY", "MINISIEM_MAX_UPLOAD_MB",
                 "MINISIEM_ADMIN_PASSWORD_HASH", "MINISIEM_SECRET_KEY"):
        monkeypatch.setenv(name, "")
        monkeypatch.delenv(name)
    monkeypatch.setattr(sys, "path", list(sys.path))  # the entry point prepends backend/

    spec = importlib.util.spec_from_file_location("vercel_entry_under_test", ENTRY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # seeds the database, like a cold start

    client = TestClient(module.app)
    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.json()["demo"] is True and health.json()["auth_configured"] is False
    alerts = client.get("/api/alerts")
    assert alerts.status_code == 200
    assert alerts.json()["total"] > 60  # the 60 base alerts plus the live replay's


def test_vercel_entry_leaves_no_settings_behind():
    # Runs after the smoke test in file order: the entry point's setdefault()s were undone.
    import os
    assert "MINISIEM_DEMO" not in os.environ and "MINISIEM_MAX_UPLOAD_MB" not in os.environ
    assert os.environ["MINISIEM_TRUST_PROXY"] == "false"  # conftest's value, not the entry point's
    assert sys.path == PATH_AT_IMPORT  # the entry point's sys.path.insert was undone

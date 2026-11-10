"""Vercel entry point: serves the MiniSIEM FastAPI app as a Python serverless function.

vercel.json rewrites every /api/* request here; FastAPI routes on the original path.
Each function instance builds its own SQLite database in /tmp from samples/examples/
on cold start, so the hosted site is a self-contained demo. ensure_seeded() also runs the
first live-replay catch-up (the last 24 hours of the sample intrusion on host demo-live);
after that, requests keep the replay current (see minisiem.demo.catch_up).
"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

# The admin variables (MINISIEM_ADMIN_PASSWORD_HASH, MINISIEM_SECRET_KEY) are optional here:
# without them visitors browse as a read-only guest and nobody can log in.
# Serverless defaults; any of these can be overridden in Vercel's environment settings.
os.environ.setdefault("MINISIEM_DB", "/tmp/minisiem.db")  # /tmp is the only writable path
os.environ.setdefault("MINISIEM_DEMO", "true")
os.environ.setdefault("MINISIEM_TRUST_PROXY", "true")  # Vercel sets X-Forwarded-For itself
os.environ.setdefault("MINISIEM_MAX_UPLOAD_MB", "4")  # Vercel caps request bodies at 4.5 MB

from minisiem.api import app  # noqa: E402
from minisiem.demo import ensure_seeded  # noqa: E402

ensure_seeded()

__all__ = ["app"]

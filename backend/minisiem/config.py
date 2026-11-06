"""Runtime configuration, read from environment variables.

Values are read through functions (not module constants) so tests can
override them with environment variables at any time.
"""

import os
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
REPO_DIR = BACKEND_DIR.parent
SAMPLES_DIR = REPO_DIR / "samples"


def db_path() -> Path:
    return Path(os.environ.get("MINISIEM_DB", BACKEND_DIR / "data" / "minisiem.db"))


def rules_dir() -> Path:
    return Path(os.environ.get("MINISIEM_RULES", BACKEND_DIR / "rules"))


def max_upload_bytes() -> int:
    return int(os.environ.get("MINISIEM_MAX_UPLOAD_MB", "10")) * 1024 * 1024

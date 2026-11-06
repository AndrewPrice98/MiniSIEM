"""Runtime configuration, read from environment variables.

Values are read through functions (not module constants) so tests can
override them with environment variables at any time.

For local development, variables can also live in backend/.env (git-ignored).
Real environment variables always win, so a hosting provider's settings
(e.g. Vercel project environment variables) take precedence.
"""

import os
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
REPO_DIR = BACKEND_DIR.parent
SAMPLES_DIR = REPO_DIR / "samples"
EXAMPLES_DIR = SAMPLES_DIR / "examples"
ENV_FILE = BACKEND_DIR / ".env"


def load_env_file(path: Path = ENV_FILE) -> None:
    """Minimal .env loader: KEY=VALUE lines, '#' comments, optional quotes.
    Never overrides variables that are already set."""
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        os.environ.setdefault(key.strip(), value)


load_env_file()


def _flag(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def db_path() -> Path:
    return Path(os.environ.get("MINISIEM_DB", BACKEND_DIR / "data" / "minisiem.db"))


def rules_dir() -> Path:
    return Path(os.environ.get("MINISIEM_RULES", BACKEND_DIR / "rules"))


def max_upload_bytes() -> int:
    return int(os.environ.get("MINISIEM_MAX_UPLOAD_MB", "10")) * 1024 * 1024


# -- authentication --------------------------------------------------------------------

def admin_user() -> str:
    return os.environ.get("MINISIEM_ADMIN_USER", "admin")


def admin_password_hash() -> str:
    return os.environ.get("MINISIEM_ADMIN_PASSWORD_HASH", "")


def secret_key() -> str:
    """Key that signs session tokens. Must be long and random; rotating it logs everyone out."""
    return os.environ.get("MINISIEM_SECRET_KEY", "")


def session_hours() -> float:
    return float(os.environ.get("MINISIEM_SESSION_HOURS", "8"))


def cookie_secure() -> bool:
    """Send the session cookie over HTTPS only. On by default (production); the local
    .env written by `create-admin` turns it off for plain-http development."""
    return _flag("MINISIEM_COOKIE_SECURE", True)


def demo_mode() -> bool:
    """Hosted demo: data is seeded from the example logs and uploads are temporary."""
    return _flag("MINISIEM_DEMO", False)


def trust_proxy() -> bool:
    """Use X-Forwarded-For for the client IP. Enable only behind a proxy you control."""
    return _flag("MINISIEM_TRUST_PROXY", False)

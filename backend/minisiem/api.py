"""REST API serving events, alerts, stats, and rules to the dashboard."""

import logging
import sqlite3
from datetime import timedelta
from typing import Annotated, Iterator

from fastapi import APIRouter, Depends, FastAPI, File, Form, HTTPException, Query, Request, Response, UploadFile
from pydantic import BaseModel, Field

from . import __version__, auth, config, db, demo
from .detection import load_rules, run_detection
from .ingest import ingest_lines
from .models import parse_utc_string, to_utc_string
from .parsers import PARSERS, ParseContext

app = FastAPI(
    title="MiniSIEM API",
    version=__version__,
    description="Log ingestion, detection, and alert triage for MiniSIEM.",
)

SEVERITY_ORDER = "CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END"
ALERT_SORTS = {
    "last_seen": "last_seen",
    "first_seen": "first_seen",
    "severity": SEVERITY_ORDER,
    "rule_id": "rule_id",
    "host": "host",
    "source_ip": "source_ip",
    "event_count": "event_count",
    "status": "status",
}
ALLOWED_UPLOAD_SUFFIXES = (".log", ".txt")

log = logging.getLogger("minisiem.api")


def get_conn() -> Iterator[sqlite3.Connection]:
    conn = db.connect()
    try:
        if config.demo_mode():
            # The demo replays its sample intrusion live; a failed catch-up must never
            # fail the request it rode in on.
            try:
                demo.catch_up(conn)
            except Exception:
                conn.rollback()
                log.exception("Demo replay catch-up failed; serving the request anyway")
        yield conn
    finally:
        conn.close()


Conn = Annotated[sqlite3.Connection, Depends(get_conn)]


# -- query helpers ------------------------------------------------------------

def _iso(value: str | None, name: str) -> str | None:
    if not value:
        return None
    try:
        return to_utc_string(parse_utc_string(value))
    except ValueError:
        raise HTTPException(400, f"{name} must be an ISO 8601 timestamp") from None


def _like(value: str) -> str:
    """Escape LIKE wildcards so user input is matched literally."""
    return "%" + value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


class Where:
    """Builds a parameterized WHERE clause. User input never enters the SQL text."""

    def __init__(self):
        self.clauses: list[str] = []
        self.params: list = []

    def add(self, clause: str, *params):
        self.clauses.append(clause)
        self.params.extend(params)

    def eq(self, column: str, value):
        if value not in (None, ""):
            self.add(f"{column} = ?", value)

    def sql(self) -> str:
        return ("WHERE " + " AND ".join(self.clauses)) if self.clauses else ""


def _rows(cur) -> list[dict]:
    return [dict(r) for r in cur]


def _alert_out(row: dict) -> dict:
    row = dict(row)
    row.pop("fingerprint", None)
    row["attack_tactics"] = [t for t in (row.get("attack_tactics") or "").split(",") if t]
    return row


def _event_out(row: dict) -> dict:
    row = dict(row)
    row.pop("fingerprint", None)
    return row


# -- public endpoints -------------------------------------------------------------

@app.get("/api/health")
def health():
    return {"status": "ok", "version": __version__, "auth_configured": auth.is_configured(),
            "demo": config.demo_mode(), "guest": config.guest_enabled()}


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


def _set_session_cookie(response: Response, token: str, expires) -> None:
    response.set_cookie(
        auth.COOKIE_NAME,
        token,
        expires=expires,
        httponly=True,  # not readable from JavaScript
        secure=config.cookie_secure(),  # HTTPS only (off for local http dev)
        samesite="strict",  # never sent on cross-site requests, which blocks CSRF
        path="/api",
    )


@app.post("/api/auth/login")
def login(body: LoginRequest, request: Request, response: Response):
    if not auth.is_configured():
        raise HTTPException(503, "Authentication is not configured. Run: python -m minisiem create-admin")
    ip = auth.client_ip(request)
    wait = auth.limiter.retry_after(ip)
    if wait:
        raise HTTPException(429, "Too many failed logins. Try again later.",
                            headers={"Retry-After": str(wait)})
    if not auth.check_credentials(body.username, body.password):
        auth.limiter.record_failure(ip)
        # Same message for unknown user and wrong password.
        raise HTTPException(401, "Invalid username or password")
    auth.limiter.reset(ip)
    token, expires = auth.issue_token(body.username)
    _set_session_cookie(response, token, expires)
    # The token is also returned for API clients (curl, scripts) that use a Bearer header.
    # The dashboard ignores it and relies on the httpOnly cookie.
    return {"username": body.username, "expires_at": to_utc_string(expires), "token": token}


@app.post("/api/auth/logout")
def logout(response: Response):
    response.delete_cookie(auth.COOKIE_NAME, path="/api", httponly=True,
                           secure=config.cookie_secure(), samesite="strict")
    return {"ok": True}


# -- authenticated endpoints ------------------------------------------------------

protected = APIRouter(dependencies=[Depends(auth.require_user)])


@protected.get("/api/auth/me")
def me(user: Annotated[str, Depends(auth.require_user)]):
    return {"username": user, "guest": user == auth.GUEST_USER}


@protected.get("/api/alerts")
def list_alerts(
    conn: Conn,
    severity: Annotated[list[str] | None, Query()] = None,
    rule_id: str | None = None,
    host: str | None = None,
    source_ip: str | None = None,
    user_name: str | None = None,
    status: str | None = None,
    technique: str | None = None,
    start: str | None = None,
    end: str | None = None,
    q: Annotated[str | None, Query(max_length=200)] = None,
    sort: str = "last_seen",
    order: str = "desc",
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    if sort not in ALERT_SORTS:
        raise HTTPException(400, f"sort must be one of {sorted(ALERT_SORTS)}")
    if order not in ("asc", "desc"):
        raise HTTPException(400, "order must be asc or desc")
    w = Where()
    if severity:
        w.add(f"severity IN ({', '.join('?' for _ in severity)})", *severity)
    w.eq("rule_id", rule_id)
    w.eq("host", host)
    w.eq("source_ip", source_ip)
    w.eq("user_name", user_name)
    w.eq("status", status)
    w.eq("attack_technique", technique)
    if s := _iso(start, "start"):
        w.add("last_seen >= ?", s)
    if e := _iso(end, "end"):
        w.add("first_seen <= ?", e)
    if q:
        w.add("(summary LIKE ? ESCAPE '\\' OR rule_title LIKE ? ESCAPE '\\')", _like(q), _like(q))

    total = conn.execute(f"SELECT COUNT(*) FROM alerts {w.sql()}", w.params).fetchone()[0]
    rows = conn.execute(
        f"SELECT * FROM alerts {w.sql()} ORDER BY {ALERT_SORTS[sort]} {order.upper()}, id DESC "
        "LIMIT ? OFFSET ?",
        [*w.params, limit, offset],
    )
    return {"total": total, "limit": limit, "offset": offset, "items": [_alert_out(r) for r in rows]}


@protected.get("/api/alerts/{alert_id}")
def get_alert(alert_id: int, conn: Conn):
    row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "alert not found")
    events = conn.execute(
        "SELECT e.* FROM events e JOIN alert_events ae ON ae.event_id = e.id "
        "WHERE ae.alert_id = ? ORDER BY e.timestamp, e.id",
        (alert_id,),
    )
    rule = next((r for r in load_rules() if r.id == row["rule_id"]), None)
    return {
        **_alert_out(row),
        "rule": rule.to_public() if rule else None,
        "events": [_event_out(e) for e in events],
    }


@protected.get("/api/events")
def list_events(
    conn: Conn,
    source_type: str | None = None,
    host: str | None = None,
    user_name: str | None = None,
    source_ip: str | None = None,
    event_action: str | None = None,
    event_outcome: str | None = None,
    start: str | None = None,
    end: str | None = None,
    q: Annotated[str | None, Query(max_length=200)] = None,
    order: str = "desc",
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    if order not in ("asc", "desc"):
        raise HTTPException(400, "order must be asc or desc")
    w = Where()
    w.eq("source_type", source_type)
    w.eq("host", host)
    w.eq("user_name", user_name)
    w.eq("source_ip", source_ip)
    w.eq("event_action", event_action)
    w.eq("event_outcome", event_outcome)
    if s := _iso(start, "start"):
        w.add("timestamp >= ?", s)
    if e := _iso(end, "end"):
        w.add("timestamp <= ?", e)
    if q:
        w.add("raw LIKE ? ESCAPE '\\'", _like(q))
    total = conn.execute(f"SELECT COUNT(*) FROM events {w.sql()}", w.params).fetchone()[0]
    rows = conn.execute(
        f"SELECT * FROM events {w.sql()} ORDER BY timestamp {order.upper()}, id {order.upper()} "
        "LIMIT ? OFFSET ?",
        [*w.params, limit, offset],
    )
    return {"total": total, "limit": limit, "offset": offset, "items": [_event_out(r) for r in rows]}


@protected.get("/api/events/facets")
def event_facets(conn: Conn):
    """Distinct values for the search filters' dropdowns."""
    def distinct(col):
        return [r[0] for r in conn.execute(
            f"SELECT {col} FROM events WHERE {col} IS NOT NULL GROUP BY {col} ORDER BY COUNT(*) DESC LIMIT 50"
        )]
    return {col: distinct(col) for col in ("source_type", "host", "event_action", "event_outcome")}


@protected.get("/api/stats")
def stats(conn: Conn, start: str | None = None, end: str | None = None):
    ew, aw = Where(), Where()
    if s := _iso(start, "start"):
        ew.add("timestamp >= ?", s)
        aw.add("last_seen >= ?", s)
    if e := _iso(end, "end"):
        ew.add("timestamp <= ?", e)
        aw.add("first_seen <= ?", e)

    total_events = conn.execute(f"SELECT COUNT(*) FROM events {ew.sql()}", ew.params).fetchone()[0]
    by_sev = dict(conn.execute(
        f"SELECT severity, COUNT(*) FROM alerts {aw.sql()} GROUP BY severity", aw.params
    ).fetchall())
    alerts_by_severity = {s: by_sev.get(s, 0) for s in ("critical", "high", "medium", "low")}

    span = conn.execute(f"SELECT MIN(timestamp), MAX(timestamp) FROM events {ew.sql()}", ew.params).fetchone()
    timeline, bucket = [], "hour"
    if span[0]:
        lo, hi = parse_utc_string(span[0]), parse_utc_string(span[1])
        bucket = "hour" if hi - lo <= timedelta(days=3) else "day"
        width = 13 if bucket == "hour" else 10
        counts = conn.execute(
            f"SELECT substr(timestamp, 1, {width}) AS b, COUNT(*), "
            "SUM(CASE WHEN event_outcome = 'failure' THEN 1 ELSE 0 END) "
            f"FROM events {ew.sql()} GROUP BY b ORDER BY b",
            ew.params,
        ).fetchall()
        alert_counts = dict(conn.execute(
            f"SELECT substr(first_seen, 1, {width}) AS b, COUNT(*) FROM alerts {aw.sql()} GROUP BY b",
            aw.params,
        ).fetchall())
        found = {b: (n, f) for b, n, f in counts}
        # Fill empty buckets so the chart has a continuous time axis.
        step = timedelta(hours=1) if bucket == "hour" else timedelta(days=1)
        cur = lo.replace(minute=0, second=0) if bucket == "hour" else lo.replace(hour=0, minute=0, second=0)
        while cur <= hi:
            key = to_utc_string(cur)[:width]
            n, f = found.get(key, (0, 0))
            timeline.append({"bucket": to_utc_string(cur), "events": n, "failures": f,
                             "alerts": alert_counts.get(key, 0)})
            cur += step

    top_ips = _rows(conn.execute(
        f"SELECT source_ip AS value, COUNT(*) AS alerts, MAX({SEVERITY_ORDER}) AS max_sev "
        f"FROM alerts {aw.sql()} {'AND' if aw.clauses else 'WHERE'} source_ip IS NOT NULL "
        "GROUP BY source_ip ORDER BY alerts DESC, max_sev DESC LIMIT 8",
        aw.params,
    ))
    sev_names = {4: "critical", 3: "high", 2: "medium", 1: "low"}
    for r in top_ips:
        r["max_severity"] = sev_names[r.pop("max_sev")]

    top_users = _rows(conn.execute(
        f"SELECT user_name AS value, COUNT(*) AS failures FROM events {ew.sql()} "
        f"{'AND' if ew.clauses else 'WHERE'} event_outcome = 'failure' AND user_name IS NOT NULL "
        "AND event_category = 'authentication' AND event_action = 'ssh_login' "
        "GROUP BY user_name ORDER BY failures DESC LIMIT 8",
        ew.params,
    ))
    by_source = dict(conn.execute(
        f"SELECT source_type, COUNT(*) FROM events {ew.sql()} GROUP BY source_type", ew.params
    ).fetchall())

    return {
        "total_events": total_events,
        "total_alerts": sum(alerts_by_severity.values()),
        "alerts_by_severity": alerts_by_severity,
        "events_by_source": by_source,
        "bucket": bucket,
        "timeline": timeline,
        "top_source_ips": top_ips,
        "top_targeted_users": top_users,
        "time_range": {"start": span[0], "end": span[1]},
    }


@protected.get("/api/rules")
def list_rules(conn: Conn):
    counts = {r[0]: (r[1], r[2]) for r in conn.execute(
        "SELECT rule_id, COUNT(*), MAX(last_seen) FROM alerts GROUP BY rule_id"
    )}
    out = []
    for rule in load_rules():
        n, last = counts.get(rule.id, (0, None))
        out.append({**rule.to_public(), "alert_count": n, "last_alert": last})
    return out


@protected.post("/api/detect")
def detect(conn: Conn, _user: Annotated[str, Depends(auth.require_writer)]):
    return run_detection(conn)


@protected.post("/api/ingest")
def ingest(
    conn: Conn,
    _user: Annotated[str, Depends(auth.require_writer)],
    file: Annotated[UploadFile, File(description="Log file (.log or .txt)")],
    source_type: Annotated[str, Form()],
    host: Annotated[str | None, Form(max_length=255)] = None,
    year: Annotated[int | None, Form(ge=1970, le=2100)] = None,
    tz_offset: Annotated[float, Form(ge=-14, le=14)] = 0,
):
    if source_type not in PARSERS:
        raise HTTPException(400, f"source_type must be one of {sorted(PARSERS)}")
    name = (file.filename or "").lower()
    base = name.rstrip("0123456789").rstrip(".")  # allow rotated files: auth.log.1
    if "." in name and not base.endswith(ALLOWED_UPLOAD_SUFFIXES):
        raise HTTPException(415, "Only .log or .txt files are accepted")

    limit = config.max_upload_bytes()
    data = file.file.read(limit + 1)
    if len(data) > limit:
        raise HTTPException(413, f"File too large (max {limit // (1024 * 1024)} MB)")
    if b"\x00" in data:
        raise HTTPException(415, "File looks binary, expected a text log")

    text = data.decode("utf-8", errors="replace")
    ctx = ParseContext.build(year=year, tz_offset_hours=tz_offset, host=host)
    result = ingest_lines(conn, text.splitlines(), source_type, ctx)
    detection = run_detection(conn)
    return {"ingest": result.to_dict(), "detection": detection}


# Registered last so every @protected route above is included.
app.include_router(protected)

"""Seeding for the hosted demo.

Serverless hosts (e.g. Vercel) give each instance a fresh, writable /tmp and nothing
else that persists. On cold start, the instance builds its own database from the
example logs, so every visitor sees a fully populated dashboard. Anything uploaded
afterwards lives only as long as that instance.

To look alive, the demo also replays the sample intrusion (samples/auth.log and
samples/access.log) on host REPLAY_HOST: every source line keeps its time of day and
is inserted once that time has passed on the current date (see catch_up). Requests
trigger the catch-up, so a visitor at any time sees new events and alerts arriving.
"""

import json
import logging
import re
import threading
import time
from datetime import datetime, timedelta, timezone

from . import config, db
from .detection import run_detection
from .models import parse_utc_string
from .ingest import ingest_file, ingest_lines
from .parsers import ParseContext, get_parser

log = logging.getLogger("minisiem.demo")

REPLAY_HOST = "demo-live"
REPLAY_SOURCES = (("auth", "auth.log"), ("web", "access.log"))
REPLAY_WINDOW = timedelta(hours=24)
DEFAULT_THROTTLE_SECONDS = 10.0

_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

# Header up to and including the hostname field, in both auth.log styles.
_AUTH_BSD = re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2} \S+ ")
_AUTH_ISO = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?P<frac>\.\d+)?(?:Z|[+-]\d{2}:?\d{2})? \S+ "
)
# Access log: "ip ident user [timestamp]"
_WEB_TS = re.compile(r"^(?P<prefix>\S+ \S+ \S+ )\[[^\]]+\]")

_replay_cache: list[tuple[int, str, str]] | None = None  # (UTC second of day, source_type, line)
_lock = threading.Lock()  # one catch-up at a time per process
_last_run: float | None = None  # time.monotonic() of the last catch-up
_seed_lock = threading.Lock()


def shift_events(conn, offset: timedelta) -> None:
    """Move every event's timestamp by `offset` (fingerprints don't include timestamps)."""
    modifier = f"{int(offset.total_seconds()):+d} seconds"
    conn.execute("UPDATE events SET timestamp = strftime('%Y-%m-%dT%H:%M:%SZ', timestamp, ?)", (modifier,))
    conn.commit()


def seed_examples(conn, now: datetime | None = None) -> int:
    """Ingest the manifest, shift the whole dataset so its newest event lands at now - 5 min,
    then run detection. Returns the new alert count."""
    now = now or datetime.now(timezone.utc)
    manifest = json.loads((config.EXAMPLES_DIR / "manifest.json").read_text(encoding="utf-8"))
    for entry in manifest:
        ctx = ParseContext.build(year=entry.get("year"), host=entry.get("host"))
        ingest_file(conn, config.EXAMPLES_DIR / entry["file"], entry["source_type"], ctx)
    newest = conn.execute("SELECT MAX(timestamp) FROM events").fetchone()[0]
    if newest:
        target = now - timedelta(minutes=5)
        shift_events(conn, target - parse_utc_string(newest))
    return run_detection(conn, skip_host=REPLAY_HOST)["new_alerts"]


def ensure_seeded() -> None:
    """Create and seed the database if this instance doesn't have one yet, then run the
    first replay catch-up so the live host already shows the last 24 hours."""
    with _seed_lock:
        conn = db.connect()
        try:
            if conn.execute("SELECT 1 FROM events LIMIT 1").fetchone():
                return
            now = datetime.now(timezone.utc)
            alerts = seed_examples(conn, now=now)
            log.info("Seeded demo database at %s with %d alerts", config.db_path(), alerts)
            try:
                replayed = catch_up(conn, now, throttle_seconds=0)
                log.info("Replayed %d live demo events", replayed)
            except Exception:
                conn.rollback()
                log.exception("First demo replay catch-up failed")
        finally:
            conn.close()


# -- live replay -------------------------------------------------------------

def retime_line(source_type: str, line: str, when: datetime, host: str) -> str:
    """Rewrite a raw line's timestamp to `when` (UTC). For auth lines the hostname field
    becomes `host` too, because the auth parser takes the host from the line."""
    when = when.astimezone(timezone.utc)
    clock = f"{when.hour:02d}:{when.minute:02d}:{when.second:02d}"
    month = _MONTHS[when.month - 1]  # not strftime("%b"), which depends on locale
    if source_type == "auth":
        if m := _AUTH_ISO.match(line):
            stamp = f"{when.year:04d}-{when.month:02d}-{when.day:02d}T{clock}{m['frac'] or ''}+00:00"
        elif m := _AUTH_BSD.match(line):
            stamp = f"{month} {when.day:>2} {clock}"
        else:
            raise ValueError(f"not an auth log line: {line[:80]!r}")
        return f"{stamp} {host} {line[m.end():]}"
    if source_type == "web":
        m = _WEB_TS.match(line)
        if not m:
            raise ValueError(f"not a web access log line: {line[:80]!r}")
        stamp = f"[{when.day:02d}/{month}/{when.year:04d}:{clock} +0000]"
        return m["prefix"] + stamp + line[m.end():]
    raise ValueError(f"no replay support for source type {source_type!r}")


def _replay_lines() -> list[tuple[int, str, str]]:
    """The replay source lines with their UTC second of day (parsed once per process).
    Lines that don't parse are dropped."""
    global _replay_cache
    if _replay_cache is None:
        items = []
        for source_type, name in REPLAY_SOURCES:
            parser = get_parser(source_type)
            ctx = ParseContext.build(host=REPLAY_HOST)
            with open(config.SAMPLES_DIR / name, encoding="utf-8", errors="replace") as fh:
                for raw in fh:
                    line = raw.rstrip("\r\n")
                    event = parser.parse_line(line, ctx)
                    if event is None:
                        continue
                    ts = parse_utc_string(event.timestamp)
                    items.append((ts.hour * 3600 + ts.minute * 60 + ts.second, source_type, line))
        items.sort(key=lambda item: item[0])
        _replay_cache = items
    return _replay_cache


def catch_up(conn, now: datetime | None = None, *,
             throttle_seconds: float = DEFAULT_THROTTLE_SECONDS) -> int:
    """Insert the replay events that fell due since the last catch-up, then run detection
    on the replay host. Returns how many events were inserted.

    Throttled per process (returns 0 if it ran less than `throttle_seconds` ago); a caller
    that finds another catch-up in progress skips instead of waiting.
    """
    global _last_run
    if not _lock.acquire(blocking=False):
        return 0
    try:
        started = time.monotonic()
        if _last_run is not None and started - _last_run < throttle_seconds:
            return 0
        _last_run = started
        return _catch_up(conn, now or datetime.now(timezone.utc))
    finally:
        _lock.release()


def _catch_up(conn, now: datetime) -> int:
    now = now.astimezone(timezone.utc).replace(microsecond=0)
    floor = now - REPLAY_WINDOW
    watermark = conn.execute(
        "SELECT MAX(timestamp) FROM events WHERE host = ?", (REPLAY_HOST,)).fetchone()[0]
    # Never reach back more than one window: an instance idle for days gets only the last 24h.
    start = max(parse_utc_string(watermark), floor) if watermark else floor
    if start >= now:
        return 0

    lines = _replay_lines()
    inserted = 0
    day = start.date()
    while day <= now.date():
        midnight = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
        due: dict[str, list[str]] = {source_type: [] for source_type, _ in REPLAY_SOURCES}
        for second, source_type, line in lines:
            when = midnight + timedelta(seconds=second)
            if start < when <= now:
                due[source_type].append(retime_line(source_type, line, when, REPLAY_HOST))
        ctx = ParseContext.build(year=day.year, host=REPLAY_HOST)
        for source_type, retimed in due.items():
            if retimed:
                inserted += ingest_lines(conn, retimed, source_type, ctx).inserted
        day += timedelta(days=1)

    if inserted:
        run_detection(conn, only_host=REPLAY_HOST)
    return inserted

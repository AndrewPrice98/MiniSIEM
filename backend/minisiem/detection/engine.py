"""Detection engine: runs rules over stored events and upserts alerts."""

import re
import sqlite3
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone

from ..models import parse_utc_string
from .rules import Rule, load_rules


@dataclass
class Hit:
    rule: Rule
    events: list[dict]
    group: tuple


# -- helpers -----------------------------------------------------------------

def _ts(event: dict) -> datetime:
    cached = event.get("_dt")
    if cached is None:
        cached = event["_dt"] = parse_utc_string(event["timestamp"])
    return cached


def _group_key(rule: Rule, event: dict) -> tuple | None:
    key = tuple(event.get(f) for f in rule.group_by)
    # Events missing a grouping field can't be attributed; skip them.
    return None if any(v is None for v in key) else key


def _fetch_events(conn: sqlite3.Connection, rule: Rule, only_host: str | None = None,
                  skip_host: str | None = None) -> list[dict]:
    where, params = [], []
    if rule.source_type:
        where.append("source_type = ?")
        params.append(rule.source_type)
    if only_host is not None:
        where.append("host = ?")
        params.append(only_host)
    if skip_host is not None:
        where.append("(host IS NULL OR host != ?)")
        params.append(skip_host)
    clause = f" WHERE {' AND '.join(where)}" if where else ""
    cur = conn.execute(f"SELECT * FROM events{clause} ORDER BY timestamp, id", params)
    return [dict(r) for r in cur]


# -- detectors (one per rule type) ------------------------------------------

def detect_match(rule: Rule, events: list[dict]) -> list[Hit]:
    return [Hit(rule, [e], (e["id"],)) for e in events if rule.selection.matches(e)]


def detect_threshold(rule: Rule, events: list[dict]) -> list[Hit]:
    """N matching events per group inside the timeframe.

    One alert per burst: once a group fires, later events within the
    timeframe of the previous one extend the same alert.
    """
    windows: dict[tuple, deque] = defaultdict(deque)
    active: dict[tuple, Hit] = {}
    hits = []
    for e in events:
        if not rule.selection.matches(e):
            continue
        key = _group_key(rule, e)
        if key is None:
            continue
        now = _ts(e)
        hit = active.get(key)
        if hit is not None:
            if now - _ts(hit.events[-1]) <= rule.timeframe:
                hit.events.append(e)
                continue
            del active[key]
        window = windows[key]
        window.append(e)
        while window and now - _ts(window[0]) > rule.timeframe:
            window.popleft()
        if len(window) >= rule.threshold:
            hit = Hit(rule, list(window), key)
            hits.append(hit)
            active[key] = hit
            window.clear()
    return hits


def detect_sequence(rule: Rule, events: list[dict]) -> list[Hit]:
    """At least `min_count` events matching step 1, then one matching step 2,
    from the same group inside the timeframe."""
    (first, min_count), (second, _) = rule.steps
    pending: dict[tuple, deque] = defaultdict(deque)
    hits = []
    for e in events:
        key = _group_key(rule, e)
        if key is None:
            continue
        now = _ts(e)
        window = pending[key]
        while window and now - _ts(window[0]) > rule.timeframe:
            window.popleft()
        if first.matches(e):
            window.append(e)
        elif second.matches(e):
            if len(window) >= min_count:
                hits.append(Hit(rule, [*window, e], key))
            window.clear()
    return hits


def detect_first_seen(rule: Rule, events: list[dict]) -> list[Hit]:
    """A new value of `field` for a group that already has history.

    The first value seen for a group is the baseline and never alerts.
    """
    seen: dict[tuple, set] = defaultdict(set)
    hits = []
    for e in events:
        if not rule.selection.matches(e):
            continue
        key = _group_key(rule, e)
        value = e.get(rule.new_value_field)
        if key is None or value is None:
            continue
        known = seen[key]
        if known and value not in known:
            hits.append(Hit(rule, [e], key))
        known.add(value)
    return hits


DETECTORS = {
    "match": detect_match,
    "threshold": detect_threshold,
    "sequence": detect_sequence,
    "first_seen": detect_first_seen,
}


# -- alert storage ------------------------------------------------------------

def _common(events: list[dict], field: str):
    """The field's value if all events agree, else the most common one."""
    values = [e.get(field) for e in events if e.get(field) is not None]
    if not values:
        return None
    return Counter(values).most_common(1)[0][0]


def _human_timeframe(rule: Rule) -> str:
    if not rule.timeframe:
        return ""
    secs = int(rule.timeframe.total_seconds())
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if secs % size == 0:
            return f"{secs // size}{unit}"
    return f"{secs}s"


def _render_summary(rule: Rule, alert: dict) -> str:
    values = {**alert, "count": alert["event_count"], "timeframe": _human_timeframe(rule)}
    if rule.type == "first_seen":
        values["new_value"] = alert.get(rule.new_value_field)
    if rule.type == "sequence":
        values["first_step_count"] = alert["event_count"] - 1
    if rule.type == "match":
        ev = alert["_events"][0]
        values.update({k: v for k, v in ev.items() if not k.startswith("_") and v is not None})
    # Simple {name} substitution; unknown names render as "?".
    return re.sub(r"\{(\w+)\}", lambda m: str(values.get(m[1]) if values.get(m[1]) is not None else "?"),
                  rule.summary)


def _store_hit(conn: sqlite3.Connection, hit: Hit) -> bool:
    """Upsert one alert. Returns True if it was new."""
    rule, events = hit.rule, hit.events
    first = events[0]
    group = ",".join(str(v) for v in hit.group)
    fingerprint = f"{rule.id}|{group}|{first['id']}"
    alert = {
        "fingerprint": fingerprint,
        "rule_id": rule.id,
        "rule_title": rule.title,
        "severity": rule.severity,
        "attack_technique": rule.attack_technique,
        "attack_name": rule.attack_name,
        "attack_tactics": ",".join(rule.attack_tactics),
        "host": _common(events, "host"),
        "source_ip": _common(events, "source_ip"),
        "user_name": _common(events, "user_name"),
        "first_seen": events[0]["timestamp"],
        "last_seen": events[-1]["timestamp"],
        "event_count": len(events),
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "_events": events,
    }
    if rule.type == "first_seen":
        alert[rule.new_value_field] = first.get(rule.new_value_field)
    if rule.type == "sequence":
        # The interesting account is the one the final step (e.g. success) hit.
        alert["user_name"] = events[-1].get("user_name") or alert["user_name"]
    alert["summary"] = _render_summary(rule, alert)

    existed = conn.execute("SELECT 1 FROM alerts WHERE fingerprint = ?", (fingerprint,)).fetchone()
    cols = [k for k in alert if not k.startswith("_") and k in _ALERT_COLUMNS]
    conn.execute(
        f"INSERT INTO alerts ({', '.join(cols)}) VALUES ({', '.join('?' for _ in cols)}) "
        "ON CONFLICT(fingerprint) DO UPDATE SET "
        "last_seen = excluded.last_seen, event_count = excluded.event_count, "
        "summary = excluded.summary, severity = excluded.severity",
        [alert[c] for c in cols],
    )
    alert_id = conn.execute("SELECT id FROM alerts WHERE fingerprint = ?", (fingerprint,)).fetchone()[0]
    conn.executemany(
        "INSERT OR IGNORE INTO alert_events (alert_id, event_id) VALUES (?, ?)",
        [(alert_id, e["id"]) for e in events],
    )
    return existed is None


_ALERT_COLUMNS = {
    "fingerprint", "rule_id", "rule_title", "severity", "attack_technique", "attack_name",
    "attack_tactics", "host", "source_ip", "user_name", "summary", "first_seen", "last_seen",
    "event_count", "created_at",
}


def run_detection(conn: sqlite3.Connection, rules: list[Rule] | None = None, *,
                  only_host: str | None = None, skip_host: str | None = None) -> dict:
    """Run every enabled rule over stored events (optionally scoped to or excluding one host).
    Safe to re-run."""
    rules = load_rules() if rules is None else rules
    per_rule = {}
    new_total = 0
    events_by_source: dict[str | None, list[dict]] = {}
    for rule in rules:
        if not rule.enabled:
            continue
        if rule.source_type not in events_by_source:
            events_by_source[rule.source_type] = _fetch_events(conn, rule, only_host, skip_host)
        hits = DETECTORS[rule.type](rule, events_by_source[rule.source_type])
        new = sum(_store_hit(conn, h) for h in hits)
        new_total += new
        per_rule[rule.id] = {"hits": len(hits), "new_alerts": new}
    conn.commit()
    return {"rules_run": len(per_rule), "new_alerts": new_total, "per_rule": per_rule}

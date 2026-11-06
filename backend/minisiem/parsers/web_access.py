"""Parser for Apache/Nginx access logs (Common and Combined Log Format).

203.0.113.9 - - [01/Nov/2026:02:40:01 +0000] "GET /admin HTTP/1.1" 404 153 "-" "gobuster/3.6"
"""

import re
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote_plus

from ..models import Event, to_utc_string
from .base import ParseContext

ACCESS_LINE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<req>[^"]*)" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
)
TS = re.compile(
    r"^(?P<day>\d{2})/(?P<mon>[A-Z][a-z]{2})/(?P<year>\d{4}):(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})"
    r"(?: (?P<sign>[+-])(?P<oh>\d{2})(?P<om>\d{2}))?$"
)
MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1
)}


def _parse_ts(value: str, ctx: ParseContext) -> str | None:
    # Parsed by hand instead of strptime("%b") so it does not depend on locale.
    m = TS.match(value)
    if not m or m["mon"] not in MONTHS:
        return None
    tz = ctx.tz
    if m["sign"]:
        offset = timedelta(hours=int(m["oh"]), minutes=int(m["om"]))
        tz = timezone(offset if m["sign"] == "+" else -offset)
    try:
        dt = datetime(int(m["year"]), MONTHS[m["mon"]], int(m["day"]),
                      int(m["h"]), int(m["m"]), int(m["s"]), tzinfo=tz)
    except ValueError:
        return None
    return to_utc_string(dt)


class WebAccessParser:
    source_type = "web"

    def parse_line(self, line: str, ctx: ParseContext) -> Event | None:
        line = line.rstrip("\r\n")
        m = ACCESS_LINE.match(line)
        if not m:
            return None
        timestamp = _parse_ts(m["ts"], ctx)
        if timestamp is None:
            return None

        method, path = None, m["req"]
        parts = m["req"].split(" ")
        if len(parts) == 3 and parts[2].startswith("HTTP/"):
            method, path = parts[0], parts[1]
        status = int(m["status"])
        user = m["user"] if m["user"] != "-" else None
        ua = m["ua"] if m["ua"] not in (None, "-") else None
        decoded = unquote_plus(path)

        return Event(
            timestamp=timestamp,
            source_type=self.source_type,
            raw=line,
            host=ctx.host,
            source_ip=m["ip"],
            user_name=user,
            event_category="web",
            event_action="http_request",
            event_outcome="success" if status < 400 else "failure",
            http_method=method,
            url_path=decoded,
            http_status=status,
            user_agent=ua,
            message=f"{method or '?'} {decoded} -> {status}",
        )

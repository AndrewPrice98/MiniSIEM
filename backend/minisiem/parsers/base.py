from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Protocol

from ..models import Event


@dataclass
class ParseContext:
    """Facts a log line does not carry itself."""

    # Classic syslog timestamps have no year.
    year: int = field(default_factory=lambda: datetime.now(timezone.utc).year)
    # Offset of the log's local time zone from UTC, for formats without one.
    tz: timezone = timezone.utc
    # Host name for formats that do not include one (e.g. web access logs).
    host: str | None = None

    @classmethod
    def build(cls, year: int | None = None, tz_offset_hours: float = 0, host: str | None = None):
        ctx = cls(tz=timezone(timedelta(hours=tz_offset_hours)), host=host or None)
        if year is not None:
            ctx.year = year
        return ctx


class Parser(Protocol):
    source_type: str

    def parse_line(self, line: str, ctx: ParseContext) -> Event | None: ...

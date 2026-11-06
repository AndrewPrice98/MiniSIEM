"""The common event schema every parser produces."""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone

# Fields that detection rules and API filters may reference.
EVENT_FIELDS = (
    "timestamp",
    "source_type",
    "host",
    "source_ip",
    "destination_ip",
    "user_name",
    "group_name",
    "event_category",
    "event_action",
    "event_outcome",
    "process",
    "message",
    "http_method",
    "url_path",
    "http_status",
    "user_agent",
    "raw",
)


@dataclass
class Event:
    timestamp: str
    source_type: str
    raw: str
    host: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    user_name: str | None = None
    group_name: str | None = None
    event_category: str | None = None
    event_action: str | None = None
    event_outcome: str | None = None
    process: str | None = None
    message: str | None = None
    http_method: str | None = None
    url_path: str | None = None
    http_status: int | None = None
    user_agent: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def to_utc_string(dt: datetime) -> str:
    """Format a timezone-aware datetime as a sortable UTC string."""
    if dt.tzinfo is None:
        raise ValueError("datetime must be timezone-aware")
    return dt.astimezone(timezone.utc).strftime(TS_FORMAT)


def parse_utc_string(value: str) -> datetime:
    """Parse any ISO 8601 string; naive values are treated as UTC."""
    dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

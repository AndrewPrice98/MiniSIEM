# MiniSIEM — Decisions (M0)

Decisions that the rest of the project depends on. Change them here first if they change.

| # | Decision | Choice | Why |
|---|---|---|---|
| 0.1 | MVP log source | **Linux auth logs** (`auth.log` / `secure`) | Simple line format, rich security signal (SSH, sudo, account changes). Web access logs added in M6. |
| 0.2 | Backend language | **Python 3.12+ with FastAPI** | Strong text/log tooling, common in security work, auto-generated OpenAPI docs at `/docs`. |
| 0.3 | Storage | **SQLite** (single file, `backend/data/minisiem.db`) | Zero setup for anyone cloning the repo. Schema is plain SQL so PostgreSQL is a later swap. |
| 0.4 | Event schema | Flat table with **ECS-style field names** (`source_ip`, `user_name`, `event_action`, `event_outcome`…) | See below. Industry-recognisable, easy to query. |
| 0.5 | Rule format | **Sigma-like YAML** in `backend/rules/` | Rules are data, not code. Thresholds are editable without touching Python. |
| 0.6 | Ingestion method | **CLI import + HTTP file upload** (`POST /api/ingest`) | Covers scripted demos and dashboard uploads. Real-time is an M8 stretch. |
| 0.7 | Architecture | Collector → Parser → SQLite → Detection engine → REST API → React dashboard | See README diagram. |
| — | Frontend | Existing **React 18 + Vite** scaffold, `react-router-dom`, hand-drawn SVG charts | No charting dependency for a handful of simple charts. |

## Common event schema

| Field | ECS equivalent | Notes |
|---|---|---|
| `timestamp` | `@timestamp` | ISO 8601, **always UTC**, second precision (`2026-11-01T03:12:09Z`) |
| `source_type` | `event.dataset` | `auth` or `web` |
| `host` | `host.name` | Host that produced the log |
| `source_ip` | `source.ip` | Remote client |
| `destination_ip` | `destination.ip` | Rarely present in these sources |
| `user_name` | `user.name` | Account the event is about |
| `group_name` | `group.name` | For group-membership changes |
| `event_category` | `event.category` | `authentication`, `privilege`, `iam`, `session`, `web`, `system` |
| `event_action` | `event.action` | e.g. `ssh_login`, `sudo_command`, `user_created`, `http_request` |
| `event_outcome` | `event.outcome` | `success` / `failure` / null |
| `process` | `process.name` / `process.command_line` | Program name, or the sudo command line |
| `message` | `message` | Human-readable summary |
| `http_method`, `url_path`, `http_status`, `user_agent` | `http.*`, `url.*`, `user_agent.original` | Web events only. `url_path` is URL-decoded. |
| `raw` | `event.original` | **Original line, always kept** |

## Ingestion rules

- **Unparseable lines** (no recognisable header/format) are skipped and counted; a few are returned as samples so you can see what failed.
- **Re-ingesting the same file is idempotent.** Each event gets a fingerprint from `(source_type, raw line, occurrence number of that line in the upload)`, so duplicates are ignored but legitimately repeated lines are still kept.
- **Classic syslog timestamps have no year.** The year defaults to the current UTC year and can be overridden (`--year`). The time zone is assumed to be UTC unless `--tz-offset` is given.

## Detection rules

- Rule types: `match` (single event), `threshold` (N events per group in a window), `sequence` (N of A then B), `first_seen` (new value for a group, after a baseline exists).
- **Re-running detection is idempotent.** Alerts are fingerprinted by rule, group and first event, and are upserted, so re-runs extend alerts rather than duplicating them.

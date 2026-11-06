"""Parser for Linux authentication logs (/var/log/auth.log, /var/log/secure).

Supports both header styles:
  Classic BSD syslog:  Nov  1 03:12:09 web01 sshd[1234]: Failed password ...
  RFC 3339 (Ubuntu 24.04+ default):
                       2026-11-01T03:12:09.123456+00:00 web01 sshd[1234]: ...
"""

import re
from datetime import datetime

from ..models import Event, to_utc_string
from .base import ParseContext

_PROG = r"(?P<prog>[A-Za-z0-9_\-./()]+?)(?:\[(?P<pid>\d+)\])?"

BSD_HEADER = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) " + _PROG + r": (?P<msg>.*)$"
)
ISO_HEADER = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?) "
    r"(?P<host>\S+) " + _PROG + r": (?P<msg>.*)$"
)

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1
)}

# sshd
SSH_FAILED = re.compile(
    r"^Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S*) from (?P<ip>\S+) port \d+"
)
SSH_ACCEPTED = re.compile(r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port \d+")
SSH_INVALID_USER = re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>\S+)")
# pam_unix
PAM_RHOST = re.compile(r"\brhost=(?P<ip>\S+)")
PAM_USER = re.compile(r"\buser=(?P<user>\S+)")
PAM_SESSION = re.compile(r"session (?P<state>opened|closed) for user (?P<user>[^\s(]+)")
# account management
USERADD = re.compile(r"^new user: name=(?P<user>[^,]+),")
USERMOD_GROUP = re.compile(r"^add '(?P<user>[^']+)' to group '(?P<group>[^']+)'")
GPASSWD_GROUP = re.compile(r"^user (?P<user>\S+) added by \S+ to group (?P<group>\S+)")


class LinuxAuthParser:
    source_type = "auth"

    def parse_line(self, line: str, ctx: ParseContext) -> Event | None:
        line = line.rstrip("\r\n")
        header = self._parse_header(line, ctx)
        if header is None:
            return None
        timestamp, host, prog, msg = header

        event = Event(
            timestamp=timestamp,
            source_type=self.source_type,
            raw=line,
            host=host,
            process=prog,
            message=msg,
            event_category="system",
            event_action="other",
        )
        base_prog = prog.split("(")[0]
        if base_prog == "sshd":
            self._sshd(msg, event)
        elif base_prog == "sudo":
            self._sudo(msg, event)
        elif base_prog in ("useradd", "usermod", "gpasswd"):
            self._account(msg, event)
        if event.event_action == "other":
            self._pam(msg, event)
        return event

    # -- header -------------------------------------------------------------

    def _parse_header(self, line: str, ctx: ParseContext):
        m = ISO_HEADER.match(line)
        if m:
            try:
                dt = datetime.fromisoformat(m["ts"].replace("Z", "+00:00"))
            except ValueError:
                return None
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=ctx.tz)
            return to_utc_string(dt), m["host"], m["prog"], m["msg"]

        m = BSD_HEADER.match(line)
        if m:
            month = MONTHS.get(m["mon"])
            if month is None:
                return None
            try:
                hh, mm, ss = (int(x) for x in m["time"].split(":"))
                dt = datetime(ctx.year, month, int(m["day"]), hh, mm, ss, tzinfo=ctx.tz)
            except ValueError:
                return None  # e.g. Feb 30
            return to_utc_string(dt), m["host"], m["prog"], m["msg"]
        return None

    # -- program-specific messages -----------------------------------------

    @staticmethod
    def _sshd(msg: str, e: Event) -> None:
        if m := SSH_FAILED.match(msg):
            e.event_category, e.event_action, e.event_outcome = "authentication", "ssh_login", "failure"
            e.user_name, e.source_ip = m["user"] or None, m["ip"]
        elif m := SSH_ACCEPTED.match(msg):
            e.event_category, e.event_action, e.event_outcome = "authentication", "ssh_login", "success"
            e.user_name, e.source_ip = m["user"], m["ip"]
        elif m := SSH_INVALID_USER.match(msg):
            # sshd also logs a "Failed password" line for the same attempt, so
            # this gets its own action and is not double-counted as a login.
            e.event_category, e.event_action, e.event_outcome = "authentication", "ssh_invalid_user", "failure"
            e.user_name, e.source_ip = m["user"] or None, m["ip"]

    @staticmethod
    def _sudo(msg: str, e: Event) -> None:
        # alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update
        # bob : 3 incorrect password attempts ; TTY=pts/1 ; ... ; COMMAND=/bin/su
        if " : " not in msg or "COMMAND=" not in msg:
            return
        user, rest = msg.split(" : ", 1)
        before_cmd, command = rest.split("COMMAND=", 1)
        fields, errors = {}, []
        for part in before_cmd.split(" ; "):
            part = part.strip(" ;")
            if not part:
                continue
            key, sep, value = part.partition("=")
            if sep and key.isupper():
                fields[key] = value
            else:
                errors.append(part)
        e.event_category, e.event_action = "privilege", "sudo_command"
        e.event_outcome = "failure" if errors else "success"
        e.user_name = user.strip()
        e.process = command.strip()
        target = fields.get("USER", "?")
        e.message = (
            f"{e.user_name} ran as {target}: {e.process}"
            + (f" ({'; '.join(errors)})" if errors else "")
        )

    @staticmethod
    def _account(msg: str, e: Event) -> None:
        if m := USERADD.match(msg):
            e.event_category, e.event_action, e.event_outcome = "iam", "user_created", "success"
            e.user_name = m["user"]
        elif (m := USERMOD_GROUP.match(msg)) or (m := GPASSWD_GROUP.match(msg)):
            e.event_category, e.event_action, e.event_outcome = "iam", "group_member_added", "success"
            e.user_name, e.group_name = m["user"], m["group"]

    @staticmethod
    def _pam(msg: str, e: Event) -> None:
        if "pam_unix" not in msg and "pam_unix" not in (e.process or ""):
            return
        if "authentication failure;" in msg:
            e.event_category, e.event_action, e.event_outcome = "authentication", "pam_auth_failure", "failure"
            if m := PAM_RHOST.search(msg):
                e.source_ip = m["ip"]
            if m := PAM_USER.search(msg):
                e.user_name = m["user"]
        elif m := PAM_SESSION.search(msg):
            e.event_category = "session"
            e.event_action = f"session_{m['state']}"
            e.event_outcome = "success"
            e.user_name = m["user"]

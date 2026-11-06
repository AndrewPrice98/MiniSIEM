import pytest

from minisiem.parsers import ParseContext, get_parser

auth = get_parser("auth")
web = get_parser("web")
CTX = ParseContext.build(year=2026)


def p(line, ctx=CTX):
    return auth.parse_line(line, ctx)


# -- Linux auth: headers -------------------------------------------------------

def test_bsd_header_uses_context_year_and_utc():
    e = p("Nov  1 03:12:09 bastion sshd[1234]: Connection closed by 1.2.3.4 port 22")
    assert e.timestamp == "2026-11-01T03:12:09Z"
    assert e.host == "bastion"
    assert e.process == "sshd"
    assert e.event_action == "other"


def test_bsd_header_applies_timezone_offset():
    ctx = ParseContext.build(year=2026, tz_offset_hours=-5)
    e = p("Nov  1 22:00:00 h sshd[1]: hello", ctx)
    assert e.timestamp == "2026-11-02T03:00:00Z"


def test_iso_header_with_offset_is_normalized_to_utc():
    e = p("2026-11-01T05:12:09.123456+02:00 bastion sshd[99]: hello")
    assert e.timestamp == "2026-11-01T03:12:09Z"


def test_raw_line_is_kept():
    line = "Nov  1 03:12:09 bastion sshd[1234]: Accepted publickey for alice from 10.0.0.1 port 22 ssh2"
    assert p(line).raw == line


@pytest.mark.parametrize("line", [
    "",
    "garbage",
    "Foo  1 03:12:09 host sshd[1]: bad month",
    "Feb 30 03:12:09 host sshd[1]: impossible date",
    "2026-13-01T00:00:00Z host sshd[1]: bad iso",
    "Nov  1 03:12:09 host-without-program",
])
def test_unparseable_lines_return_none(line):
    assert p(line) is None


# -- Linux auth: sshd ------------------------------------------------------------

def test_failed_password():
    e = p("Nov  1 03:12:09 h sshd[1]: Failed password for root from 203.0.113.45 port 50122 ssh2")
    assert (e.event_category, e.event_action, e.event_outcome) == ("authentication", "ssh_login", "failure")
    assert (e.user_name, e.source_ip) == ("root", "203.0.113.45")


def test_failed_password_invalid_user():
    e = p("Nov  1 03:12:09 h sshd[1]: Failed password for invalid user oracle from 203.0.113.45 port 1 ssh2")
    assert e.event_action == "ssh_login" and e.user_name == "oracle"


def test_accepted_publickey():
    e = p("Nov  1 09:00:00 h sshd[1]: Accepted publickey for alice from 10.0.0.21 port 5 ssh2: ED25519 SHA256:x")
    assert (e.event_action, e.event_outcome, e.user_name, e.source_ip) == (
        "ssh_login", "success", "alice", "10.0.0.21")


def test_invalid_user_is_not_counted_as_login():
    e = p("Nov  1 03:12:09 h sshd[1]: Invalid user admin from 203.0.113.45 port 50122")
    assert e.event_action == "ssh_invalid_user"
    assert e.user_name == "admin"


def test_ipv6_source():
    e = p("Nov  1 03:12:09 h sshd[1]: Failed password for root from 2001:db8::1 port 2 ssh2")
    assert e.source_ip == "2001:db8::1"


# -- Linux auth: PAM, sudo, account management --------------------------------

def test_pam_auth_failure():
    e = p("Nov  1 03:12:09 h sshd[1]: pam_unix(sshd:auth): authentication failure; logname= uid=0 "
          "euid=0 tty=ssh ruser= rhost=203.0.113.45  user=root")
    assert (e.event_action, e.source_ip, e.user_name) == ("pam_auth_failure", "203.0.113.45", "root")


def test_pam_auth_failure_without_rhost():
    e = p("Nov  1 03:12:09 h sudo[1]: pam_unix(sudo:auth): authentication failure; logname=bob uid=1000 "
          "euid=0 tty=/dev/pts/1 ruser=bob rhost=  user=bob")
    assert e.source_ip is None and e.user_name == "bob"


def test_pam_session_opened():
    e = p("Nov  1 03:12:09 h sshd[1]: pam_unix(sshd:session): session opened for user alice(uid=1000) by (uid=0)")
    assert (e.event_category, e.event_action, e.user_name) == ("session", "session_opened", "alice")


def test_sudo_command():
    e = p("Nov  1 03:12:09 h sudo[1]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update")
    assert (e.event_action, e.event_outcome, e.user_name, e.process) == (
        "sudo_command", "success", "alice", "/usr/bin/apt update")


def test_sudo_failure_with_error_prefix():
    e = p("Nov  1 03:12:09 h sudo[1]:      bob : 3 incorrect password attempts ; TTY=pts/1 ; "
          "PWD=/home/bob ; USER=root ; COMMAND=/bin/su")
    assert (e.event_outcome, e.user_name, e.process) == ("failure", "bob", "/bin/su")
    assert "incorrect password" in e.message


def test_sudo_command_containing_semicolons():
    e = p("Nov  1 03:12:09 h sudo[1]: eve : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/sh -c id ; whoami")
    assert e.process == "/bin/sh -c id ; whoami"


def test_useradd():
    e = p("Nov  1 03:12:09 h useradd[1]: new user: name=svc-backup, UID=1004, GID=1004, home=/home/svc-backup, "
          "shell=/bin/bash, from=/dev/pts/2")
    assert (e.event_category, e.event_action, e.user_name) == ("iam", "user_created", "svc-backup")


def test_usermod_group_add_ignores_shadow_line():
    e = p("Nov  1 03:12:09 h usermod[1]: add 'svc-backup' to group 'sudo'")
    assert (e.event_action, e.user_name, e.group_name) == ("group_member_added", "svc-backup", "sudo")
    shadow = p("Nov  1 03:12:09 h usermod[1]: add 'svc-backup' to shadow group 'sudo'")
    assert shadow.event_action == "other"


def test_gpasswd_group_add():
    e = p("Nov  1 03:12:09 h gpasswd[1]: user eve added by root to group wheel")
    assert (e.event_action, e.user_name, e.group_name) == ("group_member_added", "eve", "wheel")


# -- Web access logs -------------------------------------------------------------

def w(line, ctx=CTX):
    return web.parse_line(line, ctx)


def test_combined_log_format():
    e = w('192.0.2.77 - - [01/Nov/2026:02:40:01 +0000] "GET /admin HTTP/1.1" 404 153 "-" "gobuster/3.6"')
    assert e.timestamp == "2026-11-01T02:40:01Z"
    assert (e.source_ip, e.http_method, e.url_path, e.http_status, e.user_agent) == (
        "192.0.2.77", "GET", "/admin", 404, "gobuster/3.6")
    assert e.event_outcome == "failure"


def test_common_log_format_without_referer_or_ua():
    e = w('10.0.0.1 - frank [10/Oct/2026:13:55:36 -0700] "GET /a.gif HTTP/1.0" 200 2326')
    assert e.timestamp == "2026-10-10T20:55:36Z"
    assert e.user_name == "frank" and e.user_agent is None and e.event_outcome == "success"


def test_url_is_decoded_and_host_comes_from_context():
    ctx = ParseContext.build(host="web01")
    e = w('1.2.3.4 - - [01/Nov/2026:02:47:00 +0000] "GET /p?id=1%27%20OR%201%3D1 HTTP/1.1" 200 1 "-" "x"', ctx)
    assert e.url_path == "/p?id=1' OR 1=1"
    assert e.host == "web01"
    assert "%27" in e.raw


def test_malformed_request_line_is_kept():
    e = w('1.2.3.4 - - [01/Nov/2026:02:47:00 +0000] "\\x16\\x03\\x01" 400 0 "-" "-"')
    assert e.http_method is None and e.http_status == 400


@pytest.mark.parametrize("line", [
    "",
    "not a log line",
    '1.2.3.4 - - [01/Nov/2026:02:47:00 +0000] "GET /pro',
    '1.2.3.4 - - [99/Nov/2026:02:47:00 +0000] "GET / HTTP/1.1" 200 1',
    '1.2.3.4 - - [01/Foo/2026:02:47:00 +0000] "GET / HTTP/1.1" 200 1',
])
def test_web_unparseable(line):
    assert w(line) is None

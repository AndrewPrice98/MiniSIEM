"""Generate the sample datasets in samples/.

Produces a day of believable background activity plus a scripted attack that
triggers every MiniSIEM detection rule. Output is deterministic (fixed seed and
date), so the demo and tests always see the same data.

    python scripts/generate_attack.py            # writes samples/auth.log, samples/access.log
    python scripts/generate_attack.py --out DIR

The attack story (all times UTC, 2026-11-01):
  02:40  192.0.2.77     runs a wordlist scan against web01           -> MSIEM-007
  02:47  192.0.2.77     tries SQLi / traversal / XSS / cmd injection -> MSIEM-008
  03:12  203.0.113.45   brute-forces SSH on srv-bastion              -> MSIEM-001
  03:20  198.51.100.23  guesses the 'deploy' password and gets in    -> MSIEM-001, 002, 006
  03:22  deploy         reads /etc/shadow, opens a root shell        -> MSIEM-003
  03:24  deploy         creates 'svc-backup' and adds it to sudo     -> MSIEM-004, 005
  14:05  bob            logs in over the new VPN range (benign)      -> MSIEM-006 (low)
"""

import argparse
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

DAY = datetime(2026, 11, 1, tzinfo=timezone.utc)
AUTH_HOST = "srv-bastion"
rng = random.Random(1337)


class Log:
    def __init__(self):
        self.lines: list[tuple[datetime, int, str]] = []
        self._seq = 0

    def add(self, when: datetime, line: str):
        self._seq += 1
        self.lines.append((when, self._seq, line))

    def render(self) -> str:
        return "\n".join(line for _, _, line in sorted(self.lines)) + "\n"


def pid() -> int:
    return rng.randint(1200, 65000)


# -- auth.log (RFC 3339 timestamps, the Ubuntu 24.04+ default) ----------------

def auth_line(log: Log, when: datetime, prog: str, msg: str, proc_id: int | None = None):
    stamp = when.strftime("%Y-%m-%dT%H:%M:%S.") + f"{rng.randint(0, 999999):06d}+00:00"
    tag = f"{prog}[{proc_id or pid()}]"
    log.add(when, f"{stamp} {AUTH_HOST} {tag}: {msg}")


def ssh_fail(log, when, user, ip, invalid=False):
    p = pid()
    port = rng.randint(30000, 65000)
    if invalid:
        auth_line(log, when, "sshd", f"Invalid user {user} from {ip} port {port}", p)
    auth_line(log, when + timedelta(seconds=1), "sshd",
              f"Failed password for {'invalid user ' if invalid else ''}{user} from {ip} port {port} ssh2", p)


def ssh_login(log, when, user, ip, method="publickey", duration_min=30):
    p = pid()
    port = rng.randint(30000, 65000)
    suffix = ": ED25519 SHA256:" + "".join(rng.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123456789", k=43)) \
        if method == "publickey" else ""
    auth_line(log, when, "sshd", f"Accepted {method} for {user} from {ip} port {port} ssh2{suffix}", p)
    auth_line(log, when, "sshd", f"pam_unix(sshd:session): session opened for user {user}(uid=1000) by (uid=0)", p)
    auth_line(log, when + timedelta(minutes=duration_min), "sshd",
              f"pam_unix(sshd:session): session closed for user {user}", p)


def sudo(log, when, user, command, tty="pts/0", cwd=None):
    auth_line(log, when, "sudo",
              f"{user} : TTY={tty} ; PWD={cwd or '/home/' + user} ; USER=root ; COMMAND={command}")
    auth_line(log, when, "sudo", f"pam_unix(sudo:session): session opened for user root(uid=0) by {user}(uid=1000)")


def build_auth() -> str:
    log = Log()

    # Hourly cron.
    for h in range(24):
        t = DAY + timedelta(hours=h, minutes=17)
        p = pid()
        auth_line(log, t, "CRON", "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)", p)
        auth_line(log, t + timedelta(seconds=1), "CRON", "pam_unix(cron:session): session closed for user root", p)

    # The CI system deploys every 2 hours with a key, from its fixed IP.
    for h in range(0, 24, 2):
        t = DAY + timedelta(hours=h, minutes=5, seconds=rng.randint(0, 50))
        ssh_login(log, t, "deploy", "10.0.0.12", duration_min=2)
        sudo(log, t + timedelta(seconds=20), "deploy", "/usr/bin/systemctl restart app.service",
             cwd="/srv/app")

    # Admins during the working day.
    admins = {"alice": "10.0.0.21", "bob": "10.0.0.34"}
    benign_sudo = {
        "alice": ["/usr/bin/apt update", "/usr/bin/systemctl status nginx", "/usr/bin/journalctl -u app -n 200"],
        "bob": ["/usr/bin/tail -n 100 /var/log/nginx/error.log", "/usr/bin/systemctl reload nginx"],
    }
    for user, ip in admins.items():
        for h in (8, 10, 13, 16):
            t = DAY + timedelta(hours=h, minutes=rng.randint(0, 50), seconds=rng.randint(0, 59))
            if user == "alice" and h == 10:
                ssh_fail(log, t - timedelta(seconds=15), user, ip)  # a typo, not an attack
            ssh_login(log, t, user, ip, duration_min=rng.randint(10, 45))
            sudo(log, t + timedelta(minutes=3), user, rng.choice(benign_sudo[user]))

    # bob works from the new VPN range in the afternoon (benign, triggers the low rule).
    ssh_login(log, DAY + timedelta(hours=14, minutes=5, seconds=12), "bob", "10.8.0.50", duration_min=20)

    # Internet background noise: a few attempts per IP, spread out (below threshold).
    for _ in range(18):
        ip = f"{rng.choice([45, 61, 91, 103, 185, 193])}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"
        t = DAY + timedelta(minutes=rng.randint(0, 24 * 60 - 1))
        for i in range(rng.randint(1, 3)):
            user = rng.choice(["root", "admin", "ubuntu", "user", "test"])
            ssh_fail(log, t + timedelta(minutes=3 * i), user, ip, invalid=user not in ("root", "ubuntu"))

    # --- Attack 1: noisy brute force that fails ---------------------------------
    t = DAY + timedelta(hours=3, minutes=12, seconds=5)
    for i, user in enumerate(["root", "root", "admin", "admin", "test", "oracle", "root", "ubuntu",
                              "postgres", "root", "admin", "git", "root", "pi"]):
        ssh_fail(log, t + timedelta(seconds=4 * i), user, "203.0.113.45",
                 invalid=user not in ("root", "ubuntu"))

    # --- Attack 2: password guessing that succeeds ------------------------------
    attacker = "198.51.100.23"
    t = DAY + timedelta(hours=3, minutes=20)
    for i in range(7):
        ssh_fail(log, t + timedelta(seconds=6 * i), "deploy", attacker)
    t_in = t + timedelta(seconds=50)
    p = pid()
    auth_line(log, t_in, "sshd", f"Accepted password for deploy from {attacker} port 51522 ssh2", p)
    auth_line(log, t_in, "sshd", "pam_unix(sshd:session): session opened for user deploy(uid=1001) by (uid=0)", p)

    # --- Post-compromise activity -----------------------------------------------
    t = t_in + timedelta(minutes=2)
    sudo(log, t, "deploy", "/usr/bin/cat /etc/shadow", tty="pts/2", cwd="/home/deploy")
    sudo(log, t + timedelta(seconds=40), "deploy", "/bin/bash", tty="pts/2", cwd="/home/deploy")
    t = t + timedelta(minutes=2)
    sudo(log, t, "deploy", "/usr/sbin/useradd -m -s /bin/bash svc-backup", tty="pts/2", cwd="/root")
    auth_line(log, t, "useradd", "new group: name=svc-backup, GID=1004")
    auth_line(log, t, "useradd",
              "new user: name=svc-backup, UID=1004, GID=1004, home=/home/svc-backup, shell=/bin/bash, from=/dev/pts/2")
    t = t + timedelta(seconds=25)
    sudo(log, t, "deploy", "/usr/sbin/usermod -aG sudo svc-backup", tty="pts/2", cwd="/root")
    p = pid()
    auth_line(log, t, "usermod", "add 'svc-backup' to group 'sudo'", p)
    auth_line(log, t, "usermod", "add 'svc-backup' to shadow group 'sudo'", p)
    auth_line(log, t + timedelta(minutes=6), "sshd", "pam_unix(sshd:session): session closed for user deploy")

    # One corrupted line, to show unparseable handling.
    log.add(DAY + timedelta(hours=12), "\x00\x00 log rotation interrupted -- partial write")
    return log.render().replace("\x00", "")


# -- access.log (Combined Log Format) ------------------------------------------

UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "Mozilla/5.0 (X11; Linux x86_64; rv:144.0) Gecko/20100101 Firefox/144.0",
]
SCAN_WORDS = [
    ".env", ".git/config", ".git/HEAD", ".htaccess", ".DS_Store", "admin", "admin.php", "administrator",
    "backup", "backup.zip", "backup.sql", "bak", "cgi-bin/", "config", "config.php", "config.json",
    "console", "dashboard", "db", "db.sql", "debug", "dev", "dump.sql", "files", "include", "install",
    "login", "login.php", "logs", "manager/html", "old", "panel", "phpinfo.php", "phpmyadmin", "private",
    "server-status", "setup", "shell.php", "sql", "staging", "temp", "test", "test.php", "tmp", "upload",
    "uploads", "user", "users", "v1", "v2", "vendor", "web.config", "webadmin", "wp-admin", "wp-config.php",
    "wp-content", "wp-includes", "wp-login.php", "xmlrpc.php", "api/v1/users", "actuator/health",
    "actuator/env", "jenkins", "solr", "graphql", ".aws/credentials", "id_rsa", "secrets", "storage",
]
FOUND = {"admin": 301, "login": 200, "api/v1/users": 401, ".git/HEAD": 403, "uploads": 403}
INJECTIONS = [
    ("GET", "/products?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--%20-", 500),
    ("GET", "/products?id=1%27%20OR%20%271%27%3D%271", 200),
    ("GET", "/download?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd", 400),
    ("GET", "/search?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E", 200),
    ("POST", "/api/ping?host=127.0.0.1;cat%20/etc/passwd", 500),
]


def access_line(log: Log, when, ip, method, path, status, ua, size=None, referer="-"):
    stamp = when.strftime("%d/%b/%Y:%H:%M:%S +0000")
    size = size if size is not None else (rng.randint(800, 48000) if status == 200 else rng.randint(150, 600))
    log.add(when, f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {size} "{referer}" "{ua}"')


def build_access() -> str:
    log = Log()
    clients = [f"{rng.choice([24, 67, 73, 98, 172, 174])}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"
               for _ in range(40)]
    pages = ["/", "/products", "/about", "/contact", "/cart"] + [f"/products/{i}" for i in range(1, 41)]

    # Visits weighted toward daytime.
    for _ in range(260):
        hour = min(23, max(0, int(rng.gauss(14, 4.5))))
        t = DAY + timedelta(hours=hour, minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
        ip, ua = rng.choice(clients), rng.choice(UAS)
        page = rng.choice(pages)
        access_line(log, t, ip, "GET", page, 200, ua, referer="https://shop.example.com/")
        access_line(log, t, ip, "GET", "/static/css/main.css", rng.choice([200, 304]), ua, referer=page)
        access_line(log, t + timedelta(seconds=1), ip, "GET", "/static/js/app.js", rng.choice([200, 304]), ua)
        if rng.random() < 0.15:
            access_line(log, t + timedelta(seconds=2), ip, "GET", "/favicon.ico", 404, ua)
        if rng.random() < 0.1:
            access_line(log, t + timedelta(seconds=30), ip, "POST", "/api/cart", 201, ua)
        if rng.random() < 0.03:
            access_line(log, t + timedelta(seconds=40), ip, "GET", "/products/999", 404, ua)

    # Attack: wordlist scan.
    scanner, ua = "192.0.2.77", "gobuster/3.6"
    t = DAY + timedelta(hours=2, minutes=40)
    for i, word in enumerate(SCAN_WORDS):
        access_line(log, t + timedelta(milliseconds=650 * i), scanner, "GET", f"/{word}",
                    FOUND.get(word, 404), ua, size=rng.randint(150, 400))

    # Attack: injection attempts against the endpoints it found.
    t = DAY + timedelta(hours=2, minutes=47)
    for i, (method, path, status) in enumerate(INJECTIONS):
        access_line(log, t + timedelta(seconds=9 * i), scanner, method, path, status, "sqlmap/1.9#stable")

    # A truncated line, to show unparseable handling.
    log.add(DAY + timedelta(hours=18), '73.12.9.4 - - [01/Nov/2026:18:00:00 +0000] "GET /pro')
    return log.render()


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--out", type=Path, default=Path(__file__).resolve().parent.parent / "samples")
    args = p.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    for name, text in (("auth.log", build_auth()), ("access.log", build_access())):
        path = args.out / name
        path.write_text(text, encoding="utf-8", newline="\n")
        print(f"wrote {path} ({text.count(chr(10))} lines)")


if __name__ == "__main__":
    main()

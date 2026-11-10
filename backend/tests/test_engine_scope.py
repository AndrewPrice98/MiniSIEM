from minisiem.detection import run_detection


def fail(t, ip):
    return f"{t} bastion sshd[1]: Failed password for root from {ip} port 4444 ssh2"


def _burst(host, ip):
    return [fail(f"2026-11-01T03:00:{i * 10:02d}+00:00", ip).replace("bastion", host, 1)
            for i in range(5)]


def _load_both(load):
    load("auth", _burst("host-a", "203.0.113.1") + _burst("demo-live", "203.0.113.2"))


def test_run_detection_scoped_by_host(conn, load):
    _load_both(load)
    assert run_detection(conn, only_host="demo-live")["new_alerts"] == 1
    hosts = [r[0] for r in conn.execute("SELECT host FROM alerts")]
    assert hosts == ["demo-live"]


def test_run_detection_skip_host(conn, load):
    _load_both(load)
    assert run_detection(conn, skip_host="demo-live")["new_alerts"] == 1
    assert [r[0] for r in conn.execute("SELECT host FROM alerts")] == ["host-a"]
    assert run_detection(conn)["new_alerts"] == 1  # the remaining group

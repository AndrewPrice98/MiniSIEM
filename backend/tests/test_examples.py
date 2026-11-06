"""Every file in samples/examples/ raises exactly the alerts its manifest promises."""

import json
from collections import Counter

import pytest

from minisiem import config, db
from minisiem.detection import run_detection
from minisiem.ingest import ingest_file
from minisiem.parsers import ParseContext

MANIFEST = json.loads((config.EXAMPLES_DIR / "manifest.json").read_text(encoding="utf-8"))


def _load(conn, entry):
    ctx = ParseContext.build(year=entry.get("year"), host=entry.get("host"))
    return ingest_file(conn, config.EXAMPLES_DIR / entry["file"], entry["source_type"], ctx)


def _alert_counts(conn) -> dict:
    return dict(Counter(r[0] for r in conn.execute("SELECT rule_id FROM alerts")))


@pytest.mark.parametrize("entry", MANIFEST, ids=[e["file"] for e in MANIFEST])
def test_example_raises_expected_alerts(tmp_path, rules, entry):
    conn = db.connect(tmp_path / "ex.db")
    try:
        result = _load(conn, entry)
        assert result.unparsed == entry["expected_unparsed"], result.unparsed_samples
        assert result.inserted > 0
        run_detection(conn, list(rules.values()))
        assert _alert_counts(conn) == entry["expected_alerts"]
    finally:
        conn.close()


def test_examples_do_not_interfere_when_loaded_together(tmp_path, rules):
    """Scenarios use separate dates, hosts, users and IPs, so loading them all at once
    gives exactly the sum of the per-file expectations."""
    conn = db.connect(tmp_path / "all.db")
    try:
        for entry in MANIFEST:
            _load(conn, entry)
        run_detection(conn, list(rules.values()))
        expected = Counter()
        for entry in MANIFEST:
            expected.update(entry["expected_alerts"])
        assert _alert_counts(conn) == dict(expected)
    finally:
        conn.close()


def test_every_rule_is_exercised_by_some_example(rules):
    covered = {rule_id for e in MANIFEST for rule_id in e["expected_alerts"]}
    assert covered == set(rules)

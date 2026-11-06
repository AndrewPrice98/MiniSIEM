"""Command-line interface.

    python -m minisiem demo                     # reset, load samples, detect
    python -m minisiem ingest FILE --source auth
    python -m minisiem detect
    python -m minisiem serve
"""

import argparse
import json
import sys
from pathlib import Path

from . import config, db
from .detection import load_rules, run_detection
from .ingest import ingest_file
from .parsers import PARSERS, ParseContext

SAMPLE_FILES = [
    ("auth.log", "auth", "srv-bastion"),
    ("access.log", "web", "web01"),
]


def _print(obj):
    print(json.dumps(obj, indent=2))


def cmd_ingest(args):
    conn = db.connect()
    try:
        ctx = ParseContext.build(year=args.year, tz_offset_hours=args.tz_offset, host=args.host)
        result = ingest_file(conn, Path(args.file), args.source, ctx)
        out = {"ingest": result.to_dict()}
        if not args.no_detect:
            out["detection"] = run_detection(conn)
        _print(out)
    finally:
        conn.close()


def cmd_detect(_args):
    conn = db.connect()
    try:
        _print(run_detection(conn))
    finally:
        conn.close()


def cmd_reset(_args):
    db.reset()
    print(f"Cleared all events and alerts in {config.db_path()}")


def cmd_demo(args):
    db.reset()
    conn = db.connect()
    try:
        for filename, source, host in SAMPLE_FILES:
            path = config.SAMPLES_DIR / filename
            if not path.exists():
                sys.exit(f"Missing {path}. Run: python scripts/generate_attack.py")
            r = ingest_file(conn, path, source, ParseContext.build(host=host))
            print(f"Ingested {r.inserted:>5} {source} events from {filename}"
                  f"  ({r.unparsed} unparseable line(s) skipped)")
        result = run_detection(conn)
        print(f"\nDetection raised {result['new_alerts']} alerts:")
        titles = {r.id: r.title for r in load_rules()}
        for rule_id, info in result["per_rule"].items():
            print(f"  {rule_id}  {titles[rule_id]:<45} {info['hits']:>3}")
    finally:
        conn.close()
    if args.serve:
        cmd_serve(args)


def load_examples(conn) -> list[dict]:
    """Ingest every file listed in samples/examples/manifest.json. Returns the manifest."""
    manifest_path = config.EXAMPLES_DIR / "manifest.json"
    if not manifest_path.exists():
        sys.exit(f"Missing {manifest_path}. Run: python scripts/generate_examples.py")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for entry in manifest:
        ctx = ParseContext.build(year=entry.get("year"), host=entry.get("host"))
        r = ingest_file(conn, config.EXAMPLES_DIR / entry["file"], entry["source_type"], ctx)
        print(f"  {entry['file']:<36} {r.inserted:>6} events  {r.unparsed:>3} unparseable")
    return manifest


def cmd_examples(args):
    db.reset()
    conn = db.connect()
    try:
        print("Loading samples/examples/ ...")
        manifest = load_examples(conn)
        result = run_detection(conn)
        expected = sum(sum(e["expected_alerts"].values()) for e in manifest)
        print(f"\nDetection raised {result['new_alerts']} alerts (manifest expects {expected}).")
    finally:
        conn.close()
    if args.serve:
        cmd_serve(args)


def cmd_rules(_args):
    for r in load_rules():
        print(f"{r.id}  {r.severity:<8} {r.attack_technique or '-':<10} {r.title}")


def cmd_serve(args):
    import uvicorn

    uvicorn.run("minisiem.api:app", host=args.host_addr, port=args.port, reload=args.reload)


def main(argv=None):
    p = argparse.ArgumentParser(prog="minisiem", description="MiniSIEM command line")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("ingest", help="parse a log file into events (and run detection)")
    s.add_argument("file")
    s.add_argument("--source", required=True, choices=sorted(PARSERS))
    s.add_argument("--host", help="host name for logs that don't include one (web logs)")
    s.add_argument("--year", type=int, help="year for syslog timestamps without one")
    s.add_argument("--tz-offset", type=float, default=0, help="log local time offset from UTC, in hours")
    s.add_argument("--no-detect", action="store_true", help="skip running detection afterwards")
    s.set_defaults(func=cmd_ingest)

    sub.add_parser("detect", help="run all detection rules").set_defaults(func=cmd_detect)
    sub.add_parser("rules", help="list detection rules").set_defaults(func=cmd_rules)
    sub.add_parser("reset", help="delete all events and alerts").set_defaults(func=cmd_reset)

    for name, func, help_ in (("serve", cmd_serve, "run the API server"),
                              ("demo", cmd_demo, "reset and load the sample dataset"),
                              ("examples", cmd_examples, "reset and load every log in samples/examples/")):
        s = sub.add_parser(name, help=help_)
        s.add_argument("--host", dest="host_addr", default="127.0.0.1")
        s.add_argument("--port", type=int, default=8000)
        s.add_argument("--reload", action="store_true")
        if name in ("demo", "examples"):
            s.add_argument("--serve", action="store_true", help="start the API afterwards")
        s.set_defaults(func=func)

    args = p.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()

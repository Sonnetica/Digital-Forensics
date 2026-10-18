"""Command-line entry point."""

import argparse
import json
import sqlite3
import sys
from pathlib import Path

from . import __version__
from .case import Case
from .correlate import analyze
from .model import RuleConfig


def emit(value):
    print(json.dumps(value, indent=2, ensure_ascii=True))


def main(argv=None):
    parser = argparse.ArgumentParser(prog="etrace", description="Email evidence reconstruction")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="Create a case without overwriting an existing file")
    init.add_argument("case", type=Path)
    init.add_argument("--name", required=True)
    ingest = commands.add_parser("ingest", help="Read EML or MSG evidence into a case")
    ingest.add_argument("case", type=Path)
    ingest.add_argument("paths", nargs="+", type=Path)
    analysis = commands.add_parser("analyze", help="Reconstruct relationships with rule provenance")
    analysis.add_argument("case", type=Path)
    analysis.add_argument("--window-seconds", type=int, default=3600)
    analysis.add_argument("--minimum-signals", type=int, default=2)
    analysis.add_argument("--timestamp-source", choices=("date", "received"), default="date")
    analysis.add_argument("--max-candidates", type=int, default=250000)
    analysis.add_argument("--max-events", type=int, default=50000)
    for name in ("info", "verify", "export"):
        command = commands.add_parser(name)
        command.add_argument("case", type=Path)
        if name == "export":
            command.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            emit(Case.create(args.case, args.name).summary())
            return 0
        case = Case(args.case)
        if args.command == "info":
            emit(case.summary())
        elif args.command == "analyze":
            config = RuleConfig(
                args.window_seconds,
                args.minimum_signals,
                args.timestamp_source,
                args.max_candidates,
                args.max_events,
            )
            if not case.verify()["ok"]:
                raise ValueError("Case integrity verification failed. Analysis was not run.")
            result = case.save_run(analyze(case.records(), config))
            emit(
                {
                    "run_id": result["id"],
                    **result["statistics"],
                    "diagnostics": result["diagnostics"],
                }
            )
        elif args.command == "verify":
            result = case.verify()
            emit(result)
            return 0 if result["ok"] else 1
        elif args.command == "export":
            with args.output.open("x", encoding="utf-8") as stream:
                json.dump(case.export(), stream, indent=2, ensure_ascii=True)
            emit({"output": str(args.output.resolve())})
        elif args.command == "ingest":
            results, errors = [], []
            paths = []
            for path in args.paths:
                if path.is_dir() and not path.is_symlink():
                    paths.extend(
                        p
                        for p in path.rglob("*")
                        if p.is_file() and p.suffix.lower() in (".eml", ".msg")
                    )
                else:
                    paths.append(path)
            if not paths:
                raise ValueError("No supported evidence files found.")
            for path in sorted(set(paths)):
                try:
                    results.append({"source": str(path), **case.ingest_file(path)})
                except (ValueError, OSError, RecursionError) as exc:
                    errors.append({"source": str(path), "error": str(exc)})
            emit({"ingested": results, "errors": errors})
            return 1 if errors else 0
        return 0
    except (ValueError, OSError, sqlite3.DatabaseError) as exc:
        print(f"etrace: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

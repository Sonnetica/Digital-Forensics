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
    analysis.add_argument(
        "--background-min-outside",
        type=int,
        default=10,
        help="Occurrences outside a pair's window before a value can count as routine background",
    )
    analysis.add_argument(
        "--background-ratio",
        type=float,
        default=5.0,
        help="Outside-to-inside occurrence ratio at which a value is routine background for a pair",
    )
    analysis.add_argument(
        "--organisation-domain",
        action="append",
        default=[],
        help="Confirmed domain of the investigated organisation; its links are ignored for coordination",
    )
    analysis.add_argument(
        "--trusted-wrapper-host",
        action="append",
        default=[],
        help="Extra link-protection host using the Safe Links url= format (normally not needed)",
    )
    analysis.add_argument("--exclude-url-domain", action="append", default=[])
    server = commands.add_parser("serve", help="Open the local investigator interface")
    server.add_argument("case", type=Path)
    server.add_argument("--port", type=int, default=8765)
    for name in ("info", "verify", "export"):
        command = commands.add_parser(name)
        command.add_argument("case", type=Path)
        if name == "export":
            command.add_argument("--output", type=Path, required=True)
            command.add_argument(
                "--bundle",
                action="store_true",
                help="Write a zip with the original sources, hashes, settings and audit record",
            )
    restore = commands.add_parser(
        "import-bundle", help="Rebuild a case from a bundle and reproduce its analyses"
    )
    restore.add_argument("bundle", type=Path)
    restore.add_argument("--case", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            emit(Case.create(args.case, args.name).summary())
            return 0
        if args.command == "import-bundle":
            from .bundle import import_bundle

            report = import_bundle(args.bundle, args.case)
            emit(report)
            return 0 if report["ok"] else 1
        case = Case(args.case)
        if args.command == "serve":
            from .web import serve

            serve(args.case, args.port)
            return 0
        if args.command == "info":
            emit({**case.summary(), "latest_run": case.run_status()})
        elif args.command == "analyze":
            config = RuleConfig(
                window_seconds=args.window_seconds,
                minimum_signals=args.minimum_signals,
                timestamp_source=args.timestamp_source,
                max_candidates=args.max_candidates,
                max_events=args.max_events,
                background_min_outside=args.background_min_outside,
                background_ratio=args.background_ratio,
                organisation_domains=args.organisation_domain,
                excluded_url_domains=args.exclude_url_domain,
                trusted_wrapper_hosts=args.trusted_wrapper_host,
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
        elif args.command == "export" and args.bundle:
            from .bundle import export_bundle

            emit({"output": str(args.output.resolve()), **export_bundle(case, args.output)})
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

"""Loopback-only investigator application; evidence content is never rendered as HTML."""

import io
import json
import secrets
import sqlite3
from collections import Counter
from datetime import datetime
from pathlib import Path

from flask import Flask, abort, jsonify, render_template, request, send_file, session
from werkzeug.exceptions import HTTPException

from .case import Case
from .correlate import analyze
from .model import MAX_FILE_BYTES, RULES, RuleConfig, object_digest


def brief(record):
    return {
        key: record[key]
        for key in (
            "id",
            "subject",
            "senders",
            "recipients",
            "date_utc",
            "received_utc",
            "size",
            "format",
        )
    } | {
        "warning_count": len(record["warnings"]),
        "artifact_counts": dict(Counter(a["kind"] for a in record["artifacts"])),
    }


def create_app(case_path):
    case = Case(case_path)
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=secrets.token_hex(32),
        MAX_CONTENT_LENGTH=100 * 1024 * 1024,
        MAX_FORM_MEMORY_SIZE=512 * 1024,
        MAX_FORM_PARTS=200,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        TRUSTED_HOSTS=["127.0.0.1", "localhost", "[::1]"],
    )

    @app.before_request
    def protect():
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("Origin")
            if origin and origin != request.host_url.rstrip("/"):
                abort(403, "Cross-origin requests are not accepted.")
            expected = session.get("csrf")
            supplied = request.headers.get("X-CSRF-Token", "")
            if not expected or not secrets.compare_digest(supplied, expected):
                abort(403, "Reload the application before submitting this request.")

    @app.after_request
    def headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
            "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(Exception)
    def error(exc):
        if isinstance(exc, HTTPException):
            return jsonify(error=exc.description), exc.code
        if isinstance(exc, (ValueError, TypeError)):
            return jsonify(error=str(exc)), 400
        if isinstance(exc, KeyError):
            return jsonify(error="The requested evidence or relationship was not found."), 404
        if isinstance(exc, sqlite3.DatabaseError):
            app.logger.exception("Case database error")
            return jsonify(
                error="Case database error. Check integrity and available disk space."
            ), 500
        app.logger.exception("Request failed")
        return jsonify(error="Request failed. See the server console for details."), 500

    @app.get("/")
    def home():
        session.setdefault("csrf", secrets.token_hex(32))
        return render_template("index.html", csrf=session["csrf"], case_name=case.summary()["name"])

    @app.get("/api/case")
    def summary():
        result = case.run()
        info = case.summary()
        records = case.records()
        info["warnings"] = sum(len(r["warnings"]) for r in records)
        info["undated"] = sum(r["date_utc"] is None for r in records)
        info["latest_run"] = (
            None
            if result is None
            else {
                "id": result["id"],
                "statistics": result["statistics"],
                "config": result["config"],
                "counts": dict(Counter(e["type"] for e in result["events"])),
                "stale": result["evidence_digest"]
                != object_digest(sorted(r["id"] for r in records)),
            }
        )
        return jsonify(info)

    def paginate(items):
        offset = int(request.args.get("offset", 0))
        limit = int(request.args.get("limit", 50))
        if offset < 0 or not 1 <= limit <= 200:
            raise ValueError("Invalid pagination; limit must be 1 to 200 and offset nonnegative.")
        return {
            "items": items[offset : offset + limit],
            "total": len(items),
            "offset": offset,
            "limit": limit,
        }

    def query_matches(record, query):
        if not query:
            return True
        return (
            query
            in " ".join(
                [
                    record["id"],
                    record["subject"],
                    record["body_preview"],
                    *(a["address"] for a in record["senders"] + record["recipients"]),
                    *(a["value"] for a in record["artifacts"]),
                ]
            ).casefold()
        )

    @app.get("/api/emails")
    def emails():
        query = request.args.get("q", "").casefold().strip()
        items = [brief(r) for r in case.records() if query_matches(r, query)]
        items.sort(key=lambda r: (r["date_utc"] is None, r["date_utc"] or "", r["id"]))
        return jsonify(paginate(items))

    @app.get("/api/emails/<evidence_id>")
    def evidence(evidence_id):
        return jsonify(case.evidence(evidence_id))

    @app.get("/api/emails/<evidence_id>/source")
    def source(evidence_id):
        raw, suffix = case.raw(evidence_id)
        return send_file(
            io.BytesIO(raw),
            mimetype="application/octet-stream",
            as_attachment=True,
            download_name=f"{evidence_id}.{suffix}",
        )

    @app.post("/api/ingest")
    def ingest():
        files = request.files.getlist("files")
        if not files or len(files) > 100:
            raise ValueError("Select 1 to 100 EML or MSG files per upload.")
        results, errors = [], []
        for upload in files:
            # Submitted paths are labels only. They are never filesystem targets.
            name = (upload.filename or "unnamed").replace("\\", "/").rsplit("/", 1)[-1]
            try:
                result = case.ingest_bytes(upload.stream.read(MAX_FILE_BYTES + 1), "upload:" + name)
                results.append({"name": name, **result})
            except (ValueError, OSError, RecursionError) as exc:
                errors.append({"name": name, "error": str(exc)})
        return jsonify(ingested=results, errors=errors), 207 if errors else 200

    @app.post("/api/analyze")
    def run_analysis():
        params = request.get_json()
        if not isinstance(params, dict):
            raise ValueError("Analysis parameters must be an object.")
        if not case.verify()["ok"]:
            raise ValueError("Case integrity verification failed; analysis was not run.")
        result = case.save_run(analyze(case.records(), RuleConfig(**params)))
        return jsonify(
            id=result["id"], statistics=result["statistics"], diagnostics=result["diagnostics"]
        )

    def filtered_events():
        run_id = request.args.get("run")
        result = case.run(run_id)
        if run_id and result is None:
            abort(404, "Analysis run not found.")
        if result is None:
            return [], {}, None
        kind = request.args.get("type", "")
        if kind and kind not in RULES:
            raise ValueError("Unknown relationship type.")
        query = request.args.get("q", "").strip().casefold()
        records = {r["id"]: r for r in case.records()}
        matching = {i for i, r in records.items() if query_matches(r, query)}
        start, end = request.args.get("start"), request.args.get("end")
        for value in (start, end):
            if value:
                datetime.strptime(value, "%Y-%m-%d")
        if start and end and start > end:
            raise ValueError("Start date must not be after end date.")
        events = []
        for event in result["events"]:
            if kind and kind != event["type"]:
                continue
            if query and not matching.intersection(event["email_ids"]):
                continue
            if start and (not event["end_utc"] or event["end_utc"][:10] < start):
                continue
            if end and (not event["start_utc"] or event["start_utc"][:10] > end):
                continue
            events.append(event)
        return events, records, result

    @app.get("/api/events")
    def events():
        items, records, result = filtered_events()
        summaries = [
            {k: v for k, v in e.items() if k not in ("support", "context")}
            | {
                "context_count": len(e["context"]),
                "support_count": len(e["support"]),
                "subjects": [records[i]["subject"] for i in e["email_ids"][:3]],
            }
            for e in items
        ]
        return jsonify(**paginate(summaries), run_id=result["id"] if result else None)

    @app.get("/api/events/<event_id>")
    def event(event_id):
        result = case.run(request.args.get("run"))
        if result:
            for item in result["events"]:
                if item["id"] == event_id:
                    return jsonify(
                        **item, messages=[brief(case.evidence(i)) for i in item["email_ids"]]
                    )
        abort(404)

    @app.get("/api/runs")
    def runs():
        with case.connect() as db:
            return jsonify(
                [
                    dict(row) | {"config": json.loads(row["config"])}
                    for row in db.execute(
                        "SELECT id,created_at,evidence_digest,config FROM runs ORDER BY created_at DESC,id DESC"
                    )
                ]
            )

    @app.get("/api/diagnostics")
    def diagnostics():
        result = case.run(request.args.get("run"))
        return jsonify(result["diagnostics"] if result else [])

    @app.get("/api/graph")
    def graph():
        events, records, result = filtered_events()
        nodes, links, chosen = {}, [], 0
        for event in events:
            new_ids = set(event["email_ids"]) - nodes.keys()
            if len(nodes) + len(new_ids) + 1 > 180:
                continue
            chosen += 1
            nodes[event["id"]] = {
                "id": event["id"],
                "kind": "event",
                "type": event["type"],
                "label": event["type"].replace("_", " "),
            }
            for evidence_id in event["email_ids"]:
                record = records[evidence_id]
                nodes[evidence_id] = {
                    "id": evidence_id,
                    "kind": "email",
                    "label": record["subject"] or "(no subject)",
                    "date": record["date_utc"],
                }
                source, target = evidence_id, event["id"]
                if event["direction"] and event["direction"]["child"] == evidence_id:
                    source, target = target, source
                links.append(
                    {"source": source, "target": target, "directed": event["type"] == "reply"}
                )
        return jsonify(
            nodes=list(nodes.values()),
            links=links,
            shown_events=chosen,
            total_events=len(events),
            truncated=chosen != len(events),
            run_id=result["id"] if result else None,
        )

    @app.get("/api/verify")
    def verify():
        return jsonify(case.verify())

    @app.get("/api/export")
    def export():
        content = json.dumps(case.export(), indent=2, ensure_ascii=True).encode()
        return send_file(
            io.BytesIO(content),
            mimetype="application/json",
            as_attachment=True,
            download_name="etrace-evidence-export.json",
        )

    return app


def serve(case_path, port=8765):
    from waitress import serve as run_server

    if not 1024 <= port <= 65535:
        raise ValueError("Port must be between 1024 and 65535.")
    print(f"E-TRACE: http://127.0.0.1:{port}", flush=True)
    print(f"Case: {Path(case_path).resolve()}", flush=True)
    print("Press Ctrl+C to stop.", flush=True)
    run_server(
        create_app(case_path),
        host="127.0.0.1",
        port=port,
        threads=4,
        max_request_body_size=100 * 1024 * 1024,
        clear_untrusted_proxy_headers=True,
    )

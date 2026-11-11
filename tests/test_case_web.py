"""Check legacy case preservation and graph filtering."""

import json
import sys
import tempfile
import unittest
from email.message import EmailMessage
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from etrace import __version__  # noqa: E402
from etrace.case import Case  # noqa: E402
from etrace.correlate import analyze  # noqa: E402
from etrace.model import canonical, digest, object_digest  # noqa: E402
from etrace.web import create_app  # noqa: E402


def raw_email(name, *, subject="Shared", body="https://example.net/shared", inline=False):
    message = EmailMessage()
    message["From"] = "sender@example.org"
    message["To"] = "recipient@example.org"
    message["Date"] = "Mon, 12 Oct 2026 09:00:00 +0000"
    message["Subject"] = subject
    message["Message-ID"] = f"<{name}@example.org>"
    message.set_content(body)
    if inline:
        message.add_attachment(
            b"logo", maintype="image", subtype="png", filename="logo.png", disposition="inline"
        )
    return message.as_bytes()


class CaseAndWebTests(unittest.TestCase):
    def test_old_case_reparsed_for_analysis_without_changing_stored_evidence(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as directory:
            case = Case.create(Path(directory) / "case.db", "Legacy parser test")
            evidence_id = case.ingest_bytes(raw_email("old", inline=True), "old.eml")["id"]
            with case.connect() as db:
                row = db.execute("SELECT record FROM evidence WHERE id=?", (evidence_id,)).fetchone()
                old = json.loads(row["record"])
                old["parser_version"] = "1.0.0"
                old.pop("content_digest")
                for artifact in old["artifacts"]:
                    if artifact["kind"] == "inline_resource_sha256":
                        artifact["kind"] = "attachment_sha256"
                        artifact["metadata"].pop("content_id", None)
                encoded = canonical(old)
                record_hash = digest(encoded.encode())
                db.execute(
                    "UPDATE evidence SET record=?,record_hash=? WHERE id=?",
                    (encoded, record_hash, evidence_id),
                )
                db.execute("DELETE FROM artifacts WHERE evidence_id=?", (evidence_id,))
                db.executemany(
                    "INSERT INTO artifacts VALUES(?,?,?,?,?)",
                    [
                        (evidence_id, a["kind"], a["value"], a["location"], canonical(a))
                        for a in old["artifacts"]
                    ],
                )
                audit = db.execute("SELECT * FROM audit WHERE action='ingest'").fetchone()
                payload = json.loads(audit["payload"])
                payload["record_hash"] = record_hash
                payload = canonical(payload)
                audit_hash = object_digest(
                    [audit["timestamp"], audit["action"], payload, audit["previous_hash"]]
                )
                db.execute(
                    "UPDATE audit SET payload=?,hash=? WHERE sequence=?",
                    (payload, audit_hash, audit["sequence"]),
                )
            self.assertTrue(case.verify()["ok"])
            current = case.records()[0]
            self.assertEqual(current["stored_parser_version"], "1.0.0")
            self.assertTrue(current["content_digest"])
            self.assertTrue(any(a["kind"] == "inline_resource_sha256" for a in current["artifacts"]))
            exported = case.export()
            stored = exported["evidence"][0]
            self.assertNotIn("content_digest", stored)
            derived = stored["analysis_record"]
            self.assertEqual(derived["parser_version"], exported["parser_version"])
            self.assertTrue(any(a["kind"] == "inline_resource_sha256" for a in derived["artifacts"]))
            self.assertTrue(case.verify()["ok"])

    def test_graph_hides_coordination_by_default_and_timeline_keeps_pair_count(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as directory:
            path = Path(directory) / "case.db"
            case = Case.create(path, "Graph test")
            case.ingest_bytes(raw_email("one"), "one.eml")
            case.ingest_bytes(raw_email("two"), "two.eml")
            case.save_run(analyze(case.records()))
            client = create_app(path).test_client()
            home = client.get("/")
            self.assertEqual(home.status_code, 200)
            self.assertIn(b"graph-coordination", home.data)
            self.assertIn(f"E-TRACE / {__version__}".encode(), home.data)
            self.assertIn(b'id="organisation-domains"', home.data)
            summary = client.get("/api/case").get_json()
            self.assertEqual(summary["suggested_organisation_domains"], ["example.org"])
            graph = client.get("/api/graph").get_json()
            self.assertEqual(graph["hidden_coordination"], 1)
            self.assertEqual(graph["total_events"], 1)  # URL reuse remains visible.
            shown = client.get("/api/graph?include_coordination=1").get_json()
            self.assertEqual(shown["hidden_coordination"], 0)
            self.assertEqual(shown["total_events"], 2)
            events = client.get("/api/events?type=possible_coordination").get_json()
            self.assertEqual(events["items"][0]["pair_count"], 1)
            # The list view stays light; pairwise support loads with the detail view.
            self.assertNotIn("pairs", events["items"][0])
            self.assertIs(events["items"][0]["bulk_mail_indicators"], False)
            detail = client.get(f"/api/events/{events['items'][0]['id']}").get_json()
            self.assertEqual(len(detail["pairs"]), 1)
            self.assertTrue(detail["pairs"][0]["support"])
            inline = client.get("/api/events?type=inline_resource_reuse")
            self.assertEqual(inline.status_code, 200)
            self.assertEqual(client.get("/api/events?type=unknown").status_code, 400)
            self.assertTrue(case.verify()["ok"])

    def test_latest_run_is_out_of_date_after_rule_parser_or_evidence_changes(self):
        import contextlib
        import io

        from etrace.cli import main
        from etrace.model import PARSER_VERSION, RULE_VERSION

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as directory:
            path = Path(directory) / "case.db"
            case = Case.create(path, "Run status")
            case.ingest_bytes(raw_email("one"), "one.eml")
            case.ingest_bytes(raw_email("two"), "two.eml")
            current = analyze(case.records())
            client = create_app(path).test_client()
            # A run saved by rules 1.0.0: version only on its events, no parser versions.
            old = json.loads(json.dumps(current))
            old.pop("rule_version")
            old.pop("parser_versions")
            for event in old["events"]:
                event["rule_version"] = "1.0.0"
            old["id"] = object_digest({k: v for k, v in old.items() if k != "id"})
            case.save_run(old)
            run = client.get("/api/case").get_json()["latest_run"]
            self.assertTrue(run["stale"])
            self.assertEqual(
                [r["code"] for r in run["stale_reasons"]], ["rule_version", "parser_version"]
            )
            self.assertIn("rules 1.0.0", run["stale_reasons"][0]["detail"])
            self.assertIn("not recorded", run["stale_reasons"][1]["detail"])
            # A run from the current code is current.
            case.save_run(current)
            run = client.get("/api/case").get_json()["latest_run"]
            self.assertEqual((run["stale"], run["stale_reasons"]), (False, []))
            self.assertEqual(run["current_rule_version"], RULE_VERSION)
            self.assertEqual(run["parser_versions"], [PARSER_VERSION])
            # New evidence makes it out of date again; the CLI reports the same status.
            case.ingest_bytes(raw_email("three"), "three.eml")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(["info", str(path)]), 0)
            info = json.loads(output.getvalue())
            self.assertEqual([r["code"] for r in info["latest_run"]["stale_reasons"]], ["evidence"])
            self.assertTrue(case.verify()["ok"])

    def test_empty_case_analysis_is_current(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as directory:
            path = Path(directory) / "case.db"
            case = Case.create(path, "Empty")
            case.save_run(analyze(case.records()))
            status = case.run_status()
            self.assertEqual((status["stale"], status["stale_reasons"]), (False, []))
            run = create_app(path).test_client().get("/api/case").get_json()["latest_run"]
            self.assertFalse(run["stale"])

    def test_changed_parsed_records_make_the_run_out_of_date(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as directory:
            path = Path(directory) / "case.db"
            case = Case.create(path, "Record digest")
            evidence_id = case.ingest_bytes(raw_email("one"), "one.eml")["id"]
            case.save_run(analyze(case.records()))
            self.assertFalse(Case(path).run_status()["stale"])
            # Same evidence and versions, but the stored parse no longer matches the run.
            with case.connect() as db:
                row = db.execute("SELECT record FROM evidence WHERE id=?", (evidence_id,)).fetchone()
                record = json.loads(row["record"])
                record["subject"] = "Altered after analysis"
                encoded = canonical(record)
                db.execute(
                    "UPDATE evidence SET record=?,record_hash=? WHERE id=?",
                    (encoded, digest(encoded.encode()), evidence_id),
                )
            status = Case(path).run_status()
            self.assertEqual([r["code"] for r in status["stale_reasons"]], ["records"])
            run = create_app(path).test_client().get("/api/case").get_json()["latest_run"]
            self.assertEqual([r["code"] for r in run["stale_reasons"]], ["records"])

    def test_summary_cards_follow_the_selected_run(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as directory:
            path = Path(directory) / "case.db"
            case = Case.create(path, "Selected run")
            case.ingest_bytes(raw_email("one"), "one.eml")
            older = case.save_run(analyze(case.records()))
            case.ingest_bytes(raw_email("two"), "two.eml")
            latest = case.save_run(analyze(case.records()))
            self.assertEqual(older["statistics"]["events"], 0)
            self.assertGreater(latest["statistics"]["events"], 0)
            client = create_app(path).test_client()
            default = client.get("/api/case").get_json()
            self.assertEqual(default["selected_run"]["id"], latest["id"])
            self.assertTrue(default["selected_run"]["is_latest"])
            chosen = client.get(f"/api/case?run={older['id']}").get_json()
            self.assertEqual(chosen["selected_run"]["id"], older["id"])
            self.assertFalse(chosen["selected_run"]["is_latest"])
            self.assertEqual(chosen["selected_run"]["statistics"]["events"], 0)
            # The latest run's own status is still reported alongside.
            self.assertEqual(chosen["latest_run"]["id"], latest["id"])
            self.assertEqual(
                chosen["latest_run"]["statistics"]["events"], latest["statistics"]["events"]
            )
            self.assertEqual(client.get("/api/case?run=missing").status_code, 404)

    def test_cli_analysis_accepts_background_and_domain_options(self):
        import contextlib
        import io

        from etrace.cli import main

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as directory:
            path = Path(directory) / "case.db"
            case = Case.create(path, "CLI options")
            case.ingest_bytes(raw_email("one"), "one.eml")
            case.ingest_bytes(raw_email("two"), "two.eml")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(
                    [
                        "analyze",
                        str(path),
                        "--background-min-outside",
                        "20",
                        "--background-ratio",
                        "3",
                        "--organisation-domain",
                        "Example.org",
                        "--exclude-url-domain",
                        "example.net",
                        "--trusted-wrapper-host",
                        "safelinks.mailprotect.example",
                    ]
                )
            self.assertEqual(status, 0)
            config = case.run()["config"]
            self.assertEqual(config["background_min_outside"], 20)
            self.assertEqual(config["background_ratio"], 3.0)
            self.assertEqual(config["organisation_domains"], ["example.org"])
            self.assertEqual(config["trusted_wrapper_hosts"], ["safelinks.mailprotect.example"])
            self.assertEqual(config["excluded_url_domains"], ["example.net"])
            self.assertEqual(json.loads(output.getvalue())["coordination_pairs"], 0)


if __name__ == "__main__":
    unittest.main()

"""Portable case bundles: export, tamper detection, rebuild and reproduction."""

import contextlib
import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from test_case_web import raw_email  # noqa: E402

from etrace.bundle import export_bundle, import_bundle  # noqa: E402
from etrace.case import Case  # noqa: E402
from etrace.cli import main  # noqa: E402
from etrace.correlate import analyze  # noqa: E402
from etrace.model import RuleConfig, digest  # noqa: E402
from etrace.web import create_app  # noqa: E402


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir=ROOT)
        self.root = Path(self.directory.name)
        self.case = Case.create(self.root / "case.db", "Handoff")
        self.case.ingest_bytes(raw_email("one"), "inbox/one.eml")
        self.older = self.case.save_run(analyze(self.case.records()))
        self.case.ingest_bytes(raw_email("two"), "inbox/two.eml")
        self.case.ingest_bytes(raw_email("two"), "copies/two.eml")  # second acquisition
        self.latest = self.case.save_run(
            analyze(self.case.records(), RuleConfig(excluded_url_domains=["example.com"]))
        )
        self.bundle = self.root / "handoff.zip"
        self.summary = export_bundle(self.case, self.bundle)

    def tearDown(self):
        self.directory.cleanup()

    def rewrite(self, change):
        """Copy the bundle with one change, keeping SHA256SUMS as is unless changed."""
        with zipfile.ZipFile(self.bundle) as source:
            files = {name: source.read(name) for name in source.namelist()}
        change(files)
        altered = self.root / "altered.zip"
        with zipfile.ZipFile(altered, "w") as target:
            for name, data in files.items():
                target.writestr(name, data)
        return altered

    def test_bundle_holds_sources_hashes_settings_and_audit(self):
        self.assertEqual((self.summary["sources"], self.summary["runs"]), (2, 2))
        self.assertTrue(self.summary["integrity_ok"])
        with zipfile.ZipFile(self.bundle) as bundle:
            names = set(bundle.namelist())
            manifest = json.loads(bundle.read("manifest.json"))
            export = json.loads(bundle.read("case-export.json"))
            sums = bundle.read("SHA256SUMS").decode()
            for line in sums.splitlines():  # the same check as sha256sum -c
                value, name = line.split("  ")
                self.assertEqual(digest(bundle.read(name)), value)
            for entry in manifest["sources"]:
                self.assertEqual(digest(bundle.read(entry["path"])), entry["sha256"])
        self.assertIn("README.txt", names)
        self.assertEqual(len([n for n in names if n.startswith("sources/")]), 2)
        self.assertEqual(manifest["case"]["audit_head"], self.case.verify()["audit_head"])
        two = next(e for e in manifest["sources"] if len(e["acquisitions"]) == 2)
        self.assertEqual(
            sorted(a["name"] for a in two["acquisitions"]), ["copies/two.eml", "inbox/two.eml"]
        )
        configs = {run["id"]: run["config"] for run in export["runs"]}
        self.assertEqual(configs[self.latest["id"]]["excluded_url_domains"], ["example.com"])
        self.assertEqual([r["active"] for r in manifest["runs"]].count(True), 1)
        with self.assertRaises(FileExistsError):  # never overwrites
            export_bundle(self.case, self.bundle)

    def test_import_rebuilds_the_case_and_reproduces_every_run(self):
        report = import_bundle(self.bundle, self.root / "rebuilt.db")
        self.assertTrue(report["ok"])
        self.assertTrue(report["original_audit_chain_ok"])
        self.assertTrue(report["rebuilt_integrity_ok"])
        self.assertEqual((report["sources_verified"], report["acquisitions"]), (2, 3))
        self.assertEqual(report["runs_compared"], 2)
        by_run = {r["original_run"]: r for r in report["runs"]}
        for original in (self.older, self.latest):  # the older run used a subset of evidence
            self.assertTrue(by_run[original["id"]]["findings_match"])
            self.assertTrue(by_run[original["id"]]["run_id_match"])  # same Python here
        self.assertEqual(report["saved_run"], self.latest["id"])
        rebuilt = Case(self.root / "rebuilt.db")
        self.assertEqual(rebuilt.run()["id"], self.latest["id"])
        self.assertFalse(rebuilt.run_status()["stale"])
        audit = rebuilt.export()["audit"]
        imports = [row for row in audit if row["action"] == "import_bundle"]
        self.assertEqual(len(imports), 1)
        self.assertIn(self.summary["audit_head"], imports[0]["payload"])

    def test_altered_source_or_unlisted_file_is_refused(self):
        def swap_source(files):
            name = next(n for n in files if n.startswith("sources/"))
            files[name] = files[name].replace(b"Shared", b"Shored")

        def add_file(files):
            files["sources/../../evil.eml"] = b"x"

        def fix_sums_but_not_name(files):
            name = next(n for n in files if n.startswith("sources/"))
            files[name] = files[name] + b"\r\n"
            files["SHA256SUMS"] = "".join(
                f"{digest(data)}  {n}\n" for n, data in sorted(files.items()) if n != "SHA256SUMS"
            ).encode()

        for change, message in (
            (swap_source, "Hash mismatch"),
            (add_file, "Unexpected bundle entry"),
            (fix_sums_but_not_name, "does not match the manifest"),
        ):
            with self.subTest(change=change.__name__):
                target = self.root / f"{change.__name__}.db"
                with self.assertRaisesRegex(ValueError, message):
                    import_bundle(self.rewrite(change), target)
                self.assertFalse(target.exists())

    def test_tampered_original_audit_is_reported(self):
        def edit_audit(files):
            export = json.loads(files["case-export.json"])
            export["audit"][1]["timestamp"] = "2000-01-01T00:00:00.000000Z"
            files["case-export.json"] = json.dumps(export).encode()
            files["SHA256SUMS"] = "".join(
                f"{digest(data)}  {n}\n" for n, data in sorted(files.items()) if n != "SHA256SUMS"
            ).encode()

        report = import_bundle(self.rewrite(edit_audit), self.root / "audit.db")
        self.assertFalse(report["ok"])
        self.assertFalse(report["original_audit_chain_ok"])
        self.assertTrue(any("entry 2" in e for e in report["original_audit_errors"]))

    def test_cli_and_web_export_bundles(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = main(["export", str(self.case.path), "--bundle", "--output", str(self.root / "cli.zip")])
            self.assertEqual(status, 0)
            status = main(["import-bundle", str(self.root / "cli.zip"), "--case", str(self.root / "cli.db")])
        self.assertEqual(status, 0)
        response = create_app(self.case.path).test_client().get("/api/export-bundle")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "application/zip")
        with zipfile.ZipFile(io.BytesIO(response.data)) as bundle:
            self.assertIn("SHA256SUMS", bundle.namelist())


if __name__ == "__main__":
    unittest.main()

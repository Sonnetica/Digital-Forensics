"""Portable case handoff: original sources, hashes, settings and audit record in one zip.

A bundle can be checked with standard tools (``sha256sum -c SHA256SUMS``) and rebuilt
with ``etrace import-bundle``, which re-verifies every hash and the original audit
chain, then re-runs each analysis with its saved settings and compares the findings.
"""

import io
import json
import re
import zipfile
from pathlib import Path

from . import __version__
from .case import Case
from .correlate import analyze
from .model import (
    MAX_FILE_BYTES,
    PARSER_VERSION,
    RULE_VERSION,
    RuleConfig,
    canonical,
    digest,
    object_digest,
    utc_now,
)

BUNDLE_VERSION = 1
MANIFEST, EXPORT, SUMS, README = "manifest.json", "case-export.json", "SHA256SUMS", "README.txt"
SOURCE_NAME = re.compile(r"sources/([0-9a-f]{64})\.(eml|msg)")
MAX_JSON_BYTES = 512 * 1024 * 1024
# Parts of a result that describe what was found, independent of the Python runtime
# recorded in parsed records (which makes run IDs machine-specific).
FINDING_KEYS = (
    "email_ids",
    "copy_groups",
    "copy_content_variations",
    "events",
    "diagnostics",
    "statistics",
)

BUNDLE_README = """E-TRACE case bundle
===================

sources/       Original evidence files, named by their SHA-256.
case-export.json  Case metadata, parsed records, every analysis run with its
               settings, the audit trail and the integrity check at export time.
manifest.json  Inventory: hashes, sizes, acquisition names and times, runs.
SHA256SUMS     SHA-256 of every other file in this bundle.

1. Check the files with standard tools
   Linux/macOS:  sha256sum -c SHA256SUMS
   Windows:      Get-FileHash -Algorithm SHA256 <file>   (compare with SHA256SUMS)

2. Rebuild the case and reproduce the analysis (E-TRACE {version} or compatible)
   etrace import-bundle <this-bundle.zip> --case rebuilt.etrace

   The import re-checks every hash and the original audit chain, ingests the
   original files, re-runs each analysis with its saved settings and reports
   whether the findings match. The rebuilt case has its own audit trail; the
   original one is preserved in case-export.json.
"""


def findings_digest(result):
    return object_digest({key: result.get(key) for key in FINDING_KEYS})


def export_bundle(case, target):
    """Write a bundle to a path (never overwritten) or a binary file object."""
    export = case.export()
    with case.connect() as db:
        run_rows = {
            row["id"]: row["created_at"] for row in db.execute("SELECT id,created_at FROM runs")
        }
    active = export["case"].get("active_run")
    sources, files = [], {}
    for record in export["evidence"]:
        raw, form = case.raw(record["id"])
        path = f"sources/{record['id']}.{form}"
        files[path] = raw
        sources.append(
            {
                "path": path,
                "sha256": record["id"],
                "size": len(raw),
                "format": form,
                "acquisitions": record["sources"],
            }
        )
    runs = [
        {
            "id": run["id"],
            "created_at": run_rows.get(run["id"]),
            "application_version": run.get("application_version"),
            "rule_version": run.get("rule_version"),
            "parser_versions": run.get("parser_versions"),
            "findings_digest": findings_digest(run),
            "active": run["id"] == active,
        }
        for run in export["runs"]
    ]
    manifest = {
        "bundle_version": BUNDLE_VERSION,
        "created_at": utc_now(),
        "application_version": __version__,
        "parser_version": PARSER_VERSION,
        "rule_version": RULE_VERSION,
        "case": {
            "name": export["case"]["name"],
            "created_at": export["case"].get("created_at"),
            "audit_head": export["case"]["audit_head"],
            "integrity_ok": export["integrity"]["ok"],
        },
        "sources": sources,
        "runs": runs,
    }
    files[EXPORT] = json.dumps(export, indent=2, ensure_ascii=True).encode()
    files[MANIFEST] = json.dumps(manifest, indent=2, ensure_ascii=True).encode()
    files[README] = BUNDLE_README.format(version=__version__).encode()
    sums = "".join(f"{digest(data)}  {name}\n" for name, data in sorted(files.items()))
    files[SUMS] = sums.encode()
    if isinstance(target, (str, Path)):
        stream = Path(target).open("xb")
    else:
        stream = target
    try:
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            for name in sorted(files):
                bundle.writestr(name, files[name])
    finally:
        if stream is not target:
            stream.close()
    return {
        "sources": len(sources),
        "runs": len(runs),
        "audit_head": manifest["case"]["audit_head"],
        "integrity_ok": manifest["case"]["integrity_ok"],
    }


def _read_bundle(path):
    """Read and hash-check every member; refuse anything unexpected."""
    with zipfile.ZipFile(path) as bundle:
        infos = bundle.infolist()
        names = [info.filename for info in infos]
        if len(names) != len(set(names)):
            raise ValueError("Bundle contains duplicate entries.")
        for info in infos:
            limit = MAX_FILE_BYTES if info.filename.startswith("sources/") else MAX_JSON_BYTES
            if (
                info.filename not in (MANIFEST, EXPORT, SUMS, README)
                and not SOURCE_NAME.fullmatch(info.filename)
            ) or info.is_dir():
                raise ValueError(f"Unexpected bundle entry: {info.filename!r}")
            if info.file_size > limit:
                raise ValueError(f"Bundle entry is too large: {info.filename}")
        missing = {MANIFEST, EXPORT, SUMS} - set(names)
        if missing:
            raise ValueError(f"Bundle is missing {', '.join(sorted(missing))}.")
        files = {name: bundle.read(name) for name in names}
    listed = {}
    for line in files.pop(SUMS).decode("ascii").splitlines():
        value, _, name = line.partition("  ")
        if not re.fullmatch(r"[0-9a-f]{64}", value) or not name or name in listed:
            raise ValueError("SHA256SUMS is malformed.")
        listed[name] = value
    if set(listed) != set(files):
        raise ValueError("SHA256SUMS does not list exactly the files in the bundle.")
    for name, data in files.items():
        if digest(data) != listed[name]:
            raise ValueError(f"Hash mismatch for {name}; the bundle was altered or damaged.")
    return files


def _check_original_audit(export, manifest, source_ids):
    """Recompute the original hash chain from the exported audit trail."""
    errors, previous = [], "0" * 64
    runs = {run["id"]: run for run in export["runs"]}
    for expected_sequence, row in enumerate(export["audit"], 1):
        if row["sequence"] != expected_sequence:
            errors.append(f"Audit sequence gap at entry {row['sequence']}")
        if row["previous_hash"] != previous or row["hash"] != object_digest(
            [row["timestamp"], row["action"], row["payload"], previous]
        ):
            errors.append(f"Audit chain mismatch at entry {row['sequence']}")
        payload = json.loads(row["payload"])
        if row["action"] == "ingest" and payload["evidence_id"] not in source_ids:
            errors.append(f"Audit entry {row['sequence']} names evidence absent from the bundle")
        if row["action"] == "analyze":
            run = runs.get(payload["run_id"])
            if run is None or digest(canonical(run).encode()) != payload["result_hash"]:
                errors.append(f"Audit entry {row['sequence']} does not match a bundled run")
        previous = row["hash"]
    if previous != manifest["case"]["audit_head"] or previous != export["case"]["audit_head"]:
        errors.append("Audit head does not match the manifest.")
    for run in export["runs"]:
        if object_digest({k: v for k, v in run.items() if k != "id"}) != run["id"]:
            errors.append(f"Bundled run {run['id'][:12]} does not match its identity")
    return errors


def import_bundle(bundle_path, case_path):
    """Rebuild a case from a bundle and reproduce its analyses. Returns a report."""
    files = _read_bundle(bundle_path)
    manifest = json.loads(files[MANIFEST])
    export = json.loads(files[EXPORT])
    if manifest.get("bundle_version") != BUNDLE_VERSION:
        raise ValueError("Unsupported bundle version.")
    sources = {}
    for entry in manifest["sources"]:
        match = SOURCE_NAME.fullmatch(entry["path"])
        data = files.get(entry["path"])
        if (
            match is None
            or data is None
            or match.group(1) != entry["sha256"]
            or digest(data) != entry["sha256"]
            or len(data) != entry["size"]
        ):
            raise ValueError(f"Source does not match the manifest: {entry['path']}")
        sources[entry["sha256"]] = (data, entry)
    stray = {name for name in files if name.startswith("sources/")} - {
        entry[1]["path"] for entry in sources.values()
    }
    exported_ids = {record["id"] for record in export["evidence"]}
    if stray or exported_ids != set(sources):
        raise ValueError("Bundle sources, manifest and case export do not agree.")
    audit_errors = _check_original_audit(export, manifest, set(sources))

    case = Case.create(case_path, manifest["case"]["name"])
    acquisitions = sorted(
        (acquisition["acquired_at"], acquisition["name"], evidence_id)
        for evidence_id, (_, entry) in sources.items()
        for acquisition in entry["acquisitions"]
    )
    for _, name, evidence_id in acquisitions:
        case.ingest_bytes(sources[evidence_id][0], name)
    case.record_bundle_import(
        {
            "bundle_sha256": digest(Path(bundle_path).read_bytes()),
            "original_case": manifest["case"]["name"],
            "original_audit_head": manifest["case"]["audit_head"],
            "original_integrity_ok": manifest["case"]["integrity_ok"],
            "original_audit_chain_ok": not audit_errors,
            "sources": len(sources),
            "acquisitions": len(acquisitions),
        }
    )

    records = {record["id"]: record for record in case.records()}
    active = export["case"].get("active_run")
    created = {run["id"]: run.get("created_at") or "" for run in manifest["runs"]}
    reports, to_save = [], None
    for original in sorted(export["runs"], key=lambda run: (created.get(run["id"], ""), run["id"])):
        report = {
            "original_run": original["id"],
            "created_at": created.get(original["id"]),
            "original_versions": {
                "application": original.get("application_version"),
                "rules": original.get("rule_version"),
                "parser": original.get("parser_versions"),
            },
        }
        reports.append(report)
        comparable = original.get("rule_version") == RULE_VERSION and original.get(
            "parser_versions"
        ) in ([PARSER_VERSION], [])
        try:
            config = RuleConfig(**original["config"])
            result = analyze([records[i] for i in original["email_ids"]], config)
        except (TypeError, ValueError, KeyError) as exc:
            report.update(reproduced=False, comparable=False, note=f"Could not re-run: {exc}")
            continue
        report.update(
            reproduced=True,
            reproduced_run=result["id"],
            comparable=comparable,
            findings_match=findings_digest(result) == findings_digest(original),
            run_id_match=result["id"] == original["id"],
        )
        if not comparable:
            report["note"] = (
                f"Made with rules {original.get('rule_version')} and parser "
                f"{original.get('parser_versions')}; this E-TRACE uses rules {RULE_VERSION} and "
                f"parser {PARSER_VERSION}, so differences are expected."
            )
        elif report["findings_match"] and not report["run_id_match"]:
            report["note"] = (
                "Findings match; the run ID differs because parsed records note the Python "
                "or library version used."
            )
        if original["id"] == active and set(original["email_ids"]) == set(records):
            to_save = result
    if to_save is not None:
        case.save_run(to_save)
    comparable_runs = [r for r in reports if r.get("comparable")]
    return {
        "case": str(case.path),
        "original_case": manifest["case"]["name"],
        "sources_verified": len(sources),
        "acquisitions": len(acquisitions),
        "original_integrity_ok": manifest["case"]["integrity_ok"],
        "original_audit_chain_ok": not audit_errors,
        "original_audit_errors": audit_errors,
        "original_audit_head": manifest["case"]["audit_head"],
        "runs": reports,
        "runs_compared": len(comparable_runs),
        "runs_with_matching_findings": sum(bool(r.get("findings_match")) for r in reports),
        "saved_run": to_save["id"] if to_save else None,
        "rebuilt_integrity_ok": case.verify()["ok"],
        "ok": (
            not audit_errors
            and manifest["case"]["integrity_ok"]
            and all(r["findings_match"] for r in comparable_runs)
        ),
    }


def bundle_bytes(case):
    buffer = io.BytesIO()
    export_bundle(case, buffer)
    return buffer.getvalue()

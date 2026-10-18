"""SQLite case storage, acquisition records, and integrity verification."""

import json
import sqlite3
from contextlib import closing, contextmanager
from pathlib import Path

from . import __version__
from .model import MAX_FILE_BYTES, canonical, digest, object_digest, utc_now
from .parser import parse_email

SCHEMA_VERSION = 1
SCHEMA = """
CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE evidence(
    id TEXT PRIMARY KEY, format TEXT NOT NULL, raw BLOB NOT NULL,
    record TEXT NOT NULL, record_hash TEXT NOT NULL
);
CREATE TABLE sources(
    id INTEGER PRIMARY KEY, evidence_id TEXT NOT NULL REFERENCES evidence(id),
    name TEXT NOT NULL, acquired_at TEXT NOT NULL, source_size INTEGER NOT NULL,
    UNIQUE(evidence_id, name)
);
CREATE TABLE artifacts(
    evidence_id TEXT NOT NULL REFERENCES evidence(id), kind TEXT NOT NULL,
    value TEXT NOT NULL, location TEXT NOT NULL, observation TEXT NOT NULL
);
CREATE INDEX artifact_lookup ON artifacts(kind, value);
CREATE TABLE runs(
    id TEXT PRIMARY KEY, created_at TEXT NOT NULL, evidence_digest TEXT NOT NULL,
    config TEXT NOT NULL, result TEXT NOT NULL, result_hash TEXT NOT NULL
);
CREATE TABLE audit(
    sequence INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, action TEXT NOT NULL,
    payload TEXT NOT NULL, previous_hash TEXT NOT NULL, hash TEXT NOT NULL
);
"""


class Case:
    def __init__(self, path):
        self.path = Path(path).expanduser().resolve()
        if not self.path.is_file():
            raise ValueError(f"Case does not exist: {self.path}. Create it with etrace init.")
        with self.connect() as db:
            try:
                version = db.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()
            except sqlite3.DatabaseError as exc:
                raise ValueError("This is not an eTrace case database.") from exc
            if version is None or version[0] != str(SCHEMA_VERSION):
                raise ValueError("Unsupported case schema version.")

    @classmethod
    def create(cls, path, name):
        path = Path(path).expanduser().resolve()
        if not name.strip() or len(name) > 200:
            raise ValueError("Case name must contain 1 to 200 characters.")
        path.parent.mkdir(parents=True, exist_ok=True)
        # Exclusive creation prevents accidental overwriting of another case.
        with path.open("xb"):
            pass
        try:
            with closing(sqlite3.connect(path)) as db, db:
                db.executescript(SCHEMA)
                db.executemany(
                    "INSERT INTO metadata VALUES (?, ?)",
                    [
                        ("schema_version", str(SCHEMA_VERSION)),
                        ("name", name.strip()),
                        ("created_at", utc_now()),
                        ("application_version", __version__),
                    ],
                )
                cls._audit(db, "create", {"name": name.strip(), "version": __version__})
        except Exception:
            path.unlink(missing_ok=True)
            raise
        return cls(path)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True, timeout=30)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def _audit(db, action, payload):
        previous = db.execute("SELECT hash FROM audit ORDER BY sequence DESC LIMIT 1").fetchone()
        previous_hash = previous[0] if previous else "0" * 64
        timestamp = utc_now()
        encoded = canonical(payload)
        hashed = object_digest([timestamp, action, encoded, previous_hash])
        db.execute(
            "INSERT INTO audit(timestamp, action, payload, previous_hash, hash) VALUES(?,?,?,?,?)",
            (timestamp, action, encoded, previous_hash, hashed),
        )

    def ingest_bytes(self, raw, name):
        if not name or len(name) > 4096 or "\x00" in name:
            raise ValueError("Invalid source name.")
        record = parse_email(raw, name)
        evidence_id = record["id"]
        encoded = canonical(record)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            exists = db.execute(
                "SELECT record_hash,record FROM evidence WHERE id=?", (evidence_id,)
            ).fetchone()
            if not exists:
                db.execute(
                    "INSERT INTO evidence VALUES(?,?,?,?,?)",
                    (evidence_id, record["format"], raw, encoded, digest(encoded.encode())),
                )
                db.executemany(
                    "INSERT INTO artifacts VALUES(?,?,?,?,?)",
                    [
                        (evidence_id, a["kind"], a["value"], a["location"], canonical(a))
                        for a in record["artifacts"]
                    ],
                )
            acquired = utc_now()
            record_hash = exists["record_hash"] if exists else digest(encoded.encode())
            inserted = db.execute(
                "INSERT OR IGNORE INTO sources(evidence_id,name,acquired_at,source_size) VALUES(?,?,?,?)",
                (evidence_id, name, acquired, len(raw)),
            ).rowcount
            if inserted:
                self._audit(
                    db,
                    "ingest",
                    {
                        "evidence_id": evidence_id,
                        "source": name,
                        "record_hash": record_hash,
                        "size": len(raw),
                        "acquired_at": acquired,
                    },
                )
        return {
            "id": evidence_id,
            "new_evidence": not bool(exists),
            "new_source": bool(inserted),
            "warnings": json.loads(exists["record"])["warnings"] if exists else record["warnings"],
        }

    def ingest_file(self, path):
        path = Path(path).expanduser()
        if path.is_symlink():
            raise ValueError(
                "Symbolic links are not ingested; select the original file explicitly."
            )
        with path.open("rb") as stream:
            raw = stream.read(MAX_FILE_BYTES + 1)
        return self.ingest_bytes(raw, str(path.resolve()))

    def records(self):
        with self.connect() as db:
            records = [
                json.loads(row[0]) for row in db.execute("SELECT record FROM evidence ORDER BY id")
            ]
        return records

    def evidence(self, evidence_id):
        with self.connect() as db:
            row = db.execute("SELECT record FROM evidence WHERE id=?", (evidence_id,)).fetchone()
            if row is None:
                raise KeyError(evidence_id)
            record = json.loads(row[0])
            record["sources"] = [
                dict(r)
                for r in db.execute(
                    "SELECT name,acquired_at,source_size FROM sources WHERE evidence_id=? ORDER BY id",
                    (evidence_id,),
                )
            ]
        return record

    def raw(self, evidence_id):
        with self.connect() as db:
            row = db.execute(
                "SELECT raw,format FROM evidence WHERE id=?", (evidence_id,)
            ).fetchone()
            if row is None:
                raise KeyError(evidence_id)
            return bytes(row[0]), row[1]

    def summary(self):
        with self.connect() as db:
            return self._summary(db)

    @staticmethod
    def _summary(db):
        metadata = dict(db.execute("SELECT key,value FROM metadata"))
        counts = {
            table: db.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            for table in ("evidence", "sources", "artifacts", "runs")
        }
        head = db.execute("SELECT hash FROM audit ORDER BY sequence DESC LIMIT 1").fetchone()
        return {**metadata, **counts, "audit_head": head[0] if head else None}

    def save_run(self, result):
        encoded = canonical(result)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            current_digest = object_digest(
                [r[0] for r in db.execute("SELECT id FROM evidence ORDER BY id")]
            )
            if current_digest != result["evidence_digest"]:
                raise ValueError("Evidence changed during analysis. Run analysis again.")
            db.execute(
                "INSERT OR IGNORE INTO runs VALUES(?,?,?,?,?,?)",
                (
                    result["id"],
                    utc_now(),
                    result["evidence_digest"],
                    canonical(result["config"]),
                    encoded,
                    digest(encoded.encode()),
                ),
            )
            db.execute(
                "INSERT OR REPLACE INTO metadata(key,value) VALUES('active_run',?)", (result["id"],)
            )
            self._audit(
                db, "analyze", {"run_id": result["id"], "result_hash": digest(encoded.encode())}
            )
        return result

    def run(self, run_id=None):
        with self.connect() as db:
            if run_id is None:
                active = db.execute("SELECT value FROM metadata WHERE key='active_run'").fetchone()
                run_id = active[0] if active else None
            if run_id:
                row = db.execute("SELECT result FROM runs WHERE id=?", (run_id,)).fetchone()
            else:
                row = db.execute(
                    "SELECT result FROM runs ORDER BY created_at DESC, id DESC LIMIT 1"
                ).fetchone()
        return json.loads(row[0]) if row else None

    def verify(self):
        with self.connect() as db:
            db.execute("BEGIN")
            return self._verify(db)

    @staticmethod
    def _verify(db):
        errors = []
        previous = "0" * 64
        try:
            if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                errors.append("SQLite integrity check failed.")
            if db.execute("PRAGMA foreign_key_check").fetchone():
                errors.append("Foreign key check failed.")
            evidence_hashes = {}
            for row in db.execute("SELECT * FROM evidence"):
                if digest(row["raw"]) != row["id"]:
                    errors.append(f"Source hash mismatch: {row['id']}")
                if digest(row["record"].encode()) != row["record_hash"]:
                    errors.append(f"Parsed record hash mismatch: {row['id']}")
                evidence_hashes[row["id"]] = row["record_hash"]
                record = json.loads(row["record"])
                if (
                    record["id"] != row["id"]
                    or record["sha256"] != row["id"]
                    or record["size"] != len(row["raw"])
                    or record["format"] != row["format"]
                ):
                    errors.append(f"Evidence metadata mismatch: {row['id']}")
                actual = sorted(
                    tuple(r)
                    for r in db.execute(
                        "SELECT kind,value,location,observation FROM artifacts WHERE evidence_id=?",
                        (row["id"],),
                    )
                )
                if actual != sorted(
                    (a["kind"], a["value"], a["location"], canonical(a))
                    for a in record["artifacts"]
                ):
                    errors.append(f"Artifact index mismatch: {row['id']}")
            runs = {}
            for row in db.execute("SELECT * FROM runs"):
                if digest(row["result"].encode()) != row["result_hash"]:
                    errors.append(f"Analysis hash mismatch: {row['id']}")
                result = json.loads(row["result"])
                if (
                    result["id"] != row["id"]
                    or object_digest({k: v for k, v in result.items() if k != "id"}) != row["id"]
                ):
                    errors.append(f"Analysis identity mismatch: {row['id']}")
                if (
                    canonical(result["config"]) != row["config"]
                    or result["evidence_digest"] != row["evidence_digest"]
                ):
                    errors.append(f"Analysis index mismatch: {row['id']}")
                runs[row["id"]] = row["result_hash"]
            seen_sources = set()
            seen_runs = set()
            last_run = None
            metadata = dict(db.execute("SELECT key,value FROM metadata"))
            sequence = 0
            for row in db.execute("SELECT * FROM audit ORDER BY sequence"):
                sequence += 1
                if row["sequence"] != sequence:
                    errors.append(f"Audit sequence gap at entry {row['sequence']}")
                expected = object_digest(
                    [row["timestamp"], row["action"], row["payload"], previous]
                )
                if expected != row["hash"] or row["previous_hash"] != previous:
                    errors.append(f"Audit chain mismatch at entry {row['sequence']}")
                payload = json.loads(row["payload"])
                if sequence == 1 and row["action"] != "create":
                    errors.append("The audit trail does not begin with case creation.")
                if row["action"] == "create":
                    if (
                        payload["name"] != metadata["name"]
                        or payload["version"] != metadata["application_version"]
                        or sequence != 1
                    ):
                        errors.append("Case metadata does not match its creation record.")
                elif row["action"] == "ingest":
                    if evidence_hashes.get(payload["evidence_id"]) != payload["record_hash"]:
                        errors.append(f"Acquisition record mismatch at entry {row['sequence']}")
                    seen_sources.add((payload["evidence_id"], payload["source"]))
                    source = db.execute(
                        "SELECT acquired_at,source_size FROM sources WHERE evidence_id=? AND name=?",
                        (payload["evidence_id"], payload["source"]),
                    ).fetchone()
                    if (
                        source is None
                        or source["source_size"] != payload["size"]
                        or (
                            "acquired_at" in payload
                            and source["acquired_at"] != payload["acquired_at"]
                        )
                    ):
                        errors.append(
                            f"Source acquisition metadata mismatch at entry {row['sequence']}"
                        )
                elif row["action"] == "analyze":
                    if runs.get(payload["run_id"]) != payload["result_hash"]:
                        errors.append(f"Analysis audit mismatch at entry {row['sequence']}")
                    seen_runs.add(payload["run_id"])
                    last_run = payload["run_id"]
                else:
                    errors.append(f"Unknown audit action at entry {row['sequence']}")
                previous = row["hash"]
            if sequence == 0:
                errors.append("The case audit trail is empty.")
            actual_sources = set(
                tuple(r) for r in db.execute("SELECT evidence_id,name FROM sources")
            )
            if actual_sources != seen_sources:
                errors.append("Source inventory does not match the audit trail.")
            if {source[0] for source in actual_sources} != set(evidence_hashes):
                errors.append("Evidence inventory does not match source acquisitions.")
            if set(runs) != seen_runs:
                errors.append("Analysis inventory does not match the audit trail.")
            if "active_run" in metadata and metadata["active_run"] != last_run:
                errors.append("Active analysis does not match the audit trail.")
        except (ValueError, KeyError, TypeError, sqlite3.DatabaseError) as exc:
            errors.append(f"Case records are malformed: {exc}")
        return {
            "ok": not errors,
            "errors": errors,
            "audit_head": previous,
            "scope": "Internal consistency; compare the audit head with a separately retained export.",
        }

    def export(self):
        with self.connect() as db:
            db.execute("BEGIN")
            evidence = []
            for row in db.execute("SELECT id,record FROM evidence ORDER BY id"):
                record = json.loads(row["record"])
                record["sources"] = [
                    dict(source)
                    for source in db.execute(
                        "SELECT name,acquired_at,source_size FROM sources WHERE evidence_id=? ORDER BY id",
                        (row["id"],),
                    )
                ]
                evidence.append(record)
            return {
                "schema_version": SCHEMA_VERSION,
                "application_version": __version__,
                "case": self._summary(db),
                "evidence": evidence,
                "runs": [
                    json.loads(r[0])
                    for r in db.execute("SELECT result FROM runs ORDER BY created_at,id")
                ],
                "audit": [dict(r) for r in db.execute("SELECT * FROM audit ORDER BY sequence")],
                "integrity": self._verify(db),
            }

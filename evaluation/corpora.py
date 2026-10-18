"""Acquire pinned public corpora and prepare byte-preserving email inputs."""

import argparse
import hashlib
import json
import random
import tarfile
import urllib.request
from datetime import UTC, datetime
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from pathlib import Path

from generate import RULES

SOURCES = {
    "20030228_easy_ham.tar.bz2": (
        "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2",
        "2b7b65904bcfcc31d2b5f51946f2d261370b257402cbbd62930b46ab83367438",
    ),
    "20030228_hard_ham.tar.bz2": (
        "https://spamassassin.apache.org/old/publiccorpus/20030228_hard_ham.tar.bz2",
        "ce2ce67880643dbde65ea7f85bffbfe4417349c4bd80b6b0de56262ae6b0a9c9",
    ),
    "20030228_spam.tar.bz2": (
        "https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2",
        "c08debc32413804949a866be45ef78195cec2cbafd1da744ed76cdb860589743",
    ),
    "Enron_threads_corpora.zip": (
        "https://www.cs.cmu.edu/~einat/Enron_threads_corpora.zip",
        "28e0feb8a4860c625f850b3f63d29bb2d04aff41174c79f97d4200469d057653",
    ),
    "threads_datasets.zip": (
        "https://www.cs.cmu.edu/~einat/threads_datasets.zip",
        "583db911b719e99b7b3f3e55e3ca25751aa795cfdcc4481c81d94056242b23d4",
    ),
}
MAX_DOWNLOAD = 50 * 1024 * 1024
MAX_MESSAGE = 25 * 1024 * 1024


def external(path):
    path = Path(path).expanduser().resolve()
    if path.is_relative_to(Path(__file__).resolve().parent.parent):
        raise ValueError("Keep downloads, datasets and results outside the source repository.")
    return path


def empty_directory(path):
    path = external(path)
    if path.exists() and (not path.is_dir() or any(path.iterdir())):
        raise ValueError("Output directory must be empty.")
    path.mkdir(parents=True, exist_ok=True)
    return path


def write_json(path, value):
    path = external(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def fetch(name, cache):
    cache = external(cache)
    cache.mkdir(parents=True, exist_ok=True)
    target = cache / name
    url, expected = SOURCES[name]
    if not target.exists():
        partial = target.with_name(target.name + ".part")
        if partial.exists():
            raise ValueError(
                f"Incomplete download already exists; inspect it before retrying: {partial}"
            )
        try:
            with partial.open("xb") as stream:
                with urllib.request.urlopen(url, timeout=60) as response:
                    size = 0
                    while block := response.read(1024 * 1024):
                        size += len(block)
                        if size > MAX_DOWNLOAD:
                            raise ValueError("Download exceeds the corpus size limit.")
                        stream.write(block)
            if hashlib.sha256(partial.read_bytes()).hexdigest() != expected:
                raise ValueError(f"Archive hash mismatch: {name}")
            partial.rename(target)
        except Exception:
            if partial.exists():
                partial.unlink()
            raise
    if target.stat().st_size > MAX_DOWNLOAD:
        raise ValueError(f"Oversized archive: {name}")
    if hashlib.sha256(target.read_bytes()).hexdigest() != expected:
        raise ValueError(f"Archive hash mismatch: {name}")
    return target


def source_description(names):
    return [
        {"archive": name, "url": SOURCES[name][0], "sha256": SOURCES[name][1]} for name in names
    ]


def message_date(raw):
    header = BytesParser(policy=policy.default).parsebytes(raw, headersonly=True)
    dates = header.get_all("Date", [])
    if len(dates) != 1:
        return None
    try:
        value = parsedate_to_datetime(str(dates[0]))
        return value.astimezone(UTC) if value.utcoffset() is not None else None
    except (ValueError, TypeError, OverflowError):
        return None


def prepare(output, cache, count=1000, seed=47):
    if type(count) is not int or not 1 <= count <= 10000:
        raise ValueError("Message count must be between 1 and 10000.")
    output = empty_directory(output)
    names = [name for name in SOURCES if name.endswith(".tar.bz2")]
    messages = {}
    excluded_members = []
    for name in names:
        with tarfile.open(fetch(name, cache), "r:bz2") as archive:
            members = archive.getmembers()
            if len(members) > 10000 or sum(m.size for m in members) > 200 * 1024 * 1024:
                raise ValueError("Archive expands beyond the corpus size limit.")
            for member in members:
                if not member.isfile():
                    continue
                basename = Path(member.name).name
                # Apache names evidence as a sequence number followed by an MD5.
                parts = basename.split(".")
                if len(parts) != 2 or not parts[0].isdigit() or len(parts[1]) != 32:
                    excluded_members.append({"archive": name, "member": member.name})
                    continue
                if member.size > MAX_MESSAGE:
                    raise ValueError(f"Oversized message: {member.name}")
                with archive.extractfile(member) as stream:
                    raw = stream.read(MAX_MESSAGE + 1)
                sha = hashlib.sha256(raw).hexdigest()
                entry = messages.setdefault(
                    sha, {"raw": raw, "date": message_date(raw), "sources": []}
                )
                entry["sources"].append({"archive": name, "member": member.name})
    if count > len(messages):
        raise ValueError(
            f"Requested {count} messages; corpus has {len(messages)} unique byte streams."
        )
    ordered = sorted(
        messages, key=lambda sha: (messages[sha]["date"] or datetime.max.replace(tzinfo=UTC), sha)
    )
    start = random.Random(seed).randrange(len(ordered) - count + 1)
    selected = ordered[start : start + count]
    (output / "messages").mkdir()
    files, provenance = {}, {}
    for sha in selected:
        name = f"messages/{sha}.eml"
        (output / name).write_bytes(messages[sha]["raw"])
        files[name] = sha
        provenance[name] = messages[sha]["sources"]
    dated = [messages[sha]["date"] for sha in selected if messages[sha]["date"] is not None]
    manifest = {
        "schema_version": 2,
        "tier": "public-background",
        "seed": seed,
        "files": files,
        "relationships": {rule: [] for rule in RULES},
        "negative_relationships": {rule: [] for rule in RULES},
        "complete_for": {rule: [] for rule in RULES},
        "expected_parameters": {},
        "scope": "Unlabelled historical email workload. Spam/ham labels are not relationship truth. No accuracy claim is available without independent relationship assessment.",
        "provenance": {
            "dataset": "Apache SpamAssassin public corpus, February 2003 release",
            "documentation": "https://spamassassin.apache.org/old/publiccorpus/readme.html",
            "archives": source_description(names),
            "selection": "Seeded contiguous window after sorting unique files by aware Date then SHA-256; unknown dates sort last. No filtering by E-TRACE outcomes. Whole threads are not guaranteed.",
            "window_start_index": start,
            "population_unique_messages": len(messages),
            "excluded_nonmessage_members": excluded_members,
            "message_sources": provenance,
            "transformations": "Renamed to SHA-256.eml; message bytes unchanged from pinned archive members. Upstream address obfuscation and header edits remain.",
            "selected_unknown_dates": count - len(dated),
            "earliest_date_utc": min(dated).isoformat() if dated else None,
            "latest_date_utc": max(dated).isoformat() if dated else None,
        },
    }
    write_json(output / "ground_truth.json", manifest)
    return {
        "output": str(output),
        "messages": count,
        "provenance": {k: v for k, v in manifest["provenance"].items() if k != "message_sources"},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--count", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=47)
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(args.output, args.cache, args.count, args.seed), indent=2))
    except (OSError, ValueError, tarfile.TarError) as exc:
        parser.exit(2, f"corpora: {exc}\n")


if __name__ == "__main__":
    main()

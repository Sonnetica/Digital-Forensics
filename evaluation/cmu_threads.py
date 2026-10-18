"""Measure header-linked adjacency coverage against published CMU threading queries."""

import argparse
import hashlib
import json
import platform
import time
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

from corpora import empty_directory, fetch, source_description, write_json

from etrace.correlate import analyze
from etrace.model import RuleConfig
from etrace.parser import parse_email


def evaluate_threading(cache, output, split="test"):
    if split not in ("train", "test"):
        raise ValueError("Choose the published train or test split.")
    output = empty_directory(output)
    names = ("Enron_threads_corpora.zip", "threads_datasets.zip")
    paths = [fetch(name, cache) for name in names]
    groups = {}
    with zipfile.ZipFile(paths[0]) as corpus, zipfile.ZipFile(paths[1]) as labels:
        for owner in ("farmer-d", "germany-c"):
            queries = {}
            for line in labels.read(f"threads_dataset_{owner}.txt").decode("utf-8").splitlines():
                fields = line.split()
                if not fields or fields[0].startswith("//"):
                    continue
                if fields[0] == split:
                    queries[f"{int(fields[1]):05d}"] = {f"{int(x):05d}" for x in fields[2:]}
            records, mapping, hashes = {}, {}, {}
            header_coverage = Counter()
            started = time.perf_counter()
            for member in sorted(corpus.namelist()):
                if not member.startswith(owner + "/") or member.endswith("/"):
                    continue
                raw = corpus.read(member)
                if len(raw) > 25 * 1024 * 1024:
                    raise ValueError("Oversized CMU source member.")
                # The research release prepends a blank line before its headers.
                derived = raw.lstrip(b"\r\n")
                sha = hashlib.sha256(derived).hexdigest()
                relative = f"inputs/{owner}/{Path(member).name}.eml"
                path = output / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(derived)
                hashes[relative] = {
                    "archive_member": member,
                    "original_sha256": hashlib.sha256(raw).hexdigest(),
                    "derived_sha256": sha,
                    "removed_leading_bytes": len(raw) - len(derived),
                }
                record = parse_email(derived, relative)
                records.setdefault(sha, record)
                mapping[Path(member).name] = sha
                for key in ("message_id", "in_reply_to", "references"):
                    header_coverage[key] += int(any(a["kind"] == key for a in record["artifacts"]))
            result = analyze(list(records.values()), RuleConfig())
            neighbors = defaultdict(set)
            for event in result["events"]:
                if event["type"] == "reply":
                    a, b = event["direction"]["parent"], event["direction"]["child"]
                    neighbors[a].add(b)
                    neighbors[b].add(a)
            rows = []
            for query, answers in sorted(queries.items()):
                if query not in mapping or any(answer not in mapping for answer in answers):
                    raise ValueError("Published query references an absent corpus member.")
                expected = {mapping[a] for a in answers}
                actual = neighbors[mapping[query]]
                rows.append(
                    {
                        "query": query,
                        "expected_adjacent_files": sorted(answers),
                        "recovered_adjacent_files": sorted(
                            a for a in answers if mapping[a] in actual
                        ),
                        "predicted_neighbors": len(actual),
                        "correct_neighbors": len(expected & actual),
                        "expected_neighbors": len(expected),
                    }
                )
            recovered = sum(r["correct_neighbors"] for r in rows)
            expected_count = sum(r["expected_neighbors"] for r in rows)
            predicted_count = sum(r["predicted_neighbors"] for r in rows)
            groups[owner] = {
                "messages": len(mapping),
                "unique_byte_streams": len(records),
                "queries": len(rows),
                "published_adjacent_answers": expected_count,
                "recovered_answers": recovered,
                "adjacency_recall": recovered / expected_count if expected_count else None,
                "adjacency_precision": recovered / predicted_count if predicted_count else None,
                "header_coverage": dict(header_coverage),
                "query_results": rows,
                "input_hashes": hashes,
                "run_id": result["id"],
                "parse_and_analysis_seconds": time.perf_counter() - started,
            }
    report = {
        "schema_version": 1,
        "benchmark": "CMU SIGIR 2006 threading",
        "split": split,
        "source": "https://www.cs.cmu.edu/~einat/datasets.html",
        "paper": "https://www.cs.cmu.edu/~einat/sigir-06.pdf",
        "archives": source_description(names),
        "corpora": groups,
        "python": platform.python_version(),
        "config": RuleConfig().as_dict(),
        "task_mapping": "Published queries ask for adjacent parent OR child messages. E-TRACE directed reply edges are made undirected solely for this adjacency assessment. Query-answer occurrences are scored, not whole-corpus negative pairs.",
        "limitations": "The paper identifies parents using subject and timestamp. The supplied corpus lacks Message-ID, In-Reply-To and References. Leading blank lines are removed in explicitly hashed derivatives; no missing headers are invented. Zero recovery exposes the limit of header-only threading, not a parser defect or an implementation of the paper's ranked retrieval method. This benchmark says nothing about attachment or campaign accuracy.",
    }
    write_json(output / "results.json", report)
    return {
        "output": str(output / "results.json"),
        "split": split,
        "corpora": {
            owner: {k: v for k, v in item.items() if k not in ("input_hashes", "query_results")}
            for owner, item in groups.items()
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--split", choices=("train", "test"), default="test")
    args = parser.parse_args()
    try:
        print(json.dumps(evaluate_threading(args.cache, args.output, args.split), indent=2))
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as exc:
        parser.exit(2, f"cmu_threads: {exc}\n")


if __name__ == "__main__":
    main()

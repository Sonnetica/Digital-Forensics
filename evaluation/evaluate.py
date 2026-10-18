"""Measure pairwise rule accuracy against a fixed, hash-verified synthetic corpus."""

import argparse
import hashlib
import json
import time
import tracemalloc
from collections import defaultdict
from datetime import datetime
from itertools import combinations
from pathlib import Path

from etrace.correlate import analyze
from etrace.model import RULES, RuleConfig
from etrace.parser import parse_email


def metrics(expected, predicted, universe):
    tp, fp, fn = len(expected & predicted), len(predicted - expected), len(expected - predicted)
    tn = universe - tp - fp - fn
    if tn < 0:
        raise ValueError("Ground truth or predictions exceed the candidate universe.")
    return summarize(tp, fp, fn, tn)


def summarize(tp, fp, fn, tn):
    def ratio(a, b):
        return a / b if b else None

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": ratio(tp, tp + fp),
        "recall": ratio(tp, tp + fn),
        "f1": ratio(2 * tp, 2 * tp + fp + fn),
        "false_positive_rate": ratio(fp, fp + tn),
        "false_negative_rate": ratio(fn, fn + tp),
    }


def evaluate(dataset, config=None):
    config = config or RuleConfig()
    dataset = Path(dataset).expanduser().resolve()
    truth = json.loads((dataset / "ground_truth.json").read_text(encoding="utf-8"))
    if truth.get("schema_version") != 1 or set(truth["relationships"]) != set(RULES):
        raise ValueError("Unsupported ground-truth schema.")
    records, file_ids = [], {}
    tracemalloc.start()
    started = time.perf_counter()
    for name, expected_hash in sorted(truth["files"].items()):
        path = (dataset / name).resolve()
        if not path.is_relative_to(dataset) or path.suffix.lower() not in (".eml", ".msg"):
            raise ValueError("Ground truth contains an invalid evidence path.")
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected_hash:
            raise ValueError(f"Corpus hash mismatch: {name}")
        record = parse_email(raw, name)
        file_ids[name] = record["id"]
        records.append(record)
    if len(set(file_ids.values())) != len(file_ids):
        raise ValueError(
            "Duplicate bytes must be declared as duplicate acquisitions, not independent ground truth."
        )
    for alias, original in truth.get("duplicate_acquisitions", {}).items():
        path = (dataset / alias).resolve()
        if not path.is_relative_to(dataset) or original not in file_ids:
            raise ValueError("Invalid duplicate-acquisition manifest.")
        if hashlib.sha256(path.read_bytes()).hexdigest() != file_ids[original]:
            raise ValueError(f"Duplicate acquisition mismatch: {alias}")
    parse_seconds = time.perf_counter() - started
    started = time.perf_counter()
    result = analyze(records, config)
    correlation_seconds = time.perf_counter() - started
    peak_bytes = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    predicted = {rule: set() for rule in RULES}
    for event in result["events"]:
        if event["type"] == "reply":
            predicted["reply"].add((event["direction"]["parent"], event["direction"]["child"]))
        else:
            count = len(event["email_ids"])
            if count * (count - 1) // 2 > 2_000_000:
                raise ValueError("Pairwise evaluation limit exceeded for one group.")
            predicted[event["type"]].update(combinations(sorted(event["email_ids"]), 2))
    expected = {rule: set() for rule in RULES}
    for rule, pairs in truth["relationships"].items():
        for pair in pairs:
            if len(pair) != 2 or pair[0] == pair[1] or any(name not in file_ids for name in pair):
                raise ValueError("Invalid ground-truth relationship.")
            ids = tuple(file_ids[name] for name in pair)
            expected[rule].add(ids if rule == "reply" else tuple(sorted(ids)))
    n = len(records)
    per_rule = {
        rule: metrics(expected[rule], predicted[rule], n * (n - 1) // (1 if rule == "reply" else 2))
        for rule in RULES
    }
    micro = summarize(*(sum(m[key] for m in per_rule.values()) for key in ("tp", "fp", "fn", "tn")))

    # This baseline deliberately requires only one reused payload category and
    # does not exclude reply threads. It shares the parser and time window.
    index, baseline = defaultdict(set), set()
    times = {
        r["id"]: datetime.fromisoformat(r[config.timestamp_source + "_utc"])
        for r in records
        if r[config.timestamp_source + "_utc"]
    }
    for record in records:
        for artifact in record["artifacts"]:
            if artifact["kind"] in ("url", "attachment_sha256"):
                index[(artifact["kind"], artifact["value"])].add(record["id"])
    for ids in index.values():
        for a, b in combinations(sorted(ids), 2):
            if (
                a in times
                and b in times
                and abs((times[a] - times[b]).total_seconds()) <= config.window_seconds
            ):
                baseline.add((a, b))
    filenames = {value: name for name, value in file_ids.items()}
    errors = {
        rule: {
            "false_positives": [
                [filenames[a], filenames[b]] for a, b in sorted(predicted[rule] - expected[rule])
            ],
            "false_negatives": [
                [filenames[a], filenames[b]] for a, b in sorted(expected[rule] - predicted[rule])
            ],
        }
        for rule in RULES
    }
    return {
        "schema_version": 1,
        "tier": truth["tier"],
        "seed": truth["seed"],
        "messages": n,
        "run_id": result["id"],
        "config": config.as_dict(),
        "matches_reference_parameters": all(
            config.as_dict()[k] == v for k, v in truth["expected_parameters"].items()
        ),
        "per_rule": per_rule,
        "micro": micro,
        "errors": errors,
        "single_payload_coordination_baseline": metrics(
            expected["possible_coordination"], baseline, n * (n - 1) // 2
        ),
        "performance": {
            "parse_seconds": parse_seconds,
            "correlation_seconds": correlation_seconds,
            "peak_traced_python_bytes": peak_bytes,
            "timing_includes_tracemalloc_overhead": True,
        },
        "diagnostics": result["diagnostics"],
        "statistics": result["statistics"],
        "definitions": {
            "candidate_universe": "All distinct source pairs for each rule; ordered for reply, unordered for the other three rules.",
            "group_scoring": "Artifact groups expand to unordered pairs; each pair counts once per rule.",
            "undefined_ratios": "null when a metric denominator is zero.",
            "baseline": "Single shared URL or attachment within the selected window; no reply-thread exclusion. This is an internal ablation, not an external product comparison.",
        },
        "scope": truth["scope"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--window-seconds", type=int, default=3600)
    parser.add_argument("--minimum-signals", type=int, default=2)
    parser.add_argument("--timestamp-source", choices=("date", "received"), default="date")
    args = parser.parse_args()
    try:
        output = args.output.expanduser().resolve()
        if output.is_relative_to(Path(__file__).resolve().parent.parent):
            raise ValueError("Keep evaluation results outside the source repository.")
        result = evaluate(
            args.dataset,
            RuleConfig(args.window_seconds, args.minimum_signals, args.timestamp_source),
        )
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("x", encoding="utf-8") as stream:
            json.dump(result, stream, indent=2)
            stream.write("\n")
        print(
            json.dumps(
                {
                    "output": str(output),
                    "messages": result["messages"],
                    "per_rule": result["per_rule"],
                    "micro": result["micro"],
                    "performance": result["performance"],
                },
                indent=2,
            )
        )
        return 0 if result["micro"]["fp"] == 0 and result["micro"]["fn"] == 0 else 1
    except (ValueError, KeyError, OSError) as exc:
        parser.exit(2, f"evaluate: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())

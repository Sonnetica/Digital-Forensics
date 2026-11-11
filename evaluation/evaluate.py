"""Evaluate hash-verified evidence with explicit labelled and unassessed scopes."""

import argparse
import hashlib
import json
import platform
import random
import time
import tracemalloc
from collections import defaultdict
from datetime import datetime
from itertools import combinations
from pathlib import Path

from etrace.correlate import analyze
from etrace.model import RULE_VERSION, RULES, RuleConfig
from etrace.parser import parse_email

PAIR_LIMIT = 2_000_000


def named_pairs(pairs, rule, file_ids):
    result = set()
    for pair in pairs:
        if len(pair) != 2 or pair[0] == pair[1] or any(name not in file_ids for name in pair):
            raise ValueError("Invalid ground-truth relationship.")
        ids = tuple(file_ids[name] for name in pair)
        result.add(ids if rule == "reply" else tuple(sorted(ids)))
    return result


def prediction_pairs(result):
    predicted = {rule: set() for rule in RULES}
    for event in result["events"]:
        rule = event["type"]
        if rule not in predicted:
            continue  # informational event types (inline resource reuse) are not scored
        if rule == "reply":
            predicted[rule].add((event["direction"]["parent"], event["direction"]["child"]))
        elif rule == "possible_coordination" and "pairs" in event:
            predicted[rule].update(tuple(pair["email_ids"]) for pair in event["pairs"])
        else:
            count = len(event["email_ids"])
            if count * (count - 1) // 2 > PAIR_LIMIT:
                raise ValueError("Pairwise evaluation limit exceeded for one group.")
            predicted[rule].update(combinations(sorted(event["email_ids"]), 2))
        if len(predicted[rule]) > PAIR_LIMIT:
            raise ValueError("Pairwise evaluation limit exceeded for one rule.")
    return predicted


def scoped_metrics(expected, negatives, predicted, complete, directed=False):
    if expected & negatives:
        raise ValueError("A pair cannot be both positive and negative.")

    def inside(pair):
        return pair[0] in complete and pair[1] in complete

    labelled = expected | negatives
    assessed = {pair for pair in predicted if inside(pair) or pair in labelled}
    extra = {pair for pair in labelled if not inside(pair)}
    n = len(complete)
    universe = n * (n - 1) // (1 if directed else 2) + len(extra)
    value = metrics(expected, assessed, universe)
    value.update(
        {
            "assessed_candidate_pairs": universe,
            "predicted_pairs": len(predicted),
            "unassessed_predictions": len(predicted - assessed),
            "complete_scope_messages": n,
            "explicit_positive_labels": len(expected),
            "explicit_negative_labels": len(negatives),
        }
    )
    return value, assessed


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


def evaluate(dataset, config=None, reviews=None):
    config = config or RuleConfig()
    dataset = Path(dataset).expanduser().resolve()
    truth = json.loads((dataset / "ground_truth.json").read_text(encoding="utf-8"))
    if truth.get("schema_version") not in (1, 2) or set(truth["relationships"]) != set(RULES):
        raise ValueError("Unsupported ground-truth schema.")
    if truth["schema_version"] == 2 and (
        set(truth.get("complete_for", {})) != set(RULES)
        or set(truth.get("negative_relationships", {})) != set(RULES)
    ):
        raise ValueError("Partial ground truth must declare every rule's assessment scope.")
    records, file_ids = [], {}
    tracemalloc.start()
    try:
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
    finally:
        tracemalloc.stop()
    # Score logical messages: every preserved copy of one message maps to the
    # representative identifier the engine uses for that copy group.
    representative = {i: i for i in file_ids.values()}
    for group in result.get("copy_groups", []):
        for evidence_id in group:
            representative[evidence_id] = min(group)

    def logical(pairs, rule):
        mapped = set()
        for a, b in pairs:
            a, b = representative[a], representative[b]
            if a != b:
                mapped.add((a, b) if rule == "reply" else tuple(sorted((a, b))))
        return mapped

    file_predicted = prediction_pairs(result)
    predicted = {rule: logical(pairs, rule) for rule, pairs in file_predicted.items()}
    file_expected, file_negatives, file_complete = {}, {}, {}
    expected, negatives, complete = {}, {}, {}
    filenames = {value: name for name, value in file_ids.items()}
    conflicts_found = []
    for rule, pairs in truth["relationships"].items():
        file_expected[rule] = named_pairs(pairs, rule, file_ids)
        file_negatives[rule] = named_pairs(
            truth.get("negative_relationships", {}).get(rule, []), rule, file_ids
        )
        names = truth["complete_for"][rule] if truth["schema_version"] == 2 else list(file_ids)
        if any(name not in file_ids for name in names) or len(set(names)) != len(names):
            raise ValueError("Invalid complete assessment scope.")
        file_complete[rule] = {file_ids[name] for name in names}
        expected[rule] = logical(file_expected[rule], rule)
        negatives[rule] = logical(file_negatives[rule], rule)
        for pair in sorted(expected[rule] & negatives[rule]):
            positive = sorted(p for p in file_expected[rule] if logical([p], rule) == {pair})
            negative = sorted(p for p in file_negatives[rule] if logical([p], rule) == {pair})
            conflicts_found.append(
                f"{rule}: positive {[[filenames[i] for i in p] for p in positive]} "
                f"and negative {[[filenames[i] for i in p] for p in negative]}"
            )
        complete[rule] = {representative[i] for i in file_complete[rule]}
    if conflicts_found:
        # Copies of one message cannot be both related and unrelated to the same
        # message. Scoring such labels would report a misleading result.
        raise ValueError(
            "Ground-truth labels conflict once preserved copies are grouped as one message; "
            "correct the labels before scoring: " + "; ".join(conflicts_found)
        )
    review_metadata = []
    if reviews is not None:
        review_data = json.loads(Path(reviews).read_text(encoding="utf-8"))
        if review_data.get("run_id") != result["id"]:
            raise ValueError("Reviews belong to a different analysis run.")
        for entry in review_data["review_queue"]:
            if entry.get("label") == "unassessed":
                continue
            if entry.get("label") not in ("positive", "negative"):
                raise ValueError("Review labels must be positive, negative or unassessed.")
            if not entry.get("reviewer", "").strip() or not entry.get("rationale", "").strip():
                raise ValueError("Assessed reviews require a reviewer and independent rationale.")
            rule = entry["rule"]
            if rule not in RULES:
                raise ValueError("Invalid reviewed rule.")
            pairs = logical(named_pairs([entry["files"]], rule, file_ids), rule)
            if not pairs or not pairs <= predicted[rule]:
                raise ValueError("Review queue accepts only predictions from the specified run.")
            pair = next(iter(pairs))
            if pair[0] in complete[rule] and pair[1] in complete[rule]:
                raise ValueError("Reviews cannot override the fixed complete-scope benchmark.")
            (expected if entry["label"] == "positive" else negatives)[rule].update(pairs)
            review_metadata.append(entry)
    n = len(records)
    logical_n = len(set(representative.values()))
    per_rule, assessed, file_level = {}, {}, {}
    for rule in RULES:
        per_rule[rule], assessed[rule] = scoped_metrics(
            expected[rule], negatives[rule], predicted[rule], complete[rule], rule == "reply"
        )
        file_level[rule] = scoped_metrics(
            file_expected[rule],
            file_negatives[rule],
            file_predicted[rule],
            file_complete[rule],
            rule == "reply",
        )[0]
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
        if len(ids) * (len(ids) - 1) // 2 > PAIR_LIMIT:
            raise ValueError("Baseline pairwise evaluation limit exceeded.")
        for a, b in combinations(sorted(ids), 2):
            if (
                a in times
                and b in times
                and abs((times[a] - times[b]).total_seconds()) <= config.window_seconds
            ):
                if representative[a] != representative[b]:
                    baseline.add(tuple(sorted((representative[a], representative[b]))))
                if len(baseline) > PAIR_LIMIT:
                    raise ValueError("Baseline pairwise evaluation limit exceeded.")
    errors = {
        rule: {
            "false_positives": [
                [filenames[a], filenames[b]] for a, b in sorted(assessed[rule] - expected[rule])
            ],
            "false_negatives": [
                [filenames[a], filenames[b]] for a, b in sorted(expected[rule] - predicted[rule])
            ],
        }
        for rule in RULES
    }
    review_queue = []
    for rule in RULES:
        population = sorted(predicted[rule] - assessed[rule])
        for a, b in random.Random(47).sample(population, min(20, len(population))):
            review_queue.append(
                {
                    "rule": rule,
                    "files": [filenames[a], filenames[b]],
                    "label": "unassessed",
                    "reviewer": "",
                    "rationale": "",
                }
            )
    warnings = defaultdict(int)
    for record in records:
        for warning in record["warnings"]:
            warnings[warning["code"]] += 1
    return {
        "schema_version": 2,
        "tier": truth["tier"],
        "seed": truth["seed"],
        "messages": n,
        "logical_messages": logical_n,
        "scoring_unit": "logical_message",
        "copy_groups": [
            sorted(filenames[i] for i in group) for group in result.get("copy_groups", [])
        ],
        "run_id": result["id"],
        "config": config.as_dict(),
        "matches_reference_parameters": all(
            config.as_dict()[k] == v for k, v in truth["expected_parameters"].items()
        ),
        "rule_definition_compatible": truth.get("rule_version", "1.0.0") == RULE_VERSION,
        "per_rule": per_rule,
        "micro": micro,
        "file_level_per_rule": file_level,
        "assessment": {
            "fully_labelled": all(len(complete[rule]) == logical_n for rule in RULES),
            "rule_definition_compatible": truth.get("rule_version", "1.0.0") == RULE_VERSION,
            "unassessed_predictions": sum(m["unassessed_predictions"] for m in per_rule.values()),
            "interpretation": "Metrics apply only to explicitly assessed pairs and declared complete scopes. Unassessed predictions are excluded, never assumed false. Reviewed predictions alone do not establish population recall. Rule definitions must match before treating precision or recall as a current-rule benchmark.",
            "reviews": review_metadata,
        },
        "errors": errors,
        "single_payload_coordination_baseline": scoped_metrics(
            expected["possible_coordination"],
            negatives["possible_coordination"],
            baseline,
            complete["possible_coordination"],
        )[0],
        "performance": {
            "parse_seconds": parse_seconds,
            "correlation_seconds": correlation_seconds,
            "peak_traced_python_bytes": peak_bytes,
            "timing_includes_tracemalloc_overhead": True,
        },
        "diagnostics": result["diagnostics"],
        "statistics": result["statistics"],
        "extraction": {
            "warning_occurrences": dict(sorted(warnings.items())),
            "messages_with_warnings": sum(bool(r["warnings"]) for r in records),
            "messages_with_date": sum(bool(r["date_utc"]) for r in records),
            "messages_with_received": sum(bool(r["received_utc"]) for r in records),
        },
        "runtime": {"python": platform.python_version(), "platform": platform.platform()},
        "ground_truth_sha256": hashlib.sha256(
            (dataset / "ground_truth.json").read_bytes()
        ).hexdigest(),
        "review_queue": review_queue,
        "definitions": {
            "candidate_universe": "All distinct pairs within each rule's complete scope, plus explicitly labelled pairs outside it. Ordered for reply, unordered otherwise. Background pairs without labels are unknown.",
            "group_scoring": "Reuse groups expand to unordered pairs; coordination clusters score only their explicitly supported pairs. Each pair counts once per rule.",
            "scoring_unit": "Labels and predictions are mapped onto the run's copy groups (the same message preserved in several mailboxes) and scored per logical message. Pairs between copies of one message are dropped. file_level_per_rule repeats the scoring per preserved file for comparison.",
            "undefined_ratios": "null when a metric denominator is zero.",
            "baseline": "Single shared URL or attachment within the selected window; no reply-thread exclusion. This is an internal ablation, not an external product comparison.",
            "review_queue": "Up to 20 uniformly sampled unassessed predictions per rule using seed 47. Inspect originals independently and enter positive/negative labels with reviewer and rationale. Coordination review concerns observable rule support, not malicious intent. Sampling predicted pairs cannot establish global recall.",
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
    parser.add_argument("--background-min-outside", type=int, default=10)
    parser.add_argument("--background-ratio", type=float, default=5.0)
    parser.add_argument("--organisation-domain", action="append", default=[])
    parser.add_argument("--trusted-wrapper-host", action="append", default=[])
    parser.add_argument("--exclude-url-domain", action="append", default=[])
    parser.add_argument(
        "--reviews",
        type=Path,
        help="A previously exported result with independently completed review_queue entries",
    )
    args = parser.parse_args()
    try:
        output = args.output.expanduser().resolve()
        if output.is_relative_to(Path(__file__).resolve().parent.parent):
            raise ValueError("Keep evaluation results outside the source repository.")
        result = evaluate(
            args.dataset,
            RuleConfig(
                window_seconds=args.window_seconds,
                minimum_signals=args.minimum_signals,
                timestamp_source=args.timestamp_source,
                background_min_outside=args.background_min_outside,
                background_ratio=args.background_ratio,
                organisation_domains=args.organisation_domain,
                excluded_url_domains=args.exclude_url_domain,
                trusted_wrapper_hosts=args.trusted_wrapper_host,
            ),
            args.reviews,
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
                    "logical_messages": result["logical_messages"],
                    "per_rule": result["per_rule"],
                    "micro": result["micro"],
                    "assessment": result["assessment"],
                    "rule_definition_compatible": result["rule_definition_compatible"],
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

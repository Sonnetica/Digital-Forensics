"""Combine unchanged public email with time-aligned, explicitly scoped scenarios."""

import argparse
import hashlib
import json
from datetime import UTC, timedelta
from pathlib import Path

from corpora import empty_directory, message_date, write_json
from generate import RULES, generate


def mix(background, output, seed=97):
    background = Path(background).expanduser().resolve()
    source_bytes = (background / "ground_truth.json").read_bytes()
    source = json.loads(source_bytes)
    if source.get("tier") != "public-background" or source.get("schema_version") != 2:
        raise ValueError("Use a public background prepared by corpora.py.")
    material, dates = {}, []
    for name, expected in sorted(source["files"].items()):
        path = (background / name).resolve()
        if not path.is_relative_to(background) or path.suffix != ".eml":
            raise ValueError("Invalid public evidence path.")
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError(f"Public evidence hash mismatch: {name}")
        material[name] = raw
        if date := message_date(raw):
            dates.append(date)
    dates.sort()
    if not dates or dates[-1] - dates[0] < timedelta(hours=3):
        raise ValueError("Background must cover at least three hours with known dates.")
    # Plant around the middle of the observed period; never alter public dates.
    anchor = min(dates[len(dates) // 2], dates[-1] - timedelta(hours=3))
    output = empty_directory(output)
    generate(output / "planted", tier="simple", seed=seed, noise=0, start=anchor.isoformat())
    planted_path = output / "planted" / "ground_truth.json"
    planted = json.loads(planted_path.read_text(encoding="utf-8"))
    files = {f"planted/{name}": sha for name, sha in planted["files"].items()}
    (output / "background").mkdir()
    for name, raw in material.items():
        target = "background/" + Path(name).name
        (output / target).write_bytes(raw)
        files[target] = hashlib.sha256(raw).hexdigest()
    names = ["planted/" + name for name in planted["files"]]
    truth = {
        "schema_version": 2,
        "tier": "mixed-public-and-planted",
        "seed": seed,
        "files": files,
        "relationships": {
            rule: [["planted/" + a, "planted/" + b] for a, b in planted["relationships"][rule]]
            for rule in RULES
        },
        "negative_relationships": {rule: [] for rule in RULES},
        "complete_for": {rule: names for rule in RULES},
        "expected_parameters": planted["expected_parameters"],
        "scope": "Recovery and discrimination within the planted subgraph in historical public mail. Public-public and public-planted relationships are unassessed. This does not establish campaign accuracy or transfer-path attribution.",
        "provenance": {
            "background_manifest_sha256": hashlib.sha256(source_bytes).hexdigest(),
            "background": source["provenance"],
            "planted_start_utc": anchor.astimezone(UTC).isoformat(),
            "planted_messages": len(names),
            "background_messages": len(material),
            "time_alignment": "All eight planted messages fall within the background's observed date range. Real message bytes and dates are unchanged. The planted scenarios are controlled, not real incidents.",
            "limitations": "Planted artifacts are distinctive reserved-domain values. Their recovery does not measure resistance to confusing real artifacts; public predictions require independent review. A different seed changes values, not scenario structure.",
        },
    }
    write_json(output / "ground_truth.json", truth)
    return {
        "output": str(output),
        "background_messages": len(material),
        "planted_messages": len(names),
        "planted_start_utc": anchor.isoformat(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("background", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=97)
    args = parser.parse_args()
    try:
        print(json.dumps(mix(args.background, args.output, args.seed), indent=2))
    except (OSError, ValueError, KeyError) as exc:
        parser.exit(2, f"mix: {exc}\n")


if __name__ == "__main__":
    main()

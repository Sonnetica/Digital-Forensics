"""Generate deterministic evaluation corpora and independently specified ground truth."""

import argparse
import hashlib
import json
import random
from datetime import UTC, datetime, timedelta
from email import policy
from email.message import EmailMessage
from email.utils import format_datetime
from itertools import combinations
from pathlib import Path

RULES = ("attachment_reuse", "url_reuse", "reply", "possible_coordination")
TIERS = {"simple": (1, 6), "medium": (4, 40), "complex": (12, 160)}


def generate(output, tier="simple", seed=47, noise=None):
    output = Path(output).expanduser().resolve()
    repository = Path(__file__).resolve().parent.parent
    if output.is_relative_to(repository):
        raise ValueError("Generate evaluation data outside the source repository.")
    if output.exists() and any(output.iterdir()):
        raise ValueError("Output directory must be empty; existing evidence is never overwritten.")
    output.mkdir(parents=True, exist_ok=True)
    campaign_count, default_noise = TIERS[tier]
    noise = default_noise if noise is None else noise
    if not 0 <= noise <= 100000:
        raise ValueError("Noise count must be between 0 and 100000.")
    rng = random.Random(seed)
    base = datetime(2026, 10, 1, 8, tzinfo=UTC)
    manifest, aliases, expected = {}, {}, {rule: set() for rule in RULES}
    scenarios = []
    counter = 0

    def emit(
        name,
        *,
        subject,
        body="No shared URL in this message.",
        attachment=None,
        when=None,
        parent=None,
        references=None,
        message_id=None,
        sender=None,
        html=False,
        unknown_offset=False,
    ):
        nonlocal counter
        counter += 1
        message = EmailMessage(policy=policy.SMTP)
        message["From"] = sender or f"sender{counter}@source{counter % 3}.example"
        message["To"] = f"recipient{counter}@mail.example"
        message["Subject"] = subject
        message["Message-ID"] = message_id or f"<{name}.{seed}@evidence.example>"
        if when is not None:
            message["Date"] = format_datetime(when.replace(tzinfo=None) if unknown_offset else when)
            message["Received"] = (
                f"from source{counter}.example ([203.0.113.{counter % 250 + 1}]) "
                f"by relay.example [192.0.2.25]; {format_datetime(when + timedelta(seconds=10))}"
            )
        if parent:
            message["In-Reply-To"] = parent
        if references:
            message["References"] = references
        message.set_content(body)
        if html:
            message.add_alternative(
                f'<html><body><p>Review the notice.</p><a href="{body}">Open document</a></body></html>',
                subtype="html",
            )
        if attachment is not None:
            message.add_attachment(
                attachment, maintype="application", subtype="octet-stream", filename="document.bin"
            )
        for i, part in enumerate(message.walk()):
            if part.is_multipart():
                part.set_boundary(f"etrace-{seed}-{name}-{i}")
        raw = message.as_bytes()
        filename = name + ".eml"
        (output / filename).write_bytes(raw)
        manifest[filename] = hashlib.sha256(raw).hexdigest()
        return filename

    def pairs(rule, names):
        expected[rule].update(tuple(sorted(pair)) for pair in combinations(names, 2))

    for campaign in range(campaign_count):
        token = f"{rng.getrandbits(64):016x}"
        url = f"https://distribution.example/{token}?document=1&version=2"
        attachment = f"Controlled evaluation payload {seed}/{token}".encode()
        when = base + timedelta(hours=campaign * 6)
        members = [
            emit(
                f"campaign-{campaign}-{i}",
                subject=f"Document review {token}",
                body=url,
                attachment=attachment,
                when=when + timedelta(minutes=i * 5),
                html=i == 1,
            )
            for i in range(3)
        ]
        url_control = emit(
            f"url-control-{campaign}",
            subject=f"Unrelated link {campaign}",
            body=url,
            when=when + timedelta(minutes=2),
        )
        hash_control = emit(
            f"hash-control-{campaign}",
            subject=f"Archive attachment {campaign}",
            attachment=attachment,
            when=when + timedelta(minutes=3),
        )
        pairs("attachment_reuse", members + [hash_control])
        pairs("url_reuse", members + [url_control])
        pairs("possible_coordination", members)
        scenarios.append(
            {
                "name": "multi-artifact distribution with single-artifact controls",
                "files": members + [url_control, hash_control],
            }
        )

        thread_url = f"https://discussion.example/{token}"
        thread = []
        for i in range(3):
            parent = f"<thread-{campaign}-{i - 1}.{seed}@evidence.example>" if i else None
            name = emit(
                f"thread-{campaign}-{i}",
                subject=("Re: " if i else "") + f"Planning {token}",
                body=thread_url,
                when=when + timedelta(hours=2, minutes=i),
                parent=parent,
                references=parent,
            )
            if thread:
                expected["reply"].add((thread[-1], name))
            thread.append(name)
        pairs("url_reuse", thread)
        scenarios.append({"name": "reply chain with quoted URL; no coordination", "files": thread})

    if tier in ("medium", "complex"):
        unknown = emit(
            "unknown-time-a", subject="Missing time", body="https://unknown.example/same"
        )
        unknown_offset = emit(
            "unknown-time-b",
            subject="Missing time",
            body="https://unknown.example/same",
            when=base,
            unknown_offset=True,
        )
        pairs("url_reuse", [unknown, unknown_offset])
        scenarios.append(
            {"name": "missing date and unknown UTC offset", "files": [unknown, unknown_offset]}
        )
        boundary = [
            emit(
                f"boundary-{i}",
                subject="Window boundary",
                body="https://boundary.example/a",
                when=base + timedelta(days=10, seconds=seconds),
            )
            for i, seconds in enumerate((0, 3600, 3601))
        ]
        pairs("url_reuse", boundary)
        expected["possible_coordination"].update(
            [tuple(sorted(boundary[:2])), tuple(sorted(boundary[1:]))]
        )
        scenarios.append(
            {"name": "inclusive time-window boundary and one-second exclusion", "files": boundary}
        )

    if tier == "complex":
        collision = [
            emit(
                f"collision-{i}",
                subject=f"Identifier collision {i}",
                message_id="<duplicate@evidence.example>",
                when=base,
            )
            for i in range(2)
        ]
        child = emit(
            "collision-child",
            subject="Ambiguous parent",
            parent="<duplicate@evidence.example>",
            when=base,
        )
        scenarios.append(
            {"name": "duplicate Message-ID; no invented parent", "files": collision + [child]}
        )
        cycle = [
            emit(
                f"cycle-{i}",
                subject="Cyclic headers",
                body="https://cycle.example/",
                when=base + timedelta(hours=i),
                parent=f"<cycle-{1 - i}.{seed}@evidence.example>",
            )
            for i in range(2)
        ]
        pairs("url_reuse", cycle)
        expected["reply"].update([(cycle[0], cycle[1]), (cycle[1], cycle[0])])
        scenarios.append({"name": "reply cycle and reversed time retained", "files": cycle})
        original = "campaign-0-0.eml"
        duplicate = "duplicate-acquisition.eml"
        (output / duplicate).write_bytes((output / original).read_bytes())
        aliases[duplicate] = original
        variants = [
            "https://query.example/a?x=1&y=2",
            "https://query.example/a?y=2&x=1",
            "https://query.example/a?x=1&y=2#different",
        ]
        names = [
            emit(f"url-distinction-{i}", subject=f"Distinct URL {i}", body=url, when=base)
            for i, url in enumerate(variants)
        ]
        scenarios.append({"name": "query order and fragments stay distinct", "files": names})

    for i in range(noise):
        token = f"{rng.getrandbits(96):024x}"
        emit(
            f"unrelated-{i:05d}",
            subject=f"Independent message {token}",
            body=f"https://unrelated.example/{token}",
            when=base + timedelta(days=30, seconds=i * 17),
        )
    truth = {
        "schema_version": 1,
        "seed": seed,
        "tier": tier,
        "expected_parameters": {
            "window_seconds": 3600,
            "minimum_signals": 2,
            "timestamp_source": "date",
        },
        "files": manifest,
        "duplicate_acquisitions": aliases,
        "relationships": {
            rule: [list(pair) for pair in sorted(pairs)] for rule, pairs in expected.items()
        },
        "scenarios": scenarios,
        "scope": "Controlled rule behavior. Synthetic accuracy does not establish real-world detection accuracy or investigation time savings.",
    }
    (output / "ground_truth.json").write_text(json.dumps(truth, indent=2) + "\n", encoding="utf-8")
    return {
        "output": str(output),
        "tier": tier,
        "seed": seed,
        "unique_messages": len(manifest),
        "duplicate_acquisitions": len(aliases),
        "expected_relationships": {k: len(v) for k, v in expected.items()},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--tier", choices=TIERS, default="simple")
    parser.add_argument("--seed", type=int, default=47)
    parser.add_argument(
        "--noise", type=int, help="Override unrelated-message count for scaling evaluation"
    )
    args = parser.parse_args()
    try:
        print(json.dumps(generate(args.output, args.tier, args.seed, args.noise), indent=2))
    except (ValueError, OSError) as exc:
        parser.exit(1, f"generate: {exc}\n")


if __name__ == "__main__":
    main()

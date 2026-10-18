"""Shared serialization, limits, and analysis parameters."""

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

PARSER_VERSION = "1.0.0"
RULE_VERSION = "1.0.0"
MAX_FILE_BYTES = 25 * 1024 * 1024
MAX_PARTS = 1000
MAX_TEXT_CHARS = 2_000_000
MAX_ARTIFACTS = 20_000
RULES = ("attachment_reuse", "url_reuse", "reply", "possible_coordination")


def canonical(value):
    return json.dumps(
        value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False
    )


def digest(data):
    return hashlib.sha256(data).hexdigest()


def object_digest(value):
    return digest(canonical(value).encode("utf-8"))


def utc_now():
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class RuleConfig:
    window_seconds: int = 3600
    minimum_signals: int = 2
    timestamp_source: str = "date"
    max_candidates: int = 250_000
    max_events: int = 50_000

    def __post_init__(self):
        if type(self.window_seconds) is not int or not 1 <= self.window_seconds <= 604800:
            raise ValueError("Time window must be an integer from 1 to 604800 seconds.")
        if type(self.minimum_signals) is not int or not 2 <= self.minimum_signals <= 4:
            raise ValueError("Minimum signals must be an integer from 2 to 4.")
        if self.timestamp_source not in ("date", "received"):
            raise ValueError("Timestamp source must be date or received.")
        for name in ("max_candidates", "max_events"):
            if type(getattr(self, name)) is not int or not 1 <= getattr(self, name) <= 1_000_000:
                raise ValueError(f"{name} must be an integer from 1 to 1000000.")

    def as_dict(self):
        return asdict(self)

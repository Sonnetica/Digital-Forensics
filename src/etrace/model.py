"""Shared serialization, limits, and analysis parameters."""

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

PARSER_VERSION = "1.4.0"
RULE_VERSION = "1.4.1"
MAX_FILE_BYTES = 25 * 1024 * 1024
MAX_PARTS = 1000
MAX_TEXT_CHARS = 2_000_000
MAX_ARTIFACTS = 20_000
RULES = ("attachment_reuse", "url_reuse", "reply", "possible_coordination")
# Event types an analysis can emit. Only RULES are scored by the evaluator;
# inline resource reuse is informational and never a coordination signal.
EVENT_TYPES = RULES + ("inline_resource_reuse",)


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


def clean_domains(values, label):
    """Validate hostnames (no scheme or path), normalise to IDNA lower case, sort."""
    if isinstance(values, str) or not isinstance(values, (list, tuple)) or len(values) > 100:
        raise ValueError(f"{label} must be a list of at most 100 hostnames.")
    cleaned = []
    for domain in values:
        if not isinstance(domain, str):
            raise ValueError(f"{label} must be strings.")
        try:
            value = domain.strip().lower().rstrip(".").encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError(f"{label} contain invalid Unicode.") from exc
        if (
            not value
            or len(value) > 253
            or any(
                not part
                or len(part) > 63
                or part.startswith("-")
                or part.endswith("-")
                or not part.replace("-", "").isalnum()
                for part in value.split(".")
            )
        ):
            raise ValueError(f"{label} must be hostnames without a scheme or path.")
        cleaned.append(value)
    return tuple(sorted(set(cleaned)))


@dataclass(frozen=True)
class RuleConfig:
    window_seconds: int = 3600
    minimum_signals: int = 2
    timestamp_source: str = "date"
    max_candidates: int = 250_000
    max_events: int = 50_000
    background_min_outside: int = 10
    background_ratio: float = 5.0
    organisation_domains: tuple[str, ...] = ()
    excluded_url_domains: tuple[str, ...] = ()
    trusted_wrapper_hosts: tuple[str, ...] = ()

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
        if (
            type(self.background_min_outside) is not int
            or not 1 <= self.background_min_outside <= 1_000_000
        ):
            raise ValueError("Background minimum must be an integer from 1 to 1000000.")
        if type(self.background_ratio) not in (int, float) or not 1 <= self.background_ratio <= 1000:
            raise ValueError("Background ratio must be a number from 1 to 1000.")
        for name, label in (
            ("organisation_domains", "Organisation domains"),
            ("excluded_url_domains", "Excluded URL domains"),
            ("trusted_wrapper_hosts", "Trusted wrapper hosts"),
        ):
            object.__setattr__(self, name, clean_domains(getattr(self, name), label))

    def as_dict(self):
        result = asdict(self)
        for name in ("organisation_domains", "excluded_url_domains", "trusted_wrapper_hosts"):
            result[name] = list(getattr(self, name))
        return result

"""Conservative normalization; original observations remain in the evidence record."""

import ipaddress
import re
from datetime import UTC
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit, urlunsplit


def normalize_url(raw):
    value = raw.strip()
    if any(ord(c) < 33 or ord(c) == 127 for c in value) or "\\" in value:
        return None
    try:
        parts = urlsplit(value)
        if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
            return None
        host = parts.hostname
        if ":" in host:
            host = "[" + str(ipaddress.IPv6Address(host)) + "]"
        else:
            host = host.encode("idna").decode("ascii").lower()
        port = parts.port
        authority = host
        if port is not None and (parts.scheme.lower(), port) not in (("http", 80), ("https", 443)):
            authority += f":{port}"
        if "@" in parts.netloc:
            authority = parts.netloc.rsplit("@", 1)[0] + "@" + authority
        normalized = urlunsplit(
            (parts.scheme.lower(), authority, parts.path or "/", parts.query, parts.fragment)
        )
        # Empty query/fragment delimiters can be meaningful to an application.
        if "?" in value.split("#", 1)[0] and not parts.query:
            at = normalized.find("#")
            normalized = normalized + "?" if at < 0 else normalized[:at] + "?" + normalized[at:]
        if value.endswith("#") and not normalized.endswith("#"):
            normalized += "#"
        return normalized
    except (ValueError, UnicodeError):
        return None


def parse_timestamp(raw):
    try:
        value = parsedate_to_datetime(raw)
        if value.tzinfo is None or value.utcoffset() is None:
            return None, "Timestamp has no known UTC offset."
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z"), None
    except (ValueError, TypeError, OverflowError):
        return None, "Timestamp could not be parsed."


def normalize_subject(value):
    value = re.sub(r"\s+", " ", value).strip()
    while re.match(r"^(?:re|fw|fwd)\s*:", value, re.I):
        value = re.sub(r"^(?:re|fw|fwd)\s*:\s*", "", value, count=1, flags=re.I)
    return value.casefold()


def message_ids(value):
    # Keep case: identifier equivalence is not email-address domain equivalence.
    return list(dict.fromkeys(re.findall(r"<[^<>\s]+@[^<>\s]+>", value)))


def address_domain(address):
    if "@" not in address:
        return ""
    try:
        return address.rsplit("@", 1)[1].encode("idna").decode("ascii").lower()
    except UnicodeError:
        return address.rsplit("@", 1)[1].lower()

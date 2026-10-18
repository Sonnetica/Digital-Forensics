"""Read-only EML and MSG extraction with explicit source locations."""

import ipaddress
import platform
import re
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from html.parser import HTMLParser
from pathlib import Path

from .model import MAX_ARTIFACTS, MAX_FILE_BYTES, MAX_PARTS, MAX_TEXT_CHARS, PARSER_VERSION, digest
from .normalize import (
    address_domain,
    message_ids,
    normalize_subject,
    normalize_url,
    parse_timestamp,
)

URL_PATTERN = re.compile(r"https?://[^\s<>\x00-\x20\x7f\"']+", re.I)


class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.text = []
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self.hidden += 1
        for name, value in attrs:
            if name in ("href", "src", "action", "data") and value:
                self.links.append((value, f"html:{self.getpos()[0]}:{self.getpos()[1]}:{name}"))

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self.hidden = max(0, self.hidden - 1)

    def handle_data(self, data):
        if not self.hidden:
            self.text.append(data)


def _raw_headers(raw):
    entries = []
    offset = 0
    for line in raw.splitlines(keepends=True):
        if line in (b"\r\n", b"\n", b"\r"):
            break
        if line.startswith((b" ", b"\t")) and entries:
            entries[-1]["raw"] += line.decode("utf-8", "replace")
            entries[-1]["byte_end"] = offset + len(line)
        elif b":" in line:
            name = line.split(b":", 1)[0].decode("ascii", "replace")
            entries.append(
                {
                    "name": name,
                    "raw": line.decode("utf-8", "replace"),
                    "byte_start": offset,
                    "byte_end": offset + len(line),
                }
            )
        else:
            break
        offset += len(line)
    return entries


def _ips(value):
    found = []
    candidates = re.findall(r"\[([^\]]+)\]|(?<![\w:.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w:.])", value)
    for bracket, plain in candidates:
        candidate = (bracket or plain).removeprefix("IPv6:")
        try:
            parsed = ipaddress.ip_address(candidate)
            address = str(parsed)
            if address not in found:
                found.append(address)
        except ValueError:
            continue
    return found


def parse_email(raw, filename):
    try:
        return _parse_email(raw, filename)
    except (RecursionError, LookupError, UnicodeError) as exc:
        raise ValueError(f"Email parsing failed: {type(exc).__name__}: {exc}") from exc
    except Exception as exc:
        if Path(filename).suffix.lower() == ".msg":
            from extract_msg.exceptions import ExMsgBaseException

            if isinstance(exc, ExMsgBaseException):
                raise ValueError(f"Outlook parsing failed: {exc}") from exc
        raise


def _parse_email(raw, filename):
    if not raw:
        raise ValueError("The evidence file is empty.")
    if len(raw) > MAX_FILE_BYTES:
        raise ValueError("An evidence file cannot exceed 25 MiB.")
    suffix = Path(filename).suffix.lower()
    if suffix not in (".eml", ".msg"):
        raise ValueError("Supported evidence formats are .eml and .msg.")
    record = {
        "id": digest(raw),
        "sha256": digest(raw),
        "size": len(raw),
        "format": suffix[1:],
        "parser_version": PARSER_VERSION,
        "parser_runtime": {"python": platform.python_version()},
        "headers": [],
        "artifacts": [],
        "warnings": [],
        "message_ids": [],
        "in_reply_to": [],
        "references": [],
        "subject": "",
        "senders": [],
        "recipients": [],
        "date_utc": None,
        "received_utc": None,
        "timestamps": [],
        "body_preview": "",
        "parts": [],
    }

    def warn(code, message, location):
        record["warnings"].append({"code": code, "message": message, "location": location})

    def artifact(kind, value, raw_value, location, **metadata):
        if len(record["artifacts"]) >= MAX_ARTIFACTS:
            raise ValueError("Artifact limit exceeded; this file was not ingested.")
        record["artifacts"].append(
            {
                "kind": kind,
                "value": value,
                "raw": raw_value,
                "location": location,
                "metadata": metadata,
            }
        )

    def extract_headers(message, raw_entries=None, prefix="header"):
        raw_entries = raw_entries or []
        for index, (name, value) in enumerate(message.items()):
            location = f"{prefix}:{index}"
            entry = {"name": name, "value": str(value), "location": location}
            if index < len(raw_entries) and raw_entries[index]["name"].lower() == name.lower():
                entry.update(raw_entries[index])
            record["headers"].append(entry)
            for defect in getattr(value, "defects", ()):
                warn(type(defect).__name__, str(defect) or "Malformed header.", location)
        lookup = {}
        for header in record["headers"]:
            lookup.setdefault(header["name"].lower(), []).append(header)
        for name in ("message-id", "date", "from", "subject", "in-reply-to", "references"):
            if len(lookup.get(name, [])) > 1:
                warn(
                    "duplicate_header", f"Multiple {name} headers; all values are preserved.", name
                )
        record["subject"] = str(message.get("Subject", ""))
        subjects = lookup.get("subject", [])
        if len(subjects) == 1 and normalize_subject(record["subject"]):
            artifact(
                "subject",
                normalize_subject(record["subject"]),
                record["subject"],
                subjects[0]["location"],
            )
        for field, target in (
            ("message-id", "message_ids"),
            ("in-reply-to", "in_reply_to"),
            ("references", "references"),
        ):
            for header in lookup.get(field, []):
                ids = message_ids(header["value"])
                if not ids and header["value"].strip():
                    warn(
                        "invalid_message_id",
                        f"No supported angle-bracket identifier in {field}.",
                        header["location"],
                    )
                for value in ids:
                    record[target].append(value)
                    artifact(field.replace("-", "_"), value, header["value"], header["location"])
            record[target] = list(dict.fromkeys(record[target]))
        if not record["message_ids"]:
            warn(
                "missing_message_id",
                "No usable Message-ID; source SHA-256 remains the evidence identity.",
                "header",
            )
        for field in ("from", "to", "cc", "bcc", "reply-to", "return-path"):
            for header in lookup.get(field, []):
                try:
                    addresses = getaddresses([header["value"]])
                except (ValueError, IndexError):
                    addresses = []
                for display, address in addresses:
                    if not address:
                        continue
                    item = {
                        "name": display,
                        "address": address,
                        "domain": address_domain(address),
                        "field": field,
                        "location": header["location"],
                    }
                    artifact("address", address, header["value"], header["location"], field=field)
                    if field == "from":
                        record["senders"].append(item)
                    elif field in ("to", "cc", "bcc"):
                        record["recipients"].append(item)
        dates = lookup.get("date", [])
        if not dates:
            warn("missing_date", "No Date header; no time is invented.", "header")
        for header in dates + lookup.get("received", []):
            value = header["value"]
            if header["name"].lower() == "received":
                value = value.rsplit(";", 1)[-1] if ";" in value else ""
            timestamp, error = parse_timestamp(value)
            record["timestamps"].append(
                {
                    "raw": value,
                    "utc": timestamp,
                    "location": header["location"],
                    "kind": header["name"].lower(),
                    "trusted": False,
                }
            )
            if error:
                warn("invalid_timestamp", error, header["location"])
            if header in dates and len(dates) == 1:
                record["date_utc"] = timestamp
            if lookup.get("received") and header is lookup["received"][0]:
                record["received_utc"] = timestamp
        received_times = [
            t["utc"] for t in record["timestamps"] if t["kind"] == "received" and t["utc"]
        ]
        if any(a < b for a, b in zip(received_times, received_times[1:])):
            warn(
                "received_order_conflict",
                "Received timestamps conflict with their newest-first header order.",
                "received",
            )
        if (
            record["date_utc"]
            and record["received_utc"]
            and record["date_utc"] > record["received_utc"]
        ):
            warn(
                "date_after_received",
                "Claimed send time is later than the top Received time.",
                "date",
            )
        for header in lookup.get("received", []):
            for address in _ips(header["value"]):
                artifact("observed_ip", address, header["value"], header["location"], trusted=False)
        origin = lookup.get("x-originating-ip", [])
        if len(origin) == 1:
            ips = _ips(origin[0]["value"])
            if len(ips) == 1:
                artifact(
                    "origin_ip",
                    ips[0],
                    origin[0]["value"],
                    origin[0]["location"],
                    trusted=False,
                    basis="X-Originating-IP claim",
                )
        elif not origin and lookup.get("received"):
            oldest = lookup["received"][-1]
            match = re.search(r"\bfrom\s+(.+?)(?:\s+by\s+|;|$)", oldest["value"], re.I | re.S)
            ips = _ips(match[1]) if match else []
            if len(ips) == 1:
                artifact(
                    "origin_ip",
                    ips[0],
                    oldest["value"],
                    oldest["location"],
                    trusted=False,
                    basis="from clause of oldest Received header",
                )
        for field in ("authentication-results", "received-spf", "dkim-signature"):
            for header in lookup.get(field, []):
                artifact(
                    "authentication_claim",
                    header["value"],
                    header["value"],
                    header["location"],
                    trusted=False,
                )

    total_text_chars = 0

    def extract_text(text, content_type, location):
        nonlocal total_text_chars
        total_text_chars += len(text)
        if total_text_chars > MAX_TEXT_CHARS:
            raise ValueError("Decoded text limit exceeded; this file was not ingested.")
        record["parts"].append(
            {"location": location, "content_type": content_type, "characters": len(text)}
        )
        links = []
        visible = text
        if content_type == "text/html":
            parser = LinkParser()
            parser.feed(text)
            links.extend(parser.links)
            visible = "\n".join(parser.text)
        for match in URL_PATTERN.finditer(visible):
            links.append((match[0], f"text:{match.start()}"))
        seen = set()
        for value, pointer in links:
            normalized = normalize_url(value)
            if normalized and (value, pointer) not in seen:
                seen.add((value, pointer))
                artifact(
                    "url",
                    normalized,
                    value,
                    f"{location}/{pointer}",
                    normalization="scheme/host case, IDNA, default port, empty path; query/fragment preserved",
                )
        remaining = 12000 - len(record["body_preview"])
        if remaining > 0:
            record["body_preview"] += visible[:remaining] + "\n"

    if suffix == ".eml":
        if raw.startswith(b"\xd0\xcf\x11\xe0"):
            raise ValueError("OLE data is not EML; supply the correct .msg extension.")
        message = BytesParser(policy=policy.default).parsebytes(raw)
        if not message.keys():
            raise ValueError("No email headers found.")
        extract_headers(message, _raw_headers(raw))
        count = 0

        def visit(part, location, depth=0):
            nonlocal count
            count += 1
            if count > MAX_PARTS or depth > 30:
                raise ValueError("MIME structure limit exceeded; this file was not ingested.")
            if part.get_content_type() == "message/rfc822":
                warn(
                    "embedded_message",
                    "Attached message retained in source; not attributed to the outer message.",
                    location,
                )
                record["parts"].append(
                    {
                        "location": location,
                        "content_type": "message/rfc822",
                        "filename": part.get_filename(),
                        "extracted": False,
                    }
                )
                return
            if part.is_multipart():
                for i, child in enumerate(part.iter_parts(), 1):
                    visit(child, f"{location}.{i}", depth + 1)
            else:
                payload = part.get_payload(decode=True) or b""
                content_type = part.get_content_type()
                filename = part.get_filename()
                disposition = part.get_content_disposition()
                if filename or disposition == "attachment" or not content_type.startswith("text/"):
                    artifact(
                        "attachment_sha256",
                        digest(payload),
                        digest(payload),
                        location,
                        filename=filename or "(unnamed)",
                        content_type=content_type,
                        size=len(payload),
                        disposition=disposition or "unspecified",
                        hash_basis="MIME transfer-decoded bytes",
                    )
                    record["parts"].append(
                        {
                            "location": location,
                            "content_type": content_type,
                            "filename": filename,
                            "size": len(payload),
                        }
                    )
                elif content_type in ("text/plain", "text/html"):
                    charset = part.get_content_charset() or "ascii"
                    try:
                        text = payload.decode(charset, "strict")
                    except (LookupError, UnicodeError):
                        text = payload.decode("utf-8", "replace")
                        warn(
                            "charset_fallback",
                            f"Could not decode {charset}; UTF-8 replacement used.",
                            location,
                        )
                    extract_text(text, content_type, location)
                else:
                    warn(
                        "unsupported_text_part",
                        f"{content_type} retained but not searched for URLs.",
                        location,
                    )
            for defect in part.defects:
                warn(type(defect).__name__, str(defect) or "Malformed MIME part.", location)

        visit(message, "mime:1")
    else:
        import extract_msg

        record["parser_runtime"]["extract_msg"] = extract_msg.__version__

        if not raw.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
            raise ValueError("The .msg file is not an Outlook OLE container.")
        with extract_msg.openMsg(raw) as message:
            if not hasattr(message, "header"):
                raise ValueError("This Outlook item is not an email message.")
            header_text = message.headerText
            if header_text:
                header_text = header_text.removeprefix(
                    "Microsoft Mail Internet Headers Version 2.0"
                ).lstrip()
                extract_headers(
                    BytesParser(policy=policy.default).parsebytes(
                        header_text.encode("utf-8") + b"\r\n\r\n"
                    ),
                    prefix="msg:transport-header",
                )
            else:
                extract_headers(message.header, prefix="msg:mapi-header")
                warn(
                    "synthesized_headers",
                    "Transport headers absent; fields derived from MAPI properties.",
                    "msg",
                )
            if not record["subject"] and message.subject:
                record["subject"] = message.subject
                artifact(
                    "subject", normalize_subject(message.subject), message.subject, "msg:subject"
                )
            body = message.getStringStream("__substg1.0_1000")
            html = message.getStream("__substg1.0_10130102")
            if body:
                extract_text(body, "text/plain", "msg:stream:__substg1.0_1000")
            if html:
                try:
                    html = html.decode("utf-8", "strict")
                except UnicodeError:
                    html = html.decode("utf-8", "replace")
                    warn(
                        "charset_fallback",
                        "MSG HTML decoded with UTF-8 replacement; original bytes remain in the source.",
                        "msg:stream:__substg1.0_10130102",
                    )
                extract_text(html, "text/html", "msg:stream:__substg1.0_10130102")
            if not body and not html:
                warn(
                    "unsupported_msg_body",
                    "No stored plain-text or HTML body; RTF and encrypted content remain in the source and are not expanded.",
                    "msg",
                )
            if len(message.attachments) > MAX_PARTS:
                raise ValueError("MSG attachment limit exceeded.")
            for i, attachment in enumerate(message.attachments):
                location = f"msg:attachment:{i}"
                data = attachment.data
                if isinstance(data, bytes):
                    artifact(
                        "attachment_sha256",
                        digest(data),
                        digest(data),
                        location,
                        filename=attachment.longFilename or attachment.shortFilename or "(unnamed)",
                        content_type=attachment.mimetype or "application/octet-stream",
                        size=len(data),
                        hash_basis="MAPI attachment bytes",
                    )
                else:
                    warn(
                        "embedded_msg_item",
                        "Embedded Outlook item retained in source; not flattened.",
                        location,
                    )
    record["body_preview"] = record["body_preview"][:12000]
    record["artifacts"].sort(key=lambda a: (a["kind"], a["value"], a["location"]))
    return record

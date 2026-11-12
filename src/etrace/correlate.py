"""Deterministic rules with indexed candidates and inspectable provenance."""

from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from datetime import datetime
from urllib.parse import parse_qs, unquote, urlsplit

from . import __version__
from .model import RULE_VERSION, RuleConfig, object_digest

BULK_HEADERS = ("list-unsubscribe", "list-id", "auto-submitted")
# Provider-operated Microsoft Defender Safe Links domains (worldwide and US
# government clouds). Matching is by exact domain or subdomain, never substring,
# so an attacker host such as login.safelinks.attacker.example is not trusted.
SAFE_LINKS_DOMAINS = ("safelinks.protection.outlook.com", "safelinks.protection.office365.us")
# Thresholds for the organisation-domain suggestion. A suggestion is never applied
# automatically; the investigator confirms it with --organisation-domain.
SUGGEST_RECIPIENT_SHARE = 0.5
SUGGEST_SENDER_SHARE = 0.25


def _within(host, domains):
    return any(host == domain or host.endswith("." + domain) for domain in domains)


def unwrap_url(url, trusted_hosts=()):
    """Return the destination behind a recognised link-protection wrapper.

    Only provider domains (and hosts the investigator explicitly trusts, which use
    the Safe Links url= format) are recognised. Used only to compare candidate
    mailbox copies; observations keep the URL exactly as it appears in the evidence.
    Unrecognised URLs are returned unchanged.
    """
    try:
        parts = urlsplit(url)
        if parts.scheme.lower() != "https":
            return url
        host = (parts.hostname or "").lower()
        query = parse_qs(parts.query)
        if _within(host, SAFE_LINKS_DOMAINS + tuple(trusted_hosts)) and query.get("url"):
            return query["url"][0]
        # Proofpoint URL Defense v2: u= with "-" for "%" and "_" for "/".
        if host == "urldefense.proofpoint.com" and parts.path.startswith("/v2/url") and query.get("u"):
            return unquote(query["u"][0].replace("-", "%").replace("_", "/"))
        # Proofpoint URL Defense v3: /v3/__<url>__;<checksum>
        if host == "urldefense.com" and parts.path.startswith("/v3/__"):
            return url.split("/v3/__", 1)[1].split("__;", 1)[0]
    except ValueError:
        pass
    return url


def suggest_organisation_domains(records):
    """Suggest the investigated organisation's domain; never applied automatically.

    One domain is suggested only when it is, without a tie, both the most common
    recipient domain and the most common sender domain, receives at least half
    of all recipient addresses and sends at least a quarter of the messages.
    Collections dominated by one direction of a supplier conversation (for
    example Sent mail to a vendor) therefore produce no suggestion.
    """
    recipients = Counter(r["domain"] for rec in records for r in rec["recipients"] if r["domain"])
    senders = Counter(s["domain"] for rec in records for s in rec["senders"] if s["domain"])
    total_recipients, total_senders = sum(recipients.values()), sum(senders.values())
    if not total_recipients or not total_senders:
        return []

    def unique_top(counter):
        ranked = counter.most_common(2)
        return ranked[0][0] if len(ranked) == 1 or ranked[0][1] > ranked[1][1] else None

    domain = unique_top(recipients)
    if (
        domain is None
        or domain != unique_top(senders)
        or recipients[domain] / total_recipients < SUGGEST_RECIPIENT_SHARE
        or senders[domain] / total_senders < SUGGEST_SENDER_SHARE
    ):
        return []
    return [domain]


def analyze(records, config=None):
    config = config or RuleConfig()
    records = sorted(records, key=lambda r: r["id"])
    by_id = {record["id"]: record for record in records}
    if len(by_id) != len(records):
        raise ValueError("Analysis requires unique evidence identities.")
    # A physical file remains evidence. Only strongly matching parsed messages
    # share a logical identity for relationship rules.
    header_groups = defaultdict(list)

    def group_signature(groups):
        return tuple(
            (
                group["name"].casefold() if group["name"] is not None else None,
                tuple(
                    ((member["name"] or "").casefold(), member["address"].casefold())
                    for member in group["addresses"]
                ),
            )
            for group in groups
        )

    for record in records:
        senders = sorted({s["address"].casefold() for s in record["senders"]})
        from_groups = [
            group for group in record.get("originator_groups", []) if group["field"] == "from"
        ]
        sender_groups = [
            group for group in record.get("originator_groups", []) if group["field"] == "sender"
        ]

        has_named_from_group = any(group["name"] is not None for group in from_groups)
        from_header_count = sum(h["name"].lower() == "from" for h in record["headers"])
        if has_named_from_group and from_header_count == 1:
            # An empty group has no address to use as identity. Require equal
            # decoded content as well as the same group and stable headers.
            from_identity = (
                "group",
                group_signature(from_groups),
                group_signature(sender_groups),
                record["content_digest"] if not senders else None,
            )
        elif len(senders) == 1:
            from_identity = ("mailbox", senders[0])
        else:
            from_identity = None
        recipients = sorted(
            {r["address"].casefold() for r in record["recipients"] if r["field"] in ("to", "cc")}
        )
        message_id_headers = sum(h["name"].lower() == "message-id" for h in record["headers"])
        if (
            len(record["message_ids"]) == 1
            and message_id_headers == 1
            and from_identity is not None
            and record["date_utc"]
            and record.get("content_digest")
        ):
            key = (
                record["message_ids"][0],
                from_identity,
                record["date_utc"],
                record["subject"].strip().casefold(),
                tuple(recipients),
                tuple(record["in_reply_to"]),
                tuple(record["references"]),
            )
        else:
            key = ("unverified", record["id"])
        header_groups[key].append(record["id"])

    def compatible_copy(left, right):
        if left["content_digest"] == right["content_digest"]:
            return True
        # Raw content differs. Allow only differences explained by recognised
        # link-protection rewriting: the full decoded content of every part,
        # including HTML markup, attributes and hidden fields, must be identical
        # once each URL is masked, and the URLs must match in order after unwrapping.
        left_print, right_print = left.get("copy_fingerprint"), right.get("copy_fingerprint")
        if not left_print or not right_print or left_print["structure"] != right_print["structure"]:
            return False

        def destinations(fingerprint):
            return [unwrap_url(url, config.trusted_wrapper_hosts) for url in fingerprint["urls"]]

        return destinations(left_print) == destinations(right_print)

    copies = {}
    copy_content_variations = {}
    for ids in header_groups.values():
        subgroups = []
        for evidence_id in sorted(ids):
            record = by_id[evidence_id]
            match = next(
                (
                    group
                    for group in subgroups
                    if all(compatible_copy(record, by_id[other]) for other in group)
                ),
                None,
            )
            if match is None:
                subgroups.append([evidence_id])
            else:
                match.append(evidence_id)
        for group in subgroups:
            rep = min(group)
            copies[rep] = group
            if len({by_id[i]["content_digest"] for i in group}) > 1:
                copy_content_variations[rep] = group
    representative = {evidence_id: rep for rep, ids in copies.items() for evidence_id in ids}
    index = defaultdict(lambda: defaultdict(set))
    observations = defaultdict(list)
    for record in records:
        for artifact in record["artifacts"]:
            index[artifact["kind"]][artifact["value"]].add(record["id"])
            observations[(record["id"], artifact["kind"], artifact["value"])].append(artifact)
    time_key = config.timestamp_source + "_utc"
    times = {r["id"]: datetime.fromisoformat(r[time_key]) for r in records if r[time_key]}
    events, diagnostics = [], []
    for rep, ids in copy_content_variations.items():
        diagnostics.append(
            {
                "code": "copy_content_variation",
                "email_id": rep,
                "copies": ids,
                "detail": "These mailbox copies share stable headers, and their full decoded content (including HTML markup and attachments) is identical except for URLs that decode to the same destinations through recognised link protection and whitespace. Their raw content still differs; review every preserved source.",
            }
        )

    def pointers(ids, kind, value):
        return [
            {"email_id": evidence_id, **a}
            for evidence_id in sorted(ids)
            for a in observations[(evidence_id, kind, value)]
        ]

    def context(ids):
        items = []
        domains = sorted(
            {sender["domain"] for i in ids for sender in by_id[i]["senders"] if sender["domain"]}
        )
        if len(domains) > 1:
            items.append(
                {
                    "code": "different_sender_domains",
                    "email_ids": list(ids),
                    "detail": "Claimed sender domains differ: "
                    + ", ".join(domains)
                    + ". This limits common-origin interpretation, not an exact artifact match.",
                }
            )
        for evidence_id in ids:
            if evidence_id not in times:
                items.append(
                    {
                        "code": "unknown_time",
                        "email_ids": [evidence_id],
                        "detail": f"No unambiguous {config.timestamp_source} timestamp with a known offset.",
                    }
                )
            for warning in by_id[evidence_id]["warnings"]:
                items.append(
                    {
                        "code": warning["code"],
                        "email_ids": [evidence_id],
                        "detail": warning["message"],
                        "location": warning["location"],
                    }
                )
        return items

    def add(kind, ids, support, explanation, *, direction=None, extra=None, pairs=None):
        if len(events) >= config.max_events:
            raise ValueError(
                "Event limit exceeded. Narrow the case or increase max_events; no partial run was saved."
            )
        ids = sorted(ids)
        dates = sorted(times[i].isoformat().replace("+00:00", "Z") for i in ids if i in times)
        event = {
            "type": kind,
            "rule_id": kind,
            "rule_version": RULE_VERSION,
            "parameters": config.as_dict(),
            "email_ids": ids,
            "support": support,
            "context": context(ids) + (extra or []),
            "explanation": explanation,
            "start_utc": dates[0] if dates else None,
            "end_utc": dates[-1] if dates else None,
            "direction": direction,
            "interpretation": "hypothesis"
            if kind == "possible_coordination"
            else "header-linked"
            if kind == "reply"
            else "observed reuse",
        }
        if pairs is not None:
            event["pairs"] = pairs
        event["id"] = object_digest(event)
        events.append(event)
        return event

    reuse_explanations = {
        "attachment_reuse": "Identical transfer-decoded attachment SHA-256 appears in these messages. "
        "Reuse does not establish transmission direction or malicious intent.",
        "url_reuse": "The same conservatively normalized URL appears in these messages. "
        "No destination was visited; reuse does not prove propagation or malicious intent.",
        "inline_resource_reuse": "Identical inline image bytes (for example a signature logo or an "
        "embedded QR code) appear in these messages. Shown for review only; inline resources are "
        "never used as coordination signals.",
    }
    for kind, rule in (
        ("attachment_sha256", "attachment_reuse"),
        ("url", "url_reuse"),
        ("inline_resource_sha256", "inline_resource_reuse"),
    ):
        for value, ids in sorted(index[kind].items()):
            if len({representative[i] for i in ids}) >= 2:
                add(rule, ids, pointers(ids, kind, value), reuse_explanations[rule])

    reply_edges = []
    for child_id in sorted(copies):
        child = by_id[child_id]
        child_copies = copies[child_id]
        explicit = child["in_reply_to"]
        reply_headers = [h for h in child["headers"] if h["name"].lower() == "in-reply-to"]
        if len(reply_headers) > 1 or (reply_headers and not explicit):
            diagnostics.append(
                {
                    "code": "invalid_reply_header",
                    "email_id": child["id"],
                    "detail": "Ambiguous or malformed In-Reply-To; no fallback edge created.",
                }
            )
            continue
        targets = explicit or child["references"][-1:]
        source_kind = "in_reply_to" if explicit else "references"
        multi_parent = source_kind == "in_reply_to" and len(explicit) > 1
        if multi_parent:
            # RFC 5322 section 3.6.4 permits several parent identifiers; keep each
            # resolvable edge, but never present one of them as the sole parent.
            diagnostics.append(
                {
                    "code": "multiple_in_reply_to",
                    "email_id": child["id"],
                    "targets": list(explicit),
                    "detail": "In-Reply-To lists several parent identifiers. Each resolvable parent receives its own qualified edge.",
                }
            )
        for target in targets:
            candidates = sorted(index["message_id"].get(target, set()))
            parent_groups = {representative[i] for i in candidates}
            if len(parent_groups) != 1:
                diagnostics.append(
                    {
                        "code": "ambiguous_parent" if candidates else "missing_parent",
                        "email_id": child["id"],
                        "target": target,
                        "candidates": candidates,
                        "detail": "No unique parent can be resolved; no reply edge created.",
                    }
                )
                continue
            parent = min(parent_groups)
            parent_copies = copies[parent]
            parent_record = by_id[parent]
            if (
                len(parent_record["message_ids"]) != 1
                or sum(h["name"].lower() == "message-id" for h in parent_record["headers"]) != 1
            ):
                diagnostics.append(
                    {
                        "code": "ambiguous_parent_identifier",
                        "email_id": child["id"],
                        "target": target,
                        "candidates": candidates,
                        "detail": "The candidate parent has multiple Message-ID values or headers.",
                    }
                )
                continue
            if parent == child_id:
                diagnostics.append(
                    {
                        "code": "self_reply",
                        "email_id": parent,
                        "target": target,
                        "detail": "Self-reference retained without creating a reply edge.",
                    }
                )
                continue
            extra = []
            if multi_parent:
                extra.append(
                    {
                        "code": "multiple_in_reply_to",
                        "email_ids": [child["id"]],
                        "targets": list(explicit),
                        "detail": f"In-Reply-To lists {len(explicit)} parent identifiers; this edge is one of several and does not establish a single parent.",
                    }
                )
            if source_kind == "references":
                extra.append(
                    {
                        "code": "references_fallback",
                        "email_ids": [child["id"]],
                        "detail": "Last References identifier used as a candidate parent because In-Reply-To is absent. An immediate reply is not established.",
                    }
                )
            if explicit and child["references"] and child["references"][-1] not in explicit:
                extra.append(
                    {
                        "code": "reply_headers_disagree",
                        "email_ids": [child["id"]],
                        "detail": "The last References identifier differs from In-Reply-To; both remain available.",
                    }
                )
            for group_rep in (parent, child_id):
                if group_rep in copy_content_variations:
                    extra.append(
                        {
                            "code": "copy_content_variation",
                            "email_ids": copy_content_variations[group_rep],
                            "detail": "These files match stable message headers and their full decoded content except for recognised link-protection rewriting of URLs. Review the preserved sources before relying on the reply link.",
                        }
                    )
            if parent in times and child_id in times and times[parent] > times[child_id]:
                extra.append(
                    {
                        "code": "reply_time_reversal",
                        "email_ids": [parent, child_id],
                        "detail": "The candidate reply predates its parent using the selected time source.",
                    }
                )
            event = add(
                "reply",
                parent_copies + child_copies,
                pointers(parent_copies, "message_id", target)
                + pointers(child_copies, source_kind, target),
                f"The child's {source_kind.replace('_', '-')} matches one source message represented by {len(parent_copies)} preserved file(s). Headers are not independently authenticated.",
                direction={
                    "parent": parent,
                    "child": child_id,
                    "parent_copies": parent_copies,
                    "child_copies": child_copies,
                },
                extra=extra,
            )
            reply_edges.append(event)

    # Connected reply components also prevent ordinary conversation chains from
    # being reclassified as coordinated distribution merely for quoting a URL.
    roots = {i: i for i in by_id}

    def root(i):
        while roots[i] != i:
            roots[i] = roots[roots[i]]
            i = roots[i]
        return i

    for rep, ids in copies.items():
        for evidence_id in ids:
            roots[root(evidence_id)] = root(rep)

    graph, reverse = defaultdict(set), defaultdict(set)
    for event in reply_edges:
        parent, child = event["direction"]["parent"], event["direction"]["child"]
        roots[root(parent)] = root(child)
        graph[parent].add(child)
        reverse[child].add(parent)

    # Iterative Kosaraju traversal detects cycles without recursion-depth limits.
    visited, order = set(), []
    for node in sorted(by_id):
        stack = [(node, False)]
        while stack:
            current, finished = stack.pop()
            if finished:
                order.append(current)
            elif current not in visited:
                visited.add(current)
                stack.append((current, True))
                stack.extend(
                    (neighbor, False)
                    for neighbor in sorted(graph[current], reverse=True)
                    if neighbor not in visited
                )
    components, component_sizes = {}, {}
    for node in reversed(order):
        if node in components:
            continue
        stack, size = [node], 0
        while stack:
            current = stack.pop()
            if current in components:
                continue
            components[current] = node
            size += 1
            stack.extend(reverse[current])
        component_sizes[node] = size
    for event in reply_edges:
        parent, child = event["direction"]["parent"], event["direction"]["child"]
        if components[parent] == components[child] and component_sizes[components[parent]] > 1:
            event["context"].append(
                {
                    "code": "reply_cycle",
                    "email_ids": event["email_ids"],
                    "detail": "Reply headers form a cycle; the relation is retained as conflicting evidence.",
                }
            )
            event["id"] = object_digest({k: v for k, v in event.items() if k != "id"})

    logical_index = defaultdict(lambda: defaultdict(set))
    for record in records:
        rep = representative[record["id"]]
        for artifact in record["artifacts"]:
            kind = artifact["kind"]
            if kind not in ("attachment_sha256", "url", "subject", "origin_ip"):
                continue
            # Older stored records may still label an inline MIME part as an attachment.
            if (
                kind == "attachment_sha256"
                and artifact["metadata"].get("disposition") == "inline"
                and artifact["metadata"].get("content_type", "").startswith("image/")
            ):
                continue
            logical_index[kind][artifact["value"]].add(rep)
    logical_times = {
        rep: min(times[i] for i in ids if i in times)
        for rep, ids in copies.items()
        if any(i in times for i in ids)
    }
    candidates = defaultdict(lambda: defaultdict(set))
    comparisons = 0
    suppressed = []
    background_skips = Counter()
    organisation_domains = list(config.organisation_domains)
    suggested_domains = suggest_organisation_domains(records)
    if suggested_domains and not organisation_domains:
        diagnostics.append(
            {
                "code": "organisation_domain_not_confirmed",
                "suggested": suggested_domains,
                "detail": "These domains look like the investigated organisation's own (most recipients and a substantial share of senders). They were not applied. Confirm them with --organisation-domain (or the analysis form) to keep their links out of coordination.",
            }
        )
    excluded_domains = [(d, "excluded_url_domain") for d in config.excluded_url_domains] + [
        (d, "organisation_domain") for d in organisation_domains if d not in config.excluded_url_domains
    ]
    for kind in ("attachment_sha256", "url", "subject", "origin_ip"):
        for value, ids in sorted(logical_index[kind].items()):
            if kind == "url":
                host = (urlsplit(value).hostname or "").lower()
                match = next(
                    (
                        (domain, reason)
                        for domain, reason in excluded_domains
                        if host == domain or host.endswith("." + domain)
                    ),
                    None,
                )
                if match:
                    suppressed.append(
                        {
                            "kind": kind,
                            "value": value,
                            "reason": match[1],
                            "domain": match[0],
                            "message_count": len(ids),
                            "email_ids": sorted(i for rep in ids for i in copies[rep]),
                        }
                    )
                    continue
            timed = sorted((logical_times[i], i) for i in ids if i in logical_times)
            stamps = [when.timestamp() for when, _ in timed]
            for position, (when, left) in enumerate(timed):
                for other_position in range(position + 1, len(timed)):
                    other_time, right = timed[other_position]
                    if (other_time - when).total_seconds() > config.window_seconds:
                        break
                    comparisons += 1
                    if comparisons > config.max_candidates * 8:
                        raise ValueError(
                            "Candidate comparison limit exceeded. Narrow the case; no partial run was saved."
                        )
                    if root(left) == root(right):
                        continue
                    # Background test: a value that is far more common outside this
                    # pair's surrounding window than inside it is routine traffic for
                    # this pair. Bursts, including each wave of a recurring campaign,
                    # keep their signal.
                    low = when.timestamp() - config.window_seconds
                    high = other_time.timestamp() + config.window_seconds
                    inside = bisect_right(stamps, high) - bisect_left(stamps, low)
                    outside = len(stamps) - inside
                    if (
                        outside >= config.background_min_outside
                        and outside >= config.background_ratio * inside
                    ):
                        background_skips[(kind, value)] += 1
                        continue
                    pair = tuple(sorted((left, right)))
                    if pair not in candidates and len(candidates) >= config.max_candidates:
                        raise ValueError(
                            "Candidate limit exceeded. Narrow the case or raise max_candidates; no partial run was saved."
                        )
                    candidates[pair][kind].add(value)
    cluster_roots = {rep: rep for rep in copies}

    def cluster_root(i):
        while cluster_roots[i] != i:
            cluster_roots[i] = cluster_roots[cluster_roots[i]]
            i = cluster_roots[i]
        return i

    qualified = []
    for ids, signals in sorted(candidates.items()):
        if len(signals) < config.minimum_signals:
            continue
        cluster_roots[cluster_root(ids[0])] = cluster_root(ids[1])
        source_ids = sorted(set(copies[ids[0]] + copies[ids[1]]))
        support = []
        for kind, values in sorted(signals.items()):
            for value in sorted(values):
                support.extend(pointers(source_ids, kind, value))
        for rep in ids:
            for evidence_id in copies[rep]:
                for observation in by_id[evidence_id]["timestamps"]:
                    if (
                        observation["kind"] == config.timestamp_source
                        and observation["utc"] == by_id[evidence_id][time_key]
                    ):
                        support.append(
                            {
                                "email_id": evidence_id,
                                "kind": "timestamp",
                                "value": observation["utc"],
                                "raw": observation["raw"],
                                "location": observation["location"],
                                "metadata": {"trusted": False, "basis": config.timestamp_source},
                            }
                        )
                        break
        qualified.append(
            {
                "email_ids": list(ids),
                "source_email_ids": source_ids,
                "signals": {kind: sorted(values) for kind, values in sorted(signals.items())},
                "elapsed_seconds": abs((logical_times[ids[0]] - logical_times[ids[1]]).total_seconds()),
                "support": support,
            }
        )

    clusters = defaultdict(list)
    for pair in qualified:
        clusters[cluster_root(pair["email_ids"][0])].append(pair)
    for pairs in clusters.values():
        source_ids = sorted({i for pair in pairs for i in pair["source_email_ids"]})
        logical_ids = {i for pair in pairs for i in pair["email_ids"]}
        seen_support = set()
        support = []
        for pair in pairs:
            for observation in pair["support"]:
                key = object_digest(observation)
                if key not in seen_support:
                    seen_support.add(key)
                    support.append(observation)
        bulk = sorted(
            i
            for i in source_ids
            if any(
                h["name"].lower() in BULK_HEADERS
                or (
                    h["name"].lower() == "precedence"
                    and h["value"].strip().lower() in ("bulk", "list", "junk")
                )
                for h in by_id[i]["headers"]
            )
        )
        cluster_context = [
            {
                "code": "coordination_not_proven",
                "email_ids": source_ids,
                "detail": "Shared templates, infrastructure or ordinary bulk mail can produce the same pattern. Sender and timing claims are unverified.",
            }
        ]
        if bulk:
            cluster_context.append(
                {
                    "code": "bulk_mail_indicators",
                    "email_ids": bulk,
                    "detail": f"{len(bulk)} of {len(source_ids)} files carry List-Unsubscribe, List-Id, Auto-Submitted or Precedence bulk/list/junk headers, which ordinary newsletters and automated mail use. This is a review-priority hint, not proof of benign intent.",
                }
            )
        add(
            "possible_coordination",
            source_ids,
            support,
            f"{len(pairs)} qualifying pair(s) connect {len(logical_ids)} distinct messages "
            f"within the {config.window_seconds}-second inclusive window. Only the listed pairs have direct signal support. "
            "This cluster is a candidate for investigator review, not an attribution or a campaign verdict.",
            extra=cluster_context,
            pairs=pairs,
        )

    for entry in suppressed:
        source = (
            "the confirmed organisation domain"
            if entry["reason"] == "organisation_domain"
            else "the excluded domain"
        )
        diagnostics.append(
            {
                "code": "coordination_signal_suppressed",
                "reason": entry["reason"],
                "kind": entry["kind"],
                "value": entry["value"],
                "domain": entry["domain"],
                "message_count": entry["message_count"],
                "email_ids": entry["email_ids"],
                "detail": f"URL host is within {source} {entry['domain']}; it was not used as a coordination signal. URL reuse still reports it.",
            }
        )
    for (kind, value), skipped in sorted(background_skips.items()):
        diagnostics.append(
            {
                "code": "coordination_background_signal",
                "kind": kind,
                "value": value,
                "skipped_pairs": skipped,
                "message_count": len(logical_index[kind][value]),
                "email_ids": sorted(i for rep in logical_index[kind][value] for i in copies[rep]),
                "detail": f"For {skipped} compared pair(s) this {kind} value occurred at least {config.background_ratio:g} times more often outside the pair's window than inside it, so it was treated as routine background for those pairs.",
            }
        )
    events.sort(key=lambda e: (e["start_utc"] is None, e["start_utc"] or "", e["type"], e["id"]))
    result = {
        "application_version": __version__,
        "rule_version": RULE_VERSION,
        "parser_versions": sorted({str(r.get("parser_version")) for r in records}),
        "config": config.as_dict(),
        "evidence_digest": object_digest(sorted(by_id)),
        "record_digest": object_digest(records),
        "email_ids": sorted(by_id),
        "copy_groups": [ids for ids in copies.values() if len(ids) > 1],
        "copy_content_variations": list(copy_content_variations.values()),
        "events": events,
        "diagnostics": diagnostics,
        "statistics": {
            "messages": len(records),
            "logical_messages": len(copies),
            "copy_groups": sum(len(ids) > 1 for ids in copies.values()),
            "copy_content_variations": len(copy_content_variations),
            "events": len(events),
            "coordination_candidates": len(candidates),
            "coordination_pairs": len(qualified),
            "suppressed_signals": len(suppressed),
            "background_signal_values": len(background_skips),
            "organisation_domains": organisation_domains,
            "suggested_organisation_domains": suggested_domains,
            "comparisons": comparisons,
        },
    }
    result["id"] = object_digest(result)
    return result

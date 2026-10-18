"""Deterministic rules with indexed candidates and inspectable provenance."""

from collections import defaultdict
from datetime import datetime

from . import __version__
from .model import RULE_VERSION, RuleConfig, object_digest


def analyze(records, config=None):
    config = config or RuleConfig()
    records = sorted(records, key=lambda r: r["id"])
    by_id = {record["id"]: record for record in records}
    if len(by_id) != len(records):
        raise ValueError("Analysis requires unique evidence identities.")
    index = defaultdict(lambda: defaultdict(set))
    observations = defaultdict(list)
    for record in records:
        for artifact in record["artifacts"]:
            index[artifact["kind"]][artifact["value"]].add(record["id"])
            observations[(record["id"], artifact["kind"], artifact["value"])].append(artifact)
    time_key = config.timestamp_source + "_utc"
    times = {r["id"]: datetime.fromisoformat(r[time_key]) for r in records if r[time_key]}
    events, diagnostics = [], []

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

    def add(kind, ids, support, explanation, *, direction=None, extra=None):
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
        event["id"] = object_digest(event)
        events.append(event)
        return event

    for kind, rule in (("attachment_sha256", "attachment_reuse"), ("url", "url_reuse")):
        for value, ids in sorted(index[kind].items()):
            if len(ids) >= 2:
                add(
                    rule,
                    ids,
                    pointers(ids, kind, value),
                    "Identical transfer-decoded attachment SHA-256 appears in these messages. "
                    "Reuse does not establish transmission direction or malicious intent."
                    if rule == "attachment_reuse"
                    else "The same conservatively normalized URL appears in these messages. "
                    "No destination was visited; reuse does not prove propagation or malicious intent.",
                )

    reply_edges = []
    for child in records:
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
        for target in targets:
            candidates = sorted(index["message_id"].get(target, set()))
            if len(candidates) != 1:
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
            parent = candidates[0]
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
            if parent == child["id"]:
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
            if parent in times and child["id"] in times and times[parent] > times[child["id"]]:
                extra.append(
                    {
                        "code": "reply_time_reversal",
                        "email_ids": [parent, child["id"]],
                        "detail": "The candidate reply predates its parent using the selected time source.",
                    }
                )
            event = add(
                "reply",
                [parent, child["id"]],
                pointers([parent], "message_id", target)
                + pointers([child["id"]], source_kind, target),
                f"The child's {source_kind.replace('_', '-')} matches this unique source Message-ID. Headers are not independently authenticated.",
                direction={"parent": parent, "child": child["id"]},
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

    candidates = defaultdict(lambda: defaultdict(set))
    comparisons = 0
    for kind in ("attachment_sha256", "url", "subject", "origin_ip"):
        for value, ids in sorted(index[kind].items()):
            timed = sorted((times[i], i) for i in ids if i in times)
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
                    pair = tuple(sorted((left, right)))
                    if pair not in candidates and len(candidates) >= config.max_candidates:
                        raise ValueError(
                            "Candidate limit exceeded. Narrow the case or raise max_candidates; no partial run was saved."
                        )
                    candidates[pair][kind].add(value)
    for ids, signals in sorted(candidates.items()):
        if len(signals) < config.minimum_signals:
            continue
        support = []
        for kind, values in sorted(signals.items()):
            for value in sorted(values):
                support.extend(pointers(ids, kind, value))
        for evidence_id in ids:
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
        elapsed = abs((times[ids[0]] - times[ids[1]]).total_seconds())
        extra = [
            {
                "code": "coordination_not_proven",
                "email_ids": list(ids),
                "detail": "Shared templates, infrastructure or ordinary bulk mail can produce the same pattern. Sender and timing claims are unverified.",
            }
        ]
        add(
            "possible_coordination",
            ids,
            support,
            f"{len(signals)} distinct artifact categories overlap within {elapsed:g} seconds "
            f"(inclusive window: {config.window_seconds} seconds). The messages are not in a resolved reply component. "
            "This is a candidate for investigator review, not an attribution or a campaign verdict.",
            extra=extra,
        )

    events.sort(key=lambda e: (e["start_utc"] is None, e["start_utc"] or "", e["type"], e["id"]))
    result = {
        "application_version": __version__,
        "rule_version": RULE_VERSION,
        "config": config.as_dict(),
        "evidence_digest": object_digest(sorted(by_id)),
        "record_digest": object_digest(records),
        "email_ids": sorted(by_id),
        "events": events,
        "diagnostics": diagnostics,
        "statistics": {
            "messages": len(records),
            "events": len(events),
            "coordination_candidates": len(candidates),
            "comparisons": comparisons,
        },
    }
    result["id"] = object_digest(result)
    return result

"""Regression checks for evidence copies and coordination provenance."""

import sys
import unittest
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from etrace.correlate import analyze, suggest_organisation_domains, unwrap_url  # noqa: E402
from etrace.model import RuleConfig  # noqa: E402
from etrace.parser import parse_email  # noqa: E402

DATE = datetime(2026, 10, 12, 9, 0, tzinfo=UTC)


def email(
    name,
    *,
    message_id=None,
    subject="Update",
    body="hello",
    parent=None,
    attachments=(),
    mailbox=None,
    when=None,
    sender="alice@example.org",
    headers=(),
    html=None,
    recipient="bob@example.org",
):
    message = EmailMessage()
    message["From"] = sender
    message["To"] = recipient
    message["Date"] = (when or DATE).strftime("%a, %d %b %Y %H:%M:%S %z")
    message["Subject"] = subject
    message["Message-ID"] = message_id or f"<{name}@example.org>"
    if parent:
        message["In-Reply-To"] = parent
    if mailbox:
        message["X-Mailbox"] = mailbox
    for header, value in headers:
        message[header] = value
    message.set_content(body)
    if html is not None:
        message.add_alternative(html, subtype="html")
    for filename, data, disposition in attachments:
        message.add_attachment(
            data,
            maintype="image" if disposition == "inline" else "application",
            subtype="png" if disposition == "inline" else "octet-stream",
            filename=filename,
            disposition=disposition,
        )
    return parse_email(message.as_bytes(), name + ".eml")


class CorrelationTests(unittest.TestCase):
    def test_copy_group_resolves_reply_and_preserves_sources(self):
        parent_id = "<parent@example.org>"
        sent = email("sent", message_id=parent_id, mailbox="sent")
        inbox = email("inbox", message_id=parent_id, mailbox="inbox")
        child = email("reply", subject="Re: Update", parent=parent_id)
        result = analyze([sent, inbox, child])
        replies = [e for e in result["events"] if e["type"] == "reply"]
        self.assertEqual(len(replies), 1)
        self.assertEqual(set(replies[0]["email_ids"]), {sent["id"], inbox["id"], child["id"]})
        self.assertEqual(set(replies[0]["direction"]["parent_copies"]), {sent["id"], inbox["id"]})
        self.assertFalse(any(d["code"] == "ambiguous_parent" for d in result["diagnostics"]))
        self.assertEqual(result["statistics"]["copy_groups"], 1)

    def test_rfc6854_empty_from_group_is_preserved_and_copies_link(self):
        parent_id = "<automated@example.org>"
        sent = email("sent", message_id=parent_id, sender="Automated System:;", mailbox="sent")
        inbox = email("inbox", message_id=parent_id, sender="Automated System:;", mailbox="inbox")
        child = email("reply", parent=parent_id)
        self.assertEqual(sent["senders"], [])
        self.assertEqual(
            [group for group in sent["originator_groups"] if group["field"] == "from"][0],
            {
                "field": "from", "name": "Automated System", "addresses": [],
                "location": "header:0",
            },
        )
        self.assertFalse(any(w["code"] == "originator_parse_error" for w in sent["warnings"]))
        result = analyze([sent, inbox, child])
        replies = [event for event in result["events"] if event["type"] == "reply"]
        self.assertEqual(result["statistics"]["copy_groups"], 1)
        self.assertEqual(set(replies[0]["direction"]["parent_copies"]), {sent["id"], inbox["id"]})

    def test_rfc6854_empty_group_requires_matching_content(self):
        parent_id = "<automated@example.org>"
        first = email("first", message_id=parent_id, sender="Automated System:;", body="alpha")
        second = email("second", message_id=parent_id, sender="Automated System:;", body="beta")
        child = email("child", parent=parent_id)
        result = analyze([first, second, child])
        self.assertEqual(result["statistics"]["copy_groups"], 0)
        self.assertTrue(any(d["code"] == "ambiguous_parent" for d in result["diagnostics"]))

    def test_rfc6854_group_names_are_part_of_copy_identity(self):
        parent_id = "<group@example.org>"
        first = email("first", message_id=parent_id, sender="Team One: alice@example.org;")
        second = email("second", message_id=parent_id, sender="Team Two: alice@example.org;")
        self.assertEqual([s["address"] for s in first["senders"]], ["alice@example.org"])
        self.assertEqual(analyze([first, second])["statistics"]["copy_groups"], 0)

    def test_rfc6854_sender_and_resent_groups_are_distinct_from_authors(self):
        record = email(
            "group", sender="Team: alice@example.org, bob@example.org;",
            headers=(
                ("Sender", "Agent: carol@example.org;"),
                ("Resent-From", "Resent Team: dave@example.org;"),
                ("Resent-Sender", "Resender: eve@example.org;"),
            ),
        )
        self.assertEqual(
            {sender["address"] for sender in record["senders"]},
            {"alice@example.org", "bob@example.org"},
        )
        groups = {group["field"]: group for group in record["originator_groups"]}
        self.assertEqual(groups["sender"]["name"], "Agent")
        self.assertEqual(groups["sender"]["addresses"][0]["address"], "carol@example.org")
        self.assertEqual(groups["resent-from"]["name"], "Resent Team")
        self.assertEqual(groups["resent-sender"]["name"], "Resender")
        self.assertFalse(any(w["code"] == "missing_sender_header" for w in record["warnings"]))

    def test_rfc6854_invalid_originator_cardinality_is_reported(self):
        missing_sender = email(
            "missing-sender", sender="Team: alice@example.org, bob@example.org;"
        )
        self.assertIn("missing_sender_header", {w["code"] for w in missing_sender["warnings"]})
        multiple_sender = email(
            "multiple-sender", headers=(("Sender", "Agents: a@example.org, b@example.org;"),)
        )
        self.assertIn(
            "multiple_sender_mailboxes", {w["code"] for w in multiple_sender["warnings"]}
        )

    def test_reused_message_id_with_different_content_stays_ambiguous(self):
        parent_id = "<collision@example.org>"
        first = email("one", message_id=parent_id, body="alpha invoice schedule " * 12)
        second = email("two", message_id=parent_id, body="zebra security incident " * 12)
        child = email("child", parent=parent_id)
        result = analyze([first, second, child])
        self.assertFalse(any(e["type"] == "reply" for e in result["events"]))
        self.assertTrue(any(d["code"] == "ambiguous_parent" for d in result["diagnostics"]))

    def test_body_difference_beyond_link_rewriting_stays_ambiguous(self):
        parent_id = "<variable@example.org>"
        common = "Please review the transport plan and confirm the booking reference. " * 4
        sent = email("sent", message_id=parent_id, body=common + "Sent mailbox footer")
        inbox = email("inbox", message_id=parent_id, body=common + "Inbox mailbox footer")
        child = email("child", parent=parent_id)
        result = analyze([sent, inbox, child])
        self.assertEqual(result["statistics"]["copy_groups"], 0)
        self.assertFalse(any(e["type"] == "reply" for e in result["events"]))
        self.assertTrue(any(d["code"] == "ambiguous_parent" for d in result["diagnostics"]))

    def test_safe_links_copy_is_grouped_and_marked_provisional(self):
        parent_id = "<safelinks@example.org>"
        common = "Please settle the attached statement through our portal by Friday. " * 3
        sent = email("sent", message_id=parent_id, body=common + "Pay: https://portal.vendor.example/pay")
        inbox = email(
            "inbox",
            message_id=parent_id,
            body=common + "Pay: https://apc01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fportal.vendor.example%2Fpay&data=05%7C02%7Cbob%40example.org%7Cabc123&reserved=0",
        )
        child = email("child", parent=parent_id)
        result = analyze([sent, inbox, child])
        replies = [e for e in result["events"] if e["type"] == "reply"]
        self.assertEqual(len(replies), 1)
        self.assertEqual(set(replies[0]["direction"]["parent_copies"]), {sent["id"], inbox["id"]})
        self.assertTrue(any(c["code"] == "copy_content_variation" for c in replies[0]["context"]))
        # The wrapped URL is still preserved exactly as observed.
        self.assertTrue(any("safelinks" in a["value"] for a in inbox["artifacts"] if a["kind"] == "url"))

    def test_changed_account_number_stays_ambiguous(self):
        parent_id = "<remittance@example.org>"
        boilerplate = (
            "Dear Accounts Payable, please find our updated remittance instructions below. Kindly "
            "process the outstanding balance by Friday via the portal. Regards, Accounts Receivable. "
        ) * 2
        genuine = email(
            "genuine",
            message_id=parent_id,
            body=boilerplate + "Account: DBS 012-345678-9 https://portal.vendor.example/pay",
        )
        altered = email(
            "altered",
            message_id=parent_id,
            body=boilerplate + "Account: UOB 3-118-4471-2 https://portal.vendor.example/pay",
        )
        child = email("child", subject="Re: Update", parent=parent_id)
        result = analyze([genuine, altered, child])
        self.assertEqual(result["statistics"]["copy_groups"], 0)
        self.assertFalse(any(e["type"] == "reply" for e in result["events"]))
        self.assertTrue(any(d["code"] == "ambiguous_parent" for d in result["diagnostics"]))

    def _parent_case(self, sent_kwargs, inbox_kwargs):
        parent_id = "<markup@example.org>"
        sent = email("sent", message_id=parent_id, **sent_kwargs)
        inbox = email("inbox", message_id=parent_id, **inbox_kwargs)
        child = email("child", subject="Re: Update", parent=parent_id)
        return analyze([sent, inbox, child])

    def assert_ambiguous(self, result):
        self.assertEqual(result["statistics"]["copy_groups"], 0)
        self.assertFalse(any(e["type"] == "reply" for e in result["events"]))
        self.assertTrue(any(d["code"] == "ambiguous_parent" for d in result["diagnostics"]))

    def test_hidden_html_field_change_stays_ambiguous(self):
        text = "Please settle the statement via our portal by Friday. Regards, Accounts."
        form = (
            '<html><body><p>Please settle the statement via our portal by Friday.</p>'
            '<form action="https://portal.vendor.example/pay">'
            '<input type="hidden" name="acct" value="{}"><button>Pay</button></form></body></html>'
        )
        result = self._parent_case(
            {"body": text, "html": form.format("111111")}, {"body": text, "html": form.format("999999")}
        )
        self.assert_ambiguous(result)

    def test_html_comment_or_attribute_change_stays_ambiguous(self):
        text = "Statement attached. Regards, Accounts."
        for left, right in (
            ("<p>Statement attached.</p><!-- ref A -->", "<p>Statement attached.</p><!-- ref B -->"),
            ('<p class="a">Statement attached.</p>', '<p class="b">Statement attached.</p>'),
        ):
            with self.subTest(left=left):
                self.assert_ambiguous(self._parent_case({"body": text, "html": left}, {"body": text, "html": right}))

    def test_reordered_links_stay_ambiguous(self):
        first, second = "https://portal.vendor.example/a", "https://portal.vendor.example/b"
        self.assert_ambiguous(
            self._parent_case(
                {"body": f"Invoice: {first} Receipt: {second}"},
                {"body": f"Invoice: {second} Receipt: {first}"},
            )
        )

    def test_renamed_attachment_with_identical_bytes_stays_ambiguous(self):
        invoice = ("invoice.pdf", b"%PDF-1.4 identical bytes", "attachment")
        renamed = ("malware.exe", b"%PDF-1.4 identical bytes", "attachment")
        self.assert_ambiguous(self._parent_case({"attachments": [invoice]}, {"attachments": [renamed]}))
        # The same attachment under the same name is still one message seen twice.
        same = self._parent_case({"attachments": [invoice]}, {"attachments": [invoice]})
        self.assertEqual(same["statistics"]["copy_groups"], 1)
        self.assertTrue(any(e["type"] == "reply" for e in same["events"]))

    def test_safe_links_html_copy_with_rewritten_href_is_grouped(self):
        original = "https://portal.vendor.example/pay?invoice=10391&amp;ref=7"
        wrapped = (
            "https://apc01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fportal.vendor.example"
            "%2Fpay%3Finvoice%3D10391%26ref%3D7&amp;data=05%7C02%7Cbob%40example.org%7Cabc&amp;reserved=0"
        )
        page = '<html><body><p>Statement ready.</p><a href="{}">View statement</a></body></html>'
        text = "Statement ready. View statement: {}"
        result = self._parent_case(
            {"body": text.format(original.replace("&amp;", "&")), "html": page.format(original)},
            {"body": text.format(wrapped.replace("&amp;", "&")), "html": page.format(wrapped)},
        )
        self.assertEqual(result["statistics"]["copy_groups"], 1)
        self.assertEqual(sum(e["type"] == "reply" for e in result["events"]), 1)

    def test_unwrap_url_recognises_only_known_wrappers(self):
        self.assertEqual(unwrap_url("https://apc01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fportal.vendor.example%2Fpay&data=05%7C02%7Cbob%40example.org%7Cabc123&reserved=0"), "https://portal.vendor.example/pay")
        self.assertEqual(
            unwrap_url(
                "https://urldefense.proofpoint.com/v2/url?u=https-3A__portal.vendor.example_pay&d=DwMF&c=x"
            ),
            "https://portal.vendor.example/pay",
        )
        self.assertEqual(
            unwrap_url("https://urldefense.com/v3/__https://portal.vendor.example/pay__;!!abc$"),
            "https://portal.vendor.example/pay",
        )
        plain = "https://example.net/path?url=https%3A%2F%2Felsewhere.example"
        self.assertEqual(unwrap_url(plain), plain)
        government = "https://gcc02.safelinks.protection.office365.us/?url=https%3A%2F%2Fportal.vendor.example%2Fpay&data=x"
        self.assertEqual(unwrap_url(government), "https://portal.vendor.example/pay")
        # Look-alike and non-HTTPS hosts are never treated as a provider wrapper.
        for untrusted in (
            "https://login.safelinks.attacker.example/?url=https%3A%2F%2Fportal.vendor.example%2Fpay",
            "https://safelinks.protection.outlook.com.attacker.example/?url=https%3A%2F%2Fportal.vendor.example%2Fpay",
            "https://evilsafelinks.protection.outlook.com/?url=https%3A%2F%2Fportal.vendor.example%2Fpay",
            "http://apc01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fportal.vendor.example%2Fpay",
        ):
            self.assertEqual(unwrap_url(untrusted), untrusted)
        # An explicitly trusted host uses the Safe Links url= format.
        test_host = "https://apc01.safelinks.mailprotect.example/?url=https%3A%2F%2Fportal.vendor.example%2Fpay"
        self.assertEqual(unwrap_url(test_host), test_host)
        self.assertEqual(
            unwrap_url(test_host, ("safelinks.mailprotect.example",)), "https://portal.vendor.example/pay"
        )

    def test_look_alike_wrapper_host_does_not_create_a_copy(self):
        parent_id = "<lookalike@example.org>"
        common = "Please settle the attached statement through our portal by Friday. " * 3
        genuine = email("genuine", message_id=parent_id, body=common + "Pay: https://portal.vendor.example/pay")
        forged = email(
            "forged",
            message_id=parent_id,
            body=common
            + "Pay: https://login.safelinks.attacker.example/?url=https%3A%2F%2Fportal.vendor.example%2Fpay&data=x",
        )
        child = email("child", subject="Re: Update", parent=parent_id)
        result = analyze([genuine, forged, child])
        self.assertEqual(result["statistics"]["copy_groups"], 0)
        self.assertFalse(any(e["type"] == "reply" for e in result["events"]))
        self.assertTrue(any(d["code"] == "ambiguous_parent" for d in result["diagnostics"]))
        trusted = analyze(
            [genuine, forged, child], RuleConfig(trusted_wrapper_hosts=("safelinks.attacker.example",))
        )
        self.assertEqual(trusted["statistics"]["copy_groups"], 1)  # only because the investigator said so
        self.assertEqual(trusted["config"]["trusted_wrapper_hosts"], ["safelinks.attacker.example"])

    def test_shared_boilerplate_with_different_links_stays_ambiguous(self):
        parent_id = "<remittance@example.org>"
        boilerplate = (
            "Dear Accounts Payable, please find our remittance instructions below. Kindly process "
            "the outstanding balance by Friday. Regards, Accounts Receivable. "
        ) * 2
        genuine = email("genuine", message_id=parent_id, body=boilerplate + "Pay: https://pay.vendor.example/inv/10391")
        altered = email("altered", message_id=parent_id, body=boilerplate + "Pay: https://pay-vendor.example/inv/10391")
        child = email("child", subject="Re: Update", parent=parent_id)
        result = analyze([genuine, altered, child])
        self.assertEqual(result["statistics"]["copy_groups"], 0)
        self.assertFalse(any(e["type"] == "reply" for e in result["events"]))
        ambiguous = [d for d in result["diagnostics"] if d["code"] == "ambiguous_parent"]
        self.assertEqual(len(ambiguous), 1)
        self.assertEqual(set(ambiguous[0]["candidates"]), {genuine["id"], altered["id"]})

    def test_copies_do_not_coordinate(self):
        first = email("sent", body="https://example.net/task", mailbox="sent")
        second = email("inbox", message_id="<sent@example.org>", body="https://example.net/task", mailbox="inbox")
        result = analyze([first, second])
        self.assertEqual(result["statistics"]["logical_messages"], 1)
        self.assertEqual(result["statistics"]["coordination_pairs"], 0)
        self.assertFalse(any(e["type"] == "possible_coordination" for e in result["events"]))

    def test_inline_resource_is_preserved_without_coordination_signal(self):
        attachments = (("logo.png", b"same-logo", "inline"),)
        first = email("a", subject="Alpha", body="https://shared.example/item", attachments=attachments)
        second = email("b", subject="Beta", body="https://shared.example/item", attachments=attachments)
        self.assertTrue(any(a["kind"] == "inline_resource_sha256" for a in first["artifacts"]))
        result = analyze([first, second])
        self.assertFalse(any(e["type"] == "possible_coordination" for e in result["events"]))

    def test_organisation_domain_is_suggested_but_only_applied_when_confirmed(self):
        # Everything is sent and received @example.org, so that is suggested.
        pair = [
            email("link-a", subject="Same", body="https://intranet.example.org/home"),
            email("link-b", subject="Same", body="https://intranet.example.org/home"),
        ]
        unconfirmed = analyze(pair)
        self.assertEqual(unconfirmed["statistics"]["suggested_organisation_domains"], ["example.org"])
        self.assertEqual(unconfirmed["statistics"]["organisation_domains"], [])
        self.assertEqual(unconfirmed["statistics"]["coordination_pairs"], 1)
        notice = [d for d in unconfirmed["diagnostics"] if d["code"] == "organisation_domain_not_confirmed"]
        self.assertEqual(notice[0]["suggested"], ["example.org"])

        confirmed = analyze(pair, RuleConfig(organisation_domains=("example.org",)))
        self.assertEqual(confirmed["statistics"]["organisation_domains"], ["example.org"])
        self.assertEqual(confirmed["statistics"]["coordination_pairs"], 0)
        self.assertFalse(any(d["code"] == "organisation_domain_not_confirmed" for d in confirmed["diagnostics"]))
        listed = [d for d in confirmed["diagnostics"] if d["code"] == "coordination_signal_suppressed"]
        self.assertEqual([(d["reason"], d["domain"]) for d in listed], [("organisation_domain", "example.org")])
        self.assertEqual(len(listed[0]["email_ids"]), 2)
        self.assertTrue(any(e["type"] == "url_reuse" for e in confirmed["events"]))
        self.assertEqual(confirmed["config"]["organisation_domains"], ["example.org"])

    def test_sent_only_mail_to_a_vendor_does_not_suppress_the_vendor(self):
        def sent(name, minutes):
            message = EmailMessage()
            message["From"] = "priya@halcyon.example"
            message["To"] = "ar@vendor.example"
            message["Date"] = (DATE + timedelta(minutes=minutes)).strftime("%a, %d %b %Y %H:%M:%S %z")
            message["Subject"] = "Remittance query"
            message["Message-ID"] = f"<{name}@halcyon.example>"
            message.set_content("See https://portal.vendor.example/statement/77")
            return parse_email(message.as_bytes(), name + ".eml")

        records = [sent("s1", 0), sent("s2", 20)]
        self.assertEqual(suggest_organisation_domains(records), [])  # vendor never sends here
        result = analyze(records)
        self.assertEqual(result["statistics"]["organisation_domains"], [])
        self.assertEqual(result["statistics"]["coordination_pairs"], 1)

    def test_supplier_heavy_conversation_does_not_suggest_the_supplier(self):
        # Three messages company -> vendor and one reply: the vendor receives 75% of
        # the mail but the company sends most of it, so nothing is suggested.
        records = [
            email(f"out{i}", body="https://portal.vendor.example/statement/77", sender="priya@halcyon.example",
                  recipient="ar@vendor.example", when=DATE + timedelta(minutes=10 * i))
            for i in range(3)
        ] + [
            email("in0", body="https://portal.vendor.example/statement/77", sender="ar@vendor.example",
                  recipient="priya@halcyon.example", when=DATE + timedelta(minutes=30))
        ]
        self.assertEqual(suggest_organisation_domains(records), [])
        self.assertEqual(analyze(records)["statistics"]["coordination_pairs"], 6)
        # A tie between two domains also yields no suggestion.
        tie = records[:2] + [
            email(f"in{i}", body="x", sender="ar@vendor.example", recipient="priya@halcyon.example")
            for i in range(1, 3)
        ]
        self.assertEqual(suggest_organisation_domains(tie), [])

    def test_excluded_domains_are_listed(self):
        other = [
            email("ext-a", subject="Same", body="https://company.example/home"),
            email("ext-b", subject="Same", body="https://company.example/home"),
        ]
        self.assertEqual(analyze(other)["statistics"]["coordination_pairs"], 1)
        excluded = analyze(other, RuleConfig(excluded_url_domains=("company.example",)))
        self.assertEqual(excluded["statistics"]["coordination_pairs"], 0)
        self.assertTrue(
            any(
                d["code"] == "coordination_signal_suppressed" and d["reason"] == "excluded_url_domain"
                for d in excluded["diagnostics"]
            )
        )
        self.assertEqual(excluded["config"]["excluded_url_domains"], ["company.example"])

    def test_routine_background_value_is_skipped_for_a_pair(self):
        # A supplier portal link appears every few hours all month; two messages that
        # happen to share it and a subject within one hour should not coordinate on it.
        portal = "https://portal.supplier.example/home"
        routine = [
            email(f"routine{i}", subject=f"Order {i}", body=portal, when=DATE + timedelta(hours=6 * i))
            for i in range(1, 25)
        ]
        pair = [
            email("a", subject="Weekly order", body=portal, when=DATE),
            email("b", subject="Weekly order", body=portal, when=DATE + timedelta(minutes=10)),
        ]
        result = analyze(routine + pair)
        self.assertEqual(result["statistics"]["coordination_pairs"], 0)
        background = [d for d in result["diagnostics"] if d["code"] == "coordination_background_signal"]
        self.assertEqual([(d["kind"], d["value"]) for d in background], [("url", portal)])
        self.assertGreaterEqual(background[0]["skipped_pairs"], 1)
        self.assertEqual(result["statistics"]["background_signal_values"], 1)
        strict = analyze(routine + pair, RuleConfig(background_min_outside=1000))
        self.assertEqual(strict["statistics"]["coordination_pairs"], 1)

    def test_cluster_keeps_only_supported_pairs(self):
        first = email("a", subject="A", body="https://example.net/ab", attachments=(("x.bin", b"x", "attachment"),))
        middle = email(
            "b",
            subject="B",
            body="https://example.net/ab https://example.net/bc",
            attachments=(("x.bin", b"x", "attachment"), ("y.bin", b"y", "attachment")),
        )
        last = email("c", subject="C", body="https://example.net/bc", attachments=(("y.bin", b"y", "attachment"),))
        result = analyze([first, middle, last])
        clusters = [e for e in result["events"] if e["type"] == "possible_coordination"]
        self.assertEqual(len(clusters), 1)
        actual = {frozenset(pair["email_ids"]) for pair in clusters[0]["pairs"]}
        self.assertEqual(actual, {frozenset((first["id"], middle["id"])), frozenset((middle["id"], last["id"]))})
        self.assertEqual(result["statistics"]["coordination_pairs"], 2)
        self.assertTrue(all(pair["support"] for pair in clusters[0]["pairs"]))

    def test_multiple_in_reply_to_edges_are_flagged(self):
        first, second = email("p1"), email("p2")
        child = email("child", subject="Re: Update", parent="<p1@example.org> <p2@example.org>")
        result = analyze([first, second, child])
        replies = [e for e in result["events"] if e["type"] == "reply"]
        self.assertEqual({e["direction"]["parent"] for e in replies}, {first["id"], second["id"]})
        for event in replies:
            self.assertIn("multiple_in_reply_to", [c["code"] for c in event["context"]])
        diagnostics = [d for d in result["diagnostics"] if d["code"] == "multiple_in_reply_to"]
        self.assertEqual(len(diagnostics), 1)
        self.assertEqual(diagnostics[0]["targets"], ["<p1@example.org>", "<p2@example.org>"])

    def test_single_parent_reply_has_no_multi_parent_flag(self):
        parent = email("p1")
        child = email("child", subject="Re: Update", parent="<p1@example.org>")
        result = analyze([parent, child])
        reply = next(e for e in result["events"] if e["type"] == "reply")
        self.assertNotIn("multiple_in_reply_to", [c["code"] for c in reply["context"]])

    def test_focused_case_keeps_dominant_campaign_visible(self):
        campaign = [
            email(f"phish{i}", subject="Overdue invoice INV-10482", body="Pay now https://evil-portal.example/s/8f3")
            for i in range(12)
        ]
        others = [email(f"other{i}", subject=f"Other {i}", body=f"https://unrelated.example/{i}") for i in range(3)]
        result = analyze(campaign + others)
        self.assertEqual(result["statistics"]["suppressed_signals"], 0)
        self.assertEqual(result["statistics"]["background_signal_values"], 0)
        self.assertEqual(result["statistics"]["coordination_pairs"], 66)

    def test_recurring_campaign_waves_stay_visible(self):
        waves = [
            email(
                f"wave{w}-{i}",
                subject="Account verification required",
                body="https://verify-acct.example/a",
                when=DATE + timedelta(hours=48 * w, minutes=5 * i),
            )
            for w in range(4)
            for i in range(4)
        ]
        background = [
            email(f"bg{i}", subject=f"Routine {i}", body=f"https://intranet.example.org/{i}", when=DATE + timedelta(hours=7 * i))
            for i in range(40)
        ]
        result = analyze(waves + background)
        ids = {r["id"] for r in waves}
        within_wave = [
            pair
            for event in result["events"]
            if event["type"] == "possible_coordination"
            for pair in event["pairs"]
            if set(pair["email_ids"]) <= ids
        ]
        self.assertEqual(len(within_wave), 24)  # 4 waves x 6 pairs

    def test_bulk_mail_headers_label_cluster(self):
        news = [
            email(
                f"news{i}",
                subject="Weekly digest",
                body="https://news.example.net/issue/41",
                sender="news@example.net",
                headers=(("List-Unsubscribe", "<https://news.example.net/u/1>"), ("Precedence", "bulk")),
            )
            for i in range(3)
        ]
        phish = [
            email(f"phish{i}", subject="Verify now", body="https://evil.example/a", when=DATE + timedelta(days=2))
            for i in range(3)
        ]
        result = analyze(news + phish)
        clusters = [e for e in result["events"] if e["type"] == "possible_coordination"]
        self.assertEqual(len(clusters), 2)
        labelled = {
            frozenset(e["email_ids"])
            for e in clusters
            if any(c["code"] == "bulk_mail_indicators" for c in e["context"])
        }
        self.assertEqual(labelled, {frozenset(r["id"] for r in news)})

    def test_inline_resource_reuse_is_reported_but_not_coordination(self):
        attachments = (("qr.png", b"same-qr-code", "inline"),)
        records = [email(f"q{i}", subject=f"Salary {i}", body="scan", attachments=attachments) for i in range(3)]
        result = analyze(records)
        inline = [e for e in result["events"] if e["type"] == "inline_resource_reuse"]
        self.assertEqual(len(inline), 1)
        self.assertEqual(set(inline[0]["email_ids"]), {r["id"] for r in records})
        self.assertFalse(any(e["type"] in ("attachment_reuse", "possible_coordination") for e in result["events"]))

    def test_run_records_parser_versions(self):
        result = analyze([email("one")])
        self.assertEqual(result["parser_versions"], [email("two")["parser_version"]])


if __name__ == "__main__":
    unittest.main()

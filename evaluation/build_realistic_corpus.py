"""Build a realistic, fully labelled E-TRACE test corpus (fictional organisation).

Scenario: Halcyon Freight Pte Ltd (Singapore) receives a lookalike-supplier invoice
phishing campaign on 14-15 Oct 2026, surrounded by ordinary business mail collected
from several employees' mailboxes (inbox, sent items, drafts).

Everything is fictional. Domains use the reserved .example TLD (RFC 2606) and IPs
come from the documentation ranges 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24
(RFC 5737), so no real organisation, person or host is referenced and nothing is
reachable. Attachments are inert.

Ground truth is computed from what each scenario *declares* each message carries
(URLs written into bodies, attachment bytes, subject, origin IP, reply headers),
never by running E-TRACE's parser or correlation engine.

Usage:
    python evaluation/build_realistic_corpus.py --output <empty dir outside the repository>
"""

import argparse
import base64
import hashlib
import io
import json
import os
import random
import zipfile
from datetime import UTC, datetime, timedelta, timezone
from email import policy
from email.header import Header
from email.message import EmailMessage
from email.utils import format_datetime
from itertools import combinations
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

# Pin library output so rebuilt files are byte-identical: openpyxl writes different
# XML spacing with lxml, and Pillow 12 changed the default PNG compression level.
os.environ.setdefault("OPENPYXL_LXML", "False")

SGT = timezone(timedelta(hours=8))
JST = timezone(timedelta(hours=9))
UTC = UTC
WINDOW = 3600
RNG = random.Random(20261014)

ORG = "halcyon-freight.example"
WEBSITE = "https://www.halcyon-freight.example"
MBX = "SG2PR06MB5123.apcprd06.prod.mailhost.example"


# --------------------------------------------------------------------------- helpers
def sha(data):
    return hashlib.sha256(data).hexdigest()


def norm_url(url):
    """README spec: lowercase scheme/host, empty path -> '/', query/fragment kept."""
    p = urlsplit(url)
    return urlunsplit((p.scheme.lower(), p.netloc.lower(), p.path or "/", p.query, p.fragment))


def norm_subject(subject):
    import re

    value = re.sub(r"\s+", " ", subject).strip()
    while re.match(r"^(?:re|fw|fwd)\s*:", value, re.I):
        value = re.sub(r"^(?:re|fw|fwd)\s*:\s*", "", value, count=1, flags=re.I)
    return value.casefold() or None


def rand_b64(n):
    return base64.b64encode(RNG.randbytes(n)).decode()


def rand_hex(n):
    return RNG.randbytes(n).hex()


def fixed_zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files:
            info = zipfile.ZipInfo(name, date_time=(2026, 10, 14, 8, 30, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data)
    return buf.getvalue()


def renormalize_zip(data):
    import re

    src = zipfile.ZipFile(io.BytesIO(data))
    files = []
    for info in src.infolist():
        content = src.read(info.filename)
        if info.filename == "docProps/core.xml":  # openpyxl stamps save time; pin it
            content = re.sub(rb"(<dcterms:(?:created|modified)[^>]*>)[^<]*", rb"\g<1>2026-10-01T09:00:00Z", content)
        files.append((info.filename, content))
    return fixed_zip(files)


# --------------------------------------------------------------------------- attachments
def make_pdf(title, lines):
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4, invariant=1)
    c.setTitle(title)
    c.setAuthor("Generated test document")
    y = 800
    c.setFont("Helvetica-Bold", 15)
    c.drawString(60, y, title)
    c.setFont("Helvetica", 10)
    for line in lines:
        y -= 18
        c.drawString(60, y, line)
    c.showPage()
    c.save()
    return buf.getvalue()


def make_xlsx(title, header, rows):
    from openpyxl import Workbook

    wb = Workbook()
    ws = wb.active
    ws.title = title[:31]
    ws.append(header)
    for row in rows:
        ws.append(row)
    fixed = datetime(2026, 10, 1, 9, 0, 0)
    wb.properties.created = fixed
    wb.properties.modified = fixed
    wb.properties.creator = "Generated test document"
    buf = io.BytesIO()
    wb.save(buf)
    return renormalize_zip(buf.getvalue())


def make_logo(text, colour):
    from PIL import Image, ImageDraw

    img = Image.new("RGB", (180, 48), colour)
    d = ImageDraw.Draw(img)
    d.rectangle([4, 4, 175, 43], outline=(255, 255, 255), width=2)
    d.text((14, 17), text, fill=(255, 255, 255))
    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=False, compress_level=6)
    return buf.getvalue()


HALCYON_LOGO = make_logo("HALCYON FREIGHT", (14, 61, 102))
MERIDIAN_LOGO = make_logo("MERIDIAN MARINE", (0, 110, 90))

LEGIT_INVOICE_PDF = make_pdf(
    "Meridian Marine Supplies - Tax Invoice INV-2026-10391",
    [
        "Bill to: Halcyon Freight Pte Ltd, 21 Tuas Avenue 9, Singapore 639188",
        "Invoice date: 12 Oct 2026      Due: 11 Nov 2026 (30 days)",
        "PO: HF-PO-77310",
        "1  Mooring rope 64mm x 220m           2  @ SGD 1,840.00   SGD 3,680.00",
        "2  Fender, cylindrical 400x800        6  @ SGD   312.50   SGD 1,875.00",
        "Subtotal SGD 5,555.00   GST 9% SGD 499.95   Total SGD 6,054.95",
        "Pay to: Meridian Marine Supplies, account on file (no changes this period).",
    ],
)
HR_POLICY_PDF = make_pdf(
    "Halcyon Freight - Travel & Expense Policy v4.2",
    [
        "Effective 1 November 2026. Supersedes v4.1 (March 2025).",
        "3.1 Economy class for flights under 6 hours.",
        "3.4 Per-diem: Malaysia SGD 85, Indonesia SGD 90, Vietnam SGD 80.",
        "5.2 Claims must be submitted within 30 days with itemised receipts.",
        "7.1 Corporate card statements are reconciled monthly by Finance.",
    ],
)
Q4_XLSX = make_xlsx(
    "Q4 Tuas schedule",
    ["Week", "Inbound TEU", "Outbound TEU", "Dock doors", "Lead"],
    [
        ["W41", 312, 288, "D1-D6", "Wei Jie"],
        ["W42", 344, 301, "D1-D8", "Wei Jie"],
        ["W43", 360, 330, "D1-D8", "Hafiz"],
        ["W44", 298, 276, "D1-D6", "Wei Jie"],
    ],
)
QUOTE_XLSX = make_xlsx(
    "Q-55821",
    ["Item", "Description", "Qty", "Unit SGD", "Total SGD"],
    [
        [1, "Stretch wrap 23mic 500mm", 120, 18.40, 2208.00],
        [2, "PET strapping 16mm", 40, 42.00, 1680.00],
        [3, "Strapping seals (box 1000)", 10, 29.50, 295.00],
    ],
)
PHISH_HTML = b"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Secure Document Viewer</title>
<style>body{font-family:Segoe UI,Arial;background:#f3f6f9}.box{width:360px;margin:80px auto;
background:#fff;padding:28px;border-radius:6px;box-shadow:0 2px 8px #0002}</style></head>
<body><div class="box"><h2>Meridian Marine Supplies</h2>
<p>INV-2026-10482.pdf is protected. Sign in with your work email to view this document.</p>
<form action="https://docs-secure-portal.example/auth/collect.php" method="post">
<input name="login" placeholder="Email address"><br><input name="passwd" type="password" placeholder="Password"><br>
<button type="submit">View document</button></form>
<p style="font-size:11px;color:#888">TEST SAMPLE - inert, fictional, for forensic tool evaluation only.</p>
</div></body></html>
"""
PHISH_ZIP = fixed_zip([("INV-2026-10482.html", PHISH_HTML)])
ICS = (
    b"BEGIN:VCALENDAR\r\nPRODID:-//Generated test//EN\r\nVERSION:2.0\r\nMETHOD:REQUEST\r\n"
    b"BEGIN:VEVENT\r\nUID:040000008200E00074C5B7101A82E00800000000A0B1C2D3E4F5A6@halcyon-freight.example\r\n"
    b"SUMMARY:Phishing awareness refresher (30 min)\r\nDTSTART;TZID=Asia/Singapore:20261016T150000\r\n"
    b"DTEND;TZID=Asia/Singapore:20261016T153000\r\nLOCATION:Online meeting\r\n"
    b"ORGANIZER;CN=Jasmine Tan:mailto:jasmine.tan@halcyon-freight.example\r\n"
    b"DESCRIPTION:Join: https://meet.halcyon-freight.example/j/4825519073\r\n"
    b"END:VEVENT\r\nEND:VCALENDAR\r\n"
)


# --------------------------------------------------------------------------- people
P = {
    "priya": ("Priya Raman", f"priya.raman@{ORG}", "Accounts Payable Executive", "+65 6863 2214"),
    "siti": ("Siti Nurhaliza binte Ahmad", f"siti.ahmad@{ORG}", "Finance Assistant", "+65 6863 2219"),
    "daniel": ("Daniel Koh", f"daniel.koh@{ORG}", "Operations Manager", "+65 6863 2101"),
    "marcus": ("Marcus Lim", f"marcus.lim@{ORG}", "Procurement Lead", "+65 6863 2150"),
    "weijie": ("Ong Wei Jie", f"weijie.ong@{ORG}", "Warehouse Lead, Tuas", "+65 9123 4471"),
    "jasmine": ("Jasmine Tan", f"jasmine.tan@{ORG}", "IT Security Analyst", "+65 6863 2300"),
    "rachel": ("Rachel Goh (HR)", f"hr@{ORG}", "Human Resources", "+65 6863 2050"),
    "soc": ("Halcyon Security Operations", f"soc@{ORG}", "IT Security", "+65 6863 2300"),
    "aaron": ("Aaron Chua", "aaron.chua@meridianmarine.example", "Accounts Receivable", "+65 6271 8800"),
}


def first_name(key):
    return "Wei Jie" if key == "weijie" else P[key][0].split()[0]


def addr(key):
    name, email = P[key][0], P[key][1]
    return f"{name} <{email}>"


# --------------------------------------------------------------------------- message model
class Mail:
    def __init__(self, name, mailbox, date, subject, sender, to, scenario, cc=None):
        self.name = name
        self.mailbox = mailbox
        self.date = date  # aware datetime or None
        self.subject = subject
        self.sender = sender
        self.to = to
        self.cc = cc
        self.scenario = scenario
        self.msgid = None
        self.in_reply_to = None
        self.references = []
        self.text_urls, self.html_urls = set(), set()
        self.attachments = []  # (bytes, maintype, subtype, filename)
        self.inline = []  # (bytes, cid, filename)
        self.origin_ip = None
        self.received = []  # newest first
        self.extra_headers = []
        self.text = ""
        self.html = None
        self.quoted_inline = []
        self.raw_subject = None
        self.raw_from = None
        self.text_charset = "utf-8"
        self.embedded = None
        self.drop_close_boundary = False
        self.notes = []

    # URL recording ---------------------------------------------------------
    def t(self, url):
        self.text_urls.add(norm_url(url))
        return url

    def h(self, url):
        self.html_urls.add(norm_url(url))
        return url

    @property
    def urls(self):
        return self.text_urls | self.html_urls

    @property
    def att_hashes(self):
        hashes = {sha(a[0]) for a in self.attachments}
        hashes |= {sha(i[0]) for i in self.inline + self.quoted_inline}
        return hashes

    def quote(self, parent, text=True, html=True, images=True):
        if text:
            self.text_urls |= parent.text_urls
        if html:
            self.html_urls |= parent.html_urls
        if images:
            self.quoted_inline.extend(parent.inline + parent.quoted_inline)


MAILS = {}


def new(name, *args, **kw):
    m = Mail(name, *args, **kw)
    MAILS[name] = m
    return m


def mid_outlook(when):
    return f"<SG2PR06MB{RNG.randint(1000, 9999)}{rand_hex(8).upper()}@SG2PR06MB{RNG.randint(1000, 9999)}.apcprd06.prod.mailhost.example>"


def thread_index():
    return rand_b64(22)


# --------------------------------------------------------------------------- transport
def inbound_external(m, origin_host, origin_ip, helo_host, mailbox_addr, when, auth):
    """Mail from the internet to a Halcyon mailbox. Oldest hop names the origin IP."""
    t = when
    oldest = (
        f"from {helo_host} ({origin_host} [{origin_ip}]) by mx1.{ORG} (Postfix) with ESMTPS id "
        f"{rand_hex(5).upper()}{RNG.randint(10, 99)} for <{mailbox_addr}>; "
        f"{format_datetime((t + timedelta(seconds=2)).astimezone(SGT))}"
    )
    mid = (
        f"from mx1.{ORG} (192.0.2.10) by {MBX} (2603:1096:4:1a2::15) with Microsoft SMTP Server "
        f"(version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.8093.18; "
        f"{format_datetime((t + timedelta(seconds=4)).astimezone(SGT))}"
    )
    top = (
        f"from {MBX} (2603:1096:4:1a2::15) by SG2PR06MB4410.apcprd06.prod.mailhost.example with "
        f"HTTPS; {format_datetime((t + timedelta(seconds=5)).astimezone(SGT))}"
    )
    m.received = [top, mid, oldest]
    m.origin_ip = origin_ip
    m.extra_headers += [
        ("Authentication-Results", f"mx1.{ORG}; {auth}"),
        ("X-MS-Exchange-Organization-AuthAs", "Anonymous"),
    ]


def internal(m, mailbox_addr, when):
    """Exchange-style internal delivery: oldest hop carries an unbracketed IPv6 only."""
    t = when
    m.received = [
        f"from {MBX} (2603:1096:4:1a2::15) by SG2PR06MB4410.apcprd06.prod.mailhost.example with "
        f"HTTPS; {format_datetime((t + timedelta(seconds=2)).astimezone(SGT))}",
        f"from SG2PR06MB7781.apcprd06.prod.mailhost.example (2603:1096:4:2b1::9) by {MBX} "
        f"(2603:1096:4:1a2::15) with Microsoft SMTP Server (version=TLS1_2, "
        f"cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8093.18 via Mailbox Transport; "
        f"{format_datetime((t + timedelta(seconds=1)).astimezone(SGT))}",
    ]
    m.origin_ip = None
    m.extra_headers += [
        ("X-MS-Exchange-Organization-AuthAs", "Internal"),
        ("X-MS-Exchange-Organization-OriginalEnvelopeRecipients", mailbox_addr),
    ]


def dkim(domain, selector="s1"):
    """Return a raw, already-folded DKIM-Signature value (inserted verbatim after serialisation)."""
    b = rand_b64(128)
    chunks = [b[i : i + 70] for i in range(0, len(b), 70)]
    return (
        f"v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n        d={domain}; s={selector};\r\n"
        "        h=from:to:subject:date:message-id:mime-version:content-type;\r\n"
        f"        bh={rand_b64(32)};\r\n        b=" + "\r\n         ".join(chunks)
    )


# --------------------------------------------------------------------------- body helpers
def outlook_sig(m, key, logo=True):
    name, email, title, phone = P[key]
    text = (
        f"\n\nRegards,\n{name.replace(' (HR)', '')}\n{title} | Halcyon Freight Pte Ltd\n"
        f"T {phone} | {m.t(WEBSITE)}\n"
    )
    html = (
        f'<p class="MsoNormal">Regards,<br><b>{name.replace(" (HR)", "")}</b><br>{title} | '
        f'Halcyon Freight Pte Ltd<br>T {phone} | <a href="{m.h(WEBSITE)}">www.halcyon-freight.example</a></p>'
    )
    if logo:
        cid = "image001.png@01DD3E2A.5C9B1F40"
        text = text.replace("Regards,", "Regards,") + f"[cid:{cid}]\n"
        html += f'<p class="MsoNormal"><img width="180" height="48" src="cid:{cid}" alt="Halcyon Freight"></p>'
        m.inline.append((HALCYON_LOGO, cid, "image001.png"))
    return text, html


def meridian_sig(m):
    cid = "image001.png@01DD3C11.7A2E9F80"
    m.inline.append((MERIDIAN_LOGO, cid, "image001.png"))
    text = (
        "\n\nBest regards,\nAaron Chua\nAccounts Receivable | Meridian Marine Supplies Pte Ltd\n"
        f"T +65 6271 8800 | {m.t('https://www.meridianmarine.example')}\n[cid:{cid}]\n"
    )
    html = (
        '<p class="MsoNormal">Best regards,<br><b>Aaron Chua</b><br>Accounts Receivable | Meridian '
        f'Marine Supplies Pte Ltd<br>T +65 6271 8800 | <a href="{m.h("https://www.meridianmarine.example")}">'
        f'www.meridianmarine.example</a></p><p class="MsoNormal"><img width="180" height="48" src="cid:{cid}"></p>'
    )
    return text, html


def wrap_html(inner):
    return (
        '<html xmlns:o="urn:schemas-microsoft-com:office:office"><head><meta http-equiv="Content-Type" '
        'content="text/html; charset=utf-8"><style>p.MsoNormal{margin:0;font-size:11pt;font-family:'
        '"Calibri",sans-serif}</style></head><body lang="EN-SG"><div class="WordSection1">'
        f"{inner}</div></body></html>"
    )


def outlook_quote_header(parent):
    sent = parent.date.astimezone(SGT).strftime("%A, %d %B %Y %I:%M %p") if parent.date else "(not sent)"
    to = parent.to.replace("<", "&lt;").replace(">", "&gt;")
    sender = parent.sender.replace("<", "&lt;").replace(">", "&gt;")
    text = (
        f"\n\n________________________________\nFrom: {parent.sender}\nSent: {sent}\n"
        f"To: {parent.to}\nSubject: {parent.subject}\n\n"
    )
    html = (
        '<div style="border:none;border-top:solid #E1E1E1 1.0pt;padding:3.0pt 0in 0in 0in">'
        f'<p class="MsoNormal"><b>From:</b> {sender}<br><b>Sent:</b> {sent}<br><b>To:</b> {to}<br>'
        f"<b>Subject:</b> {parent.subject}</p></div>"
    )
    return text, html


def outlook_reply(m, parent, body_text, body_html, sig_key, logo=True):
    sig_t, sig_h = outlook_sig(m, sig_key, logo)
    qt, qh = outlook_quote_header(parent)
    m.quote(parent)
    m.text = body_text + sig_t + qt + parent.text
    m.html = wrap_html(body_html + sig_h + qh + _inner(parent.html))


def _inner(html):
    if html is None:
        return ""
    start = html.find('<div class="WordSection1">')
    if start >= 0:
        return html[start + len('<div class="WordSection1">') : html.rfind("</div></body>")]
    return html


# =========================================================================== SCENARIOS
d = lambda *a, tz=SGT: datetime(*a, tzinfo=tz)  # noqa: E731

# ---- Legitimate supplier invoice and payment confirmation ----------------------------
S_LEGIT = "Legitimate supplier invoice thread (real Meridian Marine domain)"
n01 = new(
    "priya-inbox_2026-10-12_invoice-inv-2026-10391.eml", "Priya Raman / Inbox",
    d(2026, 10, 12, 10, 3, 41), "Invoice INV-2026-10391 from Meridian Marine Supplies",
    addr("aaron"), addr("priya"), S_LEGIT,
)
n01.msgid = "<SG2PR04MB8812C1E0A4B7D2F1A9@SG2PR04MB8812.apcprd04.prod.mailhost.example>"
portal = "https://portal.meridianmarine.example/invoices/10391"
sig_t, sig_h = meridian_sig(n01)
n01.text = (
    "Dear Priya,\n\nPlease find attached our tax invoice INV-2026-10391 for PO HF-PO-77310 "
    f"(SGD 6,054.95, due 11 Nov 2026).\n\nYou can also view it on our customer portal: "
    f"{n01.t(portal)}\n\nBank details are unchanged from previous invoices." + sig_t
)
n01.html = wrap_html(
    '<p class="MsoNormal">Dear Priya,</p><p class="MsoNormal">Please find attached our tax invoice '
    "INV-2026-10391 for PO HF-PO-77310 (SGD 6,054.95, due 11 Nov 2026).</p>"
    f'<p class="MsoNormal">You can also view it on our <a href="{n01.h(portal)}">customer portal</a>.</p>'
    '<p class="MsoNormal">Bank details are unchanged from previous invoices.</p>' + sig_h
)
n01.attachments.append((LEGIT_INVOICE_PDF, "application", "pdf", "INV-2026-10391.pdf"))
inbound_external(
    n01, "mail.meridianmarine.example", "203.0.113.20", "mail.meridianmarine.example",
    P["priya"][1], n01.date,
    "spf=pass (sender IP is 203.0.113.20) smtp.mailfrom=meridianmarine.example; "
    "dkim=pass header.d=meridianmarine.example; dmarc=pass action=none header.from=meridianmarine.example",
)
n01.extra_headers += [("DKIM-Signature", dkim("meridianmarine.example")), ("X-Mailer", "Microsoft Outlook 16.0")]

n02 = new(
    "priya-sent_2026-10-12_re-invoice-inv-2026-10391.eml", "Priya Raman / Sent Items",
    d(2026, 10, 12, 10, 26, 5), "RE: Invoice INV-2026-10391 from Meridian Marine Supplies",
    addr("priya"), addr("aaron"), S_LEGIT,
)
n02.msgid = mid_outlook(n02.date)
n02.in_reply_to, n02.references = n01.msgid, [n01.msgid]
outlook_reply(
    n02, n01,
    "Hi Aaron,\n\nThanks - received. This has been approved and is scheduled for our 30 Oct payment run.",
    '<p class="MsoNormal">Hi Aaron,</p><p class="MsoNormal">Thanks - received. This has been approved '
    "and is scheduled for our 30 Oct payment run.</p>",
    "priya",
)
n02.notes.append("Sent Items copy: no Received headers, so no origin IP and no received time.")

# ---- Internal operations thread with spreadsheet ------------------------------------
S_OPS = "Internal Q4 warehouse planning thread (Outlook + iPhone replies)"
sched = "https://intranet.halcyon-freight.example/sites/ops/Shared%20Documents/Q4-2026-Tuas-schedule.xlsx"
t01 = new(
    "weijie-inbox_2026-10-12_q4-shipment-schedule.eml", "Ong Wei Jie / Inbox",
    d(2026, 10, 12, 14, 20, 12), "Q4 shipment schedule - Tuas warehouse",
    addr("daniel"), addr("weijie"), S_OPS, cc=addr("marcus"),
)
t01.msgid = mid_outlook(t01.date)
st, sh = outlook_sig(t01, "daniel", logo=False)
t01.text = (
    "Hi Wei Jie,\n\nAttached is the draft Q4 dock schedule. The live copy is on SharePoint:\n"
    f"{t01.t(sched)}\n\nW43 is tight - we have the two Tsubame reefer consignments landing the same week. "
    "Can you confirm whether D7-D8 can take the overflow?" + st
)
t01.html = wrap_html(
    '<p class="MsoNormal">Hi Wei Jie,</p><p class="MsoNormal">Attached is the draft Q4 dock schedule. '
    f'The live copy is on <a href="{t01.h(sched)}">SharePoint</a>.</p><p class="MsoNormal">W43 is tight - '
    "we have the two Tsubame reefer consignments landing the same week. Can you confirm whether D7-D8 can "
    "take the overflow?</p>" + sh
)
t01.attachments.append(
    (Q4_XLSX, "application", "vnd.openxmlformats-officedocument.spreadsheetml.sheet", "Q4-2026-Tuas-schedule.xlsx")
)
internal(t01, P["weijie"][1], t01.date)
t01.extra_headers += [("Thread-Topic", t01.subject), ("Thread-Index", thread_index()), ("X-MS-Has-Attach", "yes")]

t02 = new(
    "daniel-inbox_2026-10-12_re-q4-shipment-schedule.eml", "Daniel Koh / Inbox",
    d(2026, 10, 12, 14, 47, 55), "Re: Q4 shipment schedule - Tuas warehouse",
    addr("weijie"), addr("daniel"), S_OPS, cc=addr("marcus"),
)
t02.msgid = f"<8C4E2B1A-77D3-4F0E-9A51-{rand_hex(6).upper()}@{ORG}>"
t02.in_reply_to, t02.references = t01.msgid, [t01.msgid]
t02.quote(t01, html=False, images=False)
sent01 = t01.date.astimezone(SGT).strftime("On %d %b %Y, at %I:%M %p")
t02.text = (
    "Yes can. D7-D8 cleared after the racking repair, so overflow ok for W43. Need 2 extra forklift "
    "drivers that week though.\n\nSent from my iPhone\n\n"
    f"> {sent01}, Daniel Koh <{P['daniel'][1]}> wrote:\n>\n"
    + "\n".join("> " + line for line in t01.text.splitlines())
)
internal(t02, P["daniel"][1], t02.date)
t02.extra_headers += [("X-Mailer", "iPhone Mail (22B91)"), ("Content-Language", "en-SG")]
t02.notes.append("iOS plain-text reply; quotes the SharePoint link from the parent's text part.")

t03 = new(
    "daniel-inbox_2026-10-12_re-q4-shipment-schedule-2.eml", "Daniel Koh / Inbox",
    d(2026, 10, 12, 15, 5, 30), "RE: Q4 shipment schedule - Tuas warehouse",
    addr("marcus"), f"{addr('daniel')}, {addr('weijie')}", S_OPS,
)
t03.msgid = mid_outlook(t03.date)
t03.in_reply_to, t03.references = t02.msgid, [t01.msgid, t02.msgid]
t03.quote(t02, html=False, images=False)
st, sh = outlook_sig(t03, "marcus")
qt, qh = outlook_quote_header(t02)
t03.text = (
    "I can get 2 relief drivers from Swift Manpower for W43 - SGD 28/hr, min 8 hrs. Will raise the PO "
    "today if you're both ok." + st + qt + t02.text
)
t03.html = wrap_html(
    '<p class="MsoNormal">I can get 2 relief drivers from Swift Manpower for W43 - SGD 28/hr, min 8 hrs. '
    "Will raise the PO today if you're both ok.</p>" + sh + qh
    + "<pre>" + t02.text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;") + "</pre>"
)
# the quoted iPhone text (containing the SharePoint URL) is rendered inside <pre> in HTML too
t03.html_urls |= t02.text_urls
internal(t03, P["daniel"][1], t03.date)
t03.extra_headers += [("Thread-Topic", "Q4 shipment schedule - Tuas warehouse"), ("Thread-Index", thread_index())]

t04 = new(
    "marcus-inbox_2026-10-12_re-q4-shipment-schedule-3.eml", "Marcus Lim / Inbox",
    d(2026, 10, 12, 15, 31, 2), "RE: Q4 shipment schedule - Tuas warehouse",
    addr("daniel"), f"{addr('marcus')}, {addr('weijie')}", S_OPS,
)
t04.msgid = mid_outlook(t04.date)
t04.in_reply_to, t04.references = t03.msgid, [t01.msgid, t02.msgid, t03.msgid]
outlook_reply(
    t04, t03, "Approved, go ahead with the PO. Thanks both.",
    '<p class="MsoNormal">Approved, go ahead with the PO. Thanks both.</p>', "daniel", logo=False,
)
internal(t04, P["marcus"][1], t04.date)

# ---- Japanese customer thread (ISO-2022-JP, plain text, Thunderbird) -----------------
S_CUST = "Customer thread with Japanese client (ISO-2022-JP, plain-text URL punctuation)"
kenji = "Kenji Watanabe <kenji.watanabe@tsubame-trading.example>"
k01 = new(
    "daniel-inbox_2026-10-13_container-status-hflu4471023.eml", "Daniel Koh / Inbox",
    d(2026, 10, 13, 10, 15, 20, tz=JST), "コンテナ状況の確認 / Container status HFLU4471023",
    kenji, addr("daniel"), S_CUST,
)
k01.msgid = "<3b9f1c2e-5a7d-4e61-b0a4-9c2f8e7d1a55@tsubame-trading.example>"
k01.raw_subject = Header(k01.subject, "iso-2022-jp").encode(linesep="\r\n")
k01.raw_from = Header("渡辺 健二", "iso-2022-jp").encode() + " <kenji.watanabe@tsubame-trading.example>"
k01.text_charset = "iso-2022-jp"
k01.text = (
    "Daniel-san\n\nいつもお世話になっております。\n"
    "Could you please confirm the status of container HFLU4471023 (ex Yokohama, ETA Singapore 12 Oct)?\n"
    "Our customer is asking for the delivery date to Jurong.\n\nよろしくお願いいたします。\n\n"
    "--\n渡辺 健二 / Kenji Watanabe\nTsubame Trading Co., Ltd. | Logistics Dept.\n"
    f"{k01.t('https://www.tsubame-trading.example/')}\n"
)
k01.received = [
    f"from {MBX} (2603:1096:4:1a2::15) by SG2PR06MB4410.apcprd06.prod.mailhost.example with HTTPS; "
    f"{format_datetime((k01.date + timedelta(seconds=9)).astimezone(SGT))}",
    f"from mx1.{ORG} (192.0.2.10) by {MBX} (2603:1096:4:1a2::15) with Microsoft SMTP Server id "
    f"15.20.8093.18; {format_datetime((k01.date + timedelta(seconds=8)).astimezone(SGT))}",
    f"from smtp.tsubame-trading.example (smtp.tsubame-trading.example [203.0.113.150]) by mx1.{ORG} "
    f"(Postfix) with ESMTPS id 4HyB7c2Lm; {format_datetime((k01.date + timedelta(seconds=6)).astimezone(SGT))}",
    f"from [192.168.10.23] (pc23.tsubame-trading.example [203.0.113.151]) by smtp.tsubame-trading.example "
    f"(Postfix) with ESMTPSA id 9A1F02C0; {format_datetime(k01.date + timedelta(seconds=3))}",
]
k01.origin_ip = None  # oldest hop names two IPs (private + public) -> engine records no origin
k01.extra_headers += [
    ("Authentication-Results", f"mx1.{ORG}; spf=pass smtp.mailfrom=tsubame-trading.example; "
     "dkim=pass header.d=tsubame-trading.example; dmarc=pass header.from=tsubame-trading.example"),
    ("User-Agent", "Mozilla Thunderbird"),
    ("Content-Language", "ja"),
]
k01.notes.append("Subject, From and body are ISO-2022-JP; oldest Received names two IPs, so no single origin IP.")

track = "https://track.halcyon-freight.example/c/HFLU4471023"
k02 = new(
    "daniel-sent_2026-10-13_re-container-status-hflu4471023.eml", "Daniel Koh / Sent Items",
    d(2026, 10, 13, 9, 40, 11), "RE: コンテナ状況の確認 / Container status HFLU4471023",
    addr("daniel"), kenji, S_CUST,
)
k02.msgid = mid_outlook(k02.date)
k02.in_reply_to, k02.references = k01.msgid, [k01.msgid]
k02.quote(k01, html=False, images=False)
k02.text_urls.add(norm_url(track) + ".")  # plain-text URL with trailing full stop (kept by design)
k02.text = (
    "Hi Kenji-san,\n\nHFLU4471023 discharged at Pasir Panjang on 12 Oct and cleared customs this morning. "
    "Delivery to Jurong is booked for 15 Oct, 0900-1200.\n\n"
    f"Tracking: {track}.\n\nRegards,\nDaniel Koh\nOperations Manager | Halcyon Freight Pte Ltd\n"
    f"T +65 6863 2101 | {k02.t(WEBSITE)}\n\n-----Original Message-----\nFrom: {k01.sender}\n"
    f"Sent: Tuesday, 13 October 2026 9:15 AM\nTo: {k01.to}\nSubject: {k01.subject}\n\n" + k01.text
)
k02.notes.append(
    "Plain-text only. 'Tracking: <url>.' - the full stop is captured as part of the URL, a documented "
    "limitation; it will NOT match the clean link in other messages."
)

k03 = new(
    "daniel-inbox_2026-10-13_re-container-status-hflu4471023.eml", "Daniel Koh / Inbox",
    d(2026, 10, 13, 11, 2, 45, tz=JST), "Re: RE: コンテナ状況の確認 / Container status HFLU4471023",
    kenji, addr("daniel"), S_CUST,
)
k03.msgid = "<a71e0c94-2f3b-4d88-8e15-6b0d2c9f4e21@tsubame-trading.example>"
k03.in_reply_to, k03.references = k02.msgid, [k01.msgid, k02.msgid]
k03.quote(k02, html=False, images=False)  # text quote keeps the full-stop variant
quoted_k02 = "\n".join("> " + line for line in k02.text.splitlines())
k03.text = (
    "Daniel-san\n\nThank you, 15 Oct morning is fine. I have informed our customer.\n\n"
    f"On 2026/10/13 10:40, Daniel Koh wrote:\n{quoted_k02}\n"
)
esc = lambda s: s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")  # noqa: E731
body_before, body_after = k02.text.split(f"Tracking: {track}.", 1)
k03.html = (
    '<html><head><meta http-equiv="content-type" content="text/html; charset=UTF-8"></head><body>'
    "<p>Daniel-san</p><p>Thank you, 15 Oct morning is fine. I have informed our customer.</p>"
    '<div class="moz-cite-prefix">On 2026/10/13 10:40, Daniel Koh wrote:<br></div>'
    '<blockquote type="cite"><pre class="moz-quote-pre" wrap="">' + esc(body_before)
    + f'Tracking: <a class="moz-txt-link-freetext" href="{k03.h(track)}">{track}</a>.'
    + esc(body_after) + "</pre></blockquote></body></html>"
)
# Thunderbird auto-links the URLs that appear inside the quoted <pre> text too
k03.html_urls.add(norm_url(WEBSITE))
k03.html_urls.add(norm_url("https://www.tsubame-trading.example/"))
k03.received = [
    f"from {MBX} (2603:1096:4:1a2::15) by SG2PR06MB4410.apcprd06.prod.mailhost.example with HTTPS; "
    f"{format_datetime((k03.date + timedelta(seconds=7)).astimezone(SGT))}",
    f"from smtp.tsubame-trading.example (smtp.tsubame-trading.example [203.0.113.150]) by mx1.{ORG} "
    f"(Postfix) with ESMTPS id 4HyD1q8Zp; {format_datetime((k03.date + timedelta(seconds=5)).astimezone(SGT))}",
    f"from [192.168.10.23] (pc23.tsubame-trading.example [203.0.113.151]) by smtp.tsubame-trading.example "
    f"(Postfix) with ESMTPSA id 9A1F7E11; {format_datetime(k03.date + timedelta(seconds=2))}",
]
k03.extra_headers += [("User-Agent", "Mozilla Thunderbird"), ("Content-Language", "en-US")]
k03.notes.append("HTML part auto-links the tracking URL without the full stop; text part keeps it.")

# ---- Industry mailing list (References-only reply, missing parent) -------------------
S_LIST = "Industry mailing list (Mailman): References-only reply and reply to an uncollected message"
LIST = "sg-freight-forum@lists.logisticsforum.example"
footer_url = "https://lists.logisticsforum.example/mailman/listinfo/sg-freight-forum"


def list_mail(m, author_received, body, origin_ip):
    m.text = body + (
        "\n\n_______________________________________________\nSG-Freight mailing list\n"
        f"{LIST}\n{m.t(footer_url)}\n"
    )
    t = m.date
    m.received = [
        f"from {MBX} (2603:1096:4:1a2::15) by SG2PR06MB4410.apcprd06.prod.mailhost.example with HTTPS; "
        f"{format_datetime((t + timedelta(seconds=40)).astimezone(SGT))}",
        f"from lists.logisticsforum.example (lists.logisticsforum.example [198.51.100.90]) by mx1.{ORG} "
        f"(Postfix) with ESMTPS id {rand_hex(4).upper()}; "
        f"{format_datetime((t + timedelta(seconds=38)).astimezone(SGT))}",
        f"from lists.logisticsforum.example (localhost [127.0.0.1]) by lists.logisticsforum.example "
        f"(Postfix) with ESMTP id {rand_hex(4).upper()}; "
        f"{format_datetime((t + timedelta(seconds=30)).astimezone(SGT))}",
        author_received,
    ]
    m.origin_ip = origin_ip
    m.extra_headers += [
        ("List-Id", "Singapore freight forwarders forum <sg-freight-forum.lists.logisticsforum.example>"),
        ("List-Unsubscribe", f"<{footer_url}>, <mailto:sg-freight-forum-request@lists.logisticsforum.example?subject=unsubscribe>"),
        ("List-Post", f"<mailto:{LIST}>"),
        ("Precedence", "list"),
        ("Sender", '"SG-Freight" <sg-freight-forum-bounces@lists.logisticsforum.example>'),
    ]


ravi = "Ravi Shankar <ravi@sgfreightcoop.example>"
m01 = new(
    "marcus-inbox_2026-10-13_sg-freight-tuas-gate3.eml", "Marcus Lim / Inbox",
    d(2026, 10, 13, 8, 5, 0), "[SG-Freight] PSA Tuas Gate 3 congestion this week?", ravi, LIST, S_LIST,
)
m01.msgid = "<20261013000500.GA14420@laptop-rs.sgfreightcoop.example>"
list_mail(
    m01,
    f"from [10.1.4.22] (bb-118.isp.example [203.0.113.88]) by mail.sgfreightcoop.example (Postfix) with "
    f"ESMTPSA id 77C1A2; {format_datetime(d(2026, 10, 13, 8, 5, 6))}",
    "Morning all,\n\nAnyone else seeing 2-3 hr queues at Tuas Gate 3 since Saturday? Our trucks missed two "
    "vessel cut-offs yesterday. Is PSA rerouting through Gate 5?\n\nRavi",
    None,
)
m01.notes.append("Oldest Received from-clause holds two IPs -> no origin IP.")

m02 = new(
    "marcus-inbox_2026-10-13_re-sg-freight-tuas-gate3.eml", "Marcus Lim / Inbox",
    d(2026, 10, 13, 8, 47, 13), "Re: [SG-Freight] PSA Tuas Gate 3 congestion this week?",
    "Chua Mei Ling <meiling@portsidelogistics.example>", LIST, S_LIST,
)
m02.msgid = "<CAF7x2Lq9vR3pE+Hs1kT8wN0mYz5bQd4uJc6aV2nG7oX@mail.portsidelogistics.example>"
m02.references = [m01.msgid]  # no In-Reply-To: engine must fall back to last References id
m02.quote(m01, html=False, images=False)
list_mail(
    m02,
    f"from meiling-xps.portsidelogistics.example ([198.51.100.200]) by mail.portsidelogistics.example "
    f"with ESMTPSA id 1C33F0; {format_datetime(d(2026, 10, 13, 8, 47, 20))}",
    "Same here. PSA notice says Gate 3 lane works until 18 Oct, use Gate 5 for laden export.\n\nMei Ling\n\n"
    "On Tue, 13 Oct 2026 at 08:05, Ravi Shankar wrote:\n" + "\n".join("> " + x for x in m01.text.splitlines()),
    "198.51.100.200",
)
m02.notes.append("References header only (no In-Reply-To) -> reply edge via References fallback.")

m03 = new(
    "marcus-inbox_2026-10-13_re-sg-freight-tuas-gate3-2.eml", "Marcus Lim / Inbox",
    d(2026, 10, 13, 9, 30, 2), "Re: [SG-Freight] PSA Tuas Gate 3 congestion this week?", ravi, LIST, S_LIST,
)
m03.msgid = "<20261013013002.GB14420@laptop-rs.sgfreightcoop.example>"
m03.in_reply_to, m03.references = m02.msgid, [m01.msgid, m02.msgid]
m03.quote(m02, html=False, images=False)
list_mail(
    m03,
    f"from [10.1.4.22] (bb-118.isp.example [203.0.113.88]) by mail.sgfreightcoop.example (Postfix) with "
    f"ESMTPSA id 77D9B0; {format_datetime(d(2026, 10, 13, 9, 30, 8))}",
    "Thanks Mei Ling, switching to Gate 5.\n\n" + "\n".join("> " + x for x in m02.text.splitlines()),
    None,
)

m04 = new(
    "marcus-inbox_2026-10-13_re-sg-freight-reefer-plugs.eml", "Marcus Lim / Inbox",
    d(2026, 10, 13, 10, 12, 44), "Re: [SG-Freight] Reefer plug availability at Pasir Panjang",
    "Hafiz Rahman <hafiz.r@coolchain.example>", LIST, S_LIST,
)
m04.msgid = "<b2c4e6f8-0a1c-4e3b-9d5f-7a9b1c3d5e7f@coolchain.example>"
missing = "<20261009031522.GA2207@laptop-rs.sgfreightcoop.example>"
m04.in_reply_to, m04.references = missing, [missing]
list_mail(
    m04,
    f"from hafiz-pc.coolchain.example ([198.51.100.210]) by smtp.coolchain.example with ESMTPSA id "
    f"5F1A; {format_datetime(d(2026, 10, 13, 10, 12, 50))}",
    "Following up on last week's thread - PPT now has 40 extra plugs at berth 22-24, book via portnet.\n\nHafiz",
    "198.51.100.210",
)
m04.notes.append("Parent message was never collected -> missing_parent diagnostic, no reply edge.")

# ---- Newsletter delivered to three mailboxes (benign bulk mail) ----------------------
S_NEWS = "Vendor newsletter in three mailboxes (benign bulk mail; expected coordination false alarm)"
news_subject = "PortLink Weekly: Singapore box volumes hit Q3 record | Red Sea routing update"
articles = [
    "https://news.portlink-weekly.example/2026/10/singapore-q3-container-record?utm_source=newsletter&utm_medium=email&utm_campaign=wk41",
    "https://news.portlink-weekly.example/2026/10/red-sea-routing-update?utm_source=newsletter&utm_medium=email&utm_campaign=wk41",
    "https://news.portlink-weekly.example/2026/10/tuas-phase-3-cranes?utm_source=newsletter&utm_medium=email&utm_campaign=wk41",
]
for i, (who, mailbox, secs) in enumerate(
    [("priya", "Priya Raman / Inbox", 2), ("daniel", "Daniel Koh / Inbox", 4), ("marcus", "Marcus Lim / Inbox", 58)]
):
    m = new(
        f"{who}-inbox_2026-10-13_portlink-weekly-wk41.eml", mailbox,
        d(2026, 10, 13, 6, 30, secs, tz=UTC), news_subject,
        "PortLink Weekly <news@portlink-weekly.example>", addr(who), S_NEWS,
    )
    m.msgid = f"<0101019287{rand_hex(8)}-{rand_hex(4)}-{rand_hex(4)}-000000@mta12.mailout.example>"
    token = rand_hex(10)
    unsub = f"https://news.portlink-weekly.example/u/{token}"
    pixel = f"https://t.mailout.example/o/{rand_hex(12)}.gif"
    m.text = (
        "PORTLINK WEEKLY - Week 41, 2026\n\n"
        f"1. Singapore box volumes hit Q3 record\n{m.t(articles[0])}\n\n"
        f"2. Red Sea routing: carriers extend Cape diversions to Q1\n{m.t(articles[1])}\n\n"
        f"3. Tuas Phase 3 commissions 12 new quay cranes\n{m.t(articles[2])}\n\n"
        f"You received this because you subscribed with {P[who][1]}.\nUnsubscribe: {m.t(unsub)}\n"
    )
    m.html = (
        '<html><body style="background:#eef2f5"><table width="600" align="center" style="background:#fff;'
        'font-family:Arial"><tr><td style="background:#0a3d62;color:#fff;padding:16px"><h1>PortLink Weekly</h1>'
        "Week 41, 2026</td></tr>"
        + "".join(
            f'<tr><td style="padding:12px"><a href="{m.h(u)}">{title}</a></td></tr>'
            for u, title in zip(
                articles,
                ["Singapore box volumes hit Q3 record", "Red Sea routing update",
                 "Tuas Phase 3 commissions 12 new quay cranes"],
            )
        )
        + f'<tr><td style="font-size:11px;color:#777">You received this because you subscribed with '
        f'{P[who][1]}. <a href="{m.h(unsub)}">Unsubscribe</a></td></tr></table>'
        f'<img src="{m.h(pixel)}" width="1" height="1" alt=""></body></html>'
    )
    inbound_external(
        m, "mta12.mailout.example", "203.0.113.45", "mta12.mailout.example", P[who][1], m.date,
        "spf=pass (sender IP is 203.0.113.45) smtp.mailfrom=bounces.portlink-weekly.example; "
        "dkim=pass header.d=portlink-weekly.example; dmarc=pass header.from=portlink-weekly.example",
    )
    m.extra_headers += [
        ("DKIM-Signature", dkim("portlink-weekly.example", "pl1")),
        ("List-Unsubscribe", f"<{unsub}>"),
        ("List-Unsubscribe-Post", "List-Unsubscribe=One-Click"),
        ("Precedence", "bulk"),
    ]
    m.notes.append("Per-recipient unsubscribe link and tracking pixel; article links are identical.")

# ---- HR announcement: same Message-ID in two mailboxes, then a reply -----------------
S_HR = "All-staff HR notice collected from two mailboxes (duplicate Message-ID) and a reply to it"
hr_mid = "<SG2PR06MB3305E2F9B1A7C4D8E0@SG2PR06MB3305.apcprd06.prod.mailhost.example>"
hr_url = "https://intranet.halcyon-freight.example/hr/policies/travel-expense"
hr_copies = []
for who in ("priya", "siti"):
    m = new(
        f"{who}-inbox_2026-10-13_travel-expense-policy.eml", f"{P[who][0]} / Inbox",
        d(2026, 10, 13, 11, 0, 30), "Updated Travel & Expense Policy - effective 1 November 2026",
        addr("rachel"), f"All Staff <all-staff@{ORG}>", S_HR,
    )
    m.msgid = hr_mid
    st, sh = outlook_sig(m, "rachel")
    m.text = (
        "Dear colleagues,\n\nPlease note the updated Travel & Expense Policy (v4.2) takes effect on 1 November "
        "2026. Key changes: revised per-diem rates for MY/ID/VN and a 30-day claim submission deadline.\n\n"
        f"Full policy: {m.t(hr_url)}\n\nThe PDF is attached for reference." + st
    )
    m.html = wrap_html(
        '<p class="MsoNormal">Dear colleagues,</p><p class="MsoNormal">Please note the updated Travel &amp; '
        "Expense Policy (v4.2) takes effect on <b>1 November 2026</b>. Key changes: revised per-diem rates "
        f'for MY/ID/VN and a 30-day claim submission deadline.</p><p class="MsoNormal"><a href="{m.h(hr_url)}">'
        "Read the full policy on the intranet</a>. The PDF is attached for reference.</p>" + sh
    )
    m.attachments.append((HR_POLICY_PDF, "application", "pdf", "Travel-Expense-Policy-v4.2.pdf"))
    internal(m, P[who][1], m.date)
    m.notes.append("Same Message-ID as the other mailbox copy; bytes differ only in delivery headers.")
    hr_copies.append(m)

hr3 = new(
    "siti-sent_2026-10-13_re-travel-expense-policy.eml", "Siti Nurhaliza binte Ahmad / Sent Items",
    d(2026, 10, 13, 11, 41, 9), "RE: Updated Travel & Expense Policy - effective 1 November 2026",
    addr("siti"), addr("rachel"), S_HR,
)
hr3.msgid = mid_outlook(hr3.date)
hr3.in_reply_to, hr3.references = hr_mid, [hr_mid]
outlook_reply(
    hr3, hr_copies[1],
    "Hi Rachel,\n\nDoes the 30-day deadline apply to claims for trips that started before 1 Nov?",
    '<p class="MsoNormal">Hi Rachel,</p><p class="MsoNormal">Does the 30-day deadline apply to claims for '
    "trips that started before 1 Nov?</p>",
    "siti",
)
hr3.notes.append("In-Reply-To matches two collected messages -> ambiguous_parent, no reply edge.")

# ---- Meeting invite --------------------------------------------------------------------
S_CAL = "Calendar invite (text/calendar body part and .ics attachment)"
meet = "https://meet.halcyon-freight.example/j/4825519073"
cal = new(
    "weijie-inbox_2026-10-13_phishing-awareness-refresher.eml", "Ong Wei Jie / Inbox",
    d(2026, 10, 13, 16, 2, 18), "Phishing awareness refresher (30 min)",
    addr("jasmine"), f"All Staff <all-staff@{ORG}>", S_CAL,
)
cal.msgid = mid_outlook(cal.date)
st, sh = outlook_sig(cal, "jasmine")
cal.text = (
    "Hi all,\n\nA short refresher on spotting invoice and payment-change scams, following recent reports "
    f"across the industry.\n\nFri 16 Oct, 3:00-3:30 PM SGT\nJoin online: {cal.t(meet)}" + st
)
cal.html = wrap_html(
    '<p class="MsoNormal">Hi all,</p><p class="MsoNormal">A short refresher on spotting invoice and '
    "payment-change scams, following recent reports across the industry.</p><p class=\"MsoNormal\">"
    f'Fri 16 Oct, 3:00-3:30 PM SGT<br><a href="{cal.h(meet)}">Join online meeting</a></p>' + sh
)
cal.attachments.append((ICS, "text", "calendar", "invite.ics"))
internal(cal, P["weijie"][1], cal.date)
cal.calendar_alternative = True
cal.notes.append("Unnamed text/calendar alternative is retained but not searched (unsupported_text_part).")

# ---- Routine 14 Oct traffic -------------------------------------------------------------
S_NOISE = "Routine unrelated traffic on incident day"
x01 = new(
    "siti-inbox_2026-10-14_parcel-out-for-delivery.eml", "Siti Nurhaliza binte Ahmad / Inbox",
    d(2026, 10, 14, 8, 15, 33), "Your parcel 7781 4402 1190 is out for delivery",
    "SwiftParcel <notifications@swiftparcel.example>", addr("siti"), S_NOISE,
)
x01.msgid = f"<{rand_hex(16)}@notify.swiftparcel.example>"
trk = "https://swiftparcel.example/track?n=778144021190&lang=en"
x01.text = f"Good news! Parcel 778144021190 is out for delivery today between 10:00 and 14:00.\nTrack: {x01.t(trk)}\n"
x01.html = (
    f'<html><body><p>Good news! Parcel <b>778144021190</b> is out for delivery today between 10:00 and 14:00.</p>'
    f'<p><a href="{x01.h(trk)}">Track your parcel</a></p></body></html>'
)
inbound_external(
    x01, "out-3.swiftparcel.example", "203.0.113.61", "out-3.swiftparcel.example", P["siti"][1], x01.date,
    "spf=pass smtp.mailfrom=swiftparcel.example; dkim=pass header.d=swiftparcel.example; dmarc=pass",
)

x02 = new(
    "daniel-inbox_2026-10-14_it-ticket-20931-resolved.eml", "Daniel Koh / Inbox",
    d(2026, 10, 14, 8, 47, 2), "[HF-IT #20931] VPN token replacement - Resolved",
    f"Halcyon IT Service Desk <servicedesk@{ORG}>", addr("daniel"), S_NOISE,
)
x02.msgid = f"<ticket-20931-{rand_hex(6)}@servicedesk.{ORG}>"
tk = "https://servicedesk.halcyon-freight.example/ticket/20931"
x02.text = (
    f"Your request #20931 (VPN token replacement) has been resolved.\nView ticket: {x02.t(tk)}\n\n"
    "Please do not reply to this automated message.\n"
)
x02.received = [
    f"from {MBX} (2603:1096:4:1a2::15) by SG2PR06MB4410.apcprd06.prod.mailhost.example with HTTPS; "
    f"{format_datetime(x02.date + timedelta(seconds=3))}",
    f"from itsm01.{ORG} ([192.0.2.31]) by {MBX} (2603:1096:4:1a2::15) with Microsoft SMTP Server id "
    f"15.20.8093.18; {format_datetime(x02.date + timedelta(seconds=2))}",
]
x02.origin_ip = "192.0.2.31"
x02.extra_headers += [("Auto-Submitted", "auto-generated")]

x03 = new(
    "daniel-inbox_2026-10-14_forklift-4-maintenance.eml", "Daniel Koh / Inbox",
    d(2026, 10, 14, 9, 20, 41), "Forklift #4 maintenance",
    addr("weijie"), addr("daniel"), S_NOISE,
)
x03.msgid = f"<5D1E9A44-0C2B-4A7F-8E63-{rand_hex(6).upper()}@{ORG}>"
x03.text = (
    "Daniel, forklift #4 hydraulic leak again. Taking it out of service, vendor coming Thu. We are running "
    "on 5 units today.\n\nSent from my iPhone"
)
internal(x03, P["daniel"][1], x03.date)
x03.extra_headers += [("X-Mailer", "iPhone Mail (22B91)")]

x04 = new(
    "marcus-inbox_2026-10-14_quotation-q-55821.eml", "Marcus Lim / Inbox",
    d(2026, 10, 14, 10, 10, 9), "Quotation Q-55821 - pallet wrap & strapping",
    "PackRight Sales <sales@packright.example>", addr("marcus"), S_NOISE,
)
x04.msgid = f"<{rand_hex(12)}.{rand_hex(4)}@packright.example>"
x04.text = (
    "Hi Marcus,\n\nAttached our quotation Q-55821 as discussed. Prices valid 30 days.\n\n"
    f"Thanks,\nJolene\nPackRight Industrial Supplies\n{x04.t('https://www.packright.example/')}\n"
)
x04.attachments.append(
    (QUOTE_XLSX, "application", "vnd.openxmlformats-officedocument.spreadsheetml.sheet", "Q-55821.xlsx")
)
inbound_external(
    x04, "smtp.packright.example", "198.51.100.23", "smtp.packright.example", P["marcus"][1], x04.date,
    "spf=pass smtp.mailfrom=packright.example; dkim=none; dmarc=none",
)

# =========================================================================== THE INCIDENT
S_W1 = "Phishing wave 1: lookalike-supplier invoice lure (attacker-sent)"
S_RESP = "Victim and responder activity around wave 1"
U1 = "https://docs-secure-portal.example/s/8f3KQ2?inv=10482"
PH_SUBJ = "Overdue invoice INV-2026-10482 – action required"
reply_to = "Meridian Accounts <meridian.accounts@securemail-box.example>"


def phish_body(m, url_text, url_html, greeting):
    m.text = (
        f"Dear {greeting},\n\nOur records show invoice INV-2026-10482 (SGD 18,420.60) is now 21 days overdue. "
        "Please review the attached invoice and arrange payment today to avoid suspension of your account.\n\n"
        "Note: our banking details have changed. Updated remittance instructions are in the secure document.\n\n"
        f"View invoice<{m.t(url_text)}>\n\nBest regards,\nAccounts Receivable\nMeridian Marine Supplies Pte Ltd\n"
    )
    m.html = (
        '<html><body style="font-family:Calibri,Arial;font-size:11pt"><p>Dear ' + greeting + ",</p>"
        "<p>Our records show invoice <b>INV-2026-10482</b> (SGD 18,420.60) is now <b>21 days overdue</b>. "
        "Please review the attached invoice and arrange payment today to avoid suspension of your account.</p>"
        '<p style="color:#b00">Note: our banking details have changed. Updated remittance instructions are in '
        "the secure document.</p>"
        f'<p><a href="{m.h(url_html)}" style="background:#006e5a;color:#fff;padding:8px 14px;'
        'text-decoration:none">View invoice</a></p><p>Best regards,<br>Accounts Receivable<br>'
        "Meridian Marine Supplies Pte Ltd</p></body></html>"
    )


wave1 = [
    # name, victim, local time, sender, sender-domain, origin ip, url(text), url(html), filename, auth, subject-encoding
    ("priya", d(2026, 10, 14, 9, 12, 7), "Meridian Marine Supplies <accounts@meridianmarine-billing.example>",
     "meridianmarine-billing.example", "198.51.100.77", U1, U1, "INV-2026-10482.html",
     "spf=pass (sender IP is 198.51.100.77) smtp.mailfrom=meridianmarine-billing.example; dkim=pass "
     "header.d=meridianmarine-billing.example; dmarc=pass action=none header.from=meridianmarine-billing.example",
     "policy"),
    ("siti", d(2026, 10, 14, 9, 14, 51), "Meridian Marine Supplies <accounts@meridianmarine-billing.example>",
     "meridianmarine-billing.example", "198.51.100.77", U1,
     "HTTPS://DOCS-SECURE-PORTAL.EXAMPLE/s/8f3KQ2?inv=10482", "INV-2026-10482.html",
     "spf=pass (sender IP is 198.51.100.77) smtp.mailfrom=meridianmarine-billing.example; dkim=pass "
     "header.d=meridianmarine-billing.example; dmarc=pass action=none header.from=meridianmarine-billing.example",
     "base64"),
    ("marcus", d(2026, 10, 14, 9, 21, 30), "Meridian Marine Supplies <ar@meridian-rnarine.example>",
     "meridian-rnarine.example", "198.51.100.77", U1, U1, "Invoice_10482.html",
     "spf=none smtp.mailfrom=meridian-rnarine.example; dkim=none; dmarc=none header.from=meridian-rnarine.example",
     "policy"),
    ("daniel", d(2026, 10, 14, 9, 36, 2), "Meridian Marine Supplies <invoices@mms-payments.example>",
     "mms-payments.example", "198.51.100.78", U1 + "&r=ZGFuaWVsLmtvaA", U1 + "&r=ZGFuaWVsLmtvaA",
     "INV-2026-10482.html",
     "spf=softfail (sender IP is 198.51.100.78) smtp.mailfrom=mms-payments.example; dkim=none; "
     "dmarc=fail action=quarantine header.from=mms-payments.example", "policy"),
]
W1 = {}
for who, when, sender, sdomain, ip, url_t, url_h, fname, auth, enc in wave1:
    m = new(
        f"{who}-inbox_2026-10-14_overdue-invoice-inv-2026-10482.eml", f"{P[who][0]} / Inbox",
        when.astimezone(UTC), PH_SUBJ, sender, addr(who), S_W1,
    )
    m.msgid = f"<{rand_hex(10)}.{RNG.randint(10000, 99999)}@mail.{sdomain}>"
    phish_body(m, url_t, url_h, first_name(who))
    m.attachments.append((PHISH_HTML, "text", "html", fname))
    inbound_external(m, f"vps-{ip.rsplit('.', 1)[1]}.cloudhost.example", ip, f"mail.{sdomain}", P[who][1], when, auth)
    m.extra_headers += [("Reply-To", reply_to), ("X-Mailer", "PHPMailer 6.9.1 (https://github.example/PHPMailer)")]
    if sdomain == "meridianmarine-billing.example":
        m.extra_headers.append(("DKIM-Signature", dkim(sdomain)))
    if enc == "base64":
        m.raw_subject = Header(PH_SUBJ, "utf-8").encode(linesep="\r\n")
    W1[who] = m
W1["siti"].notes.append("Link host written in upper case; must normalise to the same URL as the other copies.")
W1["marcus"].notes.append("Same attachment bytes under a different filename; second lookalike domain (rn vs m).")
W1["daniel"].notes.append("Personalised link (&r=...) and different sending IP; shares attachment and subject only.")
W1["siti"].notes.append("Subject is base64-encoded UTF-8 (others quoted-printable); decodes identically.")
W1["priya"].notes.append("Lookalike domain passes SPF/DKIM/DMARC - authentication is not legitimacy.")

p05 = new(
    "priya-sent_2026-10-14_re-overdue-invoice-inv-2026-10482.eml", "Priya Raman / Sent Items",
    d(2026, 10, 14, 9, 48, 40), "RE: " + PH_SUBJ, addr("priya"), reply_to, S_RESP,
)
p05.msgid = mid_outlook(p05.date)
p05.in_reply_to, p05.references = W1["priya"].msgid, [W1["priya"].msgid]
outlook_reply(
    p05, W1["priya"],
    "Hi,\n\nI tried to open the invoice but it is asking me to sign in again and then shows an error. "
    "Can you send the invoice as a normal PDF? Also please confirm the new bank details by phone.",
    '<p class="MsoNormal">Hi,</p><p class="MsoNormal">I tried to open the invoice but it is asking me to sign '
    "in again and then shows an error. Can you send the invoice as a normal PDF? Also please confirm the new "
    "bank details by phone.</p>",
    "priya",
)
p05.notes.append("Victim replied to the attacker's Reply-To address (credential entry implied).")

p06 = new(
    "priya-drafts_re-overdue-invoice-inv-2026-10482.eml", "Priya Raman / Drafts",
    None, "RE: " + PH_SUBJ, addr("priya"), reply_to, S_RESP,
)
p06.msgid = mid_outlook(None)
p06.in_reply_to, p06.references = W1["priya"].msgid, [W1["priya"].msgid]
outlook_reply(
    p06, W1["priya"],
    "Hi, I have entered my login twice now but the document still does not",
    '<p class="MsoNormal">Hi, I have entered my login twice now but the document still does not</p>',
    "priya",
)
p06.extra_headers += [("X-Unsent", "1")]
p06.notes.append("Unsent draft: no Date and no Received headers, so no time is known.")

p11 = new(
    "marcus-sent_2026-10-14_automatic-reply-overdue-invoice.eml", "Marcus Lim / Sent Items",
    d(2026, 10, 14, 9, 21, 34), "Automatic reply: " + PH_SUBJ, addr("marcus"),
    "Meridian Marine Supplies <ar@meridian-rnarine.example>", S_RESP,
)
p11.msgid = mid_outlook(p11.date)
p11.in_reply_to, p11.references = W1["marcus"].msgid, [W1["marcus"].msgid]
p11.text = (
    "I am at the Tuas warehouse today with limited access to email. For urgent procurement matters please "
    f"contact procurement@{ORG}.\n"
)
p11.extra_headers += [("Auto-Submitted", "auto-replied"), ("X-Auto-Response-Suppress", "All")]
p11.notes.append("Out-of-office auto-reply to the attacker; 'Automatic reply:' prefix is not stripped.")

p07 = new(
    "soc-inbox_2026-10-14_fw-overdue-invoice-as-attachment.eml", "SOC shared mailbox / Inbox",
    d(2026, 10, 14, 9, 58, 12), "FW: " + PH_SUBJ, addr("daniel"), addr("soc"), S_RESP,
)
p07.msgid = mid_outlook(p07.date)
st, sh = outlook_sig(p07, "daniel", logo=False)
p07.text = (
    "Hi team,\n\nGot this just now - looks like a fake Meridian invoice (sender is mms-payments, not "
    "meridianmarine). Original attached as .eml, I did not open the HTML file." + st
)
p07.html = wrap_html(
    '<p class="MsoNormal">Hi team,</p><p class="MsoNormal">Got this just now - looks like a fake Meridian '
    "invoice (sender is mms-payments, not meridianmarine). Original attached as .eml, I did not open the "
    "HTML file.</p>" + sh
)
p07.embedded = W1["daniel"]
internal(p07, P["soc"][1], p07.date)
p07.notes.append(
    "Forward-as-attachment (message/rfc822): the inner email's URL and HTML attachment are NOT attributed "
    "to this message."
)

p08 = new(
    "jasmine-inbox_2026-10-14_fwd-overdue-invoice-inline.eml", "Jasmine Tan / Inbox",
    d(2026, 10, 14, 10, 7, 55), "Fwd: " + PH_SUBJ, addr("marcus"), addr("jasmine"), S_RESP,
)
p08.msgid = mid_outlook(p08.date)
st, sh = outlook_sig(p08, "marcus")
qt, qh = outlook_quote_header(W1["marcus"])
p08.quote(W1["marcus"])
p08.text = "Jasmine, FYI - is this legit? We don't owe Meridian anything this month." + st + qt + W1["marcus"].text
p08.html = wrap_html(
    '<p class="MsoNormal">Jasmine, FYI - is this legit? We don\'t owe Meridian anything this month.</p>'
    + sh + qh + W1["marcus"].html.split("<body", 1)[1].split(">", 1)[1].rsplit("</body>", 1)[0]
)
p08.attachments.append((PHISH_HTML, "text", "html", "Invoice_10482.html"))
internal(p08, P["jasmine"][1], p08.date)
p08.notes.append("Inline forward: re-attaches the identical HTML file and carries the lure URL.")

p10 = new(
    "marcus-inbox_2026-10-14_re-fwd-overdue-invoice.eml", "Marcus Lim / Inbox",
    d(2026, 10, 14, 10, 40, 18), "RE: Fwd: " + PH_SUBJ, addr("jasmine"), addr("marcus"), S_RESP,
)
p10.msgid = mid_outlook(p10.date)
p10.in_reply_to, p10.references = p08.msgid, [p08.msgid]
outlook_reply(
    p10, p08,
    "Hi Marcus,\n\nNot legit - please delete it and don't open the attachment. I've blocked both sender "
    "domains and the portal URL at the gateway.",
    '<p class="MsoNormal">Hi Marcus,</p><p class="MsoNormal">Not legit - please delete it and don\'t open the '
    "attachment. I've blocked both sender domains and the portal URL at the gateway.</p>",
    "jasmine",
)
internal(p10, P["marcus"][1], p10.date)

p09 = new(
    "siti-inbox_2026-10-14_security-alert-meridian-phishing.eml", "Siti Nurhaliza binte Ahmad / Inbox",
    d(2026, 10, 14, 10, 31, 0), "[SECURITY ALERT] Phishing emails impersonating Meridian Marine Supplies",
    addr("soc"), f"All Staff <all-staff@{ORG}>", S_RESP,
)
p09.msgid = mid_outlook(p09.date)
report = "https://intranet.halcyon-freight.example/security/report-phishing"
st, sh = outlook_sig(p09, "jasmine")
iocs = (
    "Indicators (defanged - do not click):\n"
    "  Sender domains: meridianmarine-billing[.]example, meridian-rnarine[.]example, mms-payments[.]example\n"
    "  Link: hxxps://docs-secure-portal[.]example/s/8f3KQ2\n"
    f"  Attachment: INV-2026-10482.html / Invoice_10482.html, SHA-256 {sha(PHISH_HTML)}\n"
)
p09.text = (
    "All,\n\nSeveral colleagues received emails this morning claiming to be from Meridian Marine Supplies "
    "about an overdue invoice INV-2026-10482. These are phishing. Meridian has confirmed they did not send "
    "them and their bank details have not changed.\n\n" + iocs
    + f"\nIf you clicked the link or entered your password, contact IT Security immediately and report it "
    f"here: {p09.t(report)}" + st
)
p09.html = wrap_html(
    '<p class="MsoNormal">All,</p><p class="MsoNormal">Several colleagues received emails this morning '
    "claiming to be from Meridian Marine Supplies about an overdue invoice INV-2026-10482. These are "
    "phishing.</p><pre>" + iocs + "</pre>"
    f'<p class="MsoNormal">If you clicked the link or entered your password, <a href="{p09.h(report)}">report '
    "it here</a>.</p>" + sh
)
internal(p09, P["siti"][1], p09.date)
p09.notes.append("IOCs are defanged (hxxps, [.]) so they must NOT match the live lure URL.")

# Priya checks with the real supplier
n03 = new(
    "priya-sent_2026-10-14_query-inv-2026-10482.eml", "Priya Raman / Sent Items",
    d(2026, 10, 14, 11, 5, 30), "Query: INV-2026-10482", addr("priya"), addr("aaron"), S_LEGIT,
)
n03.msgid = mid_outlook(n03.date)
st, sh = outlook_sig(n03, "priya")
n03.text = (
    "Hi Aaron,\n\nWe received an overdue notice for INV-2026-10482 (SGD 18,420.60) with new bank details. "
    "Can you confirm whether this is from Meridian?" + st
)
n03.html = wrap_html(
    '<p class="MsoNormal">Hi Aaron,</p><p class="MsoNormal">We received an overdue notice for INV-2026-10482 '
    "(SGD 18,420.60) with new bank details. Can you confirm whether this is from Meridian?</p>" + sh
)

n04 = new(
    "priya-inbox_2026-10-14_re-query-inv-2026-10482.eml", "Priya Raman / Inbox",
    d(2026, 10, 14, 11, 32, 10), "RE: Query: INV-2026-10482", addr("aaron"), addr("priya"), S_LEGIT,
)
n04.msgid = "<SG2PR04MB8812F7A3C9E1B5D204@SG2PR04MB8812.apcprd04.prod.mailhost.example>"
n04.in_reply_to, n04.references = n03.msgid, [n03.msgid]
sig_t, sig_h = meridian_sig(n04)
qt, qh = outlook_quote_header(n03)
n04.quote(n03)
n04.text = (
    "Hi Priya,\n\nThat is NOT from us - INV-2026-10482 does not exist and our bank details have not changed. "
    f"Our only portal is {n04.t('https://portal.meridianmarine.example/')} . We have had two other customers "
    "report the same email." + sig_t + qt + n03.text
)
n04.html = wrap_html(
    '<p class="MsoNormal">Hi Priya,</p><p class="MsoNormal">That is <b>NOT</b> from us - INV-2026-10482 does '
    "not exist and our bank details have not changed. Our only portal is "
    f'<a href="{n04.h("https://portal.meridianmarine.example/")}">portal.meridianmarine.example</a>. We have had '
    "two other customers report the same email.</p>" + sig_h + qh + _inner(n03.html)
)
inbound_external(
    n04, "mail.meridianmarine.example", "203.0.113.20", "mail.meridianmarine.example", P["priya"][1], n04.date,
    "spf=pass smtp.mailfrom=meridianmarine.example; dkim=pass header.d=meridianmarine.example; dmarc=pass",
)
n04.extra_headers += [("DKIM-Signature", dkim("meridianmarine.example")), ("X-Mailer", "Microsoft Outlook 16.0")]
n04.notes.append("Real supplier's Outlook signature logo is the same image as in INV-2026-10391.")

# Unrelated credential phish from the same hosting IP, hours later
S_OTHER = "Separate credential phish from the same hosting IP, hours later"
r01 = new(
    "weijie-inbox_2026-10-14_mailbox-almost-full.eml", "Ong Wei Jie / Inbox",
    d(2026, 10, 14, 13, 15, 44), "Action required: your mailbox is 98% full",
    "Halcyon IT Helpdesk <it-helpdesk@halcyon-freight-support.example>", addr("weijie"), S_OTHER,
)
r01.msgid = f"<{rand_hex(10)}@halcyon-freight-support.example>"
q_url = "https://mailbox-quota.example/verify?u=weijie.ong"
r01.text = (
    "Your mailbox has reached 98% of its quota. Incoming mail will be rejected in 24 hours.\n"
    f"Verify your account to receive 50 GB of free storage: {r01.t(q_url)}\n\nIT Helpdesk\n"
)
r01.html = (
    "<html><body><p>Your mailbox has reached <b>98%</b> of its quota. Incoming mail will be rejected in 24 "
    f'hours.</p><p><a href="{r01.h(q_url)}">Verify account</a> to receive 50 GB of free storage.</p>'
    "<p>IT Helpdesk</p></body></html>"
)
inbound_external(
    r01, "vps-77.cloudhost.example", "198.51.100.77", "mail.halcyon-freight-support.example", P["weijie"][1],
    r01.date, "spf=pass smtp.mailfrom=halcyon-freight-support.example; dkim=none; dmarc=none",
)
r01.notes.append("Same origin IP as wave 1 but 4 hours later; shared IP alone is not a rule match.")

# ---- Wave 2 (next morning) --------------------------------------------------------------
S_W2 = "Phishing wave 2: 'FINAL NOTICE' follow-up with new link (attacker-sent)"
U2 = "https://invoice-view.example/d/QX77?ref=10482"
W2_SUBJ = "RE: Overdue invoice INV-2026-10482 – FINAL NOTICE"
wave2 = [
    ("priya", d(2026, 10, 15, 8, 52, 19), "198.51.100.77", (PHISH_HTML, "text", "html", "INV-2026-10482-FINAL.html")),
    ("siti", d(2026, 10, 15, 8, 55, 3), "198.51.100.77", (PHISH_HTML, "text", "html", "INV-2026-10482-FINAL.html")),
    ("weijie", d(2026, 10, 15, 9, 3, 47), "198.51.100.79", (PHISH_ZIP, "application", "zip", "INV-2026-10482.zip")),
]
W2 = {}
for who, when, ip, att in wave2:
    m = new(
        f"{who}-inbox_2026-10-15_final-notice-inv-2026-10482.eml", f"{P[who][0]} / Inbox",
        when.astimezone(UTC), W2_SUBJ, "Meridian Marine Supplies <accounts@meridianmarine-billing.example>",
        addr(who), S_W2,
    )
    m.msgid = f"<{rand_hex(10)}.{RNG.randint(10000, 99999)}@mail.meridianmarine-billing.example>"
    m.text = (
        f"Dear {first_name(who)},\n\nFINAL NOTICE: invoice INV-2026-10482 remains unpaid. Failure to settle "
        "within 24 hours will result in this matter being referred to our collections agency.\n\n"
        f"Secure invoice: {m.t(U2)}\n\nAccounts Receivable\nMeridian Marine Supplies Pte Ltd\n"
    )
    m.html = (
        f"<html><body><p>Dear {first_name(who)},</p><p><b>FINAL NOTICE:</b> invoice INV-2026-10482 remains "
        "unpaid. Failure to settle within 24 hours will result in this matter being referred to our collections "
        f'agency.</p><p><a href="{m.h(U2)}">Open secure invoice</a></p><p>Accounts Receivable<br>Meridian '
        "Marine Supplies Pte Ltd</p></body></html>"
    )
    m.attachments.append(att)
    inbound_external(
        m, f"vps-{ip.rsplit('.', 1)[1]}.cloudhost.example", ip, "mail.meridianmarine-billing.example",
        P[who][1], when,
        "spf=pass smtp.mailfrom=meridianmarine-billing.example; dkim=pass header.d=meridianmarine-billing.example; "
        "dmarc=pass header.from=meridianmarine-billing.example",
    )
    m.extra_headers += [("Reply-To", reply_to), ("DKIM-Signature", dkim("meridianmarine-billing.example"))]
    W2[who] = m

fake_parent = "<a3f9c1d2e4.55120@mail.meridianmarine-billing.example>"
W2["priya"].in_reply_to, W2["priya"].references = fake_parent, [fake_parent]
W2["priya"].notes.append("Fabricated In-Reply-To pointing at a message that never existed -> missing_parent.")
W2["priya"].notes.append("Fake 'RE:' prefix; normalised subject still differs from wave 1 ('FINAL NOTICE').")
# Date header claims 08:55:03 but the server received it at 08:43 -> date_after_received warning
siti2 = W2["siti"]
siti2.received = [
    r.rsplit(";", 1)[0] + "; " + format_datetime(d(2026, 10, 15, 8, 43, 12 - i)) for i, r in enumerate(siti2.received)
]
siti2.notes.append("Date header is ~12 min later than the server receipt time (forged/skewed clock).")
W2["weijie"].drop_close_boundary = True
W2["weijie"].notes.append("HTML lure inside a ZIP (different hash); final MIME boundary missing (malformed).")


# =========================================================================== BUILD
def serialise(m):
    msg = EmailMessage(policy=policy.SMTP)
    for value in m.received:
        msg["Received"] = value
    for name, value in m.extra_headers:
        if name == "Authentication-Results":
            msg[name] = value
        elif name == "DKIM-Signature":
            msg[name] = "XDKIMPLACEHOLDERX"
    msg["From"] = "XFROMPLACEHOLDERX" if m.raw_from else m.sender
    msg["To"] = m.to
    if m.cc:
        msg["Cc"] = m.cc
    msg["Subject"] = "XSUBJPLACEHOLDERX" if m.raw_subject else m.subject
    if m.date is not None:
        msg["Date"] = format_datetime(m.date)
    msg["Message-ID"] = m.msgid
    if m.in_reply_to:
        msg["In-Reply-To"] = m.in_reply_to
    if m.references:
        msg["References"] = " ".join(m.references)
    for name, value in m.extra_headers:
        if name not in ("Authentication-Results", "DKIM-Signature"):
            msg[name] = value
    msg.set_content(m.text, charset=m.text_charset)
    if m.html is not None:
        msg.add_alternative(m.html, subtype="html")
        html_part = msg.get_body(("html",))
        for data, cid, fname in m.inline + m.quoted_inline:
            html_part.add_related(data, "image", "png", cid=f"<{cid}>", filename=fname, disposition="inline")
    if getattr(m, "calendar_alternative", False):
        if not msg.is_multipart():
            msg.make_alternative()
        cal_part = EmailMessage(policy=policy.SMTP)
        cal_part.set_content(ICS.decode(), subtype="calendar", params={"method": "REQUEST"})
        del cal_part["Content-Disposition"]
        msg.attach(cal_part)
    if m.embedded is not None:
        inner = BytesParserForEmbedded(m.embedded)
        msg.add_attachment(inner, filename=f"{m.embedded.subject}.eml")
    for data, maintype, subtype, fname in m.attachments:
        if maintype == "text":
            msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=fname)
        else:
            msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=fname)
    for i, part in enumerate(msg.walk()):
        if part.is_multipart():
            part.set_boundary(f"_{i:03d}_{rand_hex(14).upper()}_")
    raw = msg.as_bytes()
    if m.raw_subject:
        raw = raw.replace(b"Subject: XSUBJPLACEHOLDERX", b"Subject: " + m.raw_subject.encode("ascii"), 1)
    for name, value in m.extra_headers:
        if name == "DKIM-Signature":
            raw = raw.replace(b"DKIM-Signature: XDKIMPLACEHOLDERX", b"DKIM-Signature: " + value.encode("ascii"), 1)
    if m.raw_from:
        raw = raw.replace(b"From: XFROMPLACEHOLDERX", b"From: " + m.raw_from.encode("ascii"), 1)
    if m.drop_close_boundary:
        outer = msg.get_boundary().encode()
        raw = raw.replace(b"--" + outer + b"--", b"", 1).rstrip() + b"\r\n"
    return raw


def BytesParserForEmbedded(inner_mail):
    from email.parser import BytesParser

    return BytesParser(policy=policy.SMTP).parsebytes(RAW[inner_mail.name])


RAW = {}


def build(output):
    output = Path(output).resolve()
    if output.exists() and any(output.iterdir()):
        raise SystemExit("Output directory must be empty.")
    output.mkdir(parents=True, exist_ok=True)
    # embedded originals must be serialised before their wrappers
    order = sorted(MAILS.values(), key=lambda m: m.embedded is not None)
    for m in order:
        RAW[m.name] = serialise(m)
        (output / m.name).write_bytes(RAW[m.name])
    return output


# =========================================================================== GROUND TRUTH
def ground_truth(output):
    mails = sorted(MAILS.values(), key=lambda m: m.name)
    ids = {}
    for m in mails:
        ids.setdefault(m.msgid, []).append(m.name)
    edges = []
    for child in mails:
        target = child.in_reply_to or (child.references[-1] if child.references else None)
        if target and len(ids.get(target, [])) == 1 and ids[target][0] != child.name:
            edges.append((ids[target][0], child.name))
    parent = {m.name: m.name for m in mails}

    def root(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for a, b in edges:
        parent[root(a)] = root(b)

    att, url, coord = set(), set(), set()
    for a, b in combinations(mails, 2):
        pair = tuple(sorted((a.name, b.name)))
        shared_att = a.att_hashes & b.att_hashes
        shared_url = a.urls & b.urls
        if shared_att:
            att.add(pair)
        if shared_url:
            url.add(pair)
        if a.date is None or b.date is None or root(a.name) == root(b.name):
            continue
        if abs((a.date - b.date).total_seconds()) > WINDOW:
            continue
        cats = sum(
            [
                bool(shared_att),
                bool(shared_url),
                norm_subject(a.subject) is not None and norm_subject(a.subject) == norm_subject(b.subject),
                a.origin_ip is not None and a.origin_ip == b.origin_ip,
            ]
        )
        if cats >= 2:
            coord.add(pair)

    scenarios = {}
    for m in mails:
        scenarios.setdefault(m.scenario, []).append(m.name)
    files = {m.name: sha(RAW[m.name]) for m in mails}
    per_message = {
        m.name: {
            "collected_from": m.mailbox,
            "date": m.date.isoformat() if m.date else None,
            "from": m.sender,
            "subject": m.subject,
            "notes": m.notes,
        }
        for m in mails
    }
    base = {
        "seed": 20261014,
        "start_utc": "2026-10-12T00:00:00+00:00",
        "expected_parameters": {"window_seconds": WINDOW, "minimum_signals": 2, "timestamp_source": "date"},
        "files": files,
        "duplicate_acquisitions": {},
        "scenarios": [{"name": k, "files": v} for k, v in scenarios.items()],
        "messages": per_message,
    }
    rule_truth = dict(
        base,
        schema_version=1,
        tier="realistic-conformance",
        relationships={
            "attachment_reuse": sorted(map(list, att)),
            "url_reuse": sorted(map(list, url)),
            "reply": sorted(map(list, edges)),
            "possible_coordination": sorted(map(list, coord)),
        },
        scope=(
            "Realistic fictional incident. Labels state what each rule SHOULD report from the artifacts that "
            "were deliberately written into each message (rule conformance). Benign matches (newsletters, "
            "signature logos, forwards, victim replies) are positives here because the rule definition covers "
            "them; see the intent variant for the investigative question."
        ),
    )
    campaign = sorted([m.name for m in list(W1.values()) + list(W2.values())])
    intent_truth = dict(
        rule_truth,
        tier="realistic-intent",
        relationships=dict(
            rule_truth["relationships"],
            possible_coordination=sorted(list(p) for p in combinations(campaign, 2)),
        ),
        scope=(
            "Same evidence. possible_coordination labels = pairs of messages that belong to the attacker's "
            "planned distribution (waves 1 and 2), independent of whether the heuristic can see it. Other "
            "rules keep observable labels. Use this to measure how well the coordination heuristic answers "
            "the investigator's real question; misses and false alarms are expected."
        ),
    )
    return rule_truth, intent_truth


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    out = Path(args.output).resolve()
    if out.is_relative_to(Path(__file__).resolve().parent.parent):
        raise SystemExit("Build corpora outside the source repository; evidence files are not committed.")
    conformance, intent = out / "conformance", out / "intent"
    build(conformance)
    rule_truth, intent_truth = ground_truth(conformance)
    (conformance / "ground_truth.json").write_text(json.dumps(rule_truth, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    intent.mkdir(parents=True, exist_ok=True)
    for name, raw in RAW.items():
        (intent / name).write_bytes(raw)
    (intent / "ground_truth.json").write_text(json.dumps(intent_truth, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({
        "messages": len(MAILS),
        "expected_conformance": {k: len(v) for k, v in rule_truth["relationships"].items()},
        "expected_intent_coordination": len(intent_truth["relationships"]["possible_coordination"]),
    }, indent=2))


if __name__ == "__main__":
    main()

"""Build a large, realistic, fully labelled E-TRACE corpus (fictional organisation).

Halcyon Freight Pte Ltd (Singapore), 2-23 October 2026. Ten custodian mailboxes plus a
SOC shared mailbox were collected (Inbox, Sent Items, Deleted Items, Drafts). Ordinary
business mail is mixed with a multi-stage attack:

  P1  7 Oct   credential-phish "file share" wave, throttled over ~2.5 h, two sending IPs
  P2  7 Oct   attacker uses Priya's stolen password: internal Bcc blast from her real
              mailbox (OWA, X-Originating-IP), bounces, reply chain with the attacker
  P3  8-20 Oct supplier thread hijack (BEC) from the supplier's real, compromised mailbox,
              Reply-To / follow-ups on a lookalike domain, bank-change letters, payment
  P4  19 Oct  QR-code "salary adjustment" PDFs, unique per recipient, rotating senders

Realistic confounders: Microsoft-Safe-Links-style URL rewriting for the finance and
procurement pilot group, the same message collected from sender Sent Items and every
recipient Inbox (duplicate Message-IDs), signature logos, newsletters, a legitimate
phishing simulation, payroll notifications, scanners without time zones, ISO-2022-JP,
GB2312 and Malay mail, a London traveller across the BST->GMT change, list mail, NDRs,
out-of-office replies, drafts and a duplicate acquisition.

All domains are .example (RFC 2606); public IPs are RFC 5737 documentation ranges.
Attachments are inert. Ground truth is derived from what each scenario writes into each
message, never from E-TRACE's parser or engine.

    python evaluation/build_complex_corpus.py --output <empty dir outside the repository>
"""

import argparse
import hashlib
import html as htmlmod
import io
import json
import os
import random
import re
import zipfile
from datetime import UTC, datetime, timedelta, timezone
from email import policy
from email.header import Header
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import format_datetime
from itertools import combinations
from pathlib import Path
from urllib.parse import parse_qs, quote, urlsplit, urlunsplit

# Pin library output so rebuilt files are byte-identical: openpyxl writes different
# XML spacing with lxml, and Pillow 12 changed the default PNG compression level.
os.environ.setdefault("OPENPYXL_LXML", "False")

SGT = timezone(timedelta(hours=8))
JST = timezone(timedelta(hours=9))
BST = timezone(timedelta(hours=1))
UTC = UTC
WINDOW = 3600
SEED = 20261007
RNG = random.Random(SEED)
ORG = "halcyon-freight.example"
WEBSITE = "https://www.halcyon-freight.example"
MBX = "SG2PR06MB5123.apcprd06.prod.mailhost.example"
SAFELINKS = "https://apc01.safelinks.mailprotect.example/"


def D(day, hm, tz=SGT, sec=None):
    h, m = map(int, hm.split(":"))
    s = RNG.randint(0, 59) if sec is None else sec
    return datetime(2026, 10, day, h, m, s, tzinfo=tz)


def sha(b):
    return hashlib.sha256(b).hexdigest()


def rhex(n):
    return RNG.randbytes(n).hex()


def norm_url(url):
    p = urlsplit(url)
    host = (p.hostname or "").lower()
    netloc = host + (f":{p.port}" if p.port and (p.scheme.lower(), p.port) not in (("http", 80), ("https", 443)) else "")
    return urlunsplit((p.scheme.lower(), netloc, p.path or "/", p.query, p.fragment))


def norm_subject(s):
    v = re.sub(r"\s+", " ", s).strip()
    while re.match(r"^(?:re|fw|fwd)\s*:", v, re.I):
        v = re.sub(r"^(?:re|fw|fwd)\s*:\s*", "", v, count=1, flags=re.I)
    return v.casefold() or None


SHORTENERS = {}


def destination(url):
    """Investigator view: unwrap Safe Links and resolve known short links."""
    if url.startswith(SAFELINKS):
        url = parse_qs(urlsplit(url).query)["url"][0]
    url = SHORTENERS.get(url, url)
    return norm_url(url)


# =================================================================== attachments
def pdf(title, lines, qr=None):
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4, invariant=1)
    c.setTitle(title)
    y = 800
    c.setFont("Helvetica-Bold", 14)
    c.drawString(60, y, title)
    c.setFont("Helvetica", 10)
    for line in lines:
        y -= 17
        c.drawString(60, y, line)
    if qr:
        from reportlab.graphics import renderPDF
        from reportlab.graphics.barcode.qr import QrCodeWidget
        from reportlab.graphics.shapes import Drawing

        w = QrCodeWidget(qr)
        b = w.getBounds()
        dr = Drawing(160, 160, transform=[160.0 / (b[2] - b[0]), 0, 0, 160.0 / (b[3] - b[1]), 0, 0])
        dr.add(w)
        renderPDF.draw(dr, c, 60, y - 200)
    c.showPage()
    c.save()
    return buf.getvalue()


def fixed_zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files:
            z.writestr(zipfile.ZipInfo(name, date_time=(2026, 10, 1, 9, 0, 0)), data)
    return buf.getvalue()


def xlsx(title, header, rows):
    from openpyxl import Workbook

    wb = Workbook()
    ws = wb.active
    ws.title = title[:31]
    ws.append(header)
    for r in rows:
        ws.append(r)
    buf = io.BytesIO()
    wb.save(buf)
    src = zipfile.ZipFile(io.BytesIO(buf.getvalue()))
    files = []
    for info in src.infolist():
        data = src.read(info.filename)
        if info.filename == "docProps/core.xml":
            data = re.sub(rb"(<dcterms:(?:created|modified)[^>]*>)[^<]*", rb"\g<1>2026-10-01T09:00:00Z", data)
        files.append((info.filename, data))
    return fixed_zip(files)


def png(text, colour):
    from PIL import Image, ImageDraw

    img = Image.new("RGB", (180, 48), colour)
    d = ImageDraw.Draw(img)
    d.rectangle([4, 4, 175, 43], outline=(255, 255, 255), width=2)
    d.text((14, 17), text, fill=(255, 255, 255))
    b = io.BytesIO()
    img.save(b, format="PNG", compress_level=6)
    return b.getvalue()


LOGO = png("HALCYON FREIGHT", (14, 61, 102))
MERIDIAN_LOGO = png("MERIDIAN MARINE", (0, 110, 90))
XLSX_CT = ("application", "vnd.openxmlformats-officedocument.spreadsheetml.sheet")


def doc(title, *lines):
    return (pdf(title, list(lines)), "application", "pdf")


def sheet(title, header, rows):
    return (xlsx(title, header, rows),) + XLSX_CT


# =================================================================== people
# key: name, email, title, phone, logo-in-signature, custodian, safe-links pilot
STAFF = {
    "priya": ("Priya Raman", "priya.raman", "Accounts Payable Executive", "+65 6863 2214", True, True, True),
    "siti": ("Siti Nurhaliza binte Ahmad", "siti.ahmad", "Finance Assistant", "+65 6863 2219", True, True, True),
    "benjamin": ("Benjamin Ng", "benjamin.ng", "Finance Manager", "+65 6863 2201", True, True, True),
    "aisyah": ("Nur Aisyah Rahim", "aisyah.rahim", "Accounts Executive", "+65 6863 2216", False, True, True),
    "marcus": ("Marcus Lim", "marcus.lim", "Procurement Lead", "+65 6863 2150", True, True, True),
    "chloe": ("Chloe Lee", "chloe.lee", "Procurement Executive", "+65 6863 2152", True, True, True),
    "daniel": ("Daniel Koh", "daniel.koh", "Operations Manager", "+65 6863 2101", False, True, False),
    "grace": ("Grace Lim", "grace.lim", "Senior Account Manager", "+65 6863 2120", True, True, False),
    "michael": ("Michael Tan", "michael.tan", "Managing Director", "+65 6863 2000", True, True, False),
    "jasmine": ("Jasmine Tan", "jasmine.tan", "IT Security Analyst", "+65 6863 2300", True, True, False),
    "soc": ("Halcyon Security Operations", "soc", "IT Security", "+65 6863 2300", True, True, False),
    "weijie": ("Ong Wei Jie", "weijie.ong", "Warehouse Lead, Tuas", "+65 9123 4471", False, False, False),
    "hafiz": ("Hafiz Ismail", "hafiz.ismail", "Reefer Coordinator", "+65 6863 2133", False, False, False),
    "arun": ("Arun Kumar", "arun.kumar", "Customs Executive", "+65 6863 2140", False, False, False),
    "ryan": ("Ryan Teo", "ryan.teo", "IT Support Engineer", "+65 6863 2310", False, False, False),
    "rachel": ("Rachel Goh", "rachel.goh", "HR Manager", "+65 6863 2050", True, False, False),
    "jonathan": ("Jonathan Seah", "jonathan.seah", "Business Development Director", "+65 6863 2125", False, False, False),
    "fatimah": ("Fatimah Yusof", "fatimah.yusof", "Office Administrator", "+65 6863 2010", True, False, False),
}
FIRST = {"weijie": "Wei Jie", "siti": "Siti", "aisyah": "Aisyah"}
EXT = {
    "aaron": ("Aaron Chua", "aaron.chua@meridianmarine.example"),
    "aaron_fake": ("Aaron Chua", "aaron.chua@meridian-rnarine.example"),
    "kenji": ("Kenji Watanabe", "kenji.watanabe@tsubame-trading.example"),
    "liwei": ("Zhang Liwei", "zhang.liwei@shenzhen-rackworks.example"),
    "azman": ("Azman Hashim", "azman@jbhaulage.example"),
    "jolene": ("Jolene Ho", "sales@packright.example"),
    "kestrel": ("Kestrel Shipping Accounts", "accounts@kestrelshipping.example"),
}


def first(k):
    return FIRST.get(k, STAFF[k][0].split()[0])


def email_of(k):
    return f"{STAFF[k][1]}@{ORG}" if k in STAFF else EXT[k][1]


def name_of(k):
    return STAFF[k][0] if k in STAFF else EXT[k][0]


def disp(k):
    return f"{name_of(k)} <{email_of(k)}>"


def custodian(k):
    return k in STAFF and STAFF[k][5]


def pilot(k):
    return k in STAFF and STAFF[k][6]


# =================================================================== rendering context
class Ctx:
    """Renders one copy of a message; records exactly which URLs/images it writes."""

    def __init__(self, rewrite, owner, msgid):
        self.rewrite, self.owner, self.msgid = rewrite, owner, msgid
        self.urls, self.dests, self.inline = set(), set(), []

    def _final(self, url):
        if self.rewrite and not url.startswith(SAFELINKS):
            h = hashlib.sha256(f"{self.owner}{self.msgid}{url}".encode()).hexdigest()
            data = f"05|02|{email_of(self.owner)}|{h[:32]}|{h[32:48]}|0|0|6386{int(h[48:56], 16) % 10**8:08d}"
            return (
                f"{SAFELINKS}?url={quote(url, safe='')}&data={quote(data, safe='')}"
                f"&sdata={quote(h[:43], safe='')}%3D&reserved=0"
            )
        return url

    def _rec(self, raw, dest_from):
        self.urls.add(norm_url(raw))
        self.dests.add(destination(dest_from))

    def u(self, url, trail=""):
        """Plain-text URL; trailing punctuation (if any) is part of the token by design."""
        final = self._final(url)
        self._rec(final + trail, final)
        return final + trail

    def ut(self, url, label):
        """Outlook plain-text rendering of a hyperlink: label<url>."""
        return f"{label}<{self.u(url)}>"

    def a(self, url, label=None):
        """HTML anchor. Safe Links rewrites href only; a visible URL label stays original."""
        final = self._final(url)
        self._rec(final, final)
        if label is None:
            label = url
            self._rec(url, url)
        return f'<a href="{htmlmod.escape(final)}">{htmlmod.escape(label)}</a>'

    def img(self, url):
        final = self._final(url)
        self._rec(final, final)
        return f'<img src="{htmlmod.escape(final)}" width="1" height="1" alt="">'

    def sub(self, rewrite):
        c = Ctx(self.rewrite or rewrite, self.owner, self.msgid)
        c.urls, c.dests, c.inline = self.urls, self.dests, self.inline
        return c


LINK = re.compile(r"\[\[(\S+?)(?:\|([^\]]+))?\]\]")


def render_markup(ctx, src):
    """[[url|label]] -> hyperlink, [[url]] -> visible URL. Returns (text, html)."""
    parts_t, parts_h, pos = [], [], 0
    for m in LINK.finditer(src):
        before = src[pos : m.start()]
        parts_t.append(before)
        parts_h.append(htmlmod.escape(before))
        url, label = m.group(1), m.group(2)
        if label:
            parts_t.append(ctx.ut(url, label))
            parts_h.append(ctx.a(url, label))
        else:
            parts_t.append(ctx.u(url))
            parts_h.append(ctx.a(url))
        pos = m.end()
    parts_t.append(src[pos:])
    parts_h.append(htmlmod.escape(src[pos:]))
    text = "".join(parts_t)
    html = "".join(f'<p class="MsoNormal">{p.replace(chr(10), "<br>")}</p>' for p in "".join(parts_h).split("\n\n"))
    return text, html


def render_plain(ctx, src):
    """Plain-text only: links become visible URLs."""
    out, pos = [], 0
    for m in LINK.finditer(src):
        out.append(src[pos : m.start()])
        out.append((m.group(2) + " " if m.group(2) else "") + ctx.u(m.group(1)))
        pos = m.end()
    out.append(src[pos:])
    return "".join(out)


def signature(ctx, k, style):
    if k not in STAFF:
        return "", ""
    name, _, title, phone, logo = STAFF[k][:5]
    if style == "iphone":
        return "\n\nSent from my iPhone", ""
    if style == "plain":
        return f"\n\nRegards,\n{name}\n{title} | Halcyon Freight Pte Ltd\nT {phone} | {ctx.u(WEBSITE)}", ""
    t = f"\n\nRegards,\n{name}\n{title} | Halcyon Freight Pte Ltd\nT {phone} | {ctx.u(WEBSITE)}"
    h = (
        f'<p class="MsoNormal">Regards,<br><b>{htmlmod.escape(name)}</b><br>{title} | Halcyon Freight Pte Ltd'
        f'<br>T {phone} | {ctx.a(WEBSITE, "www.halcyon-freight.example")}</p>'
    )
    if logo:
        cid = "image001.png@01DD3E2A.5C9B1F40"
        t += f"\n[cid:{cid}]"
        h += f'<p class="MsoNormal"><img width="180" height="48" src="cid:{cid}" alt="Halcyon Freight"></p>'
        ctx.inline.append((LOGO, cid))
    return t, h


# =================================================================== logical messages
class Msg:
    def __init__(self, **kw):
        self.__dict__.update(kw)


LOGICAL = []
COPIES = []  # serialised files (spec records)
DUPLICATES = {}


def when_text(dt):
    return dt.astimezone(SGT).strftime("%A, %d %B %Y %I:%M %p") if dt else ""


def is_external(m):
    return m.sender not in STAFF and not (m.ext or {}).get("internal_relay")


def view(parent, viewer, ctx):
    """Render `parent` as the viewer saw it, inside ctx (for quoting)."""
    inbound = is_external(parent) and viewer in STAFF
    sub = ctx.sub(inbound and pilot(viewer))
    return parent.render(sub, viewer)


def make(key, sender, to, subject, date, body, cc=(), bcc=(), style=None, quote=None, quote_style=None,
         attachments=(), collect=None, skip=(), ext=None, headers=(), xoip=None, irt=None, refs=None,
         charset="utf-8", raw_subject=None, raw_from=None, raw_date=None, sig=True, html_only=None,
         extra_copies=(), scenario="routine", attacker=False, wave=None):
    """Create a logical message and every collected copy of it."""
    if style is None:
        style = "outlook" if sender in STAFF else "external"
    msgid = None
    if isinstance(key, str) and key.startswith("<"):
        msgid = key
    m = Msg(key=key, sender=sender, to=list(to), cc=list(cc), bcc=list(bcc), subject=subject, date=date,
            body=body, style=style, quote=quote, quote_style=quote_style or style, attachments=list(attachments),
            ext=ext, headers=list(headers), xoip=xoip, charset=charset, raw_subject=raw_subject, raw_from=raw_from,
            raw_date=raw_date, sig=sig, html_only=html_only, scenario=scenario, attacker=attacker, wave=wave)
    if msgid is None:
        if sender in STAFF:
            msgid = f"<SG2PR06MB{RNG.randint(1000, 9999)}{rhex(8).upper()}@SG2PR06MB{RNG.randint(1000, 9999)}.apcprd06.prod.mailhost.example>"
        else:
            domain = (ext or {}).get("domain") or email_of(sender).split("@")[1]
            msgid = f"<{rhex(10)}.{RNG.randint(10000, 99999)}@mail.{domain}>"
    m.msgid = msgid
    if irt is None and quote is not None:
        irt = quote.msgid
        refs = (quote.refs or []) + [quote.msgid] if refs is None else refs
    m.irt, m.refs = irt, (refs or ([irt] if irt else []))

    def render(ctx, viewer):
        st = m.style
        if callable(m.body):
            text, html = m.body(ctx, viewer)
        elif st in ("iphone", "plain"):
            text, html = render_plain(ctx, m.body), None
        else:
            text, html = render_markup(ctx, m.body)
        if m.sig and st != "external":
            sig_t, sig_h = signature(ctx, m.sender, st)
            text += sig_t
            if html is not None:
                html += sig_h
        if m.quote is not None:
            qt, qh = quoted(ctx, m.quote, m.sender, m.quote_style)
            text += qt
            if html is not None:
                html += qh
        return text, html

    m.render = render
    LOGICAL.append(m)
    if collect is None:
        collect = []
        if custodian(sender):
            collect.append((sender, "sent"))
        for r in list(to) + list(cc) + list(bcc):
            if custodian(r) and r != sender and (r, "inbox") not in collect:
                collect.append((r, "inbox"))
    collect = [c for c in collect if c not in skip] + list(extra_copies)
    for owner, folder in collect:
        COPIES.append(build_copy(m, owner, folder))
    return m


def quoted(ctx, parent, replier, style):
    if style not in ("outlook", None):
        # plain-text and mobile quoting carries text only: inline images are not re-embedded
        tmp = ctx.sub(False)
        tmp.inline = []
        pt, ph = view(parent, replier, tmp)
    else:
        pt, ph = view(parent, replier, ctx)
    sender = disp(parent.sender)
    if style == "iphone":
        return (
            f"\n\n> On {parent.date.astimezone(SGT):%d %b %Y}, at {parent.date.astimezone(SGT):%I:%M %p}, "
            f"{sender} wrote:\n>\n" + "\n".join("> " + x for x in pt.splitlines()),
            "",
        )
    if style in ("thunderbird", "gmail", "list", "plain"):
        head = f"On {parent.date.astimezone(SGT):%a, %d %b %Y at %H:%M}, {sender} wrote:" if parent.date else ""
        t = f"\n\n{head}\n" + "\n".join("> " + x for x in pt.splitlines())
        h = f"<div>{htmlmod.escape(head)}</div><blockquote>{ph or '<pre>' + htmlmod.escape(pt) + '</pre>'}</blockquote>"
        return t, h
    to = ", ".join(disp(x) for x in parent.to)
    t = f"\n\n________________________________\nFrom: {sender}\nSent: {when_text(parent.date)}\nTo: {to}\nSubject: {parent.subject}\n\n{pt}"
    h = (
        '<div style="border:none;border-top:solid #E1E1E1 1.0pt;padding:3.0pt 0in 0in 0in"><p class="MsoNormal">'
        f"<b>From:</b> {htmlmod.escape(sender)}<br><b>Sent:</b> {when_text(parent.date)}<br><b>To:</b> "
        f"{htmlmod.escape(to)}<br><b>Subject:</b> {htmlmod.escape(parent.subject)}</p></div>"
        + (ph if ph is not None else "<pre>" + htmlmod.escape(pt) + "</pre>")
    )
    return t, h


# =================================================================== transport
def fd(dt):
    return format_datetime(dt.astimezone(SGT))


def received_chain(m, owner, folder):
    """Return (received headers newest-first, origin_ip per spec, extra headers)."""
    if folder in ("sent", "drafts", "deleted") or m.date is None:
        return [], None, []
    t = m.date
    rcpt = email_of(owner)
    db = 1000 + int(hashlib.sha256(owner.encode()).hexdigest()[:6], 16) % 9000
    top = f"from {MBX} (2603:1096:4:1a2::15) by SG2PR06MB{db}.apcprd06.prod.mailhost.example with HTTPS; {fd(t + timedelta(seconds=6))}"
    if m.sender in STAFF or (m.ext or {}).get("internal_relay"):
        hops = [top, f"from SG2PR06MB7781.apcprd06.prod.mailhost.example (2603:1096:4:2b1::9) by {MBX} "
                f"(2603:1096:4:1a2::15) with Microsoft SMTP Server (version=TLS1_2, "
                f"cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8093.18 via Mailbox Transport; "
                f"{fd(t + timedelta(seconds=4))}"]
        if (m.ext or {}).get("internal_relay"):
            hops.append(m.ext["internal_relay"].format(date=fd(t + timedelta(seconds=2))))
        extra = [("X-MS-Exchange-Organization-AuthAs", "Internal"),
                 ("X-MS-Exchange-Organization-OriginalEnvelopeRecipients", rcpt)]
        origin = None
        if (m.ext or {}).get("internal_relay"):
            origin = m.ext.get("origin")
        if m.xoip:
            extra.append(("X-Originating-IP", f"[{m.xoip}]"))
            origin = m.xoip
        return hops, origin, extra
    e = m.ext
    oldest = (e["oldest"].format(date=fd(t + timedelta(seconds=2))) if e.get("oldest") else None) or (
        f"from {e['helo']} ({e['host']} [{e['ip']}]) by mx1.{ORG} (Postfix) with ESMTPS id "
        f"{rhex(5).upper()} for <{rcpt}>; {fd(t + timedelta(seconds=2))}"
    )
    hops = [top, f"from mx1.{ORG} (192.0.2.10) by {MBX} (2603:1096:4:1a2::15) with Microsoft SMTP Server "
            f"(version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.8093.18; {fd(t + timedelta(seconds=4))}"]
    if e.get("pre"):
        hops.append(oldest)
        hops.extend(h.format(date=fd(t + timedelta(seconds=1))) for h in e["pre"])
        origin = e.get("origin")
    else:
        hops.append(oldest)
        origin = e.get("origin", e.get("ip"))
    extra = [("Authentication-Results", f"mx1.{ORG}; {e.get('auth', 'spf=pass; dkim=none; dmarc=none')}"),
             ("X-MS-Exchange-Organization-AuthAs", "Anonymous"),
             ("X-MS-Exchange-Organization-OriginalEnvelopeRecipients", rcpt)]
    return hops, origin, extra


def dkim_value(domain):
    b = RNG.randbytes(128).hex()
    import base64

    b = base64.b64encode(bytes.fromhex(b)).decode()
    chunks = [b[i : i + 70] for i in range(0, len(b), 70)]
    bh = base64.b64encode(RNG.randbytes(32)).decode()
    return (f"v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n        d={domain}; s=s1;\r\n"
            f"        h=from:to:subject:date:message-id:mime-version:content-type;\r\n        bh={bh};\r\n        b="
            + "\r\n         ".join(chunks))


def slug(s):
    s = re.sub(r"^(?:(?:re|fw|fwd|automatic reply|undeliverable)\s*:\s*)+", "", s, flags=re.I)
    s = re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")
    return s[:48] or "message"


USED = set()


def build_copy(m, owner, folder):
    inbound = is_external(m) and owner in STAFF and folder == "inbox"
    ctx = Ctx(inbound and pilot(owner), owner, m.msgid)
    text, html = m.render(ctx, owner)
    received, origin, extra = received_chain(m, owner, folder)
    stamp = m.date.astimezone(SGT).strftime("%Y-%m-%d_%H%M") if m.date else "undated"
    base = f"{stamp}_{owner}-{folder}_{slug(m.subject)}"
    name, i = base + ".eml", 2
    while name in USED:
        name, i = f"{base}-{i}.eml", i + 1
    USED.add(name)
    hashes = {sha(a[0]) for a in m.attachments if a[1] != "message"} | {sha(img) for img, _ in ctx.inline}
    return Msg(name=name, logical=m, owner=owner, folder=folder, text=text, html=html, inline=list(ctx.inline),
               urls=set(ctx.urls), dests=set(ctx.dests), hashes=hashes, received=received, origin=origin,
               extra=extra, date=m.date)


# =================================================================== serialisation
def serialise(c):
    m = c.logical
    msg = EmailMessage(policy=policy.SMTP)
    for r in c.received:
        msg["Received"] = r
    for k, v in c.extra:
        if k == "Authentication-Results":
            msg[k] = v
    if (m.ext or {}).get("dkim") and c.received:
        msg["DKIM-Signature"] = "XDKIMX"
    msg["From"] = "XFROMX" if m.raw_from else disp(m.sender)
    if m.to:
        msg["To"] = ", ".join(disp(x) for x in m.to)
    if m.cc:
        msg["Cc"] = ", ".join(disp(x) for x in m.cc)
    if m.bcc and c.folder in ("sent", "deleted"):
        msg["Bcc"] = ", ".join(disp(x) if x in STAFF or x in EXT else x for x in m.bcc)
    msg["Subject"] = "XSUBJX" if m.raw_subject else m.subject
    if m.raw_date:
        msg["Date"] = "XDATEX"
    elif m.date is not None:
        msg["Date"] = format_datetime(m.date)
    msg["Message-ID"] = m.msgid
    if m.irt:
        msg["In-Reply-To"] = m.irt
    if m.refs:
        msg["References"] = " ".join(m.refs)
    for k, v in m.headers:
        msg[k] = v
    for k, v in c.extra:
        if k != "Authentication-Results":
            msg[k] = v
    if c.folder == "drafts":
        msg["X-Unsent"] = "1"
    if m.html_only is not None:
        msg.set_content(c.html, subtype="html")
    else:
        msg.set_content(c.text, charset=m.charset)
        if c.html is not None:
            msg.add_alternative(wrap(c.html), subtype="html")
            if c.inline:
                part = msg.get_body(("html",))
                seen = set()
                for i, (img, cid) in enumerate(c.inline):
                    if (sha(img), cid) in seen:
                        continue
                    seen.add((sha(img), cid))
                    part.add_related(img, "image", "png", cid=f"<{cid}>", filename=f"image{i + 1:03d}.png",
                                     disposition="inline")
    for data, maintype, subtype, fname in m.attachments:
        if maintype == "message":
            msg.add_attachment(BytesParser(policy=policy.SMTP).parsebytes(data), filename=fname)
        else:
            msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=fname)
    for i, part in enumerate(msg.walk()):
        if part.is_multipart() and part.get_content_type() != "message/rfc822":
            part.set_boundary(f"_{i:03d}_{rhex(14).upper()}_")
    raw = msg.as_bytes()
    if m.raw_subject:
        raw = raw.replace(b"Subject: XSUBJX", b"Subject: " + m.raw_subject.encode(), 1)
    if m.raw_from:
        raw = raw.replace(b"From: XFROMX", b"From: " + m.raw_from.encode(), 1)
    if m.raw_date:
        raw = raw.replace(b"Date: XDATEX", b"Date: " + m.raw_date.encode(), 1)
    if b"DKIM-Signature: XDKIMX" in raw:
        raw = raw.replace(b"DKIM-Signature: XDKIMX", b"DKIM-Signature: " + dkim_value(m.ext["dkim"]).encode(), 1)
    return raw


def wrap(inner):
    return ('<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"><style>'
            'p.MsoNormal{margin:0;font-size:11pt;font-family:"Calibri",sans-serif}</style></head>'
            f'<body lang="EN-SG"><div class="WordSection1">{inner}</div></body></html>')


# =================================================================== external sender profiles
def ext_profile(ip, host, helo=None, auth="spf=pass; dkim=pass; dmarc=pass", dkim=None, **kw):
    return dict(ip=ip, host=host, helo=helo or host, auth=auth, dkim=dkim, **kw)


MERIDIAN_REAL = ext_profile(
    "203.0.113.21", "aaron-pc.meridianmarine.example", "mail.meridianmarine.example",
    "spf=pass (sender IP is 203.0.113.20) smtp.mailfrom=meridianmarine.example; dkim=pass "
    "header.d=meridianmarine.example; dmarc=pass header.from=meridianmarine.example",
    dkim="meridianmarine.example", domain="meridianmarine.example",
)
MERIDIAN_REAL["oldest"] = None


def meridian_ext(origin_ip, oldest_helo):
    e = dict(MERIDIAN_REAL)
    e["pre"] = [f"from {oldest_helo} ([{origin_ip}]) by mail.meridianmarine.example with ESMTPSA id "
                f"{rhex(4).upper()}; {{date}}"]
    e["oldest"] = (f"from mail.meridianmarine.example (mail.meridianmarine.example [203.0.113.20]) by mx1.{ORG} "
                   f"(Postfix) with ESMTPS id {rhex(5).upper()}; {{date}}")
    e["origin"] = origin_ip
    return e


def fix_oldest(m_ext, t):
    return m_ext


# =========================================================================== CONTENT
def thread(spec):
    """spec: subject, msgs=[(day, 'HH:MM', sender, body, opts)], first message has to/cc in opts."""
    prev, out = None, []
    for day, hm, sender, body, *rest in spec["msgs"]:
        opts = rest[0] if rest else {}
        if prev is None:
            to, cc = opts["to"], opts.get("cc", [])
            subject = spec["subject"]
        else:
            participants = [prev.sender] + prev.to + prev.cc
            to = opts.get("to", [prev.sender] if prev.sender != sender else prev.to)
            cc = opts.get("cc", [p for p in dict.fromkeys(participants) if p != sender and p not in to])
            subject = ("RE: " if opts.get("style", None) != "iphone" else "Re: ") + norm_case(spec["subject"])
        style = opts.get("style")
        prev = make(None, sender, to, subject, D(day, hm), body, cc=cc, style=style,
                    quote=prev, quote_style=style, attachments=opts.get("att", ()), skip=opts.get("skip", ()),
                    xoip=opts.get("xoip"), scenario=spec.get("scenario", "routine internal thread"))
        out.append(prev)
    return out


def norm_case(s):
    return s


def build_content():
    sp = "https://intranet.halcyon-freight.example/sites"
    # ------------------------------------------------------------- routine internal threads
    T = [
        dict(subject="Q4 shipment schedule - Tuas warehouse", msgs=[
            (5, "09:20", "daniel", f"Hi Wei Jie,\n\nAttached is the draft Q4 dock schedule. Live copy: [[{sp}/ops/Shared%20Documents/Q4-2026-Tuas-schedule.xlsx|SharePoint]]\n\nW43 is tight with the two Tsubame reefer consignments. Can D7-D8 take the overflow?",
             {"to": ["weijie"], "cc": ["marcus"], "att": [sheet("Q4 Tuas", ["Week", "Inbound TEU", "Outbound TEU"], [["W41", 312, 288], ["W42", 344, 301], ["W43", 360, 330]]) + ("Q4-2026-Tuas-schedule.xlsx",)]}),
            (5, "09:51", "weijie", "Yes can. D7-D8 cleared after racking repair. Need 2 extra forklift drivers W43.", {"style": "iphone"}),
            (5, "10:14", "marcus", "I can get 2 relief drivers from Swift Manpower, SGD 28/hr min 8 hrs. Raise PO?"),
            (5, "10:40", "daniel", "Approved, go ahead."),
        ]),
        dict(subject="Month-end close - September accruals", msgs=[
            (5, "11:05", "benjamin", "Team,\n\nSeptember close deadline is Thursday 8 Oct. Please post outstanding accruals by Wed noon. Tracker attached.",
             {"to": ["priya", "siti", "aisyah"], "att": [sheet("Sep close", ["Task", "Owner", "Status"], [["AP accruals", "Priya", "Open"], ["Bank rec", "Aisyah", "Open"], ["Intercompany", "Siti", "Open"]]) + ("Sep-2026-close-tracker.xlsx",)]}),
            (5, "11:32", "aisyah", "Noted. Bank rec for DBS operating account has two unmatched items, will clear by tomorrow.", {"style": "plain"}),
            (5, "14:08", "priya", "AP accruals for Meridian, PackRight and Swift Manpower posted. Kestrel credit note still pending from Siti."),
        ]),
        dict(subject="Forklift lease renewal - Tuas", msgs=[
            (6, "09:12", "marcus", "Hi Daniel,\n\nLiftCo has sent the renewal quote for the 6 forklifts (attached). 4% increase vs last year. Do we renew for 3 years or 2?",
             {"to": ["daniel"], "cc": ["benjamin"], "att": [doc("LiftCo renewal quote LC-2026-118", "6 x 2.5T electric forklift", "36-month term SGD 1,840/unit/month", "24-month term SGD 1,960/unit/month") + ("LiftCo-quote-LC-2026-118.pdf",)]}),
            (6, "10:30", "daniel", "3 years. Ask if they will include battery replacement in year 2.", {"style": "plain"}),
            (6, "11:47", "benjamin", "Fine with 3 years if battery is included. Please send final contract for my review before signing."),
            (7, "15:20", "marcus", "LiftCo agreed to include battery replacement. Final contract to follow."),
        ]),
        dict(subject="Team lunch Friday?", msgs=[
            (8, "11:40", "siti", "Hi all, lunch on Friday to celebrate the Sept close? Thinking Tiong Bahru, 12:30.", {"to": ["priya", "aisyah", "fatimah"]}),
            (8, "11:52", "fatimah", "Yes please! I'll book for 6."),
            (8, "12:03", "aisyah", "In!", {"style": "iphone"}),
            (8, "12:10", "priya", "Count me in."),
        ]),
        dict(subject="Laptop refresh - finance team", msgs=[
            (6, "14:15", "ryan", "Hi Benjamin,\n\n4 finance laptops are past warranty. Proposed replacement attached. Can you approve the budget?",
             {"to": ["benjamin"], "cc": ["jasmine"], "att": [doc("Laptop refresh proposal", "4 x ThinkBook 14 G7, 32GB, 1TB", "Total SGD 7,960 incl. 3-yr onsite", "Users: Priya, Siti, Aisyah, Benjamin") + ("Finance-laptop-refresh.pdf",)]}),
            (6, "16:02", "benjamin", "Approved. Please do it after month-end close."),
            (7, "09:10", "jasmine", "Ryan, please also enrol the new devices in the MFA pilot."),
        ]),
        dict(subject="Client visit - Tsubame Trading 21 Oct", msgs=[
            (9, "10:00", "grace", "Michael, Daniel,\n\nKenji-san and his manager will visit on 21 Oct, 10am. Agenda: 2027 rate card, reefer capacity, Jurong delivery SLA. Can you both join?",
             {"to": ["michael", "daniel"]}),
            (9, "10:26", "michael", "Yes. Book the boardroom and lunch.", {"style": "iphone"}),
            (9, "11:05", "daniel", "I'll join from 10:30, have a safety walk at 9."),
        ]),
        dict(subject="Insurance renewal - marine cargo policy", msgs=[
            (12, "09:30", "benjamin", "Michael,\n\nOur marine cargo policy renews 1 Nov. Broker's summary attached - premium up 6%, deductible unchanged.",
             {"to": ["michael"], "cc": ["marcus"], "att": [doc("Marine cargo policy renewal summary", "Insurer: Straits Mutual (fictional)", "Premium SGD 84,300 (+6%)", "Deductible SGD 5,000 per claim") + ("Marine-cargo-renewal-2026.pdf",)]}),
            (12, "13:45", "michael", "Ok to renew. Ask broker for a quote with SGD 10k deductible as well.", {"style": "iphone"}),
            (12, "14:20", "benjamin", "Will do."),
        ]),
        dict(subject="Draft budget FY2027 - operations", msgs=[
            (12, "16:10", "daniel", "Benjamin,\n\nDraft ops budget attached. Main drivers: +2 headcount at Tuas, forklift lease, reefer plugs.",
             {"to": ["benjamin"], "att": [sheet("FY27 ops", ["Line", "FY26", "FY27"], [["Headcount", 1820000, 1964000], ["Leases", 132480, 132480], ["Utilities", 211000, 236000]]) + ("FY2027-ops-budget-draft.xlsx",)], "style": "plain"}),
            (13, "09:40", "benjamin", "Thanks. Utilities +12% looks high, what's the assumption?"),
            (13, "10:22", "daniel", "Reefer plug usage doubled since Aug. Can share meter data.", {"style": "plain"}),
            (13, "11:00", "benjamin", "Ok, please send. Let's review Thursday."),
        ]),
        dict(subject="Vendor onboarding - PackRight", msgs=[
            (13, "14:05", "chloe", "Hi Marcus, Aisyah,\n\nPackRight's vendor registration form and bank letter attached. Please review before I create them in the vendor master.",
             {"to": ["marcus", "aisyah"], "att": [doc("Vendor registration - PackRight Industrial Supplies", "UEN 201912345K (fictional)", "Bank: OCBC (fictional) acct ending 0912", "Contact: Jolene Ho, sales@packright.example") + ("PackRight-vendor-registration.pdf",)]}),
            (13, "14:40", "aisyah", "Bank letter is on letterhead and matches the UEN. Please call-back verify on their published number before activation.", {"style": "plain"}),
            (13, "15:15", "marcus", "Agree. Chloe, log the call-back in the vendor file."),
        ]),
        dict(subject="London trip - logistics summit expenses", msgs=[
            (14, "08:05", "jonathan", "Hi Benjamin,\n\nClaims for the London summit (12-16 Oct) attached. Hotel was over the per-diem cap because of summit pricing - can you approve the exception?",
             {"to": ["benjamin"], "cc": ["rachel"], "style": "plain"}),
            (14, "09:30", "benjamin", "Approved as exception. Please attach the summit's hotel notice."),
        ]),
        dict(subject="Payment run 16 Oct - for approval", scenario="Payment run that includes the hijacked supplier payment", msgs=[
            (15, "10:10", "priya", "Hi Benjamin,\n\nPayment run for 16 Oct attached for approval (14 vendors, SGD 212,486.30). Includes Meridian INV-2026-10391 to the updated bank account.",
             {"to": ["benjamin"], "att": [sheet("Payrun 16 Oct", ["Vendor", "Invoice", "SGD", "Account"], [["Meridian Marine Supplies", "INV-2026-10391", 6054.95, "UOB-xxxx4471 (UPDATED)"], ["PackRight", "PR-55821", 4183.00, "OCBC-xxxx0912"], ["Swift Manpower", "SM-1102", 1792.00, "DBS-xxxx2210"]]) + ("Payrun-2026-10-16.xlsx",)]}),
            (15, "11:42", "benjamin", "Approved. Release today."),
            (15, "11:58", "priya", "Released. Bank ref PR-20261016-01."),
        ]),
        dict(subject="Safety audit - Tuas DC", msgs=[
            (16, "09:00", "daniel", "Wei Jie, Hafiz,\n\nMOM-style internal safety audit next Weds. Checklist attached - please close the racking and reefer-cable items first.",
             {"to": ["weijie", "hafiz"], "cc": ["michael"], "style": "plain", "att": [doc("Tuas DC safety checklist", "1. Racking inspection tags current", "2. Reefer cables off walkways", "3. Forklift pre-use checks logged") + ("Tuas-safety-checklist.pdf",)]}),
            (16, "09:44", "hafiz", "Reefer cables done by Monday.", {"style": "iphone"}),
            (16, "10:15", "michael", "Thanks Daniel. Please share the results with the board.", {"style": "iphone"}),
        ]),
        dict(subject="Credit note request - Kestrel Shipping", msgs=[
            (6, "15:35", "siti", "Priya, Kestrel disputes 2 days of storage on KS-4410. Ok to issue a credit note for SGD 640?", {"to": ["priya"]}),
            (6, "16:12", "priya", "Yes, approved. Reference their email in the CN."),
        ]),
        dict(subject="Board pack - October", msgs=[
            (19, "17:05", "michael", "Benjamin, Grace, Daniel,\n\nBoard meets 28 Oct. Please send your sections by Fri 23 Oct. Template attached.",
             {"to": ["benjamin", "grace", "daniel"], "att": [doc("Board pack template - October 2026", "1. Financial summary", "2. Commercial pipeline", "3. Operations & safety", "4. Risk & incidents") + ("Board-pack-template-Oct26.pdf",)]}),
            (20, "09:15", "grace", "Will do. Pipeline section by Thursday."),
            (20, "09:50", "benjamin", "Note the Meridian payment fraud will need to go under Risk & incidents."),
        ]),
        dict(subject="Warehouse CCTV outage", msgs=[
            (14, "07:50", "ryan", "Jasmine, Daniel - NVR at Tuas went offline 02:10-05:40 last night. Vendor suspects power supply. No signs of tampering.",
             {"to": ["jasmine", "daniel"]}),
            (14, "08:22", "jasmine", "Please keep the NVR logs and the UPS event log for 90 days."),
            (14, "09:03", "daniel", "Noted. Security guard logbook shows nothing unusual.", {"style": "plain"}),
        ]),
        dict(subject="Purchase requisition PR-8832 - pallets", msgs=[
            (9, "14:30", "marcus", "Chloe, please raise PO for 400 heat-treated pallets from PackRight, delivery W43.", {"to": ["chloe"]}),
            (9, "15:02", "chloe", "PO HF-PO-77412 raised and sent."),
        ]),
        dict(subject="Recruitment - Finance Assistant shortlist", msgs=[
            (20, "10:30", "rachel", "Benjamin, 4 shortlisted CVs attached. Interviews proposed 27-28 Oct.", {"to": ["benjamin"],
             "att": [doc("Shortlist - Finance Assistant", "Candidate A - 3 yrs AP", "Candidate B - ACCA part-qualified", "Candidate C - 5 yrs AR/AP", "Candidate D - fresh grad") + ("Finance-Assistant-shortlist.pdf",)]}),
            (20, "11:40", "benjamin", "B and C first please. I'm free 27 Oct afternoon."),
        ]),
        dict(subject="Fuel surcharge November", msgs=[
            (21, "15:05", "grace", "Michael, carriers announced BAF +7% from 1 Nov. Propose passing 5% to customers with 30-day notice.", {"to": ["michael"], "cc": ["benjamin"]}),
            (21, "16:30", "michael", "Agree. Send notice to top 20 accounts first.", {"style": "iphone"}),
        ]),
        dict(subject="MFA rollout - finance pilot", scenario="Post-incident hardening", msgs=[
            (21, "09:10", "jasmine", "Hi all,\n\nFollowing last week's incident, MFA will be enforced for finance and procurement from Monday 26 Oct. Setup guide: [[https://intranet.halcyon-freight.example/it/mfa-setup|MFA setup guide]]",
             {"to": ["benjamin", "priya", "siti", "aisyah", "marcus", "chloe"], "cc": ["ryan"]}),
            (21, "09:35", "priya", "Done, thanks Jasmine."),
            (21, "10:02", "siti", "Mine keeps asking for the number match, is that normal?"),
            (21, "10:20", "jasmine", "Yes - type the 2-digit number shown on screen into the app."),
        ]),
        dict(subject="Shipment delay - Jurong delivery", msgs=[
            (16, "16:40", "daniel", "Grace, the Jurong delivery for Tsubame slips to Monday - haulier truck breakdown. Can you inform Kenji-san?", {"to": ["grace"], "style": "plain"}),
            (16, "16:55", "grace", "Will do, thanks."),
        ]),
        dict(subject="Bank reconciliation Sept - discrepancies", msgs=[
            (7, "10:05", "aisyah", "Priya,\n\nTwo items unmatched on DBS Sept rec: SGD 1,792 (Swift Manpower?) and SGD 255.30 bank charges. Worksheet attached.",
             {"to": ["priya"], "cc": ["benjamin"], "style": "plain", "att": [sheet("Sep rec", ["Date", "Desc", "SGD"], [["2026-09-28", "GIRO SWIFT MANP", -1792], ["2026-09-30", "CHARGES", -255.3]]) + ("DBS-Sep-rec.xlsx",)]}),
            (7, "11:20", "priya", "1,792 is SM-1102, I'll match it. Charges - please post to bank fees."),
            (7, "11:30", "benjamin", "Ok, close it out."),
        ]),
        dict(subject="Year-end D&D venue", msgs=[
            (22, "14:00", "fatimah", "Rachel, Grace - shortlisted 3 venues for the 4 Dec D&D. Grace, any client tables?", {"to": ["rachel", "grace"]}),
            (22, "14:35", "grace", "Two client tables please (Tsubame, Kestrel)."),
            (22, "15:10", "fatimah", "Noted, will hold the Sentosa option."),
        ]),
        dict(subject="Overtime approval W41", msgs=[
            (9, "17:40", "weijie", "Daniel, need OT approval for 6 pax Sat 10 Oct for the Kestrel vessel.", {"to": ["daniel"], "style": "iphone"}),
            (9, "17:58", "daniel", "Approved.", {"style": "iphone"}),
        ]),
        dict(subject="Customs permit query - HFLU4471023", msgs=[
            (12, "10:45", "arun", "Daniel, TradeNet flagged HS code on HFLU4471023. I amended to 8483.40 and resubmitted.", {"to": ["daniel"], "style": "plain"}),
            (12, "11:02", "daniel", "Thanks Arun, let Grace know if delivery date moves.", {"style": "plain"}),
        ]),
    ]
    for spec in T:
        thread(spec)

    # ------------------------------------------------------------- all-staff announcements
    allstaff = [k for k in STAFF if k not in ("soc",)]
    make(None, "rachel", ["fatimah"], "Updated organisation chart - October 2026", D(5, "16:30"),
         "Dear colleagues,\n\nPlease find the updated organisation chart attached, effective today. Welcome to Chloe Lee who joins Procurement.",
         bcc=allstaff, attachments=[doc("Halcyon Freight organisation chart - Oct 2026", "MD: Michael Tan", "Finance: Benjamin Ng", "Operations: Daniel Koh", "Commercial: Grace Lim") + ("Org-chart-Oct-2026.pdf",)],
         scenario="All-staff announcement (Bcc): same Message-ID in every custodian mailbox")
    cal_ics = (b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nMETHOD:REQUEST\r\nBEGIN:VEVENT\r\nUID:040000008200E00074C5B7101A82E0080000000082C3F1@halcyon-freight.example\r\n"
               b"SUMMARY:Town hall - Q3 results\r\nDTSTART;TZID=Asia/Singapore:20261009T160000\r\nDTEND;TZID=Asia/Singapore:20261009T170000\r\n"
               b"DESCRIPTION:Join: https://meet.halcyon-freight.example/j/3310045592\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
    make(None, "fatimah", ["michael"], "Town hall - Q3 results", D(6, "09:05"),
         "Hi all,\n\nQ3 town hall this Friday 4-5pm, Level 3 pantry and online.\n\nJoin online: [[https://meet.halcyon-freight.example/j/3310045592|Join meeting]]",
         bcc=allstaff, attachments=[(cal_ics, "text", "calendar", "invite.ics")], scenario="Calendar invite to all staff")

    # ------------------------------------------------------------- external: newsletters
    subs = ["priya", "daniel", "marcus", "grace", "michael"]
    for day, wk, topics in [(6, 41, ["singapore-q3-container-record", "red-sea-routing-update"]),
                            (13, 42, ["tuas-phase-3-cranes", "bunker-prices-ease"]),
                            (20, 43, ["malacca-strait-congestion", "digital-bill-of-lading-pilot"])]:
        subj = f"PortLink Weekly #{wk}: " + " | ".join(t.replace("-", " ").title() for t in topics)
        arts = [f"https://news.portlink-weekly.example/2026/10/{t}?utm_source=newsletter&utm_medium=email&utm_campaign=wk{wk}" for t in topics]
        ext = ext_profile("203.0.113.45", "mta12.mailout.example", auth="spf=pass smtp.mailfrom=bounces.portlink-weekly.example; dkim=pass header.d=portlink-weekly.example; dmarc=pass", dkim="portlink-weekly.example")
        for i, who in enumerate(subs):
            tok = rhex(8)

            def body(ctx, viewer, arts=arts, topics=topics, tok=tok, wk=wk):
                unsub = f"https://news.portlink-weekly.example/u/{tok}"
                t = f"PORTLINK WEEKLY #{wk}\n\n" + "\n\n".join(f"{x.replace('-', ' ').title()}\n{ctx.u(a)}" for x, a in zip(topics, arts))
                t += f"\n\nUnsubscribe: {ctx.u(unsub)}\n"
                h = ('<table width="600" style="font-family:Arial"><tr><td style="background:#0a3d62;color:#fff"><h1>PortLink Weekly</h1></td></tr>'
                     + "".join(f"<tr><td>{ctx.a(a, x.replace('-', ' ').title())}</td></tr>" for x, a in zip(topics, arts))
                     + f'<tr><td style="font-size:11px">{ctx.a(unsub, "Unsubscribe")}</td></tr></table>'
                     + ctx.img(f"https://t.mailout.example/o/{tok}.gif"))
                return t, h
            make(None, "portlink", [who], subj, D(day, "06:30", tz=SGT, sec=2 + i * 9), body, style="external",
                 ext=ext, sig=False, headers=[("List-Unsubscribe", f"<https://news.portlink-weekly.example/u/{tok}>"), ("Precedence", "bulk")],
                 scenario="Weekly newsletter to five subscribers (Safe Links rewrites only pilot mailboxes)")

    # ------------------------------------------------------------- external: IT service desk notifications
    tickets = [(5, "08:40", "grace", 20871, "Outlook keeps asking for password"), (6, "13:02", "michael", 20889, "Teams camera not detected"),
               (8, "09:55", "chloe", 20902, "New starter - laptop and accounts"), (12, "15:31", "daniel", 20931, "VPN token replacement"),
               (14, "10:12", "siti", 20950, "Shared drive access - Finance\\Payroll"), (19, "11:20", "marcus", 20988, "Printer driver L3"),
               (22, "09:41", "benjamin", 21014, "MFA app on new phone")]
    for day, hm, who, num, what in tickets:
        make(None, "servicedesk", [who], f"[HF-IT #{num}] {what} - Resolved", D(day, hm),
             f"Your request #{num} ({what}) has been resolved.\n\nView ticket: [[https://servicedesk.halcyon-freight.example/ticket/{num}]]\n\nPlease do not reply to this automated message.",
             style="plain", sig=False, ext={"internal_relay": f"from itsm01.{ORG} ([192.0.2.31]) by SG2PR06MB7781.apcprd06.prod.mailhost.example with Microsoft SMTP Server; {{date}}", "origin": "192.0.2.31"},
             headers=[("Auto-Submitted", "auto-generated")], scenario="IT ticketing notifications (internal application server)")

    # ------------------------------------------------------------- external: scanner (no time zone in Date)
    for day, hm, who, pages in [(6, "10:41", "aisyah", 3), (9, "15:12", "siti", 1), (13, "11:27", "aisyah", 5), (20, "16:03", "fatimah", 2)]:
        dt = D(day, hm)
        make(None, "scanner", [who], "Scanned document from HF-L3-MFP", dt,
                 f"Please open the attached document. It was scanned and sent to you using HF-L3-MFP.\n\nNumber of Images: {pages}\nAttachment File Type: PDF\nDevice Name: HF-L3-MFP\nDevice Location: Level 3 copy room",
                 style="plain", sig=False, attachments=[doc(f"Scan {dt:%Y%m%d%H%M%S}", f"{pages} page(s)", f"Scanned for {name_of(who)}") + (f"SCAN_{dt:%Y%m%d%H%M%S}.pdf",)],
                 raw_date=dt.strftime("%a, %d %b %Y %H:%M:%S"),
                 ext={"internal_relay": f"from HF-L3-MFP.{ORG} ([10.20.3.45]) by SG2PR06MB7781.apcprd06.prod.mailhost.example with Microsoft SMTP Server; {{date}}", "origin": "10.20.3.45"},
                 scenario="Scan-to-email without a time zone in the Date header")
    # ------------------------------------------------------------- external: customers and suppliers
    TSUBAME = ext_profile(None, None, oldest=None, auth="spf=pass; dkim=pass header.d=tsubame-trading.example; dmarc=pass", domain="tsubame-trading.example")
    TSUBAME["oldest"] = f"from smtp.tsubame-trading.example (smtp.tsubame-trading.example [203.0.113.150]) by mx1.{ORG} (Postfix) with ESMTPS id 4HyB7c2; {{date}}"
    TSUBAME["pre"] = ["from [192.168.10.23] (pc23.tsubame-trading.example [203.0.113.151]) by smtp.tsubame-trading.example (Postfix) with ESMTPSA id 9A1F02C0; {date}"]
    TSUBAME["origin"] = None
    k1_subj = "コンテナ状況の確認 / Container status HFLU4471023"
    k1 = make("<3b9f1c2e-5a7d-4e61-b0a4-9c2f8e7d1a55@tsubame-trading.example>", "kenji", ["daniel"], k1_subj, D(12, "10:15", tz=JST),
              "Daniel-san\n\nいつもお世話になっております。\nCould you please confirm the status of container HFLU4471023 (ex Yokohama, ETA Singapore 12 Oct)?\n\nよろしくお願いいたします。\n\n--\n渡辺 健二 / Kenji Watanabe\nTsubame Trading Co., Ltd.\n[[https://www.tsubame-trading.example/]]",
              cc=["grace"], style="plain", ext=TSUBAME, charset="iso-2022-jp", headers=[("User-Agent", "Mozilla Thunderbird")],
              raw_subject=Header(k1_subj, "iso-2022-jp").encode(linesep="\r\n"),
              raw_from=Header("渡辺 健二", "iso-2022-jp").encode() + " <kenji.watanabe@tsubame-trading.example>",
              scenario="Japanese customer thread (ISO-2022-JP)")
    k2 = make(None, "daniel", ["kenji"], "RE: " + k1_subj, D(12, "09:40"),
              "Hi Kenji-san,\n\nHFLU4471023 discharged on 12 Oct and cleared customs this morning. Delivery to Jurong booked for 15 Oct, 0900-1200.\n\nTracking: [[https://track.halcyon-freight.example/c/HFLU4471023]].",
              cc=["grace"], style="plain", quote=k1, quote_style="plain", scenario="Japanese customer thread (ISO-2022-JP)")
    make("<a71e0c94-2f3b-4d88-8e15-6b0d2c9f4e21@tsubame-trading.example>", "kenji", ["daniel"], "Re: RE: " + k1_subj, D(12, "11:02", tz=JST),
              "Daniel-san\n\nThank you, 15 Oct morning is fine.", cc=["grace"], style="plain", quote=k2, quote_style="thunderbird", ext=TSUBAME,
              headers=[("User-Agent", "Mozilla Thunderbird")], scenario="Japanese customer thread (ISO-2022-JP)")
    make(None, "grace", ["kenji"], "RE: Delivery delay - HFLU4471023", D(16, "17:20"),
              "Dear Kenji-san,\n\nApologies - the Jurong delivery moves to Monday 19 Oct due to a haulier truck breakdown. We will confirm the time slot on Monday morning.",
              scenario="Japanese customer thread (ISO-2022-JP)")

    SZ = ext_profile("198.51.100.160", "mail.shenzhen-rackworks.example", auth="spf=pass smtp.mailfrom=shenzhen-rackworks.example; dkim=none; dmarc=none", domain="shenzhen-rackworks.example")
    cn_subj = "报价单 / Quotation SRW-Q2610 - selective pallet racking"
    c1 = make(None, "liwei", ["marcus"], cn_subj, D(8, "16:20"),
              "Dear Marcus,\n\n您好！附件是货架报价单，请查收。\nPlease find attached our quotation for 24 bays of selective racking. FOB Shekou, 35 days.\n\n张立伟 Zhang Liwei\nShenzhen Rackworks Co., Ltd.\n[[https://www.shenzhen-rackworks.example/]]",
              cc=["chloe"], style="plain", ext=SZ, charset="gb2312", raw_subject=Header(cn_subj, "gb2312").encode(linesep="\r\n"),
              attachments=[doc("Quotation SRW-Q2610", "24 bays selective racking, 4 levels", "Unit USD 1,120  Total USD 26,880", "FOB Shekou, 35 days, T/T 30/70") + ("SRW-Q2610.pdf",)],
              headers=[("X-Mailer", "Foxmail 7.2.25")], scenario="Chinese supplier thread (GB2312)")
    c2 = make(None, "marcus", ["liwei"], "RE: " + cn_subj, D(9, "09:15"),
              "Hi Liwei,\n\nThanks. Can you quote CIF Singapore and include seismic base plates?", cc=["chloe"], quote=c1, scenario="Chinese supplier thread (GB2312)")
    make(None, "liwei", ["marcus"], "RE: RE: " + cn_subj, D(10, "10:02"),
         "Dear Marcus,\n\n好的。CIF Singapore USD 28,950 incl. base plates. Revised quotation attached.", cc=["chloe"], style="plain", ext=SZ, charset="gb2312",
         quote=c2, quote_style="plain", attachments=[doc("Quotation SRW-Q2610 rev1", "CIF Singapore USD 28,950", "Includes seismic base plates") + ("SRW-Q2610-rev1.pdf",)],
         scenario="Chinese supplier thread (GB2312)")

    JB = ext_profile("198.51.100.180", "mx.jbhaulage.example", auth="spf=pass; dkim=none; dmarc=none", domain="jbhaulage.example")
    j1 = make(None, "azman", ["daniel"], "Jadual penghantaran / Delivery schedule JB-SG minggu 43", D(15, "08:45"),
              "Salam Encik Daniel,\n\nBerikut jadual lori untuk minggu 43. Lori 3 dalam servis pada Rabu, jadi kami guna lori sewa.\nTruck schedule for W43 attached.\n\nTerima kasih,\nAzman\nJB Haulage Sdn Bhd",
              style="plain", ext=JB, attachments=[sheet("W43", ["Hari", "Lori", "Masa"], [["Isnin", "JHB 4471", "06:00"], ["Rabu", "Sewa", "06:30"]]) + ("Jadual-W43.xlsx",)],
              scenario="Malaysian haulier (Malay)")
    make(None, "daniel", ["azman"], "RE: Jadual penghantaran / Delivery schedule JB-SG minggu 43", D(15, "09:30"),
         "Thanks Azman, noted. Please send the rental truck plate number by Tuesday for the gate pass.", style="plain", quote=j1, quote_style="plain",
         scenario="Malaysian haulier (Malay)")

    PR = ext_profile("198.51.100.23", "smtp.packright.example", auth="spf=pass; dkim=none; dmarc=none", domain="packright.example")
    p1 = make(None, "jolene", ["marcus"], "Quotation Q-55821 - pallet wrap & strapping", D(7, "14:10"),
              "Hi Marcus,\n\nAttached our quotation Q-55821 as discussed. Prices valid 30 days.\n\nThanks,\nJolene\nPackRight Industrial Supplies\n[[https://www.packright.example/]]",
              cc=["chloe"], style="plain", ext=PR, attachments=[sheet("Q-55821", ["Item", "Qty", "SGD"], [["Stretch wrap", 120, 2208], ["PET strapping", 40, 1680]]) + ("Q-55821.xlsx",)],
              scenario="Supplier quotation")
    make(None, "chloe", ["jolene"], "RE: Quotation Q-55821 - pallet wrap & strapping", D(7, "15:02"),
         "Hi Jolene,\n\nThanks - PO to follow this week.", cc=["marcus"], quote=p1, scenario="Supplier quotation")

    # ------------------------------------------------------------- mailing list (two subscribed custodians)
    LIST = "sg-freight-forum@lists.logisticsforum.example"
    EXT["list"] = ("SG-Freight", LIST)
    footer = "https://lists.logisticsforum.example/mailman/listinfo/sg-freight-forum"

    def lst(author, origin_pre, origin_ip):
        e = ext_profile("198.51.100.90", "lists.logisticsforum.example", auth="spf=pass; dkim=pass header.d=lists.logisticsforum.example; dmarc=pass")
        e["pre"] = [origin_pre]
        e["origin"] = origin_ip
        return e
    EXT["ravi"] = ("Ravi Shankar", "ravi@sgfreightcoop.example")
    EXT["meiling"] = ("Chua Mei Ling", "meiling@portsidelogistics.example")
    lh = [("List-Id", "Singapore freight forwarders forum <sg-freight-forum.lists.logisticsforum.example>"),
          ("List-Unsubscribe", f"<{footer}>"), ("Precedence", "list")]
    l1 = make("<20261013000500.GA14420@laptop-rs.sgfreightcoop.example>", "ravi", ["list"], "[SG-Freight] PSA Tuas Gate 3 congestion this week?", D(13, "08:05"),
              f"Morning all,\n\nAnyone else seeing 2-3 hr queues at Tuas Gate 3? Our trucks missed two cut-offs.\n\nRavi\n\n_______________________________________________\nSG-Freight mailing list\n[[{footer}]]",
              style="plain", ext=lst("ravi", "from [10.1.4.22] (bb-118.isp.example [203.0.113.88]) by mail.sgfreightcoop.example with ESMTPSA id 77C1; {date}", None),
              headers=lh, collect=[("marcus", "inbox"), ("daniel", "inbox")], scenario="Industry mailing list (two subscribers)")
    l2 = make("<CAF7x2Lq9vR3pE+Hs1kT8wN0mYz5bQd4uJc6aV2nG7oX@mail.portsidelogistics.example>", "meiling", ["list"], "Re: [SG-Freight] PSA Tuas Gate 3 congestion this week?", D(13, "08:47"),
              f"Same here. PSA notice says lane works until 18 Oct; use Gate 5 for laden export.\n\nMei Ling\n\n_______________________________________________\nSG-Freight mailing list\n[[{footer}]]",
              style="plain", quote=l1, quote_style="list", irt=False, refs=[l1.msgid],
              ext=lst("meiling", "from meiling-xps.portsidelogistics.example ([198.51.100.200]) by mail.portsidelogistics.example with ESMTPSA id 1C33; {date}", "198.51.100.200"),
              headers=lh, collect=[("marcus", "inbox"), ("daniel", "inbox")], scenario="Industry mailing list (two subscribers)")
    l2.irt = None

    # ------------------------------------------------------------- legitimate phishing simulation (benign planned distribution)
    EXT["phishdrill"] = ("Account Security", "no-reply@account-security.phishdrill.example")
    PD = ext_profile("203.0.113.70", "send.phishdrill.example", auth="spf=pass smtp.mailfrom=phishdrill.example; dkim=pass header.d=phishdrill.example; dmarc=pass", dkim="phishdrill.example")
    for i, who in enumerate([k for k in STAFF if custodian(k) and k != "soc"]):
        rid = rhex(6)
        make(None, "phishdrill", [who], "Unusual sign-in activity on your account", D(15, "09:00", sec=0) + timedelta(seconds=37 * i),
             f"We detected a sign-in to your account from a new device (Chrome on Windows, Jakarta, ID).\n\nIf this wasn't you, [[https://account-security.phishdrill.example/review?rid={rid}|review recent activity]] immediately.\n\nMicrosoft-style account team",
             ext=PD, headers=[("X-PHISHTEST", "PhishDrill simulation; campaign HF-2026-Q4-01")], sig=False,
             scenario="Authorised phishing simulation by IT (benign planned distribution)")
    EXT["phishdrill"] = ("Account Security", "no-reply@account-security.phishdrill.example")
    # ------------------------------------------------------------- legitimate payroll notification
    PAY = ext_profile("203.0.113.75", "mta.payday-hr.example", auth="spf=pass smtp.mailfrom=payday-hr.example; dkim=pass header.d=payday-hr.example; dmarc=pass", dkim="payday-hr.example")
    for i, who in enumerate([k for k in STAFF if custodian(k) and k != "soc"]):
        make(None, "payday", [who], "Your October 2026 payslip is now available", D(23, "08:00", sec=0) + timedelta(seconds=4 * i),
             f"Hi {first(who)},\n\nYour payslip for October 2026 is ready.\n\n[[https://halcyon.payday-hr.example/payslips/2026-10|View payslip]]\n\nPayDay HR on behalf of Halcyon Freight Pte Ltd",
             ext=PAY, sig=False, scenario="Legitimate monthly payslip notification")


EXT.update({
    "portlink": ("PortLink Weekly", "news@portlink-weekly.example"),
    "servicedesk": ("Halcyon IT Service Desk", f"servicedesk@{ORG}"),
    "scanner": ("HF-L3-MFP", f"scanner@{ORG}"),
    "payday": ("PayDay HR", "noreply@payday-hr.example"),
})


# =========================================================================== THE ATTACK
SHARE_URL = "https://fileshare-docs.example/s/AQx9r2?e=pz7Kd"
BLAST_URL = "https://halcyon-payroll-portal.example/sso/login?ReturnUrl=%2Fprofile%2Fverify"
SHORT = "https://lnkd-short.example/Hf7Qa"
SHORTENERS[SHORT] = BLAST_URL
EXT.update({
    "fileshare": ("Meridian Marine Supplies via FileShare", "no-reply@fileshare-notify.example"),
    "fileshare2": ("Meridian Marine Supplies via FileShare", "share-alerts@fileshare-notice.example"),
    "mailer": ("Mail Delivery System", f"MAILER-DAEMON@{MBX}"),
    "exstaff1": ("Kelvin Ong", f"kelvin.ong@{ORG}"),
    "exstaff2": ("Shirley Wong", f"shirley.wong@{ORG}"),
})
ATTACK = {}


def build_attack():
    # ---------------------------------------------------------------- P3 prelude: genuine supplier thread
    inv_pdf = doc("Meridian Marine Supplies - Tax Invoice INV-2026-10391", "Bill to: Halcyon Freight Pte Ltd", "PO HF-PO-77310", "Total SGD 6,054.95", "Bank: DBS (fictional) account ending 2290 - unchanged") + ("INV-2026-10391.pdf",)

    def meridian_body(text, html_extra=""):
        def body(ctx, viewer):
            ctx.inline.append((MERIDIAN_LOGO, "image001.png@01DD3C11.7A2E9F80"))
            t, h = render_markup(ctx, text)
            t += f"\n\nBest regards,\nAaron Chua\nAccounts Receivable | Meridian Marine Supplies Pte Ltd\n{ctx.u('https://www.meridianmarine.example')}\n[cid:image001.png@01DD3C11.7A2E9F80]"
            h += (f'<p class="MsoNormal">Best regards,<br><b>Aaron Chua</b><br>Accounts Receivable | Meridian Marine Supplies Pte Ltd<br>'
                  f'{ctx.a("https://www.meridianmarine.example", "www.meridianmarine.example")}</p><p><img src="cid:image001.png@01DD3C11.7A2E9F80"></p>' + html_extra)
            return t, h
        return body

    S = "BEC: genuine supplier thread later hijacked from the supplier's compromised mailbox"
    L1 = make("<SG2PR04MB8812C1E0A4B7D2F1A9@SG2PR04MB8812.apcprd04.prod.mailhost.example>", "aaron", ["priya"],
              "Invoice INV-2026-10391 from Meridian Marine Supplies", D(2, "10:03"),
              meridian_body("Dear Priya,\n\nPlease find attached tax invoice INV-2026-10391 for PO HF-PO-77310 (SGD 6,054.95, due 30 Oct).\n\nYou can also view it on our [[https://portal.meridianmarine.example/invoices/10391|customer portal]]."),
              cc=["benjamin"], ext=meridian_ext("203.0.113.21", "AARON-PC.meridianmarine.example"), attachments=[inv_pdf],
              headers=[("X-Mailer", "Microsoft Outlook 16.0")], scenario=S)
    L2 = make(None, "priya", ["aaron"], "RE: Invoice INV-2026-10391 from Meridian Marine Supplies", D(2, "10:26"),
              "Hi Aaron,\n\nThanks - received. Scheduled for our 30 Oct payment run.", cc=["benjamin"], quote=L1, scenario=S)
    L3 = make(None, "benjamin", ["aaron"], "RE: Invoice INV-2026-10391 from Meridian Marine Supplies", D(6, "15:12"),
              "Hi Aaron,\n\nCould you reissue with our PO reference on the invoice face? Our auditors flagged it.", cc=["priya"], quote=L2, scenario=S)
    L4 = make("<SG2PR04MB8812D4F0B6C2A9E731@SG2PR04MB8812.apcprd04.prod.mailhost.example>", "aaron", ["benjamin"],
              "RE: Invoice INV-2026-10391 from Meridian Marine Supplies", D(6, "16:40"),
              meridian_body("Hi Benjamin,\n\nNoted - PO is HF-PO-77310. Reissued invoice attached."), cc=["priya"], quote=L3,
              ext=meridian_ext("203.0.113.21", "AARON-PC.meridianmarine.example"), attachments=[inv_pdf], scenario=S)

    # ---------------------------------------------------------------- P1: credential phish "file share" wave
    S1 = "P1: credential-phish file-share wave (attacker-sent, throttled)"
    p1 = []
    plan = [("priya", "10:02", ".77", "fileshare"), ("siti", "10:09", ".77", "fileshare"), ("benjamin", "10:21", ".77", "fileshare"),
            ("marcus", "10:48", ".77", "fileshare"), ("daniel", "11:17", ".78", "fileshare2"), ("aisyah", "11:55", ".78", "fileshare2"),
            ("grace", "12:31", ".78", "fileshare2"), ("chloe", "12:40", ".78", "fileshare2")]
    for who, hm, ip, sender in plan:
        ipfull = "198.51.100" + ip
        dom = email_of(sender).split("@")[1]
        e = ext_profile(ipfull, f"vps-{ip[1:]}.cloudhost.example", f"mail.{dom}",
                        f"spf=pass (sender IP is {ipfull}) smtp.mailfrom={dom}; dkim=pass header.d={dom}; dmarc=pass header.from={dom}", dkim=dom, domain=dom)

        def body(ctx, viewer):
            t = ("Aaron Chua (aaron.chua@meridianmarine.example) shared a file with you\n\n"
                 '"Statement of Account - Q3 2026.pdf"\n\nThis link will work for anyone with the access code.\n\n'
                 f"Open: {ctx.u(SHARE_URL)}\n\nFileShare - secure document sharing\n")
            h = ('<table style="font-family:Segoe UI;width:520px"><tr><td><p><b>Aaron Chua</b> shared a file with you</p>'
                 '<p style="font-size:16px">&#128196; Statement of Account - Q3 2026.pdf</p>'
                 f'<p>{ctx.a(SHARE_URL, "Open")}</p><p style="color:#888;font-size:11px">FileShare - secure document sharing</p></td></tr></table>'
                 + ctx.img(f"https://fileshare-docs.example/t/{rhex(5)}.png"))
            return t, h
        m = make(None, sender, [who], 'Aaron Chua shared "Statement of Account - Q3 2026" with you', D(7, hm), body, ext=e, sig=False,
                 headers=[("X-Mailer", "PHPMailer 6.9.1")], scenario=S1, attacker=True, wave="P1")
        p1.append(m)
    ATTACK["P1"] = p1
    # reports
    make(None, "daniel", ["soc"], 'FW: Aaron Chua shared "Statement of Account - Q3 2026" with you', D(7, "11:31"),
         "Hi team, this looks suspicious - Meridian never uses FileShare with us. I did not click.", style="plain", quote=p1[4], quote_style="plain",
         scenario="P1 reports to the SOC")
    make(None, "grace", ["soc"], 'Suspicious email - "Statement of Account"', D(7, "12:52"),
         "Reporting the attached - Meridian is not my account but I got it anyway.",
         attachments=[(None, "message", "rfc822", "Statement of Account.eml")], scenario="P1 reports to the SOC", collect=[("soc", "inbox"), ("grace", "sent")])

    # ---------------------------------------------------------------- P2: account takeover, internal blast from Priya's mailbox
    S2 = "P2: internal Bcc blast from Priya's compromised mailbox (attacker-sent via OWA)"
    blast_bcc = ["siti", "benjamin", "aisyah", "marcus", "chloe", "daniel", "grace", "michael", "jasmine", "weijie", "hafiz", "arun", "fatimah", "exstaff1", "exstaff2"]
    blast_body = ("Hi all,\n\nHR is migrating to the new payroll portal this week. Please log in and verify your bank and CPF details by Friday 9 Oct, "
                  f"otherwise October salary may be delayed.\n\n[[{SHORT}|Verify my details]]\n\nThanks!")
    blast = make(None, "priya", ["priya"], "Payroll portal migration - verify your details by Friday", D(7, "16:42", sec=11), blast_body,
                 bcc=blast_bcc, xoip="198.51.100.77", scenario=S2, attacker=True, wave="P2",
                 extra_copies=[("priya", "inbox")], headers=[("X-MS-Exchange-Organization-Network-Message-Id", rhex(16))])
    ATTACK["P2"] = blast
    # Priya's own Inbox copy (sent to self) is also a delivered copy with the OWA X-Originating-IP
    # Deleted Items copy is byte-identical to Sent Items (attacker deleted it) -> duplicate acquisition
    sent_copy = [c for c in COPIES if c.logical is blast and c.folder == "sent"][0]
    DUPLICATES[sent_copy.name.replace("priya-sent", "priya-deleted")] = sent_copy.name
    # NDRs for the two departed staff
    for i, gone in enumerate(["exstaff1", "exstaff2"]):
        def ndr_body(ctx, viewer, gone=gone):
            return (f"Your message to {email_of(gone)} couldn't be delivered.\n\n{email_of(gone).split('@')[0]} wasn't found at {ORG}.\n\n"
                    f"Remote Server returned '550 5.1.10 RESOLVER.ADR.RecipientNotFound; Recipient not found by SMTP address lookup'"), None
        make(None, "mailer", ["priya"], "Undeliverable: Payroll portal migration - verify your details by Friday", D(7, "16:42", sec=14 + i),
             ndr_body, style="external", sig=False, collect=[("priya", "inbox")],
             ext={"internal_relay": f"from {MBX} (2603:1096:4:1a2::15) by SG2PR06MB7781.apcprd06.prod.mailhost.example with mapi; {{date}}", "origin": None},
             attachments=[("DSN", "message", "delivery-status", None), (None, "message", "rfc822", "Payroll portal migration.eml")],
             headers=[("Auto-Submitted", "auto-replied"), ("X-MS-Exchange-Message-Is-Ndr", "")], scenario=S2)
    # victim reply chain
    s_reply = make(None, "siti", ["priya"], "RE: Payroll portal migration - verify your details by Friday", D(7, "16:55"),
                   "Hi Priya, is this from HR? The link looks a bit odd.", quote=blast, scenario=S2)
    a_reply = make(None, "priya", ["siti"], "RE: Payroll portal migration - verify your details by Friday", D(7, "17:03"),
                   "Yes Rachel asked me to circulate. Please do it today, thanks!", quote=s_reply, xoip="198.51.100.77",
                   scenario=S2, attacker=True)
    make(None, "siti", ["priya"], "RE: Payroll portal migration - verify your details by Friday", D(7, "17:20"),
         "Done, thanks.", quote=a_reply, scenario=S2)
    make(None, "michael", ["jasmine"], "FW: Payroll portal migration - verify your details by Friday", D(7, "17:10"),
         "Jasmine - is this legit? I wasn't told about a new payroll portal.", style="iphone", quote=blast, quote_style="iphone", scenario=S2)
    make(None, "marcus", ["priya"], "Automatic reply: Payroll portal migration - verify your details by Friday", D(7, "16:42", sec=40),
         "I am at the Tuas warehouse today with limited access to email.", style="plain", sig=False, irt=blast.msgid, refs=[blast.msgid],
         headers=[("Auto-Submitted", "auto-replied")], scenario=S2)
    # SOC alert
    alert = ("All,\n\nDo NOT open the email 'Payroll portal migration - verify your details by Friday' sent from Priya's account at 16:42. "
             "Her account was compromised and has been locked. HR is not migrating payroll.\n\nIndicators (defanged):\n"
             "  hxxps://lnkd-short[.]example/Hf7Qa -> hxxps://halcyon-payroll-portal[.]example/sso/login\n"
             "  Sign-in IP 198.51.100[.]77\n\nIf you entered your password, change it now and call IT on 6863 2300. "
             "[[https://intranet.halcyon-freight.example/security/report-phishing|Report phishing]]")
    make(None, "soc", ["fatimah"], "[SECURITY ALERT] Do not open 'Payroll portal migration' email", D(7, "17:48"), alert,
         bcc=[k for k in STAFF if k not in ("soc",)], scenario="SOC response")
    make(None, "jasmine", ["michael"], "Incident IR-2026-014 - Priya mailbox compromise (initial notes)", D(7, "19:05"),
         "Michael,\n\nTimeline so far:\n10:02-12:40 file-share phish to 8 staff (2 sending IPs)\n~15:58 Priya entered credentials (proxy log)\n"
         "16:31 OWA sign-in from 198.51.100.77, inbox rule created (move 'Meridian' to RSS Feeds)\n16:42 internal blast to 15 recipients\n"
         "17:40 account disabled, sessions revoked, rule removed.\n\nWill update tomorrow.", cc=["benjamin"], scenario="SOC response")

    # ---------------------------------------------------------------- P3: thread hijack from the supplier's real mailbox
    S3 = "P3: BEC thread hijack (attacker-sent from compromised supplier mailbox and lookalike domain)"
    bank1 = doc("Meridian Marine Supplies - Change of Bank Details", "Effective immediately, please remit to:", "UOB (fictional), account 3-118-4471-2", "Account name: Meridian Marine Supplies Pte Ltd") + ("Meridian-bank-change-notice.pdf",)
    bank2 = doc("Meridian Marine Supplies - Change of Bank Details (signed)", "Effective immediately, please remit to:", "UOB (fictional), account 3-118-4471-2", "Signed: Finance Director, Meridian Marine Supplies") + ("Meridian-bank-change-notice-signed.pdf",)
    h1 = make(None, "aaron", ["benjamin"], "RE: Invoice INV-2026-10391 from Meridian Marine Supplies", D(8, "09:10"),
              meridian_body("Hi Benjamin, Priya,\n\nThank you. Kindly note we have changed our bank due to an audit. The notice is attached - please update your records and, if possible, settle INV-2026-10391 in your next payment run."),
              cc=["priya"], quote=L4, ext=meridian_ext("198.51.100.79", "[198.51.100.79]"), attachments=[bank1],
              headers=[("Reply-To", "Aaron Chua <aaron.chua@meridian-rnarine.example>"), ("X-Mailer", "Microsoft Outlook 16.0")],
              scenario=S3, attacker=True)
    h2 = make(None, "priya", ["aaron_fake"], "RE: Invoice INV-2026-10391 from Meridian Marine Supplies", D(8, "09:47"),
              "Hi Aaron,\n\nNoted. For our controls, could you send the notice signed by your Finance Director?", cc=["benjamin"], quote=h1, scenario=S3)
    FAKE = ext_profile("198.51.100.79", "vps-79.cloudhost.example", "mail.meridian-rnarine.example",
                       "spf=pass smtp.mailfrom=meridian-rnarine.example; dkim=pass header.d=meridian-rnarine.example; dmarc=pass", dkim="meridian-rnarine.example", domain="meridian-rnarine.example")
    h3 = make(None, "aaron_fake", ["priya"], "RE: Invoice INV-2026-10391 from Meridian Marine Supplies", D(8, "13:20"),
              meridian_body("Hi Priya,\n\nSigned notice attached. Please confirm once updated."), cc=["benjamin"], quote=h2, ext=FAKE, attachments=[bank2],
              scenario=S3, attacker=True)
    h4 = make(None, "priya", ["benjamin"], "FW: Invoice INV-2026-10391 from Meridian Marine Supplies", D(9, "10:05"),
              "Hi Benjamin,\n\nMeridian sent the signed bank change notice. OK to update the vendor master?", quote=h3, attachments=[bank2],
              irt=False, refs=[], scenario=S3)
    h4.irt, h4.refs = None, []
    make(None, "benjamin", ["priya"], "RE: Invoice INV-2026-10391 from Meridian Marine Supplies", D(9, "10:30"),
         "OK, please update and include in the 16 Oct run.", quote=h4, scenario=S3)
    # real supplier asks why payment hasn't arrived
    S4 = "Fraud discovered: genuine supplier chases payment"
    r1 = make(None, "aaron", ["priya"], "Remittance query - INV-2026-10391", D(20, "11:02"),
              meridian_body("Dear Priya,\n\nYour remittance advice says INV-2026-10391 was paid on 16 Oct to account 3-118-4471-2. That is not our account - our bank details have not changed. Could you check urgently?"),
              ext=meridian_ext("203.0.113.21", "AARON-PC.meridianmarine.example"), headers=[("X-Mailer", "Microsoft Outlook 16.0")], scenario=S4)
    r2 = make(None, "priya", ["benjamin"], "FW: Remittance query - INV-2026-10391", D(20, "11:15"),
              "Benjamin - urgent. Looks like the bank change on 8 Oct was fraudulent.", cc=["jasmine"], quote=r1, scenario=S4)
    make(None, "jasmine", ["michael"], "Incident IR-2026-015 - Meridian payment diverted", D(20, "15:40"),
         "Michael,\n\nThe 8 Oct bank-change emails came from Meridian's real mailbox (sign-in IP 198.51.100.79, same hosting range as IR-2026-014) "
         "and then a lookalike domain meridian-rnarine.example. SGD 6,054.95 paid 16 Oct. Bank recall requested; police report filed.",
         cc=["benjamin"], quote=r2, scenario=S4)

    # ---------------------------------------------------------------- P4: QR-code PDFs, unique per recipient
    S5 = "P4: QR-code 'salary adjustment' PDFs, unique per recipient (attacker-sent)"
    p4 = []
    plan4 = [("benjamin", "08:12", "203.0.113.201", "hr-notice@benefitsdesk-sg.example"), ("priya", "08:47", "203.0.113.202", "payroll@staffbenefit-hub.example"),
             ("siti", "09:30", "203.0.113.201", "hr-notice@benefitsdesk-sg.example"), ("marcus", "10:41", "203.0.113.214", "notice@paynote-services.example"),
             ("grace", "11:05", "203.0.113.202", "payroll@staffbenefit-hub.example"), ("daniel", "12:18", "203.0.113.230", "hr@salaryreview-portal.example"),
             ("chloe", "13:02", "203.0.113.214", "notice@paynote-services.example"), ("michael", "14:27", "203.0.113.230", "hr@salaryreview-portal.example"),
             ("aisyah", "14:31", "203.0.113.241", "payroll@hr-docs-centre.example")]
    for who, hm, ip, addr in plan4:
        key = "q_" + who
        EXT[key] = ("Halcyon HR Payroll", addr)
        dom = addr.split("@")[1]
        tok = rhex(6)
        pdfb = pdf(f"Q4 Salary Adjustment - {name_of(who)}", [f"Employee: {name_of(who)}", "Your Q4 salary adjustment has been approved.",
                                                            "Scan the QR code with your phone to review and e-sign within 24 hours."],
                   qr=f"https://hr-salary-review.example/q/{tok}")
        e = ext_profile(ip, f"host-{ip.rsplit('.', 1)[1]}.broadband.example", f"mail.{dom}",
                        f"spf=pass smtp.mailfrom={dom}; dkim=none; dmarc=none", domain=dom)
        m = make(None, key, [who], f"Q4 salary adjustment - {name_of(who)}", D(19, hm),
                 f"Dear {first(who)},\n\nPlease find attached your Q4 salary adjustment letter. Kindly review and e-sign within 24 hours.\n\nHR Payroll",
                 style="plain", sig=False, ext=e, attachments=[(pdfb, "application", "pdf", f"Salary_Adjustment_{first(who).replace(' ', '_')}.pdf")],
                 scenario=S5, attacker=True, wave="P4")
        p4.append(m)
    ATTACK["P4"] = p4
    make(None, "grace", [p4[4].sender], "Automatic reply: " + p4[4].subject, D(19, "11:05", sec=59),
         "I am travelling in Japan 19-21 Oct with limited access to email. For urgent matters please contact Michael Tan.",
         style="plain", sig=False, irt=p4[4].msgid, refs=[p4[4].msgid], headers=[("Auto-Submitted", "auto-replied")], scenario=S5)
    make(None, "benjamin", ["soc"], "FW: Q4 salary adjustment - Benjamin Ng", D(19, "08:40"),
         "Another one - PDF with a QR code. Not opened on phone.", attachments=[(None, "message", "rfc822", "Q4 salary adjustment.eml")],
         collect=[("soc", "inbox"), ("benjamin", "sent")], scenario="P4 reports to the SOC")


# =========================================================================== post-processing
def resolve_embedded():
    """Fill message/rfc822 attachments with the reported original's bytes."""
    by_logical = {}
    for c in COPIES:
        by_logical.setdefault(id(c.logical), []).append(c)
    pairs = {
        'Suspicious email - "Statement of Account"': ATTACK["P1"][6],
        "FW: Q4 salary adjustment - Benjamin Ng": ATTACK["P4"][0],
        "Undeliverable: Payroll portal migration - verify your details by Friday": ATTACK["P2"],
    }
    return pairs, by_logical


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    out = Path(args.output).resolve()
    if out.is_relative_to(Path(__file__).resolve().parent.parent):
        raise SystemExit("Build corpora outside the source repository; evidence files are not committed.")
    if out.exists() and any(out.iterdir()):
        raise SystemExit("Output directory must be empty.")
    build_content()
    build_attack()

    pairs, by_logical = resolve_embedded()
    raw = {}
    # serialise originals first (embedded wrappers need their bytes)
    wrappers = [c for c in COPIES if any(a[2] == "rfc822" for a in c.logical.attachments)]
    for c in COPIES:
        if c in wrappers:
            continue
        raw[c.name] = serialise(c)
    for c in wrappers:
        original = pairs[c.logical.subject]
        orig_copy = [x for x in by_logical[id(original)] if x.folder in ("inbox", "sent")][0]
        new_atts = []
        for a in c.logical.attachments:
            if a[2] == "rfc822":
                new_atts.append((raw[orig_copy.name], "message", "rfc822", a[3]))
            elif a[2] == "delivery-status":
                continue
            else:
                new_atts.append(a)
        c.logical.attachments = new_atts
        data = serialise(c)
        if "Undeliverable" in c.logical.subject:
            data = make_ndr(c, raw[orig_copy.name])
        raw[c.name] = data
    corpus = out / "conformance"
    corpus.mkdir(parents=True)
    for name, data in raw.items():
        (corpus / name).write_bytes(data)
    for alias, original in DUPLICATES.items():
        (corpus / alias).write_bytes(raw[original])
    truth = ground_truth(raw)
    (corpus / "ground_truth.json").write_text(json.dumps(truth["conformance"], indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    intent = out / "intent"
    intent.mkdir()
    for f in corpus.glob("*.eml"):
        (intent / f.name).write_bytes(f.read_bytes())
    (intent / "ground_truth.json").write_text(json.dumps(truth["intent"], indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(truth["summary"], indent=2))


def make_ndr(c, original_bytes):
    """Exchange-style NDR: multipart/report with delivery-status and the original message."""
    m = c.logical
    gone = re.search(r"to (\S+) couldn't", c.text).group(1)
    b = f"_{rhex(14).upper()}_"
    head = []
    for r in c.received:
        head.append(Header(r).encode() if False else None)
    msg = EmailMessage(policy=policy.SMTP)
    for r in c.received:
        msg["Received"] = r
    msg["From"] = disp(m.sender)
    msg["To"] = disp("priya")
    msg["Subject"] = m.subject
    msg["Date"] = format_datetime(m.date)
    msg["Message-ID"] = m.msgid
    for k, v in m.headers:
        msg[k] = v
    for k, v in c.extra:
        msg[k] = v
    hdr = msg.as_bytes().split(b"\r\n\r\n", 1)[0]
    body = (
        f"MIME-Version: 1.0\r\nContent-Type: multipart/report; report-type=delivery-status;\r\n boundary=\"{b}\"\r\n\r\n"
        f"--{b}\r\nContent-Type: text/plain; charset=\"us-ascii\"\r\nContent-Transfer-Encoding: 7bit\r\n\r\n{c.text}\r\n\r\n"
        f"--{b}\r\nContent-Type: message/delivery-status\r\n\r\nReporting-MTA: dns;{MBX}\r\nReceived-From-MTA: dns;{MBX}\r\n"
        f"Arrival-Date: {format_datetime(m.date)}\r\n\r\nFinal-Recipient: rfc822;{gone}\r\nAction: failed\r\nStatus: 5.1.10\r\n"
        f"Diagnostic-Code: smtp;550 5.1.10 RESOLVER.ADR.RecipientNotFound; Recipient not found by SMTP address lookup\r\n\r\n"
        f"--{b}\r\nContent-Type: message/rfc822\r\n\r\n"
    ).encode() + original_bytes + f"\r\n--{b}--\r\n".encode()
    c.hashes = set()
    c.urls, c.dests = set(), set()
    return hdr + b"\r\n" + body


def ground_truth(raw):
    names = sorted(raw)
    by = {c.name: c for c in COPIES}
    ids = {}
    for n in names:
        ids.setdefault(by[n].logical.msgid, []).append(n)
    edges, logical_replies = [], 0
    for n in names:
        lm = by[n].logical
        target = lm.irt or (lm.refs[-1] if lm.refs else None)
        if not target:
            continue
        logical_replies += 1
        if len(ids.get(target, [])) == 1 and ids[target][0] != n:
            edges.append((ids[target][0], n))
    parent = {n: n for n in names}

    def root(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for a, b in edges:
        parent[root(a)] = root(b)
    att, url, coord, dest = set(), set(), set(), set()
    for a, b in combinations(names, 2):
        A, B = by[a], by[b]
        pair = (a, b)
        sa, su = A.hashes & B.hashes, A.urls & B.urls
        if sa:
            att.add(pair)
        if su:
            url.add(pair)
        if A.dests & B.dests:
            dest.add(pair)
        if A.date is None or B.date is None or A.logical.raw_date or B.logical.raw_date or root(a) == root(b):
            continue
        if abs((A.date - B.date).total_seconds()) > WINDOW:
            continue
        sa_subj = norm_subject(A.logical.subject)
        cats = bool(sa) + bool(su) + (sa_subj is not None and sa_subj == norm_subject(B.logical.subject)) + \
            (A.origin is not None and A.origin == B.origin)
        if cats >= 2:
            coord.add(pair)
    waves = {}
    for n in names:
        w = by[n].logical.wave
        if w:
            waves.setdefault(w, []).append(n)
    intent_coord = {p for files in waves.values() for p in combinations(sorted(files), 2)}
    scen = {}
    for n in names:
        scen.setdefault(by[n].logical.scenario, []).append(n)
    messages = {n: {"collected_from": f"{name_of(by[n].owner)} / {by[n].folder}", "from": disp(by[n].logical.sender),
                    "subject": by[n].logical.subject, "date": by[n].date.isoformat() if by[n].date and not by[n].logical.raw_date else None,
                    "scenario": by[n].logical.scenario, "attacker_sent": by[n].logical.attacker} for n in names}
    base = {
        "seed": SEED, "start_utc": "2026-10-02T00:00:00+00:00",
        "expected_parameters": {"window_seconds": WINDOW, "minimum_signals": 2, "timestamp_source": "date"},
        "files": {n: sha(raw[n]) for n in names}, "duplicate_acquisitions": dict(DUPLICATES),
        "scenarios": [{"name": k, "files": v} for k, v in scen.items()], "messages": messages,
    }
    srt = lambda s: sorted(list(p) for p in s)  # noqa: E731
    conf = dict(base, schema_version=1, tier="realistic-complex-conformance",
                relationships={"attachment_reuse": srt(att), "url_reuse": srt(url), "reply": srt(edges), "possible_coordination": srt(coord)},
                scope="Rule conformance: what each documented rule should report from the artifacts written into each file.")
    intent = dict(base, schema_version=1, tier="realistic-complex-intent",
                  relationships={"attachment_reuse": srt(att), "url_reuse": srt(dest), "reply": srt(edges), "possible_coordination": srt(intent_coord)},
                  scope=("Investigator questions. url_reuse = same destination after unwrapping Safe Links and resolving known short links. "
                         "possible_coordination = pairs within one attacker distribution wave (P1, P2, P4). Attachment and reply labels are unchanged."))
    summary = {
        "files": len(names), "duplicate_acquisitions": len(DUPLICATES), "logical_messages": len(LOGICAL),
        "conformance": {k: len(v) for k, v in conf["relationships"].items()},
        "intent": {k: len(v) for k, v in intent["relationships"].items()},
        "header_linked_replies_in_files": logical_replies, "resolvable_reply_edges": len(edges),
    }
    return {"conformance": conf, "intent": intent, "summary": summary}


if __name__ == "__main__":
    main()

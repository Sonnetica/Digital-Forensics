"""Create a small, readable fictional case for the investigator interface."""

import argparse
from datetime import datetime, timedelta, timezone
from email import policy
from email.message import EmailMessage
from email.utils import format_datetime
from pathlib import Path

SGT = timezone(timedelta(hours=8))
DAY = datetime(2026, 10, 2, tzinfo=SGT)
PAYMENT_URL = "https://vendor-portal.example/review/oct-2026"
ACCESS_URL = "https://intranet.seabrook.example/access/q4"
ADVISORY_URL = "https://security.seabrook.example/advisory/browser-oct-2026"
PAYMENT_NOTE = (
    b"Northstar Office Supplies\n"
    b"Reference: OCT-2026-17\n"
    b"Requested change: remittance instructions\n"
    b"Status: pending independent telephone confirmation\n"
)
FLOORPLAN = (
    b"Seabrook House visitor directions\n"
    b"Reception: Level 1, east entrance\n"
    b"Meeting rooms: Level 3\n"
    b"Visitors must sign in at reception.\n"
)


def create(output):
    output = Path(output).expanduser().resolve()
    if output.exists() and any(output.iterdir()):
        raise ValueError("Demo output directory must be empty; existing files are not overwritten.")
    output.mkdir(parents=True, exist_ok=True)

    def emit(
        name,
        *,
        sender,
        recipient,
        subject,
        body,
        hour,
        minute,
        origin_ip,
        message_id,
        date=True,
        in_reply_to=None,
        references=None,
        html=None,
        attachment=None,
    ):
        when = DAY.replace(hour=hour, minute=minute)
        message = EmailMessage(policy=policy.SMTP)
        message["From"] = sender
        message["To"] = recipient
        message["Subject"] = subject
        message["Message-ID"] = message_id
        if date:
            message["Date"] = format_datetime(when)
        message["Received"] = (
            f"from client.example ([{origin_ip}]) by mx.seabrook.example with ESMTPS; "
            f"{format_datetime(when + timedelta(seconds=18))}"
        )
        message["X-Originating-IP"] = f"[{origin_ip}]"
        if in_reply_to:
            message["In-Reply-To"] = in_reply_to
        if references:
            message["References"] = " ".join(references)
        message.set_content(body)
        if html:
            message.add_alternative(html, subtype="html")
        if attachment:
            filename, content = attachment
            message.add_attachment(
                content, maintype="text", subtype="plain", filename=filename
            )
        for index, part in enumerate(message.walk()):
            if part.is_multipart():
                part.set_boundary(f"etrace-demo-{name}-{index}")
        (output / f"{name}.eml").write_bytes(message.as_bytes())

    emit(
        "01-supplier-payment-ap",
        sender="Elise Hart <elise@northstar-payments.example>",
        recipient="Priya Menon <priya@seabrook.example>",
        subject="October supplier payment update",
        body=(
            "Hi Priya,\n\nNorthstar sent a revised remittance note for the October invoice run. "
            "The copy we received is attached. Please check the request with the vendor using "
            "the telephone number already in our records before changing anything.\n\n"
            f"Review page: {PAYMENT_URL}\n\nThanks,\nElise\n"
        ),
        hour=9, minute=5, origin_ip="203.0.113.44",
        message_id="<supplier-ap-20261002@northstar-payments.example>",
        attachment=("remittance-note.txt", PAYMENT_NOTE),
    )
    emit(
        "02-supplier-payment-ops",
        sender="Elise Hart <elise@northstar-payments.example>",
        recipient="Sam Ong <sam@seabrook.example>",
        subject="October supplier payment update",
        body=(
            "Hi Sam,\n\nI am sending the same supplier note to Operations so the purchase order "
            "and invoice can be checked together. The review link is in the HTML version. "
            "Please hold any account change until Finance confirms it.\n\nElise\n"
        ),
        html=(
            "<p>Hi Sam,</p><p>Please check the attached supplier note against the purchase "
            f"order. <a href=\"{PAYMENT_URL}\">Open the review page</a>. "
            "Hold any account change until Finance confirms it.</p><p>Elise</p>"
        ),
        hour=9, minute=12, origin_ip="203.0.113.44",
        message_id="<supplier-ops-20261002@northstar-payments.example>",
        attachment=("remittance-note.txt", PAYMENT_NOTE),
    )
    emit(
        "03-supplier-payment-finance",
        sender="Billing Desk <billing@northstar-billing.example>",
        recipient="Li Wei <liwei@seabrook.example>",
        subject="Fwd: October supplier payment update",
        body=(
            "Hello Li Wei,\n\nForwarding the payment instruction sheet that reached our shared "
            "mailbox this morning. The sender name differs from the usual contact, so I have "
            "not approved the change. Can you verify it with Northstar?\n\n"
            "Review copy: HTTPS://VENDOR-PORTAL.EXAMPLE:443/review/oct-2026\n\nBilling Desk\n"
        ),
        hour=9, minute=19, origin_ip="203.0.113.44",
        message_id="<supplier-finance-20261002@northstar-billing.example>",
        attachment=("remittance-note.txt", PAYMENT_NOTE),
    )
    emit(
        "04-vendor-link-question",
        sender="Priya Menon <priya@seabrook.example>",
        recipient="Maya Chen <maya@seabrook.example>",
        subject="Can someone confirm this vendor link?",
        body=(
            "Hi Maya,\n\nI found this review address in the payment thread, but the forwarded "
            "copy has no Date header. Please use our existing contact record to confirm whether "
            "it belongs to the supplier.\n\n"
            f"{PAYMENT_URL}\n\nPriya\n"
        ),
        hour=9, minute=43, origin_ip="198.51.100.21",
        message_id="<vendor-question-20261002@seabrook.example>", date=False,
    )

    access_root = "<access-review-1-20261002@seabrook.example>"
    access_reply = "<access-review-2-20261002@seabrook.example>"
    emit(
        "05-access-review-request",
        sender="Maya Chen <maya@seabrook.example>",
        recipient="Daniel Lee <daniel@seabrook.example>",
        subject="Q4 access review",
        body=(
            "Hi Daniel,\n\nCould you check the Q4 access list before Tuesday's audit call? "
            "I have marked the two accounts that need owner confirmation.\n\n"
            f"Working page: {ACCESS_URL}\n\nMaya\n"
        ),
        hour=11, minute=5, origin_ip="198.51.100.31", message_id=access_root,
    )
    emit(
        "06-access-review-reply",
        sender="Daniel Lee <daniel@seabrook.example>",
        recipient="Maya Chen <maya@seabrook.example>",
        subject="Re: Q4 access review",
        body=(
            "Hi Maya,\n\nI checked the list. The contractor account still has access to the "
            "archive folder, so I have asked its owner to confirm whether that is needed.\n\n"
            f"I used {ACCESS_URL}\n\nDaniel\n"
        ),
        hour=11, minute=24, origin_ip="198.51.100.32", message_id=access_reply,
        in_reply_to=access_root, references=[access_root],
    )
    emit(
        "07-access-review-followup",
        sender="Maya Chen <maya@seabrook.example>",
        recipient="Daniel Lee <daniel@seabrook.example>",
        subject="Re: Q4 access review",
        body=(
            "Thanks, Daniel. I will leave the contractor entry open until the owner replies. "
            "The current list is still at the same working page.\n\n"
            f"{ACCESS_URL}\n\nMaya\n"
        ),
        hour=11, minute=41, origin_ip="198.51.100.31",
        message_id="<access-review-3-20261002@seabrook.example>",
        references=[access_root, access_reply],
    )
    emit(
        "08-browser-advisory-it",
        sender="Iris Rao <iris@seabrook.example>",
        recipient="IT Service Desk <it@seabrook.example>",
        subject="October browser advisory",
        body=(
            "Team,\n\nThe vendor advisory is relevant to the browsers on the training PCs. "
            "Please check the affected versions before scheduling an update.\n\n"
            f"Advisory: {ADVISORY_URL}\n\nIris\n"
        ),
        hour=13, minute=10, origin_ip="198.51.100.41",
        message_id="<browser-it-20261002@seabrook.example>",
    )
    emit(
        "09-browser-advisory-hr",
        sender="Nora Lim <nora@seabrook.example>",
        recipient="HR Team <hr@seabrook.example>",
        subject="Sharing browser advisory with new starters",
        body=(
            "Hi team,\n\nPlease include this security notice in Monday's onboarding pack. "
            "It explains why the training browser may restart after the update.\n\n"
            f"{ADVISORY_URL}\n\nNora\n"
        ),
        hour=13, minute=23, origin_ip="198.51.100.42",
        message_id="<browser-hr-20261002@seabrook.example>",
    )
    emit(
        "10-visitor-directions-new-hire",
        sender="Facilities <facilities@seabrook.example>",
        recipient="Alex Tan <alex@seabrook.example>",
        subject="First day arrival details",
        body=(
            "Hi Alex,\n\nWelcome to Seabrook. The attached directions show the reception "
            "entrance and meeting room floor. Bring a photo ID for the visitor desk.\n\nFacilities\n"
        ),
        hour=14, minute=5, origin_ip="198.51.100.51",
        message_id="<visitor-newhire-20261002@seabrook.example>",
        attachment=("visitor-directions.txt", FLOORPLAN),
    )
    emit(
        "11-visitor-directions-contractor",
        sender="Facilities <facilities@seabrook.example>",
        recipient="Taylor Brooks <taylor@contractor.example>",
        subject="Reception access for Tuesday",
        body=(
            "Hi Taylor,\n\nPlease use the east entrance when you arrive on Tuesday. "
            "The reception and meeting room directions are attached. Your host will meet you "
            "after sign-in.\n\nFacilities\n"
        ),
        hour=14, minute=21, origin_ip="198.51.100.52",
        message_id="<visitor-contractor-20261002@seabrook.example>",
        attachment=("visitor-directions.txt", FLOORPLAN),
    )
    emit(
        "12-missing-parent-reply",
        sender="Li Wei <liwei@seabrook.example>",
        recipient="Priya Menon <priya@seabrook.example>",
        subject="Re: Approval for October remittance change",
        body=(
            "Hi Priya,\n\nI cannot find the original approval message in this export. "
            "Until we have it, the remittance change should remain on hold.\n\nLi Wei\n"
        ),
        hour=15, minute=3, origin_ip="198.51.100.61",
        message_id="<missing-parent-reply-20261002@seabrook.example>",
        in_reply_to="<approval-not-in-export@seabrook.example>",
        references=["<approval-not-in-export@seabrook.example>"],
    )
    emit(
        "13-training-room-booking",
        sender="Maya Chen <maya@seabrook.example>",
        recipient="Nora Lim <nora@seabrook.example>",
        subject="Training room booking for Monday",
        body=(
            "Hi Nora,\n\nRoom 3B is available from 10:00 to 12:00 on Monday. "
            "I have asked reception to prepare visitor badges for the new starters.\n\nMaya\n"
        ),
        hour=8, minute=25, origin_ip="198.51.100.31",
        message_id="<room-booking-20261002@seabrook.example>",
    )
    emit(
        "14-courier-delivery",
        sender="Reception <reception@seabrook.example>",
        recipient="Facilities <facilities@seabrook.example>",
        subject="Courier parcel at reception",
        body=(
            "Hello Facilities,\n\nA parcel addressed to the office manager arrived at "
            "16:00. It is logged under the reception desk and can be collected before 18:00.\n\n"
            "Reception\n"
        ),
        hour=16, minute=2, origin_ip="198.51.100.71",
        message_id="<courier-20261002@seabrook.example>",
    )
    return sorted(output.glob("*.eml"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        files = create(args.output)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"demo: {exc}\n")
    print(f"Created {len(files)} fictional EML files in {args.output.resolve()}")


if __name__ == "__main__":
    main()

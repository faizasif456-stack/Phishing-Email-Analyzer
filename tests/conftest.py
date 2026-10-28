from email.message import EmailMessage
from pathlib import Path

import pytest

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def build_email(
    sender="Alice <alice@example.org>",
    subject="Hello",
    text="Hi there",
    html=None,
    auth="mx.example.net; spf=pass smtp.mailfrom=alice@example.org; dkim=pass header.d=example.org; dmarc=pass header.from=example.org",
    reply_to=None,
    return_path=None,
    received=None,
    attachments=(),
    message_id="<abc123@example.org>",
):
    msg = EmailMessage()
    for header in received or ["from mail.example.org (mail.example.org [8.8.4.4]) by mx.example.net; Mon, 26 Oct 2026 10:00:00 +0000"]:
        msg["Received"] = header
    if auth:
        msg["Authentication-Results"] = auth
    if return_path:
        msg["Return-Path"] = return_path
    msg["From"] = sender
    msg["To"] = "faiz@example.com"
    if reply_to:
        msg["Reply-To"] = reply_to
    msg["Subject"] = subject
    msg["Date"] = "Mon, 26 Oct 2026 10:00:00 +0000"
    if message_id:
        msg["Message-ID"] = message_id
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")
    for filename, data, mime in attachments:
        maintype, subtype = mime.split("/")
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)
    return bytes(msg)


@pytest.fixture
def make_email():
    return build_email


@pytest.fixture
def samples():
    return SAMPLES

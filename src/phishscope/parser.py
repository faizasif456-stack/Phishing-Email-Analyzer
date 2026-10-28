import email
from dataclasses import dataclass, field
from email import policy
from email.utils import getaddresses, parseaddr
from pathlib import Path

from .domains import domain_of


@dataclass
class Attachment:
    filename: str
    content_type: str
    data: bytes = field(repr=False)


@dataclass
class ParsedEmail:
    raw: bytes = field(repr=False)
    message: email.message.Message = field(repr=False)
    subject: str
    from_name: str
    from_addr: str
    reply_to: list
    return_path: str
    to: str
    date: str
    message_id: str
    received: list
    text: str
    html: str
    attachments: list

    @property
    def from_domain(self):
        return domain_of(self.from_addr)

    def headers(self, name):
        return [_safe_str(v) for v in self.message.get_all(name, [])]


def _safe_str(value):
    try:
        return " ".join(str(value).split())
    except Exception:
        return ""


def _header(msg, name):
    try:
        value = msg.get(name)
    except Exception:
        return ""
    return _safe_str(value) if value is not None else ""


def _decode_text(part):
    try:
        return part.get_content()
    except (LookupError, UnicodeError, KeyError, AssertionError):
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")


def parse(source):
    raw = source if isinstance(source, bytes) else Path(source).read_bytes()
    msg = email.message_from_bytes(raw, policy=policy.default)

    from_name, from_addr = parseaddr(_header(msg, "From"))
    reply_to = [addr for _, addr in getaddresses([_header(msg, "Reply-To")]) if addr]

    text_parts, html_parts, attachments = [], [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        content_type = part.get_content_type()
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        if filename or disposition == "attachment":
            attachments.append(Attachment(filename or "unnamed", content_type, part.get_payload(decode=True) or b""))
        elif content_type == "text/plain":
            text_parts.append(_decode_text(part))
        elif content_type == "text/html":
            html_parts.append(_decode_text(part))

    return ParsedEmail(
        raw=raw,
        message=msg,
        subject=_header(msg, "Subject"),
        from_name=from_name.strip(),
        from_addr=from_addr.lower(),
        reply_to=[a.lower() for a in reply_to],
        return_path=_header(msg, "Return-Path").strip("<>").lower(),
        to=_header(msg, "To"),
        date=_header(msg, "Date"),
        message_id=_header(msg, "Message-ID"),
        received=[_safe_str(h) for h in msg.get_all("Received", [])],
        text="\n".join(text_parts),
        html="\n".join(html_parts),
        attachments=attachments,
    )

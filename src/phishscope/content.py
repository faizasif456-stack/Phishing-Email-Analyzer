import re

from .scoring import Finding

PHRASES = [
    "urgent", "immediately", "within 24 hours", "within 48 hours", "account suspended",
    "account has been suspended", "account will be closed", "account will be locked", "verify your account",
    "verify your identity", "confirm your identity", "unusual activity", "unusual sign-in", "suspicious activity",
    "password expires", "password will expire", "password has expired", "click here", "click below",
    "final notice", "action required", "immediate action", "gift card", "wire transfer", "bank details",
    "payment failed", "update your payment", "payment information", "limited time", "security alert",
    "you have won", "claim your", "invoice attached", "overdue", "your mailbox is full", "storage is full",
    "shared a document", "kindly", "do not share this", "reset your password",
]

PATTERN = re.compile(r"(?i)\b(" + "|".join(re.escape(p) for p in PHRASES) + r")\b")


def check_content(parsed, body):
    findings = []
    text = " ".join([parsed.subject, parsed.text, body.plain_text])
    hits = sorted({m.lower() for m in PATTERN.findall(text)})
    if hits:
        quoted = ", ".join(f'"{h}"' for h in hits[:8])
        findings.append(Finding("content", f"Pressure or credential-bait language: {quoted}", min(15, 3 * len(hits))))

    if "password" in body.inputs:
        findings.append(Finding("content", "Email body contains a form with a password field", 20))
    elif body.forms:
        findings.append(Finding("content", "Email body contains an HTML form", 10))

    if not parsed.text.strip() and not body.plain_text and parsed.attachments:
        findings.append(Finding("content", "Email has no body text, only attachments", 5))

    return findings

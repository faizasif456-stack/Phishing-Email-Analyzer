import json

import pytest

from phishscope.analyzer import analyze
from phishscope.report import render_html, render_iocs, to_json
from phishscope.virustotal import Reputation


@pytest.mark.parametrize("name, verdict", [
    ("legit_github_notice.eml", "Clean"),
    ("phish_paypal_credential.eml", "Malicious"),
    ("malware_invoice_attachment.eml", "Malicious"),
])
def test_sample_verdicts(samples, name, verdict):
    assert analyze(samples / name).verdict == verdict


def test_legit_sample_scores_zero(samples):
    report = analyze(samples / "legit_github_notice.eml")
    assert report.score == 0
    assert report.originating_ip == "192.30.252.204"


def test_phish_indicators(samples):
    report = analyze(samples / "phish_paypal_credential.eml")
    assert report.originating_ip == "91.215.85.17"
    assert report.reply_to == ["paypal.resolution.team@gmail.com"]
    assert "paypal.com.account-verify.xyz" in report.iocs["domains"]
    assert "91.215.85.17" in report.iocs["ips"]
    assert report.findings[0].points >= report.findings[-1].points


def test_executable_alone_is_at_least_likely_phishing(make_email):
    raw = make_email(text="see attached", attachments=[("setup.exe", b"MZ" + b"\x00" * 100, "application/octet-stream")])
    report = analyze(raw)
    assert report.score >= 40
    assert report.verdict in ("Likely phishing", "Malicious")


class FakeVT:
    def __init__(self, bad=()):
        self.bad = set(bad)
        self.lookups = []

    def lookup(self, kind, value):
        self.lookups.append((kind, value))
        malicious = 12 if value in self.bad else 0
        return Reputation(kind, value, True, malicious=malicious, harmless=60, link=f"https://vt/{value}")


def test_reputation_raises_score(make_email):
    raw = make_email(text="https://looks-fine.example.org/doc")
    clean = analyze(raw, vt=FakeVT())
    flagged = analyze(raw, vt=FakeVT(bad={"https://looks-fine.example.org/doc"}))
    assert clean.verdict == "Clean"
    assert flagged.verdict == "Malicious"
    assert flagged.urls[0].reputation["malicious"] == 12


def test_reputation_lookup_order_and_limit(samples):
    vt = FakeVT()
    analyze(samples / "malware_invoice_attachment.eml", vt=vt, max_lookups=2)
    assert [k for k, _ in vt.lookups] == ["file", "file"]


def test_json_round_trip(samples):
    report = analyze(samples / "phish_paypal_credential.eml")
    data = json.loads(to_json([report]))
    assert data["verdict"] == "Malicious"
    assert data["urls"][0]["flags"]
    assert isinstance(data["findings"][0]["points"], int)


def test_html_report_escapes_content(make_email):
    raw = make_email(subject='<script>alert("x")</script>', sender='"<img src=x onerror=alert(1)>" <a@example.org>')
    page = render_html(analyze(raw))
    assert "<script>alert" not in page
    assert "<img src=x" not in page
    assert "&lt;script&gt;" in page
    assert "Content-Security-Policy" in page


def test_iocs_defanged(samples):
    report = analyze(samples / "phish_paypal_credential.eml")
    text = render_iocs(report)
    assert "hxxp://paypal[.]com[.]account-verify[.]xyz" in text
    assert "http://" not in text
    assert "http://paypal.com.account-verify.xyz" in render_iocs(report, raw=True)


def test_handles_garbage_input():
    report = analyze(b"this is not an email at all")
    assert report.verdict in ("Clean", "Suspicious", "Likely phishing", "Malicious")

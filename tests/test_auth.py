from phishscope.auth import check_auth, parse_authentication_results
from phishscope.parser import parse


def test_parse_gmail_style_header():
    header = ("mx.google.com; dkim=pass header.i=@github.com header.s=pf2023 header.b=Kx8v; "
              "spf=pass (google.com: domain of noreply@github.com designates 1.2.3.4 as permitted sender) "
              "smtp.mailfrom=noreply@github.com; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=github.com")
    results = {r.method: r for r in parse_authentication_results(header)}
    assert results["spf"].result == "pass" and results["spf"].domain == "github.com"
    assert results["dkim"].result == "pass" and results["dkim"].domain == "github.com"
    assert results["dmarc"].result == "pass" and results["dmarc"].domain == "github.com"


def test_all_pass_has_no_findings(make_email):
    summary, findings = check_auth(parse(make_email()))
    assert {m: v["result"] for m, v in summary.items()} == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}
    assert findings == []


def test_failures_score_points(make_email):
    raw = make_email(auth="mx.example.net; spf=fail smtp.mailfrom=alice@example.org; dkim=fail header.d=example.org; dmarc=fail header.from=example.org")
    _, findings = check_auth(parse(raw))
    assert sum(f.points for f in findings) == 65


def test_dkim_not_aligned(make_email):
    raw = make_email(auth="mx; spf=pass smtp.mailfrom=alice@example.org; dkim=pass header.d=mailer.net; dmarc=pass header.from=example.org")
    _, findings = check_auth(parse(raw))
    assert any("not aligned" in f.message and f.points == 10 for f in findings)


def test_prefers_aligned_dkim_signature(make_email):
    raw = make_email(auth="mx; spf=pass smtp.mailfrom=alice@example.org; dkim=pass header.d=esp.net; dkim=pass header.d=example.org; dmarc=pass header.from=example.org")
    summary, findings = check_auth(parse(raw))
    assert summary["dkim"]["domain"] == "example.org"
    assert findings == []


def test_missing_results(make_email):
    summary, findings = check_auth(parse(make_email(auth=None)))
    assert summary["dmarc"]["result"] == "missing"
    assert any("No SPF, DKIM or DMARC" in f.message for f in findings)


def test_received_spf_fallback():
    raw = (b"Received-SPF: Fail (protection.outlook.com: domain of evil.com does not designate 5.6.7.8) "
           b"receiver=x; client-ip=5.6.7.8; envelope-from=\"x@evil.com\";\r\n"
           b"From: x@evil.com\r\nSubject: hi\r\n\r\nbody\r\n")
    summary, _ = check_auth(parse(raw))
    assert summary["spf"] == {"result": "fail", "domain": "evil.com", "source": "Received-SPF"}

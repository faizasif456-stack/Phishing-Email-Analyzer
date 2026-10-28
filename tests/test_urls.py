from phishscope.parser import parse
from phishscope.urls import analyze_urls, extract_urls


def urls_for(make_email, **kwargs):
    urls = extract_urls(parse(make_email(**kwargs)))
    analyze_urls(urls)
    return {u.url: u for u in urls}


def test_extracts_from_text_and_html(make_email):
    found = urls_for(
        make_email,
        text="See https://example.org/a, and www.example.org/b.",
        html='<a href="https://example.org/c">here</a> <a href="mailto:x@y.z">mail</a>',
    )
    assert set(found) == {"https://example.org/a", "http://www.example.org/b", "https://example.org/c"}


def test_link_text_is_not_a_url(make_email):
    found = urls_for(make_email, text="", html='<a href="https://evil.xyz/x">https://www.paypal.com/signin</a>')
    assert list(found) == ["https://evil.xyz/x"]


def test_html_entities_decoded(make_email):
    found = urls_for(make_email, text="", html='<a href="https://example.org/?a=1&amp;b=2">x</a>')
    assert "https://example.org/?a=1&b=2" in found


def test_clean_url_has_no_flags(make_email):
    found = urls_for(make_email, text="https://github.com/settings/keys")
    assert found["https://github.com/settings/keys"].flags == []


def test_mismatched_link_text(make_email):
    found = urls_for(make_email, text="", html='<a href="https://login.evil-site.com/">www.mybank.com</a>')
    assert any("Link text shows www.mybank.com" in f for f in found["https://login.evil-site.com/"].flags)


def test_suspicious_patterns(make_email):
    found = urls_for(make_email, text="\n".join([
        "http://203.0.113.9/login",
        "https://bit.ly/abc",
        "https://www.paypal.com@evil.example/",
        "https://xn--pypal-4ve.com/",
        "https://a.b.c.d.example.top/",
    ]))
    assert any("raw IP" in f for f in found["http://203.0.113.9/login"].flags)
    assert any("shortener" in f for f in found["https://bit.ly/abc"].flags)
    assert any("'@'" in f for f in found["https://www.paypal.com@evil.example/"].flags)
    assert any("Punycode" in f for f in found["https://xn--pypal-4ve.com/"].flags)
    flags = found["https://a.b.c.d.example.top/"].flags
    assert any(".top" in f for f in flags) and any("deep subdomain" in f for f in flags)


def test_form_action_flagged(make_email):
    found = urls_for(make_email, text="", html='<form action="https://collect.example.net/p"><input type="password"></form>')
    assert any("form submits" in f for f in found["https://collect.example.net/p"].flags)

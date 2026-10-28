import html
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urlsplit

from .defang import defang
from .domains import decode_idna, impersonated_brand, is_ip, is_official, org_domain, same_org
from .scoring import Finding

URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"'`]+")
DOMAIN_IN_TEXT = re.compile(r"(?i)\b(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})\b")
TRAILING = ".,;:!?)]}'\">"

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly", "s.id", "lnkd.in", "bl.ink",
}
RISKY_TLDS = {
    "zip", "mov", "xyz", "top", "click", "link", "gq", "tk", "ml", "cf", "ga", "work", "rest",
    "country", "kim", "icu", "cam", "monster", "quest", "sbs", "cfd", "lol", "buzz", "support",
}
CREDENTIAL_WORDS = re.compile(r"(?i)(log-?in|sign-?in|verify|verification|account|secure|update|password|wallet|confirm|unlock|billing|webscr)")


@dataclass
class UrlInfo:
    url: str
    host: str
    source: str
    display_text: str = ""
    flags: list = field(default_factory=list)
    reputation: dict | None = None


class BodyParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.forms = []
        self.inputs = []
        self.text = []
        self._href = None
        self._link_text = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and attrs.get("href"):
            self._href = attrs["href"]
            self._link_text = []
        elif tag == "form":
            self.forms.append(attrs.get("action") or "")
        elif tag == "input":
            self.inputs.append((attrs.get("type") or "text").lower())
        elif tag in ("style", "script"):
            self._skip += 1

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href.strip(), " ".join("".join(self._link_text).split())))
            self._href = None
        elif tag in ("style", "script") and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if self._skip:
            return
        self.text.append(data)
        if self._href is not None:
            self._link_text.append(data)

    @property
    def plain_text(self):
        return " ".join(" ".join(self.text).split())


def parse_html(markup):
    parser = BodyParser()
    if markup:
        parser.feed(markup)
        parser.close()
    return parser


def _clean(url):
    url = html.unescape(url.strip()).rstrip(TRAILING)
    if url.lower().startswith("www."):
        url = "http://" + url
    return url


def _host(url):
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def extract_urls(parsed, body=None):
    body = body or parse_html(parsed.html)
    found = {}

    def add(raw, source, text=""):
        url = _clean(raw)
        if not url.lower().startswith(("http://", "https://")):
            return
        if url in found:
            if text and not found[url].display_text:
                found[url].display_text = text
            return
        found[url] = UrlInfo(url, _host(url), source, text)

    for href, text in body.links:
        add(href, "html", text)
    for action in body.forms:
        add(action, "form")
    for raw in URL_RE.findall(parsed.text):
        add(raw, "text")
    link_texts = " ".join(text for _, text in body.links)
    for raw in URL_RE.findall(body.plain_text):
        if raw not in link_texts:
            add(raw, "html")
    return list(found.values())


def _flags(info):
    url, host = info.url, info.host
    flags = []
    if not host:
        return [("URL has no valid host", 10)]
    netloc = urlsplit(url).netloc
    if "@" in netloc:
        flags.append(("URL hides the real host behind an '@' (user-info trick)", 20))
    if is_ip(host):
        flags.append(("Link points to a raw IP address", 20))
    if "xn--" in host:
        flags.append((f"Punycode domain, displays as {decode_idna(host)}", 15))
    brand = impersonated_brand(host)
    if brand:
        flags.append((f"Domain imitates {brand.title()}", 25))
    if org_domain(host) in SHORTENERS:
        flags.append(("URL shortener hides the destination", 10))
    tld = host.rsplit(".", 1)[-1]
    if tld in RISKY_TLDS:
        flags.append((f"Uses the high-abuse .{tld} TLD", 8))
    if len(host.split(".")) - len(org_domain(host).split(".")) >= 3:
        flags.append(("Unusually deep subdomain chain", 5))
    if info.display_text:
        shown = DOMAIN_IN_TEXT.search(info.display_text)
        if shown and not same_org(shown.group(1), host):
            flags.append((f"Link text shows {shown.group(1)} but actually goes to {host}", 25))
    if info.source == "form":
        flags.append(("HTML form submits data to this address", 15))
    if not is_official(host) and CREDENTIAL_WORDS.search(urlsplit(url).path + host):
        flags.append(("Credential-themed wording in a non-official URL", 5))
    if url.lower().startswith("http://") and info.source != "text" and CREDENTIAL_WORDS.search(url):
        flags.append(("Login-style link over plain HTTP", 5))
    return flags


def analyze_urls(urls):
    findings = []
    for info in urls:
        for message, points in _flags(info):
            info.flags.append(message)
            findings.append(Finding("urls", f"{message}: {defang(info.url)}", points))
    return findings

import base64

import pytest

from phishscope.virustotal import VirusTotal, VirusTotalError, object_id


class FakeResponse:
    def __init__(self, status, payload=None):
        self.status_code = status
        self._payload = payload or {}

    def json(self):
        return self._payload


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, url, headers=None, timeout=None):
        self.calls.append((url, headers))
        return self.responses.pop(0)


def stats(malicious=0, suspicious=0, harmless=60, undetected=10):
    return {"data": {"attributes": {"last_analysis_stats": {
        "malicious": malicious, "suspicious": suspicious, "harmless": harmless, "undetected": undetected}}}}


def client(responses, **kwargs):
    session = FakeSession(responses)
    kwargs.setdefault("cache_path", None)
    kwargs.setdefault("sleep", lambda s: None)
    return VirusTotal("test-key", session=session, **kwargs), session


def test_url_id_is_unpadded_base64():
    oid = object_id("url", "http://example.com/")
    assert "=" not in oid
    assert base64.urlsafe_b64decode(oid + "=" * (-len(oid) % 4)) == b"http://example.com/"


def test_lookup_parses_stats():
    vt, session = client([FakeResponse(200, stats(malicious=7))])
    rep = vt.lookup("domain", "evil.example")
    assert rep.found and rep.malicious == 7 and rep.engines == 77
    url, headers = session.calls[0]
    assert url.endswith("/domains/evil.example")
    assert headers == {"x-apikey": "test-key"}
    assert rep.link.endswith("/gui/domain/evil.example")


def test_not_found():
    vt, _ = client([FakeResponse(404)])
    rep = vt.lookup("file", "a" * 64)
    assert not rep.found
    assert rep.summary() == "not seen by VirusTotal"


def test_bad_key():
    vt, _ = client([FakeResponse(401)])
    with pytest.raises(VirusTotalError, match="API key"):
        vt.lookup("ip", "1.2.3.4")


def test_retries_once_on_rate_limit():
    slept = []
    vt, session = client([FakeResponse(429), FakeResponse(200, stats())], sleep=slept.append)
    assert vt.lookup("ip", "1.2.3.4").found
    assert len(session.calls) == 2
    assert 60 in slept


def test_throttles_between_requests():
    slept = []
    now = [0.0]
    vt, _ = client([FakeResponse(200, stats()), FakeResponse(200, stats())],
                   sleep=slept.append, clock=lambda: now[0], requests_per_minute=4)
    vt.lookup("ip", "1.1.1.1")
    now[0] = 5.0
    vt.lookup("ip", "2.2.2.2")
    assert slept == [10.0]


def test_cache(tmp_path):
    path = tmp_path / "vt.json"
    vt, session = client([FakeResponse(200, stats(malicious=2))], cache_path=path)
    vt.lookup("domain", "x.example")
    vt2, session2 = client([], cache_path=path)
    assert vt2.lookup("domain", "x.example").malicious == 2
    assert session2.calls == []


def test_requires_key():
    with pytest.raises(VirusTotalError):
        VirusTotal("")

import base64
import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path

import requests

API = "https://www.virustotal.com/api/v3"
GUI = "https://www.virustotal.com/gui"
DEFAULT_CACHE = Path.home() / ".cache" / "phishscope" / "virustotal.json"
CACHE_TTL = 24 * 3600

ENDPOINTS = {
    "url": ("urls", "url"),
    "file": ("files", "file"),
    "domain": ("domains", "domain"),
    "ip": ("ip_addresses", "ip-address"),
}


class VirusTotalError(Exception):
    pass


@dataclass
class Reputation:
    kind: str
    value: str
    found: bool
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    link: str = ""

    @property
    def engines(self):
        return self.malicious + self.suspicious + self.harmless + self.undetected

    def summary(self):
        if not self.found:
            return "not seen by VirusTotal"
        return f"{self.malicious}/{self.engines} malicious, {self.suspicious} suspicious"


def object_id(kind, value):
    if kind == "url":
        return base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
    return value


class VirusTotal:
    def __init__(self, api_key, cache_path=DEFAULT_CACHE, requests_per_minute=4, session=None,
                 sleep=time.sleep, clock=time.monotonic):
        if not api_key:
            raise VirusTotalError("a VirusTotal API key is required")
        self.api_key = api_key
        self.cache_path = Path(cache_path) if cache_path else None
        self.interval = 60.0 / requests_per_minute if requests_per_minute else 0
        self.session = session or requests.Session()
        self.sleep = sleep
        self.clock = clock
        self._last = None
        self._cache = self._load_cache()

    def _load_cache(self):
        if not self.cache_path or not self.cache_path.exists():
            return {}
        try:
            return json.loads(self.cache_path.read_text())
        except (OSError, ValueError):
            return {}

    def _save_cache(self):
        if not self.cache_path:
            return
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.cache_path.write_text(json.dumps(self._cache))

    def _throttle(self):
        if self._last is not None and self.interval:
            wait = self.interval - (self.clock() - self._last)
            if wait > 0:
                self.sleep(wait)
        self._last = self.clock()

    def _get(self, path):
        for attempt in range(2):
            self._throttle()
            try:
                response = self.session.get(f"{API}/{path}", headers={"x-apikey": self.api_key}, timeout=20)
            except requests.RequestException as e:
                raise VirusTotalError(f"request failed: {e.__class__.__name__}") from None
            if response.status_code == 429 and attempt == 0:
                self.sleep(60)
                continue
            return response
        return response

    def lookup(self, kind, value):
        key = f"{kind}:{value}"
        cached = self._cache.get(key)
        if cached and time.time() - cached["at"] < CACHE_TTL:
            return Reputation(**cached["data"])

        endpoint, gui = ENDPOINTS[kind]
        oid = object_id(kind, value)
        response = self._get(f"{endpoint}/{oid}")
        link = f"{GUI}/{gui}/{oid}"

        if response.status_code == 404:
            reputation = Reputation(kind, value, found=False, link=link)
        elif response.status_code in (401, 403):
            raise VirusTotalError("VirusTotal rejected the API key")
        elif response.status_code == 429:
            raise VirusTotalError("VirusTotal quota exceeded")
        elif response.status_code != 200:
            raise VirusTotalError(f"VirusTotal returned HTTP {response.status_code}")
        else:
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            reputation = Reputation(
                kind, value, found=True,
                malicious=stats.get("malicious", 0),
                suspicious=stats.get("suspicious", 0),
                harmless=stats.get("harmless", 0),
                undetected=stats.get("undetected", 0),
                link=link,
            )

        self._cache[key] = {"at": time.time(), "data": asdict(reputation)}
        self._save_cache()
        return reputation

import re
from dataclasses import dataclass

from .domains import domain_of, org_domain, same_org
from .scoring import Finding

METHODS = ("spf", "dkim", "dmarc")
COMMENT = re.compile(r"\([^()]*\)")
RESULT = re.compile(r"^(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.I)
PROPERTY = re.compile(r"([a-z]+\.[a-z-]+)\s*=\s*([^\s;]+)", re.I)

FAIL_POINTS = {
    "spf": {"fail": 20, "softfail": 10, "neutral": 5, "none": 5, "temperror": 3, "permerror": 5},
    "dkim": {"fail": 20, "neutral": 5, "none": 8, "temperror": 3, "permerror": 10, "policy": 8},
    "dmarc": {"fail": 25, "none": 8, "temperror": 3, "permerror": 8},
}

DOMAIN_PROPS = {
    "spf": ("smtp.mailfrom", "smtp.helo"),
    "dkim": ("header.d", "header.i"),
    "dmarc": ("header.from",),
}


@dataclass
class AuthResult:
    method: str
    result: str
    domain: str = ""
    source: str = "Authentication-Results"


def _domain(value):
    value = value.strip("\"'<>")
    return domain_of(value) if "@" in value else value.lower()


def parse_authentication_results(header):
    results = []
    for segment in COMMENT.sub("", header).split(";")[1:]:
        segment = segment.strip()
        match = RESULT.match(segment)
        if not match:
            continue
        method, result = match.group(1).lower(), match.group(2).lower()
        props = {k.lower(): v for k, v in PROPERTY.findall(segment)}
        domain = next((_domain(props[p]) for p in DOMAIN_PROPS[method] if p in props), "")
        results.append(AuthResult(method, result, domain))
    return results


def collect(parsed):
    results = []
    for header in parsed.headers("Authentication-Results"):
        results = parse_authentication_results(header)
        if results:
            break
    if not any(r.method == "spf" for r in results):
        for header in parsed.headers("Received-SPF"):
            word = header.split(None, 1)[0].lower() if header else ""
            if word:
                mailfrom = re.search(r"envelope-from=\"?([^\s\";]+)", header, re.I)
                results.append(AuthResult("spf", word, _domain(mailfrom.group(1)) if mailfrom else "", "Received-SPF"))
                break
    return results


def _best(results, method, from_domain):
    candidates = [r for r in results if r.method == method]
    if not candidates:
        return None
    candidates.sort(key=lambda r: (r.result != "pass", not same_org(r.domain, from_domain)))
    return candidates[0]


def check_auth(parsed):
    results = collect(parsed)
    from_domain = parsed.from_domain
    summary, findings = {}, []

    if not results:
        findings.append(Finding("auth", "No SPF, DKIM or DMARC results recorded by the receiving server", 10))

    for method in METHODS:
        best = _best(results, method, from_domain)
        if best is None:
            summary[method] = {"result": "missing", "domain": "", "source": ""}
            if results:
                findings.append(Finding("auth", f"No {method.upper()} result in the headers", 5))
            continue
        summary[method] = {"result": best.result, "domain": best.domain, "source": best.source}
        points = FAIL_POINTS[method].get(best.result, 0)
        if points:
            where = f" for {best.domain}" if best.domain else ""
            findings.append(Finding("auth", f"{method.upper()} {best.result}{where}", points))
        elif best.result == "pass" and method in ("spf", "dkim") and best.domain and from_domain:
            if not same_org(best.domain, from_domain):
                points = 10 if method == "dkim" else 5
                findings.append(Finding(
                    "auth",
                    f"{method.upper()} passed for {best.domain}, which is not aligned with the From domain {from_domain}",
                    points,
                ))

    return summary, findings


def live_checks(parsed, timeout=10.0):
    import dns.exception
    import dns.resolver

    findings = []
    domain = parsed.from_domain
    if not domain:
        return findings
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout

    def txt(name):
        try:
            answer = resolver.resolve(name, "TXT")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        return [b"".join(r.strings).decode(errors="replace") for r in answer]

    try:
        dmarc = [r for r in txt(f"_dmarc.{org_domain(domain)}") if r.lower().startswith("v=dmarc1")]
        if not dmarc:
            findings.append(Finding("auth", f"{org_domain(domain)} publishes no DMARC record, so anyone can spoof it", 10))
        else:
            policy = re.search(r"\bp\s*=\s*(\w+)", dmarc[0], re.I)
            policy = policy.group(1).lower() if policy else "none"
            if policy == "none":
                findings.append(Finding("auth", f"DMARC policy for {org_domain(domain)} is p=none (monitor only)", 3))
            else:
                findings.append(Finding("auth", f"DMARC policy for {org_domain(domain)} is p={policy}", 0))

        if not any(r.lower().startswith("v=spf1") for r in txt(domain)):
            findings.append(Finding("auth", f"{domain} publishes no SPF record", 5))
    except dns.exception.DNSException as e:
        findings.append(Finding("auth", f"Live DNS lookup failed: {e.__class__.__name__}", 0))

    if parsed.message.get("DKIM-Signature"):
        try:
            import dkim
            if dkim.verify(parsed.raw, timeout=int(timeout)):
                findings.append(Finding("auth", "Live DKIM signature verification passed", 0))
            else:
                findings.append(Finding("auth", "Live DKIM verification failed (body altered, or the key has since rotated)", 5))
        except Exception as e:
            findings.append(Finding("auth", f"Live DKIM verification could not run: {e.__class__.__name__}", 0))

    return findings

from dataclasses import asdict, dataclass, field
from pathlib import Path

from .attachments import analyze_attachments
from .auth import check_auth, live_checks
from .content import check_content
from .defang import defang
from .domains import is_ip
from .headers import check_headers, originating_ip, received_hops
from .parser import parse
from .scoring import Finding, score, verdict
from .urls import analyze_urls, extract_urls, parse_html
from .virustotal import VirusTotalError


@dataclass
class Report:
    file: str
    subject: str
    sender: str
    display_name: str
    reply_to: list
    return_path: str
    to: str
    date: str
    message_id: str
    originating_ip: str
    hops: list
    auth: dict
    urls: list
    attachments: list
    findings: list
    score: int
    verdict: str
    iocs: dict
    reputation_checked: bool = False
    errors: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


def reputation_findings(rep, label):
    if not rep.found:
        return []
    if rep.kind == "file" and rep.malicious:
        points = 50 if rep.malicious >= 3 else 30
        return [Finding("reputation", f"{label} flagged by {rep.malicious}/{rep.engines} engines on VirusTotal", points, floor=80 if rep.malicious >= 3 else 45)]
    if rep.malicious >= 3:
        return [Finding("reputation", f"{label} flagged malicious by {rep.malicious} engines on VirusTotal", 35, floor=70)]
    if rep.malicious:
        return [Finding("reputation", f"{label} flagged malicious by {rep.malicious} engine(s) on VirusTotal", 20)]
    if rep.suspicious:
        return [Finding("reputation", f"{label} marked suspicious by {rep.suspicious} engine(s) on VirusTotal", 8)]
    return []


def check_reputation(vt, urls, attachments, origin_ip, max_lookups):
    targets = []
    for a in attachments:
        targets.append(("file", a.sha256, a, f"Attachment {a.filename}"))
    for u in urls:
        targets.append(("url", u.url, u, f"URL {defang(u.url)}"))
    seen_hosts = set()
    for u in urls:
        if u.host and u.host not in seen_hosts:
            seen_hosts.add(u.host)
            kind = "ip" if is_ip(u.host) else "domain"
            targets.append((kind, u.host, None, f"{'IP' if kind == 'ip' else 'Domain'} {defang(u.host)}"))
    if origin_ip:
        targets.append(("ip", origin_ip, None, f"Sending IP {defang(origin_ip)}"))

    findings, errors = [], []
    for kind, value, owner, label in targets[:max_lookups]:
        try:
            rep = vt.lookup(kind, value)
        except VirusTotalError as e:
            errors.append(str(e))
            findings.append(Finding("reputation", f"VirusTotal lookups stopped: {e}", 0))
            break
        if owner is not None:
            owner.reputation = {"summary": rep.summary(), "malicious": rep.malicious, "found": rep.found, "link": rep.link}
        findings.extend(reputation_findings(rep, label))
    if len(targets) > max_lookups:
        findings.append(Finding("reputation", f"Checked {max_lookups} of {len(targets)} indicators (raise --max-lookups to check more)", 0))
    return findings, errors


def collect_iocs(parsed, urls, attachments, origin_ip):
    return {
        "sender": parsed.from_addr,
        "reply_to": parsed.reply_to,
        "originating_ip": origin_ip,
        "ips": sorted({u.host for u in urls if u.host and is_ip(u.host)}),
        "urls": [u.url for u in urls],
        "domains": sorted({u.host for u in urls if u.host and not is_ip(u.host)}),
        "sha256": [a.sha256 for a in attachments],
    }


def analyze(source, vt=None, live=False, max_lookups=12):
    parsed = parse(source)
    body = parse_html(parsed.html)

    auth, findings = check_auth(parsed)
    findings += check_headers(parsed)

    urls = extract_urls(parsed, body)
    findings += analyze_urls(urls)

    attachments, attachment_findings = analyze_attachments(parsed.attachments)
    findings += attachment_findings
    findings += check_content(parsed, body)

    origin = originating_ip(parsed.received)
    if live:
        findings += live_checks(parsed)

    errors = []
    if vt is not None:
        rep_findings, errors = check_reputation(vt, urls, attachments, origin, max_lookups)
        findings += rep_findings

    total = score(findings)
    findings.sort(key=lambda f: (-f.points, f.category))

    return Report(
        file=str(source) if isinstance(source, (str, Path)) else "<bytes>",
        subject=parsed.subject,
        sender=parsed.from_addr,
        display_name=parsed.from_name,
        reply_to=parsed.reply_to,
        return_path=parsed.return_path,
        to=parsed.to,
        date=parsed.date,
        message_id=parsed.message_id,
        originating_ip=origin,
        hops=received_hops(parsed.received),
        auth=auth,
        urls=urls,
        attachments=attachments,
        findings=findings,
        score=total,
        verdict=verdict(total),
        iocs=collect_iocs(parsed, urls, attachments, origin),
        reputation_checked=vt is not None,
        errors=errors,
    )

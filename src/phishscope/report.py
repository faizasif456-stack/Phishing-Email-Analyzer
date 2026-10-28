import html
import json
from datetime import datetime, timezone

from rich import box
from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__
from .defang import defang

VERDICT_STYLE = {
    "Clean": "bold green",
    "Suspicious": "bold yellow",
    "Likely phishing": "bold red",
    "Malicious": "bold white on red",
}
SEVERITY_STYLE = {
    "info": "dim",
    "low": "cyan",
    "medium": "yellow",
    "high": "red",
    "critical": "bold red",
}
RESULT_STYLE = {"pass": "green", "fail": "red", "softfail": "yellow", "missing": "dim"}


def to_json(reports):
    data = [r.to_dict() for r in reports]
    return json.dumps(data[0] if len(data) == 1 else data, indent=2, default=str)


def _t(value, style=""):
    return Text(str(value) if value is not None else "", style=style)


def render_terminal(report, console):
    style = VERDICT_STYLE.get(report.verdict, "bold")
    title = Text.assemble((f" {report.verdict.upper()} ", style), "  ", (f"risk score {report.score}/100", "bold"))

    meta = Table.grid(padding=(0, 2))
    meta.add_column(style="dim", no_wrap=True)
    meta.add_column()
    sender = f"{report.display_name} <{report.sender}>" if report.display_name else report.sender
    for label, value in [
        ("Subject", report.subject),
        ("From", sender),
        ("Reply-To", ", ".join(report.reply_to)),
        ("Return-Path", report.return_path),
        ("To", report.to),
        ("Date", report.date),
        ("Origin IP", report.originating_ip),
    ]:
        if value:
            meta.add_row(label, _t(value))

    auth = Table(box=box.SIMPLE_HEAD, title="Authentication", title_justify="left", expand=True)
    auth.add_column("Check")
    auth.add_column("Result")
    auth.add_column("Domain")
    for method, info in report.auth.items():
        auth.add_row(method.upper(), _t(info["result"], RESULT_STYLE.get(info["result"], "yellow")), _t(info["domain"]))

    findings = Table(box=box.SIMPLE_HEAD, title="Findings", title_justify="left", expand=True)
    findings.add_column("Severity", no_wrap=True)
    findings.add_column("Pts", justify="right")
    findings.add_column("Area", no_wrap=True)
    findings.add_column("Detail", ratio=1)
    for f in report.findings:
        findings.add_row(_t(f.severity, SEVERITY_STYLE[f.severity]), str(f.points), f.category, _t(f.message))
    if not report.findings:
        findings.add_row("", "", "", _t("Nothing suspicious found", "green"))

    parts = [meta, auth, findings]

    if report.urls:
        urls = Table(box=box.SIMPLE_HEAD, title=f"URLs ({len(report.urls)})", title_justify="left", expand=True)
        urls.add_column("URL (defanged)", ratio=2, overflow="fold")
        urls.add_column("Issues", ratio=2)
        if report.reputation_checked:
            urls.add_column("VirusTotal", ratio=1)
        for u in report.urls:
            row = [_t(defang(u.url)), _t("\n".join(u.flags) or "-", "red" if u.flags else "dim")]
            if report.reputation_checked:
                row.append(_t(u.reputation["summary"] if u.reputation else "not checked"))
            urls.add_row(*row)
        parts.append(urls)

    if report.attachments:
        att = Table(box=box.SIMPLE_HEAD, title=f"Attachments ({len(report.attachments)})", title_justify="left", expand=True)
        att.add_column("File", overflow="fold")
        att.add_column("Type")
        att.add_column("Size", justify="right")
        att.add_column("SHA256", overflow="fold")
        att.add_column("Issues")
        for a in report.attachments:
            issues = "\n".join(a.flags) or "-"
            if a.reputation:
                issues += f"\nVT: {a.reputation['summary']}"
            att.add_row(_t(a.filename), _t(f"{a.content_type}\n(detected: {a.detected_type})"), f"{a.size:,} B",
                        _t(a.sha256), _t(issues, "red" if a.flags else "dim"))
        parts.append(att)

    if len(report.hops) > 0:
        hops = Table(box=box.SIMPLE_HEAD, title="Delivery path (oldest first)", title_justify="left", expand=True)
        hops.add_column("#", justify="right")
        hops.add_column("From", overflow="fold")
        hops.add_column("By", overflow="fold")
        hops.add_column("IP")
        for i, hop in enumerate(report.hops, 1):
            hops.add_row(str(i), _t(hop["from"]), _t(hop["by"]), _t(hop["ip"]))
        parts.append(hops)

    if not report.reputation_checked:
        parts.append(_t("Reputation checks skipped: pass --vt-key or set VT_API_KEY to enable VirusTotal lookups.", "dim"))

    console.print(Panel(Group(*parts), title=title, subtitle=_t(report.file, "dim"), border_style=style.split()[-1]))


def render_iocs(report, raw=False):
    fmt = (lambda v: v) if raw else defang
    lines = []
    iocs = report.iocs
    if iocs["sender"]:
        lines.append(f"sender        {fmt(iocs['sender'])}")
    for addr in iocs["reply_to"]:
        lines.append(f"reply-to      {fmt(addr)}")
    if iocs["originating_ip"]:
        lines.append(f"sending-ip    {fmt(iocs['originating_ip'])}")
    for ip in iocs["ips"]:
        lines.append(f"ip            {fmt(ip)}")
    for domain in iocs["domains"]:
        lines.append(f"domain        {fmt(domain)}")
    for url in iocs["urls"]:
        lines.append(f"url           {fmt(url)}")
    for digest in iocs["sha256"]:
        lines.append(f"sha256        {digest}")
    return "\n".join(lines)


CSS = """
:root {
  --bg: #f6f7f9; --card: #ffffff; --text: #1d2330; --muted: #677083; --line: #e3e6ec;
  --info: #8a93a6; --low: #2a86c7; --medium: #c98a00; --high: #d0472f; --critical: #a1122a;
  --clean: #1f8a4c; --suspicious: #c98a00; --phishing: #d0472f; --malicious: #a1122a;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #12151b; --card: #1b1f27; --text: #e6e9ef; --muted: #98a1b3; --line: #2c323d;
    --info: #7d879b; --low: #5aaee8; --medium: #e6b23c; --high: #f0735a; --critical: #ff5470;
    --clean: #47c27f; --suspicious: #e6b23c; --phishing: #f0735a; --malicious: #ff5470;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
  font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
main { max-width: 1000px; margin: 0 auto; padding: 32px 16px 64px; }
header { display: flex; align-items: center; gap: 20px; flex-wrap: wrap; margin-bottom: 24px; }
h1 { font-size: 20px; margin: 0; }
h2 { font-size: 15px; margin: 0 0 12px; }
.badge { padding: 6px 14px; border-radius: 999px; color: #fff; font-weight: 700; letter-spacing: .03em; }
.score { font-size: 28px; font-weight: 700; }
.score small { font-size: 14px; color: var(--muted); font-weight: 400; }
.meter { flex: 1; min-width: 160px; height: 8px; background: var(--line); border-radius: 4px; overflow: hidden; }
.meter span { display: block; height: 100%; }
section { background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 18px 20px; margin-bottom: 16px; overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 7px 10px 7px 0; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
tr:last-child td { border-bottom: 0; }
dl { display: grid; grid-template-columns: max-content 1fr; gap: 6px 18px; margin: 0; }
dt { color: var(--muted); }
dd { margin: 0; word-break: break-word; }
code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12.5px; word-break: break-all; }
.sev { font-weight: 600; text-transform: capitalize; }
.info { color: var(--info); } .low { color: var(--low); } .medium { color: var(--medium); }
.high { color: var(--high); } .critical { color: var(--critical); }
.pass { color: var(--clean); font-weight: 600; } .fail { color: var(--high); font-weight: 600; }
.muted { color: var(--muted); }
ul.flags { margin: 0; padding-left: 18px; color: var(--high); }
footer { color: var(--muted); font-size: 12px; margin-top: 24px; }
"""

VERDICT_COLOR = {"Clean": "--clean", "Suspicious": "--suspicious", "Likely phishing": "--phishing", "Malicious": "--malicious"}


def render_html(report):
    e = html.escape
    color = f"var({VERDICT_COLOR.get(report.verdict, '--muted')})"
    sender = f"{report.display_name} <{report.sender}>" if report.display_name else report.sender

    meta = "".join(
        f"<dt>{label}</dt><dd>{e(value)}</dd>"
        for label, value in [
            ("Subject", report.subject), ("From", sender), ("Reply-To", ", ".join(report.reply_to)),
            ("Return-Path", report.return_path), ("To", report.to), ("Date", report.date),
            ("Message-ID", report.message_id), ("Origin IP", report.originating_ip),
        ]
        if value
    )

    def result_class(result):
        return "pass" if result == "pass" else "fail" if result in ("fail", "softfail", "permerror") else "muted"

    auth_rows = "".join(
        f"<tr><td>{m.upper()}</td><td class='{result_class(i['result'])}'>{e(i['result'])}</td><td>{e(i['domain'])}</td></tr>"
        for m, i in report.auth.items()
    )

    finding_rows = "".join(
        f"<tr><td class='sev {f.severity}'>{f.severity}</td><td>{f.points}</td><td>{e(f.category)}</td><td>{e(f.message)}</td></tr>"
        for f in report.findings
    ) or "<tr><td colspan='4' class='pass'>Nothing suspicious found</td></tr>"

    def flags(items):
        return "<ul class='flags'>" + "".join(f"<li>{e(i)}</li>" for i in items) + "</ul>" if items else "<span class='muted'>none</span>"

    sections = []
    if report.urls:
        vt_head = "<th>VirusTotal</th>" if report.reputation_checked else ""
        rows = ""
        for u in report.urls:
            vt = f"<td>{e(u.reputation['summary']) if u.reputation else 'not checked'}</td>" if report.reputation_checked else ""
            text = f"<div class='muted'>shown as: {e(u.display_text)}</div>" if u.display_text else ""
            rows += f"<tr><td><span class='mono'>{e(defang(u.url))}</span>{text}</td><td>{flags(u.flags)}</td>{vt}</tr>"
        sections.append(f"<section><h2>URLs ({len(report.urls)})</h2><table><tr><th>URL (defanged)</th><th>Issues</th>{vt_head}</tr>{rows}</table></section>")

    if report.attachments:
        rows = ""
        for a in report.attachments:
            vt = f"<div>VirusTotal: {e(a.reputation['summary'])}</div>" if a.reputation else ""
            members = f"<div class='muted'>contains: {e(', '.join(a.archive_members[:10]))}</div>" if a.archive_members else ""
            rows += (
                f"<tr><td>{e(a.filename)}{members}</td><td>{e(a.content_type)}<div class='muted'>detected: {e(a.detected_type)}</div></td>"
                f"<td>{a.size:,} B</td><td><div class='mono'>SHA256 {a.sha256}</div><div class='mono muted'>MD5 {a.md5}</div></td>"
                f"<td>{flags(a.flags)}{vt}</td></tr>"
            )
        sections.append(f"<section><h2>Attachments ({len(report.attachments)})</h2><table><tr><th>File</th><th>Type</th><th>Size</th><th>Hashes</th><th>Issues</th></tr>{rows}</table></section>")

    if report.hops:
        rows = "".join(
            f"<tr><td>{i}</td><td class='mono'>{e(h['from'])}</td><td class='mono'>{e(h['by'])}</td><td class='mono'>{e(h['ip'])}</td><td>{e(h['date'])}</td></tr>"
            for i, h in enumerate(report.hops, 1)
        )
        sections.append(f"<section><h2>Delivery path (oldest first)</h2><table><tr><th>#</th><th>From</th><th>By</th><th>IP</th><th>Date</th></tr>{rows}</table></section>")

    iocs = render_iocs(report)
    if iocs:
        sections.append(f"<section><h2>Indicators of compromise (defanged)</h2><pre class='mono'>{e(iocs)}</pre></section>")

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    vt_note = "" if report.reputation_checked else " · VirusTotal checks were not run"

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Phishscope report</title>
<style>{CSS}</style>
</head>
<body>
<main>
<header>
  <span class="badge" style="background:{color}">{e(report.verdict.upper())}</span>
  <div class="score">{report.score}<small> / 100</small></div>
  <div class="meter"><span style="width:{report.score}%;background:{color}"></span></div>
</header>
<h1>{e(report.subject or "(no subject)")}</h1>
<p class="muted">{e(report.file)}</p>
<section><h2>Message</h2><dl>{meta}</dl></section>
<section><h2>Authentication</h2><table><tr><th>Check</th><th>Result</th><th>Domain</th></tr>{auth_rows}</table></section>
<section><h2>Findings</h2><table><tr><th>Severity</th><th>Points</th><th>Area</th><th>Detail</th></tr>{finding_rows}</table></section>
{''.join(sections)}
<footer>Generated by phishscope {__version__} on {generated}{vt_note}</footer>
</main>
</body>
</html>
"""

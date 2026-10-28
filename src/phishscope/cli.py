import sys
from pathlib import Path

import click
from rich.console import Console

from . import __version__
from .analyzer import analyze
from .report import render_html, render_iocs, render_terminal, to_json
from .virustotal import DEFAULT_CACHE, VirusTotal

EXIT_CODES = {"Clean": 0, "Suspicious": 1, "Likely phishing": 2, "Malicious": 3}


@click.group()
@click.version_option(__version__, prog_name="phishscope")
def cli():
    """Triage suspicious emails from .eml files."""


@cli.command("analyze")
@click.argument("files", nargs=-1, required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--vt-key", envvar="VT_API_KEY", help="VirusTotal API key (or set VT_API_KEY).")
@click.option("--live", is_flag=True, help="Also query DNS for DMARC/SPF records and re-verify DKIM.")
@click.option("--json", "as_json", is_flag=True, help="Print the report as JSON.")
@click.option("--html", "html_path", type=click.Path(dir_okay=False, path_type=Path), help="Write an HTML report.")
@click.option("--max-lookups", default=12, show_default=True, help="Maximum VirusTotal lookups per email.")
@click.option("--vt-rate", default=4, show_default=True, help="VirusTotal requests per minute (free tier is 4).")
@click.option("--no-cache", is_flag=True, help="Do not read or write the VirusTotal cache.")
@click.option("--exit-code", is_flag=True, help="Exit 0-3 by verdict: clean, suspicious, likely phishing, malicious.")
def analyze_cmd(files, vt_key, live, as_json, html_path, max_lookups, vt_rate, no_cache, exit_code):
    """Analyze one or more .eml files."""
    if html_path and len(files) > 1:
        raise click.UsageError("--html works with a single file")

    vt = VirusTotal(vt_key, cache_path=None if no_cache else DEFAULT_CACHE, requests_per_minute=vt_rate) if vt_key else None
    console = Console(stderr=as_json)

    reports = []
    for path in files:
        if vt and not as_json:
            console.print(f"[dim]Analyzing {path.name} (VirusTotal free tier is rate limited, this can take a minute)...[/dim]")
        reports.append(analyze(path, vt=vt, live=live, max_lookups=max_lookups))

    if as_json:
        click.echo(to_json(reports))
    else:
        for report in reports:
            render_terminal(report, console)
        if len(reports) > 1:
            console.print()
            for r in reports:
                console.print(f"{r.score:>3}  {r.verdict:<16} {r.file}", markup=False, highlight=False)

    if html_path:
        html_path.write_text(render_html(reports[0]), encoding="utf-8")
        console.print(f"HTML report written to {html_path}", markup=False, highlight=False)

    if exit_code:
        sys.exit(max(EXIT_CODES[r.verdict] for r in reports))


@cli.command("iocs")
@click.argument("file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--raw", is_flag=True, help="Print live (not defanged) indicators.")
def iocs_cmd(file, raw):
    """Print the indicators of compromise in an email."""
    output = render_iocs(analyze(file), raw=raw)
    click.echo(output or "No indicators found.")

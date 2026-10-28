# Phishscope

A phishing email triage tool for the command line. Give it a suspicious `.eml` file and it checks sender authentication, header anomalies, links, attachments and wording, looks indicators up on VirusTotal, and produces a 0–100 risk score with a verdict and the reasons behind it.

It follows the same steps a tier-1 SOC analyst works through when a user reports a phishing email, and turns them into a repeatable report.

## What it checks

| Area | Checks |
|------|--------|
| **Authentication** | SPF, DKIM and DMARC results from `Authentication-Results` / `Received-SPF`, DKIM and SPF alignment with the From domain. With `--live`: the domain's DMARC policy, whether it publishes SPF, and fresh DKIM signature verification |
| **Headers** | Reply-To and Return-Path pointing to other domains, spoofed display names (`"PayPal" <x@random.top>`), lookalike sender domains, Message-ID origin, missing headers, delivery path and originating IP |
| **URLs** | Link text that shows one domain but goes to another, raw IP links, punycode/homoglyph domains (`paypa1`, `rnicrosoft`, Cyrillic look-alikes), brand names in subdomains, shorteners, high-abuse TLDs, `user@host` tricks, HTML forms that post credentials |
| **Attachments** | MD5/SHA1/SHA256, executables and scripts, double extensions, right-to-left override filenames, macro-enabled Office files, VBA hidden in `.docx`, HTML/SVG smuggling, content type vs extension mismatch via magic bytes, archive listing, encrypted archives, executables inside archives |
| **Content** | Pressure and credential-bait phrases, password fields in the email body |
| **Reputation** | VirusTotal lookups for attachment hashes, URLs, domains and the sending IP |

## Install

Requires Python 3.10+.

```bash
git clone https://github.com/<your-username>/phishscope.git
cd phishscope
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```bash
phishscope analyze samples/phish_paypal_credential.eml
phishscope analyze suspicious.eml --live
phishscope analyze suspicious.eml --vt-key YOUR_KEY
phishscope analyze suspicious.eml --html report.html
phishscope analyze suspicious.eml --json > report.json
phishscope analyze inbox/*.eml
phishscope iocs suspicious.eml
```

To save an email as `.eml`: in Gmail open the message → ⋮ → *Download message*; in Outlook drag the message to a folder or use *File → Save As*; in Thunderbird use *File → Save As → File*.

### VirusTotal

Get a free API key from [virustotal.com](https://www.virustotal.com/gui/join-us), then:

```bash
export VT_API_KEY=your_key_here
phishscope analyze suspicious.eml
```

- The free tier allows 4 requests per minute. Phishscope spaces its requests to stay under that and retries once if it is rate limited.
- Results are cached for 24 hours in `~/.cache/phishscope/virustotal.json`. Use `--no-cache` to skip the cache.
- `--max-lookups` limits how many indicators are checked per email. Attachments are checked first, then URLs, domains and the sending IP.
- Phishscope only **looks up** indicators that already exist. It never **submits** URLs or files, because URLs in phishing emails often contain the victim's email address or a session token, and anything submitted to VirusTotal is visible to other users.

Without a key, all other checks still run.

### Output formats

- **Terminal**: a colour-coded report with findings sorted by weight
- **JSON** (`--json`): for scripts, SOAR playbooks or SIEM ingestion
- **HTML** (`--html`): a self-contained report to attach to a ticket. Every value from the email is escaped, links are defanged, and the page has a strict Content-Security-Policy, so a malicious email cannot run code in the report
- **IOCs** (`phishscope iocs`): defanged indicators ready to paste into a ticket. Add `--raw` for blocklist imports

### Exit codes

With `--exit-code`, the exit status reflects the worst verdict: `0` clean, `1` suspicious, `2` likely phishing, `3` malicious. This is useful for automating a reported-phishing mailbox.

## Scoring

Each check adds points. Points are capped per area, so one noisy area cannot max out the score by itself:

| Area | Cap |
|------|-----|
| Authentication | 45 |
| Headers | 45 |
| URLs | 45 |
| Attachments | 50 |
| Content | 20 |
| Reputation | 60 |

| Score | Verdict |
|-------|---------|
| 0–14 | Clean |
| 15–39 | Suspicious |
| 40–69 | Likely phishing |
| 70–100 | Malicious |

Some findings set a minimum score. An executable attachment never scores below *Likely phishing*. A URL, domain or IP flagged by 3 or more VirusTotal engines puts the email at *Malicious*, and so does an attachment hash flagged by 3 or more engines.

## Sample output

```
╭──────────────── MALICIOUS   risk score 100/100 ────────────────╮
│ Subject      Action Required: Your account has been limited    │
│ From         PayPal Security <service@paypa1-secure.com>       │
│ Reply-To     paypal.resolution.team@gmail.com                  │
│ Origin IP    91.215.85.17                                      │
│                                                                │
│ Authentication                                                 │
│   SPF     softfail   paypa1-secure.com                         │
│   DKIM    none                                                 │
│   DMARC   fail       paypa1-secure.com                         │
│                                                                │
│ Findings                                                       │
│   high  25  auth     DMARC fail for paypa1-secure.com          │
│   high  25  headers  Sender domain paypa1-secure.com imitates  │
│                      Paypal                                    │
│   high  25  urls     Link text shows www.paypal.com but        │
│                      actually goes to                          │
│                      paypal.com.account-verify.xyz             │
│   high  20  content  Email body contains a form with a         │
│                      password field                            │
│   ...                                                          │
╰────────────────────────────────────────────────────────────────╯
```

## Samples

`samples/` contains three made-up emails used by the tests:

| File | Expected verdict |
|------|------------------|
| `legit_github_notice.eml` | Clean (0) |
| `phish_paypal_credential.eml` | Malicious: lookalike domain, mismatched links, credential form, DMARC fail |
| `malware_invoice_attachment.eml` | Malicious: `.pdf.exe`, macro document, script inside a zip |

The attachments are placeholders. The fake executable only has a valid `MZ` header and contains no code.

## Limitations

- `Authentication-Results` is trusted as written by the receiving server. A forwarded email or a header added by the attacker can be misleading. The tool reads the topmost header, which is the one added by your own mail server.
- The organisational domain is found with a built-in list of common multi-part suffixes, not the full Public Suffix List.
- The brand impersonation list is short and focused on common phishing targets. Add your organisation's brands in `domains.py`.
- `--live` DKIM verification can fail on old emails because the sender may have rotated their key since then.
- Phishscope does static analysis only. It never opens attachments or visits URLs.

## Tests

```bash
pytest
```

72 tests cover header parsing, authentication results, URL and attachment heuristics, the VirusTotal client (with a fake HTTP session), scoring, HTML escaping and the CLI.

## Project layout

```
src/phishscope/
  parser.py       .eml parsing, bodies and attachments
  auth.py         SPF / DKIM / DMARC results, alignment, live DNS checks
  headers.py      header anomalies, delivery path, originating IP
  urls.py         URL extraction and heuristics
  attachments.py  hashing, file type detection, archive inspection
  content.py      phrasing and form checks
  domains.py      brand list, lookalike detection, domain helpers
  virustotal.py   VirusTotal v3 client with throttling and cache
  scoring.py      findings, weights, verdicts
  analyzer.py     ties every check into a report
  report.py       terminal, JSON, HTML and IOC output
  cli.py          command-line interface
samples/          safe example emails
tests/            pytest suite
```

## License

MIT

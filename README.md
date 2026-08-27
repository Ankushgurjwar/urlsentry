# 🛡️ URLSentry — Phishing & Malicious URL Scanner

A heuristic-based tool that analyzes URLs for common phishing and malicious indicators — no external API key required (works fully offline), with an optional VirusTotal reputation check if you provide an API key.

Built as a hands-on cybersecurity portfolio project: a working CLI tool *and* a Flask web app, backed by a shared detection engine and a real test suite.

![verdict](https://img.shields.io/badge/status-working-brightgreen) ![python](https://img.shields.io/badge/python-3.9%2B-blue) ![tests](https://img.shields.io/badge/tests-passing-brightgreen)

## ✨ Features

The scanner checks each URL against **15 heuristics** commonly used in real phishing campaigns:

| # | Check | What it catches |
|---|---|---|
| 1 | IP address as host | `http://192.168.1.1/login` instead of a domain |
| 2 | `@` symbol in URL | Hides the real destination from the visible text |
| 3 | Missing HTTPS | Unencrypted credential submission |
| 4 | Excessive URL length | Obfuscated or padded links |
| 5 | Excess hyphens in domain | `secure-paypal-login.com`-style spoofing |
| 6 | Excess subdomains | Brand name buried deep in a fake subdomain |
| 7 | Known URL shorteners | Hides destination until after clicking |
| 8 | High-abuse TLDs | `.top`, `.xyz`, `.tk`, etc. |
| 9 | Punycode / IDN homographs | Lookalike character domains |
| 10 | Suspicious keywords | `verify`, `login`, `webscr`, `suspend`, etc. |
| 11 | Brand impersonation | Brand name present but not the real domain |
| 12 | Typosquatting | Edit-distance match to popular domains (`paypa1.com`) |
| 13 | Non-standard ports | Unusual for consumer-facing sites |
| 14 | DNS resolution check | Confirms the domain is actually live |
| 15 | *(optional)* VirusTotal reputation | Cross-check against 70+ AV engines |

Each finding contributes a weighted score (0–100). The tool returns a verdict of **No Red Flags**, **Low Risk**, **Suspicious**, or **Likely Malicious / Phishing**.

## 🖥️ Screenshots

The web UI ("URLSentry") shows a live risk gauge, verdict, and a breakdown of every triggered rule with a plain-English explanation — built for someone non-technical to understand *why* a link was flagged.

## 🚀 Getting Started

```bash
git clone https://github.com/Ankushgurjwar/urlsentry.git
cd urlsentry
pip install -r requirements.txt
```

### Run the CLI

```bash
python cli.py https://example.com
python cli.py --file urls.txt          # scan a list of URLs
python cli.py https://example.com --json   # machine-readable output
```

Exit codes: `0` = clean, `1` = suspicious, `2` = likely malicious — handy for CI pipelines or scripting.

### Run the web app

```bash
python web.py
```

Open **http://localhost:5000** in your browser.

There's also a JSON API for integrating into other tools:

```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "http://secure-paypal-login-update.top"}'
```

### Optional: enable VirusTotal reputation checks

```bash
export VT_API_KEY="your_virustotal_api_key"
```

Without a key, the tool still works — it simply relies on the 14 offline heuristics.

## 🧪 Running Tests

```bash
pip install pytest
pytest tests/ -v
```

9 unit tests cover clean URLs, typosquatting, IP-based hosts, shorteners, and combined high-risk cases.

## 📁 Project Structure

```
urlsentry/
├── app/
│   └── scanner.py       # Core detection engine (heuristics + scoring)
├── templates/
│   └── index.html       # Web UI
├── tests/
│   └── test_scanner.py  # Unit tests
├── cli.py                # Command-line interface
├── web.py                # Flask web application
├── requirements.txt
└── README.md
```

## ⚠️ Limitations & Disclaimer

This is a heuristic tool built for **educational and portfolio purposes**. It is not a replacement for enterprise threat intelligence platforms. Heuristics can produce false positives (e.g. a legitimate site with many subdomains) and false negatives (a well-disguised phishing site with no obvious red flags). Always verify suspicious links through multiple sources before trusting or dismissing them.

## 🛣️ Possible Extensions

- WHOIS-based domain age lookup (very new domains are higher risk)
- Screenshot + visual similarity comparison against known brand login pages
- Browser extension front-end
- Bulk CSV scanning with a summary report

## 👤 Author

**Ankush Gurjwar**
Cybersecurity Analyst Intern — Maincrafts Technology

---
*Built as part of a cybersecurity internship portfolio.*

"""
scanner.py
Core heuristic engine for detecting suspicious / phishing URLs.

The scanner does NOT rely on any external threat-intel API by default, so it
works fully offline. If a VirusTotal API key is supplied (via the
VT_API_KEY environment variable), an optional reputation lookup is added on
top of the heuristics for a second opinion.
"""

import re
import socket
import ipaddress
import os
from dataclasses import dataclass, field
from urllib.parse import urlparse
from typing import List

import requests

# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "cutt.ly", "rebrand.ly", "shorte.st", "bl.ink", "rb.gy",
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "gq", "tk", "ml", "ga", "cf", "work",
    "click", "link", "loan", "download", "review", "country", "kim",
}

BRAND_KEYWORDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "facebook",
    "instagram", "netflix", "bank", "verify", "account", "secure",
    "login", "signin", "update", "confirm", "wallet", "support",
]

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "confirm",
    "password", "banking", "signin", "webscr", "ebayisapi", "urgent",
    "suspend", "unlock", "gift", "free", "prize", "winner",
]


@dataclass
class Finding:
    """A single heuristic flag raised while scanning a URL."""
    rule: str
    description: str
    weight: int  # contribution to the risk score (0-100 scale, summed)


@dataclass
class ScanResult:
    url: str
    normalized_url: str
    domain: str
    score: int = 0
    verdict: str = "Unknown"
    findings: List[Finding] = field(default_factory=list)
    vt_result: dict = None

    def add(self, rule: str, description: str, weight: int) -> None:
        self.findings.append(Finding(rule, description, weight))
        self.score += weight

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "normalized_url": self.normalized_url,
            "domain": self.domain,
            "score": self.score,
            "verdict": self.verdict,
            "findings": [
                {"rule": f.rule, "description": f.description, "weight": f.weight}
                for f in self.findings
            ],
            "vt_result": self.vt_result,
        }


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _normalize(url: str) -> str:
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url):
        url = "http://" + url
    return url


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _count_subdomains(host: str) -> int:
    parts = host.split(".")
    # crude heuristic: treat everything beyond "domain.tld" as subdomain levels
    return max(0, len(parts) - 2)


def _levenshtein(a: str, b: str) -> int:
    """Small, dependency-free edit distance implementation."""
    if a == b:
        return 0
    if len(a) == 0:
        return len(b)
    if len(b) == 0:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[-1]


POPULAR_DOMAINS = [
    "paypal.com", "amazon.com", "apple.com", "microsoft.com", "google.com",
    "facebook.com", "instagram.com", "netflix.com", "bankofamerica.com",
    "chase.com", "wellsfargo.com", "linkedin.com", "twitter.com", "x.com",
]


# ---------------------------------------------------------------------------
# Main scan function
# ---------------------------------------------------------------------------

def scan_url(raw_url: str, check_reputation: bool = True) -> ScanResult:
    normalized = _normalize(raw_url)
    parsed = urlparse(normalized)
    host = parsed.hostname or ""

    result = ScanResult(url=raw_url, normalized_url=normalized, domain=host)

    # 1. IP address used instead of a domain name
    if _is_ip(host):
        result.add(
            "ip_as_host",
            "The URL uses a raw IP address instead of a domain name — a common phishing tactic to hide the real destination.",
            25,
        )

    # 2. '@' symbol in the URL (browsers ignore everything before '@')
    if "@" in normalized:
        result.add(
            "at_symbol",
            "URL contains an '@' symbol, which can be used to disguise the true destination host.",
            25,
        )

    # 3. No HTTPS
    if parsed.scheme != "https":
        result.add(
            "no_https",
            "The link does not use HTTPS, so any submitted data would not be encrypted in transit.",
            10,
        )

    # 4. Excessive URL length
    if len(normalized) > 90:
        result.add(
            "long_url",
            f"URL is unusually long ({len(normalized)} characters), which can be used to hide suspicious parameters or obscure the domain.",
            10,
        )

    # 5. Many hyphens in the domain
    hyphen_count = host.count("-")
    if hyphen_count >= 2:
        result.add(
            "many_hyphens",
            f"Domain contains {hyphen_count} hyphens, often used to imitate a brand name (e.g. secure-paypal-login.com).",
            10,
        )

    # 6. Excessive subdomains
    sub_count = _count_subdomains(host)
    if sub_count >= 3:
        result.add(
            "many_subdomains",
            f"Domain has {sub_count} subdomain levels, which can be used to bury a fake brand name deep in the URL.",
            15,
        )

    # 7. Known URL shortener
    if host in KNOWN_SHORTENERS:
        result.add(
            "url_shortener",
            "URL uses a link-shortening service, which hides the real destination until after clicking.",
            15,
        )

    # 8. Suspicious / high-abuse TLD
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld.lower() in SUSPICIOUS_TLDS:
        result.add(
            "suspicious_tld",
            f"Top-level domain '.{tld}' is frequently associated with spam and phishing campaigns.",
            15,
        )

    # 9. Punycode / IDN homograph indicator
    if host.startswith("xn--") or "xn--" in host:
        result.add(
            "punycode",
            "Domain uses punycode encoding, which can visually disguise lookalike characters (an IDN homograph attack).",
            20,
        )

    # 10. Suspicious keywords in the URL
    lowered = normalized.lower()
    hit_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in lowered]
    if hit_keywords:
        result.add(
            "suspicious_keywords",
            f"URL contains phishing-associated keywords: {', '.join(sorted(set(hit_keywords)))}.",
            5 * min(len(hit_keywords), 4),
        )

    # 11. Brand impersonation heuristic — brand name present but NOT the real domain
    for brand in BRAND_KEYWORDS:
        if brand in host.lower() and not any(host.lower() == pd or host.lower().endswith("." + pd) for pd in POPULAR_DOMAINS):
            result.add(
                "brand_in_subdomain",
                f"Domain references the brand '{brand}' but is not that brand's official domain — possible impersonation.",
                20,
            )
            break

    # 12. Typosquatting — close edit-distance to a popular domain
    registrable = ".".join(host.split(".")[-2:]) if "." in host else host
    for pd in POPULAR_DOMAINS:
        dist = _levenshtein(registrable.lower(), pd)
        if 0 < dist <= 2:
            result.add(
                "typosquatting",
                f"Domain '{registrable}' is suspiciously similar to the popular domain '{pd}' (edit distance {dist}) — possible typosquatting.",
                30,
            )
            break

    # 13. Port explicitly specified (unusual for legitimate consumer sites)
    if parsed.port and parsed.port not in (80, 443):
        result.add(
            "nonstandard_port",
            f"URL specifies a non-standard port ({parsed.port}), unusual for legitimate consumer-facing websites.",
            10,
        )

    # 14. DNS resolution check — does the host even resolve?
    try:
        socket.setdefaulttimeout(3)
        socket.gethostbyname(host)
    except Exception:
        result.add(
            "dns_unresolvable",
            "The domain does not currently resolve to any IP address — it may be inactive, sinkholed, or fabricated.",
            10,
        )

    # 15. Optional VirusTotal reputation check
    if check_reputation:
        vt = _check_virustotal(normalized)
        if vt:
            result.vt_result = vt
            if vt.get("malicious", 0) > 0 or vt.get("suspicious", 0) > 0:
                result.add(
                    "vt_reputation",
                    f"VirusTotal: {vt.get('malicious', 0)} engines flagged this URL as malicious, "
                    f"{vt.get('suspicious', 0)} as suspicious.",
                    min(40, 5 * (vt.get("malicious", 0) + vt.get("suspicious", 0))),
                )

    # Final verdict
    result.score = min(result.score, 100)
    if result.score >= 60:
        result.verdict = "Likely Malicious / Phishing"
    elif result.score >= 30:
        result.verdict = "Suspicious"
    elif result.score > 0:
        result.verdict = "Low Risk"
    else:
        result.verdict = "No Red Flags Detected"

    return result


def _check_virustotal(url: str):
    """Optional reputation lookup. Requires VT_API_KEY env var. Returns None on
    any failure so the tool always still works with pure heuristics."""
    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        return None
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": api_key},
            timeout=5,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        }
    except Exception:
        return None

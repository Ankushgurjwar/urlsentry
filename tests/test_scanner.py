import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.scanner import scan_url


def test_clean_legit_url():
    result = scan_url("https://www.python.org", check_reputation=False)
    assert result.score < 30
    assert "Malicious" not in result.verdict


def test_ip_based_url_is_flagged():
    result = scan_url("http://192.168.1.1/login", check_reputation=False)
    rules = [f.rule for f in result.findings]
    assert "ip_as_host" in rules


def test_at_symbol_is_flagged():
    result = scan_url("http://real-bank.com@evil.com/login", check_reputation=False)
    rules = [f.rule for f in result.findings]
    assert "at_symbol" in rules


def test_typosquatting_is_flagged():
    result = scan_url("http://paypa1.com/login", check_reputation=False)
    rules = [f.rule for f in result.findings]
    assert "typosquatting" in rules or "brand_in_subdomain" in rules


def test_url_shortener_is_flagged():
    result = scan_url("http://bit.ly/3xample", check_reputation=False)
    rules = [f.rule for f in result.findings]
    assert "url_shortener" in rules


def test_no_https_is_flagged():
    result = scan_url("http://example.com", check_reputation=False)
    rules = [f.rule for f in result.findings]
    assert "no_https" in rules


def test_suspicious_tld_is_flagged():
    result = scan_url("http://free-gift.top", check_reputation=False)
    rules = [f.rule for f in result.findings]
    assert "suspicious_tld" in rules


def test_high_risk_url_gets_high_score():
    # Combine several red flags
    result = scan_url(
        "http://secure-paypal-login-update.verify-account.top/webscr?cmd=confirm",
        check_reputation=False,
    )
    assert result.score >= 30
    assert result.verdict in ("Suspicious", "Likely Malicious / Phishing")


def test_to_dict_serializable():
    result = scan_url("https://example.com", check_reputation=False)
    d = result.to_dict()
    assert d["url"] == "https://example.com"
    assert "findings" in d

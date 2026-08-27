#!/usr/bin/env python3
"""
cli.py — Command-line interface for the Phishing / Malicious URL Scanner.

Usage:
    python cli.py https://example.com
    python cli.py --file urls.txt
    python cli.py https://example.com --no-reputation
"""

import argparse
import sys
import json

from app.scanner import scan_url

RESET = "\033[0m"
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BOLD = "\033[1m"


def verdict_color(verdict: str) -> str:
    if "Malicious" in verdict:
        return RED
    if "Suspicious" in verdict:
        return YELLOW
    return GREEN


def print_result(result, as_json: bool):
    if as_json:
        print(json.dumps(result.to_dict(), indent=2))
        return

    color = verdict_color(result.verdict)
    print(f"\n{BOLD}URL:{RESET} {result.url}")
    print(f"{BOLD}Verdict:{RESET} {color}{result.verdict}{RESET}  (risk score: {result.score}/100)")

    if result.findings:
        print(f"{BOLD}Findings:{RESET}")
        for f in result.findings:
            print(f"  - [{f.rule}] {f.description} (+{f.weight})")
    else:
        print("  No heuristic red flags detected.")

    if result.vt_result:
        print(f"{BOLD}VirusTotal:{RESET} {result.vt_result}")


def main():
    parser = argparse.ArgumentParser(description="Scan URLs for phishing / malicious indicators.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("url", nargs="?", help="A single URL to scan")
    group.add_argument("--file", "-f", help="Path to a text file with one URL per line")
    parser.add_argument("--no-reputation", action="store_true", help="Skip optional VirusTotal lookup")
    parser.add_argument("--json", action="store_true", help="Output raw JSON instead of formatted text")
    args = parser.parse_args()

    urls = []
    if args.url:
        urls = [args.url]
    elif args.file:
        with open(args.file) as fh:
            urls = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

    if not urls:
        print("No URLs provided.", file=sys.stderr)
        sys.exit(1)

    exit_code = 0
    for u in urls:
        result = scan_url(u, check_reputation=not args.no_reputation)
        print_result(result, args.json)
        if "Malicious" in result.verdict:
            exit_code = 2
        elif "Suspicious" in result.verdict and exit_code == 0:
            exit_code = 1

    sys.exit(exit_code)


if __name__ == "__main__":
    main()

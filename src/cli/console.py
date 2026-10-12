"""
Command Line Interface (CLI) for Phishing Awareness Analyzer.

Author: Ali Abbas Haidar (Raqin Al-Asraar)
Features:
- Single email file inspection (--file)
- Standalone URL static scanning (--url)
- Batch benchmark runner across synthetic corpus (--corpus)
- JSON export mode (--json)
- Interactive CLI prompt mode
"""

import argparse
import json
from pathlib import Path
import sys

# Bootstrap sys.path for direct execution
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.core import analyze_file, analyze_input, analyze_standalone_url

CORPUS_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "corpus"

# ANSI Terminal Colors
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
ORANGE = "\033[38;5;208m"
RED = "\033[91m"
CYAN = "\033[96m"
GRAY = "\033[90m"


def print_banner():
    print(f"{CYAN}{BOLD}===================================================================={RESET}")
    print(f"{CYAN}{BOLD}        PHISHING AWARENESS ANALYZER - CLI RUNNER{RESET}")
    print(f"        Cybersecurity Threat Detection & Heuristics Engine")
    print(f"        Author: {BOLD}Ali Abbas Haidar (Raqin Al-Asraar){RESET} | @raqinalasraar")
    print(f"{CYAN}{BOLD}===================================================================={RESET}")


def get_tier_color(tier_level: str) -> str:
    if tier_level == "low":
        return GREEN
    elif tier_level == "suspicious":
        return YELLOW
    elif tier_level == "moderate":
        return ORANGE
    return RED


def print_report_terminal(report):
    data = report.to_dict()
    score = data["risk_score"]
    tier = data["tier"]
    color = get_tier_color(tier["level"])

    print(f"\n{BOLD}[+] THREAT ASSESSMENT SUMMARY:{RESET}")
    print(f"  Risk Score:  {color}{BOLD}{score} / 100{RESET} ({color}{tier['name'].upper()}{RESET})")
    print(f"  Verdict:     {tier['verdict']}")
    print(f"  Breakdown:   Headers: +{data['component_scores']['header_points']} pts | Body: +{data['component_scores']['body_points']} pts | URLs: +{data['component_scores']['url_points']} pts | Auth: -{data['component_scores']['auth_bonus']} pts")

    if data.get("sender_info") and data["sender_info"]["from_email"]:
        s = data["sender_info"]
        print(f"\n{BOLD}[+] SENDER & AUTHENTICATION:{RESET}")
        print(f"  From:        {s['from_display']} <{s['from_email']}>")
        print(f"  Domain:      {s['from_domain']}")
        if s.get("reply_to"):
            print(f"  Reply-To:    {s['reply_to']}")
        print(f"  Subject:     {s.get('subject', 'N/A')}")
        spf_color = GREEN if s['spf'] == 'pass' else (RED if s['spf'] == 'fail' else GRAY)
        dkim_color = GREEN if s['dkim'] == 'pass' else (RED if s['dkim'] == 'fail' else GRAY)
        print(f"  SPF Record:  {spf_color}{s['spf'].upper()}{RESET} | DKIM Signature: {dkim_color}{s['dkim'].upper()}{RESET}")

    findings = data.get("findings", [])
    print(f"\n{BOLD}[+] HEURISTIC THREAT INDICATORS ({len(findings)}):{RESET}")
    if not findings:
        print(f"  {GREEN}No suspicious threat indicators flagged.{RESET}")
    else:
        for idx, f in enumerate(findings, 1):
            sev_col = RED if f["severity"] in ("critical", "high") else YELLOW
            print(f"  {idx}. [{sev_col}{f['severity'].upper()}{RESET}] {BOLD}{f['category'].replace('_', ' ').title()}{RESET} (+{f['points']} pts)")
            print(f"     {f['description']}")
            if f.get("evidence"):
                print(f"     {GRAY}Evidence: {f['evidence']}{RESET}")

    urls = data.get("urls", [])
    if urls:
        print(f"\n{BOLD}[+] EMBEDDED HYPERLINKS ({len(urls)}):{RESET}")
        for u in urls:
            u_col = RED if u["risk_score"] >= 50 else (YELLOW if u["risk_score"] >= 25 else GREEN)
            print(f"  - {u['url']} [{u_col}{u['risk_score']} pts{RESET}]")

    print(f"\n{BOLD}[+] RECOMMENDED ACTIONS:{RESET}")
    for rec in data.get("recommendations", []):
        print(f"  • {rec}")

    print(f"\n{YELLOW}{BOLD}[!] DISCLAIMER:{RESET}")
    print(f"  {GRAY}{data['disclaimer']}{RESET}\n")


def run_benchmark_cli():
    print_banner()
    print(f"\n{BOLD}[*] Running Benchmark Suite across Synthetic Corpus...{RESET}\n")
    if not CORPUS_DIR.is_dir():
        print(f"{RED}Error: Corpus directory not found at {CORPUS_DIR}{RESET}")
        return

    emls = sorted(CORPUS_DIR.glob("*.eml"))
    print(f"{'Sample File':<32} | {'Expected':<12} | {'Score':<5} | {'Tier':<14} | {'Flags':<5}")
    print("-" * 78)

    for eml in emls:
        report = analyze_file(eml)
        data = report.to_dict()
        expected = "Legitimate" if eml.name.startswith("legit_") else "Phishing"
        exp_col = GREEN if expected == "Legitimate" else RED
        tier_col = get_tier_color(data["tier"]["level"])

        print(
            f"{eml.name:<32} | "
            f"{exp_col}{expected:<12}{RESET} | "
            f"{tier_col}{data['risk_score']:<5}{RESET} | "
            f"{tier_col}{data['tier']['name']:<14}{RESET} | "
            f"{len(data['findings']):<5}"
        )
    print("-" * 78)
    print(f"{GREEN}[✓] Benchmark complete across all {len(emls)} synthetic test cases.{RESET}\n")


def main():
    parser = argparse.ArgumentParser(description="Phishing Awareness Analyzer - Threat Detection & Heuristics CLI")
    parser.add_argument("-f", "--file", help="Path to email file (.eml or text) to analyze")
    parser.add_argument("-u", "--url", help="Target URL to inspect statically")
    parser.add_argument("-c", "--corpus", action="store_true", help="Run benchmark across all synthetic corpus samples")
    parser.add_argument("-j", "--json", action="store_true", help="Output results in JSON format")

    args = parser.parse_args()

    if args.corpus:
        run_benchmark_cli()
        return

    if args.file:
        file_path = Path(args.file)
        if not file_path.is_file():
            print(f"{RED}Error: File not found: {file_path}{RESET}", file=sys.stderr)
            sys.exit(1)
        report = analyze_file(file_path)
        if args.json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print_banner()
            print(f"\n[*] Analyzed file: {file_path}")
            print_report_terminal(report)
        return

    if args.url:
        report = analyze_standalone_url(args.url)
        if args.json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print_banner()
            print(f"\n[*] Inspected URL: {args.url}")
            print_report_terminal(report)
        return

    # Interactive mode
    print_banner()
    print("\nSelect an option:")
    print("  1. Analyze email message (paste text)")
    print("  2. Inspect standalone URL")
    print("  3. Run Synthetic Corpus Benchmark")
    print("  4. Exit")

    choice = input("\nEnter choice (1-4): ").strip()
    if choice == "1":
        print("\nEnter or paste raw email message (end with Ctrl+D or an empty line with 'END'):")
        lines = []
        try:
            while True:
                line = input()
                if line.strip() == "END":
                    break
                lines.append(line)
        except EOFError:
            pass
        content = "\n".join(lines).strip()
        if content:
            rep = analyze_input(content)
            print_report_terminal(rep)
    elif choice == "2":
        u = input("Enter URL to inspect: ").strip()
        if u:
            rep = analyze_standalone_url(u)
            print_report_terminal(rep)
    elif choice == "3":
        run_benchmark_cli()
    else:
        print("Exiting.")


if __name__ == "__main__":
    main()

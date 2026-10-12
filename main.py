"""
Phishing Awareness Analyzer - Threat Detection & Heuristics Engine.

Batch 01 - Task 2: Cybersecurity Internship
Author: Ali Abbas Haidar (Raqin Al-Asraar)
GitHub: @raqinalasraar (https://github.com/raqinalasraar)
Email: aliabbashaidar313@gmail.com

Operating Modes:
- Default: Modern Web GUI (Chromium --app mode / browser)
- --qt: Native PyQt6 Desktop GUI
- --cli: Command-Line Interface (Interactive or batch)
- -f / --file: Analyze email file via CLI
- -u / --url: Inspect URL via CLI
- -c / --corpus: Run benchmark suite across synthetic test corpus
"""

import argparse
from pathlib import Path
import sys

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def main():
    parser = argparse.ArgumentParser(
        description="Phishing Awareness Analyzer - Threat Detection & Heuristics (Task 2)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python3 main.py                  # Launch modern Web GUI (Default)
  python3 main.py --qt             # Launch native PyQt6 Desktop GUI
  python3 main.py --cli            # Launch interactive CLI
  python3 main.py -f email.eml     # Analyze specific email file
  python3 main.py -u https://...   # Inspect specific URL
  python3 main.py --corpus         # Run benchmark suite across synthetic corpus
        """,
    )

    parser.add_argument("--qt", action="store_true", help="Launch native PyQt6 GUI instead of Web App")
    parser.add_argument("--cli", action="store_true", help="Launch CLI interactive console")
    parser.add_argument("-f", "--file", help="Path to email file (.eml or text) to analyze via CLI")
    parser.add_argument("-u", "--url", help="URL to inspect statically via CLI")
    parser.add_argument("-c", "--corpus", action="store_true", help="Run benchmark on synthetic test corpus")
    parser.add_argument("-j", "--json", action="store_true", help="Output results in JSON format (CLI mode)")
    parser.add_argument("-p", "--port", type=int, default=None, help="Port for Web GUI server (default: dynamic free port)")
    parser.add_argument("--no-browser", action="store_true", help="Start web server without opening browser")

    args, unknown = parser.parse_known_args()

    # Route 1: CLI mode if specific CLI flags are provided
    if args.cli or args.file or args.url or args.corpus or args.json:
        from src.cli.console import main as cli_main
        sys.argv = [sys.argv[0]] + (["-f", args.file] if args.file else []) + \
                   (["-u", args.url] if args.url else []) + \
                   (["-c"] if args.corpus else []) + \
                   (["-j"] if args.json else [])
        cli_main()
        return

    # Route 2: Native PyQt6 GUI
    if args.qt:
        try:
            from src.gui.main_window import run_gui
            run_gui()
        except ImportError as e:
            print(f"[!] PyQt6 is not installed ({e}).")
            print("[*] Falling back to modern Web GUI...")
            from src.web.server import run_web_server
            run_web_server(port=args.port, open_browser=not args.no_browser)
        return

    # Route 3: Modern Desktop Web GUI (Default)
    from src.web.server import run_web_server
    run_web_server(port=args.port, open_browser=not args.no_browser)


if __name__ == "__main__":
    main()

"""
Local Web Server & Native App Launcher for Phishing Awareness Analyzer.

Serves the modern Flutter/Material 3 style web application on 127.0.0.1 (loopback only)
and launches in Chromium --app mode for a clean native desktop window feel.
"""

from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import threading
import time
from typing import Optional
from urllib.parse import unquote, urlparse
import webbrowser

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.core import analyze_file, analyze_input

WEB_DIR = Path(__file__).resolve().parent
CORPUS_DIR = PROJECT_ROOT / "data" / "corpus"

CORPUS_METADATA = {
    "phishing_paypal.eml": {
        "title": "PayPal Account Suspension",
        "type": "Phishing",
        "description": "Display spoofing, leetspeak domain, urgency cues, SPF fail",
    },
    "phishing_m365_reset.eml": {
        "title": "Microsoft 365 Password Expiry",
        "type": "Phishing",
        "description": "Raw IP destination, credential harvesting language, high urgency",
    },
    "phishing_bank_urgency.eml": {
        "title": "Chase Bank Security Alert",
        "type": "Phishing",
        "description": "Subdomain brand trickery, generic greeting, fake security alert",
    },
    "phishing_fake_invoice.eml": {
        "title": "DHL Customs Clearance Fee",
        "type": "Phishing",
        "description": "Reply-To discrepancy, IP address host, fee extortion lure",
    },
    "legit_github_notification.eml": {
        "title": "GitHub Pull Request Notification",
        "type": "Legitimate",
        "description": "Cryptographically signed (SPF pass, DKIM pass), official domain",
    },
    "legit_newsletter.eml": {
        "title": "Python Weekly Newsletter",
        "type": "Legitimate",
        "description": "Verified publication newsletter with passing sender policies",
    },
    "legit_order_receipt.eml": {
        "title": "Store Parcel Receipt",
        "type": "Legitimate",
        "description": "Legitimate order confirmation and shipment tracking",
    },
}


class PhishingAppHandler(SimpleHTTPRequestHandler):
    """Handles static files and API requests strictly on 127.0.0.1."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_DIR), **kwargs)

    def log_message(self, format, *args):
        # Quiet logger to keep terminal clean unless debugging
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/corpus":
            self.handle_corpus_list()
        elif path.startswith("/api/corpus/"):
            filename = unquote(path[len("/api/corpus/"):])
            self.handle_corpus_file(filename)
        elif path == "/api/benchmark":
            self.handle_benchmark()
        else:
            # Serve index.html by default
            if path in ("", "/"):
                self.path = "/index.html"
            super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/analyze":
            self.handle_analyze()
        else:
            self.send_error(404, "Endpoint not found")

    def handle_analyze(self):
        try:
            content_len = int(self.headers.get("Content-Length", 0))
            post_body = self.rfile.read(content_len).decode("utf-8")
            payload = json.loads(post_body)
            raw_text = payload.get("text", "")

            report = analyze_input(raw_text)
            resp_data = report.to_dict()

            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(resp_data, indent=2).encode("utf-8"))
        except Exception as e:
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))

    def handle_corpus_list(self):
        files = []
        if CORPUS_DIR.is_dir():
            for eml in sorted(CORPUS_DIR.glob("*.eml")):
                meta = CORPUS_METADATA.get(eml.name, {
                    "title": eml.name,
                    "type": "Synthetic",
                    "description": "Corpus test email"
                })
                files.append({
                    "filename": eml.name,
                    "title": meta["title"],
                    "type": meta["type"],
                    "description": meta["description"],
                })

        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(json.dumps({"files": files}).encode("utf-8"))

    def handle_corpus_file(self, filename: str):
        safe_path = (CORPUS_DIR / filename).resolve()
        # Security check: Ensure file resides strictly within CORPUS_DIR
        if safe_path.parent != CORPUS_DIR.resolve() or not safe_path.is_file():
            self.send_error(404, "Corpus file not found")
            return

        try:
            content = safe_path.read_text(encoding="utf-8", errors="replace")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(content.encode("utf-8"))
        except Exception as e:
            self.send_error(500, f"Error reading file: {e}")

    def handle_benchmark(self):
        results = []
        if CORPUS_DIR.is_dir():
            for eml in sorted(CORPUS_DIR.glob("*.eml")):
                try:
                    report = analyze_file(eml)
                    rep_dict = report.to_dict()
                    meta = CORPUS_METADATA.get(eml.name, {
                        "title": eml.name,
                        "type": "Unknown",
                    })
                    results.append({
                        "filename": eml.name,
                        "title": meta["title"],
                        "expected_truth": meta["type"],
                        "risk_score": rep_dict["risk_score"],
                        "tier": rep_dict["tier"],
                        "findings_count": len(rep_dict["findings"]),
                    })
                except Exception as e:
                    results.append({
                        "filename": eml.name,
                        "title": eml.name,
                        "expected_truth": "Error",
                        "risk_score": -1,
                        "tier": {"name": "Error", "color": "#ef4444"},
                        "findings_count": 0,
                    })

        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(json.dumps({"results": results}).encode("utf-8"))


def find_free_port() -> int:
    """Finds an available TCP port on loopback."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def launch_browser_or_app(url: str):
    """
    Attempts to launch in Chromium / Chrome app mode for a native window experience.
    Falls back to system default browser if Chromium is unavailable.
    """
    chrome_bins = [
        "/usr/bin/chromium",
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium-browser",
        "chromium",
        "google-chrome",
    ]

    for bin_name in chrome_bins:
        path = shutil.which(bin_name)
        if path:
            try:
                subprocess.Popen(
                    [
                        path,
                        f"--app={url}",
                        "--no-first-run",
                        "--no-default-browser-check",
                        f"--user-data-dir=/tmp/phishing_app_user_data",
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                return
            except Exception:
                pass

    # Fallback to default browser
    webbrowser.open(url)


def run_web_server(port: Optional[int] = None, open_browser: bool = True):
    """Starts the local web server and opens the application."""
    if not port:
        port = find_free_port()

    server = ThreadingHTTPServer(("127.0.0.1", port), PhishingAppHandler)
    url = f"http://127.0.0.1:{port}"

    print(f"============================================================")
    print(f"  Phishing Awareness Analyzer - Desktop Web GUI")
    print(f"  Author: Ali Abbas Haidar (Raqin Al-Asraar)")
    print(f"============================================================")
    print(f"  Server running locally at: {url}")
    print(f"  Press Ctrl+C to terminate the application.")
    print(f"============================================================")

    if open_browser:
        threading.Thread(target=lambda: (time.sleep(0.4), launch_browser_or_app(url)), daemon=True).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Shutting down local web server.")
        server.server_close()


if __name__ == "__main__":
    port_arg = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else None
    run_web_server(port=port_arg)

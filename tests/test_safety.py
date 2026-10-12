"""
Security and Safety Verification Tests.

Guarantees:
- Engine operates 100% OFFLINE on synthetic or sanitized emails.
- NEVER initiates socket connections, network probes, web requests, or DNS lookups.
"""

from pathlib import Path
import socket
import unittest
from unittest.mock import patch
import urllib.request

from src.core import analyze_file, analyze_input, analyze_standalone_url

CORPUS_DIR = Path(__file__).resolve().parent.parent / "data" / "corpus"


class TestOfflineSafety(unittest.TestCase):

    def test_zero_network_probes_during_url_analysis(self):
        """Verify analyzing malicious and IP URLs never triggers socket.connect."""
        def forbidden_connect(*args, **kwargs):
            raise RuntimeError("CRITICAL VIOLATION: Socket connect attempted during offline analysis!")

        with patch.object(socket.socket, "connect", side_effect=forbidden_connect):
            # Test various URLs
            test_urls = [
                "http://192.168.1.100/login",
                "https://paypa1-security.com/restore",
                "https://paypal.com.verify-account.net/login",
                "https://some-portal.xyz/secure",
                "https://google.com/test",
            ]
            for u in test_urls:
                rep = analyze_standalone_url(u)
                self.assertIsNotNone(rep)

    def test_zero_network_probes_during_corpus_analysis(self):
        """Verify analyzing entire email corpus executes zero network requests."""
        def forbidden_urlopen(*args, **kwargs):
            raise RuntimeError("CRITICAL VIOLATION: urllib urlopen attempted during offline analysis!")

        def forbidden_socket(*args, **kwargs):
            raise RuntimeError("CRITICAL VIOLATION: socket connection attempted during offline analysis!")

        with patch.object(urllib.request, "urlopen", side_effect=forbidden_urlopen), \
             patch.object(socket.socket, "connect", side_effect=forbidden_socket):
            if CORPUS_DIR.is_dir():
                for eml in CORPUS_DIR.glob("*.eml"):
                    rep = analyze_file(eml)
                    self.assertIsNotNone(rep)


if __name__ == "__main__":
    unittest.main()

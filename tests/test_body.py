"""
Unit tests for Email Body Analyzer and Linguistic/Content Heuristics.
"""

import unittest
from src.core.body_analyzer import analyze_body, extract_links, strip_html_tags


class TestBodyAnalyzer(unittest.TestCase):

    def test_urgency_detection(self):
        body = "Action required immediately! Your account will be closed within 24 hours if no response."
        res = analyze_body(body)
        urgency_findings = [f for f in res.findings if f.category == "urgency"]
        self.assertGreater(len(urgency_findings), 0)
        self.assertIn("within 24 hours", res.urgency_matches)
        self.assertIn("immediately", res.urgency_matches)

    def test_credential_harvesting_detection(self):
        body = "Please confirm your password and update payment method to restore access."
        res = analyze_body(body)
        cred_findings = [f for f in res.findings if f.category == "credential_harvesting"]
        self.assertGreater(len(cred_findings), 0)
        self.assertIn("confirm your password", res.credential_matches)

    def test_impersonal_greeting(self):
        body = "Dear Customer,\n\nWe detected a sign-in attempt from an unknown device."
        res = analyze_body(body)
        greeting_findings = [f for f in res.findings if f.category == "impersonal_greeting"]
        self.assertEqual(len(greeting_findings), 1)
        self.assertEqual(res.greeting_match, "dear customer")

    def test_html_obfuscation_zero_width(self):
        html_body = "<html><body>Account\u200b suspended\u200b!</body></html>"
        res = analyze_body(html_body)
        obfuscation_findings = [f for f in res.findings if f.category == "html_obfuscation"]
        self.assertGreaterEqual(len(obfuscation_findings), 1)

    def test_html_hidden_styling(self):
        html_body = '<html><body><span style="display:none">harmless text</span>Please login!</body></html>'
        res = analyze_body(html_body)
        obfuscation_findings = [f for f in res.findings if f.category == "html_obfuscation"]
        self.assertGreaterEqual(len(obfuscation_findings), 1)

    def test_extract_links_html_and_plain(self):
        html = '<p>Click <a href="https://example.com/login">here</a></p> and visit https://plain.org'
        plain = 'Click here and visit https://plain.org'
        links = extract_links(plain, html)
        urls = [link.url for link in links]
        self.assertIn("https://example.com/login", urls)
        self.assertIn("https://plain.org", urls)

    def test_strip_html_tags(self):
        raw_html = "<div><p>Hello &amp; <b>World</b></p><script>alert(1)</script></div>"
        cleaned = strip_html_tags(raw_html)
        self.assertIn("Hello & World", cleaned)
        self.assertNotIn("alert(1)", cleaned)
        self.assertNotIn("<p>", cleaned)


if __name__ == "__main__":
    unittest.main()

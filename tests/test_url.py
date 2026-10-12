"""
Unit tests for URL and Hyperlink Inspection Heuristics.
"""

import unittest
from src.core.url_analyzer import analyze_single_url, analyze_urls, is_ip_address


class TestURLAnalyzer(unittest.TestCase):

    def test_ip_address_detection(self):
        self.assertTrue(is_ip_address("192.168.1.1"))
        self.assertTrue(is_ip_address("198.51.100.24:8080"))
        self.assertFalse(is_ip_address("paypal.com"))

        res = analyze_single_url("http://192.168.1.100/login")
        self.assertTrue(res.is_ip)
        ip_findings = [f for f in res.findings if f.category == "ip_host"]
        self.assertEqual(len(ip_findings), 1)
        self.assertEqual(ip_findings[0].severity, "critical")

    def test_anchor_text_mismatch(self):
        res = analyze_single_url(
            url="http://evil-attacker.com/login",
            anchor_text="https://www.paypal.com/signin",
        )
        mismatch_findings = [f for f in res.findings if f.category == "anchor_mismatch"]
        self.assertEqual(len(mismatch_findings), 1)
        self.assertEqual(mismatch_findings[0].severity, "critical")
        self.assertGreaterEqual(mismatch_findings[0].risk_points, 40)

    def test_high_risk_tld(self):
        res = analyze_single_url("https://account-verify.xyz/update")
        tld_findings = [f for f in res.findings if f.category == "high_risk_tld"]
        self.assertEqual(len(tld_findings), 1)
        self.assertEqual(tld_findings[0].severity, "high")

    def test_subdomain_brand_spoof(self):
        res = analyze_single_url("https://paypal.com.account-update.net/login")
        sub_findings = [f for f in res.findings if f.category == "subdomain_spoof"]
        self.assertEqual(len(sub_findings), 1)
        self.assertEqual(sub_findings[0].severity, "critical")

    def test_typosquatting_and_leetspeak(self):
        res1 = analyze_single_url("https://paypa1-security.com/restore")
        typo1 = [f for f in res1.findings if f.category == "typosquatting"]
        self.assertGreaterEqual(len(typo1), 1)

        res2 = analyze_single_url("https://micros0ft-portal.org/login")
        typo2 = [f for f in res2.findings if f.category == "typosquatting"]
        self.assertGreaterEqual(len(typo2), 1)

    def test_clean_legitimate_url(self):
        res = analyze_single_url("https://github.com/login")
        self.assertEqual(res.risk_score, 0)
        self.assertEqual(len(res.findings), 0)


if __name__ == "__main__":
    unittest.main()

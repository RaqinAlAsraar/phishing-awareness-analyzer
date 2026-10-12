"""
Unit tests for Header Analyzer and Spoofing Heuristics.
"""

import unittest
from src.core.header_analyzer import analyze_headers, extract_domain, parse_auth_headers


class TestHeaderAnalyzer(unittest.TestCase):

    def test_extract_domain(self):
        self.assertEqual(extract_domain("support@paypal.com"), "paypal.com")
        self.assertEqual(extract_domain("User <john@example.org>"), "example.org")
        self.assertEqual(extract_domain("invalid-string"), "")

    def test_display_name_spoofing_detected(self):
        raw = (
            'From: "PayPal Security" <attacker@randomvps.com>\n'
            'Subject: Account Alert\n'
            'To: victim@target.com\n\n'
            'Test body'
        )
        res = analyze_headers(raw)
        self.assertEqual(res.from_domain, "randomvps.com")
        spoof_findings = [f for f in res.findings if f.category == "display_spoofing"]
        self.assertEqual(len(spoof_findings), 1)
        self.assertEqual(spoof_findings[0].severity, "critical")
        self.assertGreaterEqual(spoof_findings[0].risk_points, 30)

    def test_display_name_legitimate_brand(self):
        raw = (
            'From: "PayPal Service" <service@paypal.com>\n'
            'Subject: Monthly Statement\n'
            'Authentication-Results: mx.google.com; spf=pass; dkim=pass\n\n'
            'Your monthly statement is ready.'
        )
        res = analyze_headers(raw)
        spoof_findings = [f for f in res.findings if f.category == "display_spoofing"]
        self.assertEqual(len(spoof_findings), 0)
        self.assertEqual(res.spf_status, "pass")
        self.assertEqual(res.dkim_status, "pass")
        self.assertGreater(res.auth_bonus, 0)

    def test_reply_to_mismatch(self):
        raw = (
            'From: "Support" <support@legitbrand.com>\n'
            'Reply-To: attacker-box@disposable.net\n'
            'Subject: Urgent issue\n\n'
            'Please reply to this email.'
        )
        res = analyze_headers(raw)
        mismatch_findings = [f for f in res.findings if f.category == "reply_to_mismatch"]
        self.assertEqual(len(mismatch_findings), 1)
        self.assertEqual(mismatch_findings[0].severity, "high")

    def test_spf_and_dkim_fail_parsing(self):
        raw = (
            'From: "Admin" <admin@corporate.com>\n'
            'Authentication-Results: mx.google.com; spf=fail; dkim=fail\n'
            'Subject: Test Alert\n\n'
            'Body text'
        )
        res = analyze_headers(raw)
        self.assertEqual(res.spf_status, "fail")
        self.assertEqual(res.dkim_status, "fail")
        spf_findings = [f for f in res.findings if f.category == "spf_fail"]
        dkim_findings = [f for f in res.findings if f.category == "dkim_fail"]
        self.assertEqual(len(spf_findings), 1)
        self.assertEqual(len(dkim_findings), 1)

    def test_freemail_spoof_corporate(self):
        raw = (
            'From: "Internal IT Helpdesk" <it.helpdesk2024@gmail.com>\n'
            'Subject: Password update\n\n'
            'Update your credentials.'
        )
        res = analyze_headers(raw)
        freemail_findings = [f for f in res.findings if f.category == "free_mail_spoof"]
        self.assertEqual(len(freemail_findings), 1)


if __name__ == "__main__":
    unittest.main()

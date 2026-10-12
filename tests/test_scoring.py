"""
Unit tests for Scoring Engine, Risk Tiers, and Disclaimer handling.
"""

import unittest
from src.core.scoring import FALSE_POSITIVE_DISCLAIMER, compute_risk_score, get_risk_tier
from src.core.header_analyzer import HeaderFinding
from src.core.body_analyzer import BodyFinding
from src.core.url_analyzer import URLFinding


class TestScoringEngine(unittest.TestCase):

    def test_risk_tier_mapping(self):
        self.assertEqual(get_risk_tier(0).level, "low")
        self.assertEqual(get_risk_tier(20).level, "low")
        self.assertEqual(get_risk_tier(25).level, "suspicious")
        self.assertEqual(get_risk_tier(45).level, "suspicious")
        self.assertEqual(get_risk_tier(50).level, "moderate")
        self.assertEqual(get_risk_tier(70).level, "moderate")
        self.assertEqual(get_risk_tier(75).level, "high")
        self.assertEqual(get_risk_tier(100).level, "high")

    def test_clean_input_zero_score(self):
        score_res = compute_risk_score(
            header_findings=[],
            body_findings=[],
            url_findings=[],
            auth_bonus=25,
        )
        self.assertEqual(score_res.final_score, 0)
        self.assertEqual(score_res.tier.level, "low")
        self.assertIn("No obvious phishing characteristics", score_res.recommendations[0])

    def test_critical_phishing_combination(self):
        h_find = [
            HeaderFinding("display_spoofing", "critical", "Spoofed PayPal", 35, "From: PayPal"),
            HeaderFinding("spf_fail", "critical", "SPF Fail", 30, "SPF: fail"),
        ]
        b_find = [
            BodyFinding("urgency", "critical", "Urgent notice", 25, "within 24 hours"),
            BodyFinding("credential_harvesting", "critical", "Confirm password", 30, "confirm password"),
        ]
        u_find = [
            URLFinding("ip_host", "critical", "IP host link", 40, "http://1.2.3.4"),
        ]
        score_res = compute_risk_score(h_find, b_find, u_find, auth_bonus=0)
        self.assertEqual(score_res.final_score, 100)
        self.assertEqual(score_res.tier.level, "high")
        self.assertIn("DO NOT click any links", score_res.recommendations[0])

    def test_disclaimer_presence(self):
        score_res = compute_risk_score([], [], [])
        self.assertEqual(score_res.disclaimer, FALSE_POSITIVE_DISCLAIMER)
        self.assertIn("EDUCATIONAL NOTICE", score_res.disclaimer)


if __name__ == "__main__":
    unittest.main()

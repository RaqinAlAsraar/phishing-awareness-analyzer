"""
Integration tests verifying accuracy and detection across the synthetic corpus.
"""

from pathlib import Path
import unittest

from src.core import analyze_file

CORPUS_DIR = Path(__file__).resolve().parent.parent / "data" / "corpus"


class TestCorpusBenchmark(unittest.TestCase):

    def test_synthetic_phishing_emails_flagged_high_risk(self):
        phishing_files = [
            "phishing_paypal.eml",
            "phishing_m365_reset.eml",
            "phishing_bank_urgency.eml",
            "phishing_fake_invoice.eml",
        ]
        for fn in phishing_files:
            file_path = CORPUS_DIR / fn
            self.assertTrue(file_path.is_file(), f"Missing corpus file: {fn}")
            rep = analyze_file(file_path)
            score = rep.score_breakdown.final_score
            tier = rep.score_breakdown.tier.level
            self.assertGreaterEqual(
                score, 75,
                f"Phishing email '{fn}' scored {score}, expected >= 75"
            )
            self.assertEqual(tier, "high")
            self.assertGreater(len(rep.to_dict()["findings"]), 0)

    def test_synthetic_legitimate_emails_flagged_low_risk(self):
        legit_files = [
            "legit_github_notification.eml",
            "legit_newsletter.eml",
            "legit_order_receipt.eml",
        ]
        for fn in legit_files:
            file_path = CORPUS_DIR / fn
            self.assertTrue(file_path.is_file(), f"Missing corpus file: {fn}")
            rep = analyze_file(file_path)
            score = rep.score_breakdown.final_score
            tier = rep.score_breakdown.tier.level
            self.assertLessEqual(
                score, 24,
                f"Legitimate email '{fn}' scored {score}, expected <= 24"
            )
            self.assertEqual(tier, "low")


if __name__ == "__main__":
    unittest.main()

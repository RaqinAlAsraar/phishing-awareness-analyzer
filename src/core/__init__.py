"""
Phishing Awareness Analyzer - Core Heuristics and Detection Modules.
"""

from .analyzer import PhishingReport, analyze_email, analyze_file, analyze_input, analyze_standalone_url
from .body_analyzer import BodyAnalysisResult, BodyFinding, analyze_body
from .header_analyzer import HeaderAnalysisResult, HeaderFinding, analyze_headers
from .scoring import FALSE_POSITIVE_DISCLAIMER, RISK_TIERS, RiskTier, ScoreBreakdown, compute_risk_score, get_risk_tier
from .url_analyzer import AnalyzedURL, URLAnalysisResult, URLFinding, analyze_single_url, analyze_urls

__all__ = [
    "PhishingReport",
    "analyze_email",
    "analyze_file",
    "analyze_input",
    "analyze_standalone_url",
    "HeaderAnalysisResult",
    "HeaderFinding",
    "analyze_headers",
    "BodyAnalysisResult",
    "BodyFinding",
    "analyze_body",
    "AnalyzedURL",
    "URLFinding",
    "URLAnalysisResult",
    "analyze_single_url",
    "analyze_urls",
    "RiskTier",
    "RISK_TIERS",
    "ScoreBreakdown",
    "compute_risk_score",
    "get_risk_tier",
    "FALSE_POSITIVE_DISCLAIMER",
]

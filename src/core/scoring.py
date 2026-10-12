"""
Phishing Risk Scoring, Threat Categorization, and Education Advisory Engine.

Combines findings from:
- Header Analyzer (Display spoofing, Reply-To discrepancy, SPF/DKIM status)
- Body Analyzer (Urgency language, Credential solicitation, Fake security alerts)
- URL Analyzer (Raw IPs, Anchor text mismatches, High-risk TLDs, Typosquatting)

Computes a deterministic 0-100 Risk Score, maps to Risk Tiers, and generates
educational advice with an explicit False-Positive Disclaimer.
"""

from dataclasses import dataclass, field
from typing import Any


FALSE_POSITIVE_DISCLAIMER: str = (
    "DISCLAIMER & EDUCATIONAL NOTICE: This automated heuristic analyzer evaluates structural patterns, "
    "authentication records, and linguistic cues. While effective at identifying common phishing tactics, "
    "heuristics may occasionally flag legitimate newsletters, marketing communications, or time-sensitive "
    "system alerts as suspicious (false positive), or miss novel zero-day spear-phishing techniques (false negative). "
    "Never rely solely on automated scoring—always verify sensitive requests out-of-band via trusted official channels."
)


@dataclass(frozen=True)
class RiskTier:
    name: str           # "Low Risk", "Suspicious", "Moderate Risk", "High Risk"
    level: str          # "low", "suspicious", "moderate", "high"
    min_score: int
    max_score: int
    color_hex: str      # "#10b981", "#f59e0b", "#f97316", "#ef4444"
    verdict: str        # Short summary verdict


RISK_TIERS = [
    RiskTier(
        name="Low Risk",
        level="low",
        min_score=0,
        max_score=24,
        color_hex="#10b981",
        verdict="Email appears legitimate. No critical phishing indicators or deceptive elements detected.",
    ),
    RiskTier(
        name="Suspicious",
        level="suspicious",
        min_score=25,
        max_score=49,
        color_hex="#f59e0b",
        verdict="Low-to-moderate suspicion. Contains minor anomalies or mild urgency cues; proceed with caution.",
    ),
    RiskTier(
        name="Moderate Risk",
        level="moderate",
        min_score=50,
        max_score=74,
        color_hex="#f97316",
        verdict="Potential phishing detected. Multiple deceptive tactics or unverified sender attributes found.",
    ),
    RiskTier(
        name="High Risk",
        level="high",
        min_score=75,
        max_score=100,
        color_hex="#ef4444",
        verdict="Critical phishing threat! Active deception, spoofed identities, or malicious link tactics detected.",
    ),
]


@dataclass
class ScoreBreakdown:
    header_raw_points: int
    body_raw_points: int
    url_raw_points: int
    auth_bonus: int
    final_score: int
    tier: RiskTier
    top_indicators: list[str]
    recommendations: list[str]
    disclaimer: str = FALSE_POSITIVE_DISCLAIMER


def get_risk_tier(score: int) -> RiskTier:
    """Returns the corresponding RiskTier for a given 0-100 score."""
    clamped = max(0, min(100, score))
    for tier in RISK_TIERS:
        if tier.min_score <= clamped <= tier.max_score:
            return tier
    return RISK_TIERS[-1]


def compute_risk_score(
    header_findings: list[Any],
    body_findings: list[Any],
    url_findings: list[Any],
    auth_bonus: int = 0,
) -> ScoreBreakdown:
    """
    Computes weighted aggregate phishing risk score and generates educational advice.
    """
    # 1. Calculate raw component points
    header_points = sum(getattr(f, "risk_points", 0) for f in header_findings)
    body_points = sum(getattr(f, "risk_points", 0) for f in body_findings)
    url_points = sum(getattr(f, "risk_points", 0) for f in url_findings)

    # 2. Check for critical severe smoking guns that trigger baseline thresholds
    has_critical_spoof = any(getattr(f, "category", "") == "display_spoofing" for f in header_findings)
    has_critical_url = any(
        getattr(f, "category", "") in ("ip_host", "anchor_mismatch", "typosquatting") for f in url_findings
    )
    has_cred_harvest = any(getattr(f, "category", "") == "credential_harvesting" for f in body_findings)

    raw_sum = header_points + body_points + url_points
    net_score = raw_sum - auth_bonus

    # If critical smoking gun exists, elevate baseline score
    if has_critical_url and has_cred_harvest:
        net_score = max(net_score, 85)
    elif has_critical_url or has_critical_spoof:
        net_score = max(net_score, 70)
    elif has_cred_harvest and (body_points >= 25 or header_points >= 20):
        net_score = max(net_score, 55)

    final_score = max(0, min(100, net_score))
    tier = get_risk_tier(final_score)

    # 3. Compile top indicators
    all_findings = []
    for f in header_findings + body_findings + url_findings:
        all_findings.append({
            "category": getattr(f, "category", "general"),
            "severity": getattr(f, "severity", "medium"),
            "description": getattr(f, "description", ""),
            "points": getattr(f, "risk_points", 0),
        })

    # Sort by points descending
    all_findings.sort(key=lambda x: x["points"], reverse=True)
    top_indicators = [item["description"] for item in all_findings[:5]]

    # 4. Generate context-aware recommendations
    recommendations: list[str] = []
    if final_score >= 75:
        recommendations.append("DO NOT click any links, open attachments, or reply to this message.")
        recommendations.append("Report this email immediately to your organization's IT / Security operations center (SOC).")
        recommendations.append("If you already entered credentials, immediately change your password directly on the official website.")
    elif final_score >= 50:
        recommendations.append("Do not click links inside the email. Navigate to the service directly by typing its URL into your browser.")
        recommendations.append("Inspect sender domain closely and verify with the organization using known contact information.")
        recommendations.append("Do not enter passwords or payment details on any page reached through this email.")
    elif final_score >= 25:
        recommendations.append("Exercise normal caution. Verify the sender's identity if any unexpected request or attachment is included.")
        recommendations.append("Hover over links before clicking to confirm destination domains match expectations.")
    else:
        recommendations.append("No obvious phishing characteristics detected.")
        recommendations.append("Continue observing standard cyber hygiene (never share master passwords or 2FA tokens).")

    return ScoreBreakdown(
        header_raw_points=header_points,
        body_raw_points=body_points,
        url_raw_points=url_points,
        auth_bonus=auth_bonus,
        final_score=final_score,
        tier=tier,
        top_indicators=top_indicators,
        recommendations=recommendations,
        disclaimer=FALSE_POSITIVE_DISCLAIMER,
    )

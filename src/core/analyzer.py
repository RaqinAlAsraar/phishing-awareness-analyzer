"""
Unified Phishing Awareness Analysis Orchestrator.

Integrates:
- HeaderAnalyzer: Spoofing, Reply-To discrepancy, SPF/DKIM flags
- BodyAnalyzer: Urgency keywords, credential solicitation, fake security notices
- URLAnalyzer: Static offline analysis of all embedded links (IP hosts, anchor mismatches, TLDs)
- ScoringEngine: Risk tier calculation, educational recommendations, and false-positive handling
"""

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional

from .body_analyzer import BodyAnalysisResult, analyze_body
from .header_analyzer import HeaderAnalysisResult, analyze_headers
from .scoring import ScoreBreakdown, compute_risk_score
from .url_analyzer import URLAnalysisResult, analyze_single_url, analyze_urls


@dataclass
class PhishingReport:
    input_type: str                         # "email", "url", "text"
    score_breakdown: ScoreBreakdown
    header_result: Optional[HeaderAnalysisResult]
    body_result: Optional[BodyAnalysisResult]
    url_result: URLAnalysisResult
    summary_verdict: str

    def to_dict(self) -> dict[str, Any]:
        """Serializes report into a clean JSON-friendly dictionary."""
        tier = self.score_breakdown.tier

        # Combine all findings into a unified list
        findings_json = []
        if self.header_result:
            for f in self.header_result.findings:
                findings_json.append({
                    "source": "header",
                    "category": f.category,
                    "severity": f.severity,
                    "description": f.description,
                    "points": f.risk_points,
                    "evidence": f.raw_evidence,
                })
        if self.body_result:
            for f in self.body_result.findings:
                findings_json.append({
                    "source": "body",
                    "category": f.category,
                    "severity": f.severity,
                    "description": f.description,
                    "points": f.risk_points,
                    "evidence": f.raw_evidence,
                })
        for f in self.url_result.findings:
            findings_json.append({
                "source": "url",
                "category": f.category,
                "severity": f.severity,
                "description": f.description,
                "points": f.risk_points,
                "evidence": f.raw_evidence,
            })

        urls_json = []
        for u in self.url_result.analyzed_urls:
            urls_json.append({
                "url": u.url,
                "domain": u.domain,
                "tld": u.tld,
                "is_ip": u.is_ip,
                "anchor_text": u.anchor_text,
                "risk_score": u.risk_score,
                "findings": [
                    {
                        "category": uf.category,
                        "severity": uf.severity,
                        "description": uf.description,
                        "points": uf.risk_points,
                    }
                    for uf in u.findings
                ],
            })

        return {
            "input_type": self.input_type,
            "risk_score": self.score_breakdown.final_score,
            "tier": {
                "name": tier.name,
                "level": tier.level,
                "color": tier.color_hex,
                "verdict": tier.verdict,
            },
            "summary_verdict": self.summary_verdict,
            "component_scores": {
                "header_points": self.score_breakdown.header_raw_points,
                "body_points": self.score_breakdown.body_raw_points,
                "url_points": self.score_breakdown.url_raw_points,
                "auth_bonus": self.score_breakdown.auth_bonus,
            },
            "sender_info": {
                "from_display": self.header_result.from_display if self.header_result else "",
                "from_email": self.header_result.from_email if self.header_result else "",
                "from_domain": self.header_result.from_domain if self.header_result else "",
                "reply_to": self.header_result.reply_to_email if self.header_result else "",
                "subject": self.header_result.subject if self.header_result else "",
                "spf": self.header_result.spf_status if self.header_result else "n/a",
                "dkim": self.header_result.dkim_status if self.header_result else "n/a",
            },
            "findings": findings_json,
            "urls": urls_json,
            "recommendations": self.score_breakdown.recommendations,
            "top_indicators": self.score_breakdown.top_indicators,
            "disclaimer": self.score_breakdown.disclaimer,
        }


def analyze_email(raw_email: str) -> PhishingReport:
    """Analyzes a full email message (headers + body + embedded URLs)."""
    header_res = analyze_headers(raw_email)
    body_res = analyze_body(raw_email)
    url_res = analyze_urls(body_res.extracted_links)

    score_res = compute_risk_score(
        header_findings=header_res.findings,
        body_findings=body_res.findings,
        url_findings=url_res.findings,
        auth_bonus=header_res.auth_bonus,
    )

    return PhishingReport(
        input_type="email",
        score_breakdown=score_res,
        header_result=header_res,
        body_result=body_res,
        url_result=url_res,
        summary_verdict=score_res.tier.verdict,
    )


def analyze_standalone_url(url: str) -> PhishingReport:
    """Analyzes a single standalone URL without email headers."""
    analyzed_url = analyze_single_url(url)
    url_res = URLAnalysisResult(
        analyzed_urls=[analyzed_url],
        findings=analyzed_url.findings,
        total_url_risk=analyzed_url.risk_score,
    )

    score_res = compute_risk_score(
        header_findings=[],
        body_findings=[],
        url_findings=url_res.findings,
        auth_bonus=0,
    )

    return PhishingReport(
        input_type="url",
        score_breakdown=score_res,
        header_result=None,
        body_result=None,
        url_result=url_res,
        summary_verdict=score_res.tier.verdict,
    )


def analyze_file(file_path: str | Path) -> PhishingReport:
    """Reads an email (.eml or text file) from disk and performs full analysis."""
    p = Path(file_path)
    content = p.read_text(encoding="utf-8", errors="replace")
    return analyze_email(content)


def analyze_input(text: str) -> PhishingReport:
    """
    Intelligently determines whether input is a single URL, raw email, or plain body text,
    and routes to the appropriate analyzer.
    """
    stripped = text.strip()
    # Check if single URL
    if (
        (stripped.startswith("http://") or stripped.startswith("https://"))
        and " " not in stripped
        and "\n" not in stripped
    ):
        return analyze_standalone_url(stripped)

    # Check if file path
    if (stripped.endswith(".eml") or stripped.endswith(".txt")) and "\n" not in stripped:
        p = Path(stripped)
        if p.is_file():
            return analyze_file(p)

    return analyze_email(stripped)

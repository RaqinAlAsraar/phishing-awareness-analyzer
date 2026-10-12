"""
Email Header Inspection and Spoofing Heuristics Engine.

Analyzes:
1. Display Name spoofing & domain mismatches (e.g. Display says 'PayPal' but domain is attacker.com)
2. Reply-To vs From address discrepancy
3. SPF (Sender Policy Framework) and DKIM (DomainKeys Identified Mail) status flags
4. Free-mail impersonation of trusted organizations
"""

from dataclasses import dataclass
from email import message_from_string
from email.utils import parseaddr
import re
from typing import Optional

# Well-known brands frequently targeted by phishing campaigns
WELL_KNOWN_BRANDS: dict[str, list[str]] = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "office.com", "live.com", "outlook.com"],
    "google": ["google.com", "gmail.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.co.uk"],
    "chase": ["chase.com"],
    "bank of america": ["bankofamerica.com"],
    "wells fargo": ["wellsfargo.com"],
    "dhl": ["dhl.com", "dhl.de"],
    "fedex": ["fedex.com"],
    "netflix": ["netflix.com"],
    "github": ["github.com"],
}

FREE_MAIL_PROVIDERS: set[str] = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "mail.com", "proton.me", "protonmail.com"
}


@dataclass(frozen=True)
class HeaderFinding:
    category: str      # 'display_spoofing', 'reply_to_mismatch', 'spf_fail', 'dkim_fail', 'free_mail_spoof'
    severity: str      # 'critical', 'high', 'medium', 'info'
    description: str
    risk_points: int   # Added to risk score
    raw_evidence: str


@dataclass(frozen=True)
class HeaderAnalysisResult:
    from_display: str
    from_email: str
    from_domain: str
    reply_to_email: Optional[str]
    reply_to_domain: Optional[str]
    subject: str
    spf_status: str     # 'pass', 'fail', 'softfail', 'none', 'unknown'
    dkim_status: str    # 'pass', 'fail', 'none', 'unknown'
    findings: list[HeaderFinding]
    auth_bonus: int     # Negative points for passing authentication


def extract_domain(email_addr: str) -> str:
    """Extract and lowercase the domain part from an email address."""
    if "@" in email_addr:
        return email_addr.split("@")[-1].strip(" <>\"'").lower()
    return ""


def parse_auth_headers(msg) -> tuple[str, str]:
    """
    Parse SPF and DKIM status from Authentication-Results and Received-SPF headers.
    Returns (spf_status, dkim_status).
    """
    spf_status = "unknown"
    dkim_status = "unknown"

    auth_results = msg.get("Authentication-Results", "")
    received_spf = msg.get("Received-SPF", "")

    combined_auth = f"{auth_results} {received_spf}".lower()

    # Check SPF
    if "spf=pass" in combined_auth or "pass " in received_spf.lower():
        spf_status = "pass"
    elif "spf=fail" in combined_auth or "fail " in received_spf.lower():
        spf_status = "fail"
    elif "spf=softfail" in combined_auth:
        spf_status = "softfail"
    elif "spf=none" in combined_auth:
        spf_status = "none"

    # Check DKIM
    if "dkim=pass" in combined_auth:
        dkim_status = "pass"
    elif "dkim=fail" in combined_auth:
        dkim_status = "fail"
    elif "dkim=none" in combined_auth:
        dkim_status = "none"

    return spf_status, dkim_status


def analyze_headers(raw_email_or_headers: str) -> HeaderAnalysisResult:
    """Perform heuristic security inspection on email headers."""
    findings: list[HeaderFinding] = []

    msg = message_from_string(raw_email_or_headers)

    from_header = msg.get("From", "")
    from_display, from_email = parseaddr(from_header)
    from_domain = extract_domain(from_email)

    reply_to_header = msg.get("Reply-To", "")
    _, reply_to_email = parseaddr(reply_to_header)
    reply_to_domain = extract_domain(reply_to_email) if reply_to_email else None

    subject = msg.get("Subject", "")
    spf_status, dkim_status = parse_auth_headers(msg)

    auth_bonus = 0

    # 1. Display Name Spoofing
    # e.g., Display Name claims to be "PayPal Support", but sender domain is "paypa1-security.com"
    display_lower = from_display.lower()
    for brand, legit_domains in WELL_KNOWN_BRANDS.items():
        if brand in display_lower:
            is_legit = any(from_domain == ld or from_domain.endswith("." + ld) for ld in legit_domains)
            if not is_legit:
                findings.append(
                    HeaderFinding(
                        category="display_spoofing",
                        severity="critical",
                        description=(
                            f"Display name claims to be '{from_display}' ({brand.title()}), "
                            f"but the actual sending domain is '{from_domain}', which does not belong to {brand.title()}."
                        ),
                        risk_points=35,
                        raw_evidence=f"From: {from_header}",
                    )
                )

    # 2. Free Mail Provider impersonating corporate entities
    if from_domain in FREE_MAIL_PROVIDERS and len(from_display.split()) > 1:
        if any(term in display_lower for term in ("support", "security", "admin", "billing", "service", "helpdesk")):
            findings.append(
                HeaderFinding(
                    category="free_mail_spoof",
                    severity="high",
                    description=(
                        f"Official-sounding sender '{from_display}' is using a public freemail service (@{from_domain}). "
                        "Legitimate organizations send from their own corporate domain."
                    ),
                    risk_points=25,
                    raw_evidence=f"From: {from_header}",
                )
            )

    # 3. Reply-To Domain Mismatch
    if reply_to_domain and from_domain:
        # Ignore matching root domains or legitimate subdomains
        if reply_to_domain != from_domain and not (
            reply_to_domain.endswith("." + from_domain) or from_domain.endswith("." + reply_to_domain)
        ):
            findings.append(
                HeaderFinding(
                    category="reply_to_mismatch",
                    severity="high",
                    description=(
                        f"Reply-To address points to '{reply_to_email}' (@{reply_to_domain}), "
                        f"which differs from the sender domain '@{from_domain}'. Replies will be diverted."
                    ),
                    risk_points=20,
                    raw_evidence=f"Reply-To: {reply_to_header}",
                )
            )

    # 4. SPF Authentication Status
    if spf_status == "fail":
        findings.append(
            HeaderFinding(
                category="spf_fail",
                severity="critical",
                description="SPF Authentication Failed (spf=fail). Sending server is not authorized by the sender domain's DNS record.",
                risk_points=30,
                raw_evidence="SPF: fail",
            )
        )
    elif spf_status == "softfail":
        findings.append(
            HeaderFinding(
                category="spf_fail",
                severity="medium",
                description="SPF Softfail (spf=softfail). Sending IP is suspect according to the domain's SPF policy.",
                risk_points=15,
                raw_evidence="SPF: softfail",
            )
        )

    # 5. DKIM Authentication Status
    if dkim_status == "fail":
        findings.append(
            HeaderFinding(
                category="dkim_fail",
                severity="critical",
                description="DKIM Signature Verification Failed (dkim=fail). The email content may have been tampered with in transit.",
                risk_points=25,
                raw_evidence="DKIM: fail",
            )
        )
    elif dkim_status == "none" and spf_status in ("fail", "softfail"):
        findings.append(
            HeaderFinding(
                category="dkim_fail",
                severity="medium",
                description="No cryptographic DKIM signature found on suspicious email.",
                risk_points=10,
                raw_evidence="DKIM: none",
            )
        )

    # Auth bonus if legitimate authentication passed
    if spf_status == "pass" and dkim_status == "pass":
        auth_bonus = 25  # Subtracts from final phishing risk score

    return HeaderAnalysisResult(
        from_display=from_display,
        from_email=from_email,
        from_domain=from_domain,
        reply_to_email=reply_to_email,
        reply_to_domain=reply_to_domain,
        subject=subject,
        spf_status=spf_status,
        dkim_status=dkim_status,
        findings=findings,
        auth_bonus=auth_bonus,
    )

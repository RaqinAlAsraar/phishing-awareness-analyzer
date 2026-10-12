"""
Email Body & Content Heuristics Engine.

Analyzes plain text and HTML email content for:
1. Urgency cues and high-pressure psychological manipulation (e.g., "within 24 hours", "immediate action required")
2. Credential harvesting language (e.g., "confirm your password", "update payment method")
3. Fabricated security alerts (e.g., "unauthorized transaction detected", "unusual sign-in activity")
4. Generic / impersonal greetings (e.g., "Dear Customer", "Valued Client")
5. HTML obfuscation (hidden elements, zero-width spaces, deceptive font styling)
6. Extracts all embedded URLs and anchor texts for deep URL analysis.
"""

from dataclasses import dataclass, field
from email import message_from_string
import html
import json
from pathlib import Path
import re
from typing import Optional

# Default keywords fallback in case JSON file is inaccessible
DEFAULT_KEYWORDS = {
    "urgency_keywords": [
        "immediately", "immediate action required", "within 24 hours", "within 12 hours",
        "within 48 hours", "account suspended", "account will be closed",
        "account will be terminated", "urgent notice", "critical security alert",
        "final warning", "action required", "immediate response needed", "act now",
        "limited time", "access restricted", "unauthorized access detected",
        "temporary hold", "suspension notice"
    ],
    "credential_harvesting": [
        "verify your password", "confirm your password", "reset your password",
        "update your credentials", "verify your account", "confirm your identity",
        "validate your billing", "update payment method", "enter your credit card",
        "confirm your ssn", "social security number", "login to restore",
        "click here to unlock", "authenticate your session", "submit your verification code",
        "confirm your secret question"
    ],
    "fake_security_warnings": [
        "unusual sign-in activity", "unauthorized transaction detected",
        "login from unknown device", "suspicious activity flagged",
        "breach detected", "security policy violation", "malicious login attempt",
        "compromised account", "failed login attempts exceeded"
    ],
    "impersonal_greetings": [
        "dear customer", "dear user", "dear member", "dear client",
        "valued customer", "attention account holder", "dear account owner",
        "undisclosed recipients"
    ]
}


def load_suspicious_keywords() -> dict[str, list[str]]:
    """Loads keywords from data/suspicious_keywords.json if available, or falls back to defaults."""
    keywords_path = Path(__file__).resolve().parent.parent.parent / "data" / "suspicious_keywords.json"
    if keywords_path.is_file():
        try:
            with open(keywords_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return {k: [w.lower() for w in v] for k, v in data.items()}
        except Exception:
            pass
    return DEFAULT_KEYWORDS


@dataclass(frozen=True)
class ExtractedLink:
    url: str
    anchor_text: str
    is_html: bool


@dataclass(frozen=True)
class BodyFinding:
    category: str      # 'urgency', 'credential_harvesting', 'fake_security', 'impersonal_greeting', 'html_obfuscation', 'excessive_caps'
    severity: str      # 'critical', 'high', 'medium', 'low', 'info'
    description: str
    risk_points: int
    raw_evidence: str


@dataclass
class BodyAnalysisResult:
    plain_text: str
    html_content: Optional[str]
    extracted_links: list[ExtractedLink]
    findings: list[BodyFinding]
    word_count: int
    caps_ratio: float
    urgency_matches: list[str] = field(default_factory=list)
    credential_matches: list[str] = field(default_factory=list)
    security_matches: list[str] = field(default_factory=list)
    greeting_match: Optional[str] = None


def extract_content_from_email(raw_input: str) -> tuple[str, Optional[str]]:
    """
    Extracts plain text and HTML bodies from a raw email string or RFC-822 message.
    If raw_input is plain text without headers, returns (raw_input, None).
    """
    if "From:" in raw_input or "Subject:" in raw_input or "MIME-Version:" in raw_input:
        try:
            msg = message_from_string(raw_input)
            plain_parts = []
            html_parts = []
            
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disp = str(part.get("Content-Disposition", ""))
                    if "attachment" in content_disp:
                        continue
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            charset = part.get_content_charset() or "utf-8"
                            text = payload.decode(charset, errors="replace")
                            if content_type == "text/plain":
                                plain_parts.append(text)
                            elif content_type == "text/html":
                                html_parts.append(text)
                    except Exception:
                        continue
            else:
                content_type = msg.get_content_type()
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or "utf-8"
                    text = payload.decode(charset, errors="replace")
                    if content_type == "text/html":
                        html_parts.append(text)
                    else:
                        plain_parts.append(text)

            plain_text = "\n".join(plain_parts).strip()
            html_text = "\n".join(html_parts).strip() if html_parts else None

            # If plain text was empty but HTML was present, strip HTML tags for plain_text
            if not plain_text and html_text:
                plain_text = strip_html_tags(html_text)

            if plain_text or html_text:
                return plain_text, html_text
        except Exception:
            pass

    # If not RFC-822 formatted or parsing produced nothing, check if it's HTML
    if "<html" in raw_input.lower() or "<div" in raw_input.lower() or "<p" in raw_input.lower() or "<a href" in raw_input.lower():
        return strip_html_tags(raw_input), raw_input
    
    return raw_input, None


def strip_html_tags(html_str: str) -> str:
    """Removes HTML tags and decodes entities to produce readable plain text."""
    # Remove script and style elements
    clean = re.sub(r"<(script|style)[^>]*>.*?</\1>", "", html_str, flags=re.DOTALL | re.IGNORECASE)
    # Replace block tags with newline
    clean = re.sub(r"<(br|p|div|tr|h\d)[^>]*>", "\n", clean, flags=re.IGNORECASE)
    # Remove remaining tags
    clean = re.sub(r"<[^>]+>", " ", clean)
    # Decode HTML entities
    clean = html.unescape(clean)
    # Normalize multiple whitespace
    clean = re.sub(r"[ \t]+", " ", clean)
    clean = re.sub(r"\n\s*\n", "\n\n", clean)
    return clean.strip()


def extract_links(plain_text: str, html_text: Optional[str]) -> list[ExtractedLink]:
    """Extracts all hyperlinks and their anchor texts from HTML and plain text."""
    links: list[ExtractedLink] = []
    seen_urls: set[tuple[str, str]] = set()

    # 1. Extract from HTML <a> tags
    if html_text:
        # Match <a ... href="URL" ...>ANCHOR</a>
        a_tag_pattern = re.compile(
            r'<a\s+[^>]*?href=["\'](?P<url>[^"\'>\s]+)["\'][^>]*?>(?P<anchor>.*?)</a>',
            re.IGNORECASE | re.DOTALL,
        )
        for match in a_tag_pattern.finditer(html_text):
            url = match.group("url").strip()
            anchor_raw = match.group("anchor")
            anchor_text = strip_html_tags(anchor_raw).strip()
            if url and not url.startswith("mailto:") and not url.startswith("javascript:"):
                key = (url, anchor_text)
                if key not in seen_urls:
                    seen_urls.add(key)
                    links.append(ExtractedLink(url=url, anchor_text=anchor_text, is_html=True))

    # 2. Extract plain text URLs using regex
    url_pattern = re.compile(r'https?://[^\s<>"\')]+', re.IGNORECASE)
    for match in url_pattern.finditer(plain_text):
        url = match.group(0).rstrip(".,;:?!)")
        key = (url, url)
        if key not in seen_urls:
            seen_urls.add(key)
            links.append(ExtractedLink(url=url, anchor_text=url, is_html=False))

    return links


def analyze_body(raw_email_or_text: str) -> BodyAnalysisResult:
    """
    Performs comprehensive heuristic security evaluation on the email body text and HTML.
    """
    plain_text, html_content = extract_content_from_email(raw_email_or_text)
    links = extract_links(plain_text, html_content)
    findings: list[BodyFinding] = []

    keywords_db = load_suspicious_keywords()
    lower_text = plain_text.lower()

    # 1. Urgency cues & psychological manipulation
    urgency_matches: list[str] = []
    for kw in keywords_db.get("urgency_keywords", []):
        if re.search(r"\b" + re.escape(kw) + r"\b", lower_text):
            urgency_matches.append(kw)

    if urgency_matches:
        severity = "critical" if len(urgency_matches) >= 3 else ("high" if len(urgency_matches) >= 2 else "medium")
        pts = min(35, 10 + (len(urgency_matches) * 8))
        findings.append(
            BodyFinding(
                category="urgency",
                severity=severity,
                description=(
                    f"High-urgency language detected ({len(urgency_matches)} indicators). Phishing attacks induce "
                    f"panic or artificial scarcity to prevent victims from verifying requests carefully."
                ),
                risk_points=pts,
                raw_evidence=", ".join(f"'{m}'" for m in urgency_matches[:5]),
            )
        )

    # 2. Credential harvesting language
    credential_matches: list[str] = []
    for kw in keywords_db.get("credential_harvesting", []):
        if re.search(r"\b" + re.escape(kw) + r"\b", lower_text):
            credential_matches.append(kw)

    if credential_matches:
        severity = "critical" if len(credential_matches) >= 2 else "high"
        pts = min(40, 15 + (len(credential_matches) * 12))
        findings.append(
            BodyFinding(
                category="credential_harvesting",
                severity=severity,
                description=(
                    f"Credential solicitation detected ({len(credential_matches)} phrases). "
                    "Legitimate organizations rarely request passwords, billing confirmation, or SSN via unsolicited emails."
                ),
                risk_points=pts,
                raw_evidence=", ".join(f"'{m}'" for m in credential_matches[:5]),
            )
        )

    # 3. Fake Security Alerts
    security_matches: list[str] = []
    for kw in keywords_db.get("fake_security_warnings", []):
        if re.search(r"\b" + re.escape(kw) + r"\b", lower_text):
            security_matches.append(kw)

    if security_matches:
        pts = min(25, 12 + (len(security_matches) * 6))
        findings.append(
            BodyFinding(
                category="fake_security",
                severity="high",
                description=(
                    f"Fabricated security warning detected ({len(security_matches)} indicators). "
                    "Attackers impersonate security teams claiming accounts were breached to bait victims into clicking."
                ),
                risk_points=pts,
                raw_evidence=", ".join(f"'{m}'" for m in security_matches[:4]),
            )
        )

    # 4. Impersonal / Generic Greetings
    greeting_match = None
    # Check first 500 characters where greetings normally occur
    opening_text = lower_text[:500]
    for kw in keywords_db.get("impersonal_greetings", []):
        if kw in opening_text:
            greeting_match = kw
            findings.append(
                BodyFinding(
                    category="impersonal_greeting",
                    severity="medium",
                    description=(
                        f"Impersonal greeting '{kw.title()}' detected. Phishing campaigns sent en masse "
                        "often lack your actual name or specific account identifier."
                    ),
                    risk_points=12,
                    raw_evidence=kw,
                )
            )
            break

    # 5. HTML Obfuscation checks
    if html_content:
        # Zero-width spaces
        zero_width_chars = ["\u200b", "\u200c", "\u200d", "\ufeff"]
        found_zw = [c for c in zero_width_chars if c in html_content]
        if found_zw:
            findings.append(
                BodyFinding(
                    category="html_obfuscation",
                    severity="high",
                    description="Zero-width characters detected in HTML content, commonly used to bypass heuristic keyword scanners.",
                    risk_points=20,
                    raw_evidence=f"Zero-width unicode entities present (count: {len(found_zw)})",
                )
            )

        # Hidden text elements (e.g. style="display:none" or font-size: 0)
        hidden_pattern = re.compile(
            r'style=["\'][^"\']*(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0)[^"\']*["\']',
            re.IGNORECASE,
        )
        if hidden_pattern.search(html_content):
            findings.append(
                BodyFinding(
                    category="html_obfuscation",
                    severity="high",
                    description="Hidden styling (display:none / font-size:0 / opacity:0) detected in HTML, often used to conceal malicious payload text or spam bypass tokens.",
                    risk_points=18,
                    raw_evidence="Hidden CSS attributes found",
                )
            )

    # 6. Excessive uppercase shouting
    words = re.findall(r"\b[A-Za-z]{2,}\b", plain_text)
    word_count = len(words)
    caps_words = [w for w in words if w.isupper() and len(w) > 2]
    caps_ratio = len(caps_words) / word_count if word_count > 0 else 0.0

    if word_count > 15 and caps_ratio > 0.25:
        findings.append(
            BodyFinding(
                category="excessive_caps",
                severity="low",
                description=f"Unusually high ratio of uppercase text ({caps_ratio:.1%}), indicating high emotional pressure / urgency manipulation.",
                risk_points=8,
                raw_evidence=f"{len(caps_words)} uppercase words out of {word_count}",
            )
        )

    return BodyAnalysisResult(
        plain_text=plain_text,
        html_content=html_content,
        extracted_links=links,
        findings=findings,
        word_count=word_count,
        caps_ratio=caps_ratio,
        urgency_matches=urgency_matches,
        credential_matches=credential_matches,
        security_matches=security_matches,
        greeting_match=greeting_match,
    )

"""
URL and Hyperlink Heuristics Inspection Engine.

Analyzes embedded URLs and standalone links using 100% OFFLINE static heuristics:
1. Raw IPv4 / IPv6 addresses used in place of legitimate domain names.
2. Anchor text deception (e.g. visible text displays 'https://paypal.com' but href targets 'http://evil.com').
3. High-risk, spam-prevalent top-level domains (e.g. .xyz, .top, .click, .buzz, .tk).
4. Subdomain brand spoofing (e.g. 'paypal.com.verify-access.net').
5. Typosquatting, leetspeak, and homoglyphs (e.g. 'paypa1.com', 'micros0ft.com').
6. Punycode (IDN) spoofing indicators (e.g. 'xn--...').
7. Non-standard HTTP ports (e.g. :8080, :1337).
8. Suspicious path patterns and credential-luring endpoints.

SECURITY GUARANTEE: Never performs network requests, DNS queries, or socket connections.
"""

from dataclasses import dataclass, field
import ipaddress
import re
from typing import Optional
from urllib.parse import urlparse

# High-risk TLDs statistically associated with disposable phishing campaigns
HIGH_RISK_TLDS: set[str] = {
    "xyz", "top", "click", "buzz", "work", "fit", "rest", "country", "stream",
    "gq", "cf", "ml", "tk", "ga", "loan", "men", "bar", "monster", "cam", "icu"
}

# Brands frequently impersonated in phishing links
TARGET_BRANDS: dict[str, str] = {
    "paypal": "paypal.com",
    "microsoft": "microsoft.com",
    "google": "google.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "chase": "chase.com",
    "bankofamerica": "bankofamerica.com",
    "wellsfargo": "wellsfargo.com",
    "dhl": "dhl.com",
    "fedex": "fedex.com",
    "netflix": "netflix.com",
    "github": "github.com",
}

# Leetspeak / homoglyph substitution mappings for offline detection
HOMOGLYPH_MAP: dict[str, str] = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
    "@": "a",
    "vv": "w",
}


@dataclass(frozen=True)
class URLFinding:
    category: str      # 'ip_host', 'anchor_mismatch', 'high_risk_tld', 'subdomain_spoof', 'typosquatting', 'punycode', 'unusual_port', 'credential_path'
    severity: str      # 'critical', 'high', 'medium', 'low'
    description: str
    risk_points: int
    raw_evidence: str


@dataclass
class AnalyzedURL:
    url: str
    domain: str
    tld: str
    is_ip: bool
    anchor_text: Optional[str]
    findings: list[URLFinding] = field(default_factory=list)
    risk_score: int = 0


@dataclass
class URLAnalysisResult:
    analyzed_urls: list[AnalyzedURL]
    findings: list[URLFinding]
    total_url_risk: int


def is_ip_address(host: str) -> bool:
    """Checks if host is an IPv4 or IPv6 address without DNS or network lookups."""
    # Strip port or bracket if IPv6
    clean_host = host.split(":")[0].strip("[]")
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        return False


def normalize_leetspeak(s: str) -> str:
    """Replaces common leetspeak substitutions with latin characters."""
    normalized = s.lower()
    for leet, char in HOMOGLYPH_MAP.items():
        normalized = normalized.replace(leet, char)
    return normalized


def extract_root_and_tld(hostname: str) -> tuple[str, str, list[str]]:
    """
    Splits hostname into (root_domain_with_tld, tld, subdomains).
    Offline parsing without external dependencies.
    """
    parts = hostname.lower().split(".")
    if len(parts) < 2:
        return hostname, "", []
    
    tld = parts[-1]
    # Handle two-part TLDs like co.uk, com.au
    two_part_tlds = {"co.uk", "gov.uk", "ac.uk", "com.au", "net.au", "co.jp", "com.br"}
    if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in two_part_tlds:
        root_domain = f"{parts[-3]}.{parts[-2]}.{parts[-1]}"
        subdomains = parts[:-3]
        tld = f"{parts[-2]}.{parts[-1]}"
    else:
        root_domain = f"{parts[-2]}.{parts[-1]}"
        subdomains = parts[:-2]

    return root_domain, tld, subdomains


def check_typosquatting(root_domain: str) -> Optional[tuple[str, str]]:
    """
    Checks if root_domain uses leetspeak or typosquatting against major brands.
    Returns (brand, explanation) if detected.
    """
    domain_name = root_domain.split(".")[0]
    normalized_name = normalize_leetspeak(domain_name)

    for brand, legit_fqdn in TARGET_BRANDS.items():
        # Check direct leetspeak (e.g. paypa1 vs paypal)
        if normalized_name == brand and domain_name != brand:
            return brand, f"Leetspeak substitution detected ('{domain_name}' mimics '{brand}')"

        # Check brand name embedded with hyphens/lures (e.g. paypa1-security, paypal-verify)
        if (f"{brand}-" in normalized_name or f"-{brand}" in normalized_name or brand in normalized_name) and root_domain != legit_fqdn:
            if domain_name != normalized_name:
                return brand, f"Leetspeak brand impersonation detected ('{domain_name}' mimics '{brand}')"
            elif not root_domain.endswith(f".{legit_fqdn}") and root_domain != legit_fqdn:
                return brand, f"Target brand '{brand}' used in domain name '{root_domain}'"

        # Check single-character edit distance for brand names with length >= 5
        if len(brand) >= 5 and abs(len(domain_name) - len(brand)) <= 1 and domain_name != brand:
            dist = levenshtein_distance(domain_name, brand)
            if dist == 1:
                return brand, f"Typosquatting permutation (distance 1 from '{brand}')"

    return None


def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes Levenshtein distance between two strings purely in memory."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def analyze_single_url(url: str, anchor_text: Optional[str] = None) -> AnalyzedURL:
    """Analyzes a single URL with complete heuristic rules."""
    findings: list[URLFinding] = []
    
    # Prepend scheme if missing for urlparse
    parsed_input = url if ("://" in url or url.startswith("//")) else f"http://{url}"
    parsed = urlparse(parsed_input)
    hostname = (parsed.hostname or "").lower()

    if not hostname:
        return AnalyzedURL(url=url, domain="", tld="", is_ip=False, anchor_text=anchor_text)

    is_ip = is_ip_address(hostname)
    root_domain, tld, subdomains = extract_root_and_tld(hostname) if not is_ip else (hostname, "", [])

    # 1. IP Address as host
    if is_ip:
        findings.append(
            URLFinding(
                category="ip_host",
                severity="critical",
                description=f"Raw IP address '{hostname}' used instead of a registered domain name. Attackers use IP URLs to bypass domain security filters.",
                risk_points=40,
                raw_evidence=url,
            )
        )

    # 2. Anchor text mismatch
    if anchor_text and (anchor_text.startswith("http://") or anchor_text.startswith("https://") or "www." in anchor_text):
        anchor_parsed = urlparse(anchor_text if "://" in anchor_text else f"http://{anchor_text}")
        anchor_host = (anchor_parsed.hostname or "").lower()
        if anchor_host and anchor_host != hostname:
            findings.append(
                URLFinding(
                    category="anchor_mismatch",
                    severity="critical",
                    description=(
                        f"Deceptive hyperlink detected! Visible text displays '{anchor_host}', "
                        f"but clicking navigates to '{hostname}'. Classic phishing trap."
                    ),
                    risk_points=45,
                    raw_evidence=f"Text: '{anchor_text}' -> Target: '{url}'",
                )
            )

    # 3. High-risk TLD
    if tld in HIGH_RISK_TLDS:
        findings.append(
            URLFinding(
                category="high_risk_tld",
                severity="high",
                description=f"Uncommon high-risk top-level domain (.{tld}) statistically associated with disposable phishing and malware infrastructure.",
                risk_points=25,
                raw_evidence=f"TLD: .{tld}",
            )
        )

    # 4. Subdomain brand spoofing (e.g. chase.com.attacker-site.com)
    if subdomains:
        subdomain_str = ".".join(subdomains)
        for brand, legit_fqdn in TARGET_BRANDS.items():
            if brand in subdomain_str and legit_fqdn not in root_domain:
                findings.append(
                    URLFinding(
                        category="subdomain_spoof",
                        severity="critical",
                        description=(
                            f"Subdomain trickery: Brand name '{brand}' appears in the subdomain ('{subdomain_str}'), "
                            f"but the actual destination domain is '{root_domain}'."
                        ),
                        risk_points=35,
                        raw_evidence=f"Host: {hostname}",
                    )
                )
                break

    # 5. Typosquatting / Leetspeak
    if not is_ip:
        typo_result = check_typosquatting(root_domain)
        if typo_result:
            brand, reason = typo_result
            findings.append(
                URLFinding(
                    category="typosquatting",
                    severity="critical",
                    description=f"Typosquatting / Brand spoofing detected: {reason}.",
                    risk_points=35,
                    raw_evidence=f"Domain: {root_domain} vs Brand: {brand}",
                )
            )

    # 6. Punycode (IDN) check
    if "xn--" in hostname:
        findings.append(
            URLFinding(
                category="punycode",
                severity="high",
                description="Internationalized Domain Name (Punycode 'xn--') detected. Often used for visual lookalike homograph attacks.",
                risk_points=25,
                raw_evidence=hostname,
            )
        )

    # 7. Non-standard ports
    if parsed.port and parsed.port not in (80, 443):
        findings.append(
            URLFinding(
                category="unusual_port",
                severity="medium",
                description=f"Non-standard HTTP port (:{parsed.port}) in link destination.",
                risk_points=15,
                raw_evidence=f"Port: {parsed.port}",
            )
        )

    # 8. Suspicious path endpoints
    suspicious_path_regex = re.compile(
        r'/(login|signin|verify|update-account|restore-access|banking|secure-login|wp-login|session)',
        re.IGNORECASE,
    )
    if suspicious_path_regex.search(parsed.path):
        if is_ip or tld in HIGH_RISK_TLDS or len(subdomains) >= 2 or findings:
            findings.append(
                URLFinding(
                    category="credential_path",
                    severity="high",
                    description=f"Credential-gathering path keyword ('{parsed.path}') on an unverified or high-risk domain.",
                    risk_points=20,
                    raw_evidence=f"Path: {parsed.path}",
                )
            )

    # Calculate single URL risk score
    url_risk = sum(f.risk_points for f in findings)

    return AnalyzedURL(
        url=url,
        domain=hostname,
        tld=tld,
        is_ip=is_ip,
        anchor_text=anchor_text,
        findings=findings,
        risk_score=min(100, url_risk),
    )


def analyze_urls(extracted_links: list) -> URLAnalysisResult:
    """
    Analyzes all extracted links (objects with .url and .anchor_text, or raw strings).
    Returns complete URLAnalysisResult.
    """
    analyzed_list: list[AnalyzedURL] = []
    all_findings: list[URLFinding] = []

    for item in extracted_links:
        if hasattr(item, "url"):
            url_str = item.url
            anchor = getattr(item, "anchor_text", None)
        elif isinstance(item, tuple) and len(item) >= 2:
            url_str, anchor = item[0], item[1]
        elif isinstance(item, str):
            url_str = item
            anchor = None
        else:
            continue

        analyzed = analyze_single_url(url_str, anchor_text=anchor)
        analyzed_list.append(analyzed)
        all_findings.extend(analyzed.findings)

    # Total URL risk is capped at 100
    total_risk = min(100, sum(f.risk_points for f in all_findings))

    return URLAnalysisResult(
        analyzed_urls=analyzed_list,
        findings=all_findings,
        total_url_risk=total_risk,
    )

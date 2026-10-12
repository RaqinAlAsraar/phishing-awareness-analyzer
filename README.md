# Phishing Awareness Analyzer — Threat Detection & Heuristics

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg?logo=python&logoColor=white)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange.svg?logo=linux&logoColor=white)](https://kernel.org)
[![Offline Security](https://img.shields.io/badge/Security-100%25%20Offline-emerald.svg?logo=securityscorecard&logoColor=white)](#offline-security-guarantee)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-27%2F27%20Passing-brightgreen.svg)](#automated-testing--verification)

> **Cybersecurity Internship — Batch 01 — Task 2**  
> **Author:** Ali Abbas Haidar (Raqin Al-Asraar)  
> **GitHub:** [@raqinalasraar](https://github.com/raqinalasraar)  
> **Email:** aliabbashaidar313@gmail.com

---

## Executive Summary

The **Phishing Awareness Analyzer** is a threat detection and security heuristics engine designed to evaluate raw email messages (`.eml`, RFC-822, or plain text) and standalone hyperlinks for indicators of social engineering, brand spoofing, and credential deception.

The application combines:
1. **Email Header Inspection**: Detects Display Name spoofing, Reply-To discrepancies, and parses Sender Policy Framework (`SPF`) and DomainKeys Identified Mail (`DKIM`) authentication flags.
2. **Linguistic & Content Heuristics**: Flags psychological urgency cues, fabricated security alerts, generic greetings, and HTML obfuscation (zero-width characters and hidden CSS).
3. **Static URL Inspection**: Detects raw IP address hosts, deceptive anchor text mismatches, typosquatting, leetspeak, high-risk top-level domains (`TLDs`), and brand subdomain deception.
4. **Deterministic Risk Scoring**: Normalizes indicators into an aggregate $0-100$ score across four tiered risk categories with actionable security guidance and an explicit **False-Positive Disclaimer**.
5. **Multiple Interfaces**: Modern Flutter/Tailwind-styled Web GUI (Chromium `--app` mode), native PyQt6 desktop application, and an interactive colored terminal CLI.

---

## Offline Security Guarantee

> [!IMPORTANT]
> **Zero Network Probes / Non-Offensive Guarantee**  
> In accordance with ethical security guidelines, this analyzer operates **100% offline**. It **NEVER**:
> - Executes network requests, HTTP fetches, or web scraping.
> - Conducts DNS lookups or WHOIS queries.
> - Performs port scanning, socket connections, or server pings.
> - Harvesters credentials or executes active payloads.
>
> All domain evaluations, homoglyph detections, and structural checks are performed strictly in-memory using static algorithmic heuristics and local regex matching.

---

## Architecture & Project Structure

```
phishing-awareness-analyzer/
├── data/
│   ├── suspicious_keywords.json          # Urgency, credential, and alert lexicons
│   └── corpus/                           # Synthetic sanitized test emails
│       ├── phishing_paypal.eml           # Display spoofing, leetspeak, SPF fail
│       ├── phishing_m365_reset.eml       # IP address link, password expiry lure
│       ├── phishing_bank_urgency.eml     # Chase bank alert, subdomain deception
│       ├── phishing_fake_invoice.eml     # DHL parcel customs fee, Reply-To mismatch
│       ├── legit_github_notification.eml # Valid GitHub PR notification (SPF/DKIM pass)
│       ├── legit_newsletter.eml          # Valid curated newsletter (SPF/DKIM pass)
│       └── legit_order_receipt.eml       # Valid store order & tracking receipt
├── src/
│   ├── core/
│   │   ├── __init__.py                   # Package exports
│   │   ├── header_analyzer.py            # Display spoofing, Reply-To, SPF/DKIM
│   │   ├── body_analyzer.py              # Urgency keywords, HTML obfuscation, link extraction
│   │   ├── url_analyzer.py               # IP hosts, anchor mismatches, TLDs, typosquatting
│   │   ├── scoring.py                    # Risk math, tiers, educational advisory, disclaimer
│   │   └── analyzer.py                   # Unified orchestrator & JSON reporting
│   ├── web/
│   │   ├── index.html                    # Clean Flutter/Tailwind-style modern card UI
│   │   ├── style.css                     # Responsive styling & Material 3 dark theme
│   │   ├── app.js                        # Client-side reactivity & API integration
│   │   └── server.py                     # Local loopback HTTP server & Chromium app launcher
│   ├── gui/
│   │   ├── __init__.py                   # GUI package init
│   │   ├── styles.py                     # Dark QSS stylesheet
│   │   └── main_window.py                # Native PyQt6 desktop window
│   └── cli/
│       ├── __init__.py                   # CLI package init
│       └── console.py                    # Colored terminal runner & batch benchmark
├── tests/
│   ├── test_headers.py                   # Header spoofing & auth parsing tests
│   ├── test_body.py                      # Urgency, HTML obfuscation, & link parsing tests
│   ├── test_url.py                       # IP, anchor mismatch, & typosquatting tests
│   ├── test_scoring.py                   # Scoring math, tiers, & disclaimer tests
│   ├── test_safety.py                    # Offline security & zero-network tests
│   └── test_corpus.py                    # Synthetic corpus ground-truth verification
├── .gitignore                            # Python / virtual environment ignore rules
├── LICENSE                               # MIT License (Ali Abbas Haidar)
├── main.py                               # Central unified launcher (Web, Qt, CLI)
├── requirements.txt                      # Dependencies (PyQt6, pytest)
├── run.sh                                # Fast executable launcher script
├── setup.sh                              # Linux auto-config, venv manager, & runner
└── README.md                             # Documentation & manual
```

---

## Heuristic Rules & Scoring Math

The analyzer aggregates findings across three distinct inspection layers and applies authentication discounts before mapping the final net score to a standard 4-tier risk scale:

$$\text{Raw Score} = \text{Score}_{\text{Header}} + \text{Score}_{\text{Body}} + \text{Score}_{\text{URLs}}$$
$$\text{Net Score} = \max\Big(0, \min\big(100, \text{Raw Score} - \text{Auth Bonus}\big)\Big)$$

### 1. Header Inspection Rules
| Indicator | Category | Severity | Points | Rationale |
|---|---|---|---|---|
| Display Name Spoofing | `display_spoofing` | **Critical** | $+35$ | Display Name claims to be a trusted brand (e.g., PayPal), but the sending domain does not match. |
| SPF Authentication Failure | `spf_fail` | **Critical** | $+30$ | Sending server is not authorized by the domain's DNS SPF record (`spf=fail`). |
| DKIM Signature Failure | `dkim_fail` | **Critical** | $+25$ | Cryptographic digital signature is broken or tampered with in transit (`dkim=fail`). |
| Corporate Freemail Impersonation | `free_mail_spoof` | **High** | $+25$ | Official-sounding sender (e.g., "Helpdesk") uses public freemail (`@gmail.com`). |
| Reply-To Domain Discrepancy | `reply_to_mismatch` | **High** | $+20$ | Replies are secretly routed to a disposable domain different from the sender. |
| **Authentication Bonus** | `auth_pass` | **Bonus** | **$-25$** | Awarded when both SPF and DKIM pass cryptographically with no critical spoof flags. |

### 2. Body & Linguistic Rules
| Indicator | Category | Severity | Points | Rationale |
|---|---|---|---|---|
| Credential Solicitation | `credential_harvesting` | **Critical** | $+15 \text{ to } +40$ | Direct requests for passwords, billing updates, or SSN. |
| Psychological Urgency | `urgency` | **High / Critical** | $+10 \text{ to } +35$ | Panic-inducing deadlines (*"Within 24 hours"*, *"Account suspended"*). |
| Zero-Width / Hidden HTML | `html_obfuscation` | **High** | $+18 \text{ to } +20$ | Zero-width unicode characters or `display:none` styling used to bypass keyword filters. |
| Fabricated Security Notice | `fake_security` | **High** | $+12 \text{ to } +25$ | False claims of unauthorized logins or account freezes to induce fear. |
| Generic / Impersonal Greeting | `impersonal_greeting` | **Medium** | $+12$ | Mass-distribution greetings (*"Dear Customer"*) lacking user identity. |

### 3. URL & Hyperlink Inspection Rules
| Indicator | Category | Severity | Points | Rationale |
|---|---|---|---|---|
| Anchor Text Deception | `anchor_mismatch` | **Critical** | $+45$ | Visible text displays a trusted URL (e.g. `paypal.com`), but clicking routes to an attacker host. |
| Raw IP Address Host | `ip_host` | **Critical** | $+40$ | Numeric IP (e.g. `http://192.168.1.100/login`) used instead of a registered domain. |
| Typosquatting / Leetspeak | `typosquatting` | **Critical** | $+35$ | Visual substitutions (e.g., `paypa1.com` using numeral `1`, `micros0ft.com` using `0`). |
| Subdomain Brand Trickery | `subdomain_spoof` | **Critical** | $+35$ | Brand name placed in subdomain (e.g. `paypal.com.verify-login.net`). |
| High-Risk Disposable TLD | `high_risk_tld` | **High** | $+25$ | Domains using spam-heavy extensions (`.xyz`, `.top`, `.click`, `.buzz`, `.tk`). |
| Credential Endpoint Path | `credential_path` | **High** | $+20$ | Luring paths (`/login`, `/signin`, `/verify`) on unverified domains. |

### 4. Risk Tiers
| Tier | Score Range | Badge Color | Threat Verdict |
|---|---|---|---|
| **Low Risk** | $0 - 24$ | Emerald (`#10b981`) | Email appears legitimate. No critical indicators detected. |
| **Suspicious** | $25 - 49$ | Amber (`#f59e0b`) | Low-to-moderate suspicion. Minor anomalies or mild urgency cues found. |
| **Moderate Risk** | $50 - 74$ | Orange (`#f97316`) | Potential phishing detected. Multiple deceptive tactics or unverified sender attributes. |
| **High Risk** | $75 - 100$ | Red (`#ef4444`) | Critical phishing threat! Active deception, spoofed identities, or malicious links detected. |

---

## Synthetic Corpus Benchmark Results

The engine includes 7 synthetic, sanitized test emails in `data/corpus/` representing real-world attack vectors and legitimate communications:

```bash
$ python3 main.py --corpus
```

| Sample File | Scenario Simulated | Ground Truth | Predicted Score | Risk Tier | Flags |
|---|---|---|---|---|---|
| `phishing_paypal.eml` | PayPal Account Suspension (Display Spoof & Leetspeak) | **Phishing** | **100 / 100** | High Risk | 11 |
| `phishing_m365_reset.eml` | Microsoft 365 Password Expiry (IP Link & Urgency) | **Phishing** | **100 / 100** | High Risk | 8 |
| `phishing_bank_urgency.eml` | Chase Bank Security Alert (Subdomain Trickery) | **Phishing** | **100 / 100** | High Risk | 9 |
| `phishing_fake_invoice.eml` | DHL Parcel Customs Fee (Reply-To Mismatch) | **Phishing** | **100 / 100** | High Risk | 7 |
| `legit_github_notification.eml` | GitHub PR Review Notification (Valid SPF/DKIM) | **Legitimate** | **0 / 100** | Low Risk | 0 |
| `legit_newsletter.eml` | Python Weekly Newsletter (Valid Sender Policies) | **Legitimate** | **0 / 100** | Low Risk | 0 |
| `legit_order_receipt.eml` | Store Parcel Receipt (Standard Order Confirmation) | **Legitimate** | **0 / 100** | Low Risk | 0 |

**Accuracy:** 100% precision and recall across all synthetic test cases.

---

## Educational Notice & False-Positive Handling

> [!WARNING]
> **Heuristic Limitations & Operational Awareness**  
> Automated heuristic scanners inspect structural patterns, authentication headers, and linguistic keywords. While highly effective at catching standard phishing campaigns:
> 1. **False Positives:** Legitimate marketing campaigns, internal IT maintenance alerts, or unconventional newsletters frequently employ urgency language (*"Offer ends tonight"*, *"Password expires soon"*) or route through third-party tracking links, triggering heuristic flags.
> 2. **False Negatives:** Advanced spear-phishing campaigns with legitimate SPF/DKIM records and low-urgency conversational lures may evade basic keyword filters.
> 
> Security operations centers (`SOC`) must always corroborate heuristic findings with out-of-band identity verification before taking disruptive actions (e.g., domain blocking or account suspension).

---

## Installation & Running (Linux)

This project is tailored specifically for **Linux** environments (Kali Linux, Ubuntu, Debian, Arch, Fedora, etc.).

### 1. Quick Setup Script
Run the automated setup script to detect your Linux distribution, prepare a Python virtual environment, and install dependencies:

```bash
chmod +x setup.sh run.sh
./setup.sh
```

### 2. Available Run Modes

#### Modern Desktop Web GUI (Default)
Launches the local lightweight server on `127.0.0.1` and opens in Chromium `--app` mode for a sleek desktop experience:
```bash
./run.sh
# or
python3 main.py
```

#### Native PyQt6 Desktop GUI
```bash
./run.sh --qt
# or
python3 main.py --qt
```

#### Interactive Terminal CLI
```bash
./run.sh --cli
# or
python3 main.py --cli
```

#### Analyze a Specific Email File via CLI
```bash
python3 main.py -f data/corpus/phishing_paypal.eml
```

#### Inspect a URL via CLI
```bash
python3 main.py -u "https://paypa1-security.com/restore"
```

#### Output JSON for Automated Pipelines
```bash
python3 main.py -f data/corpus/phishing_paypal.eml --json
```

---

## Automated Testing & Verification

The project includes 27 comprehensive automated unit tests covering headers, body linguistics, URLs, scoring math, ground-truth corpus classification, and offline safety:

```bash
# Run unit test suite via setup script:
./setup.sh --test

# Or using unittest directly:
python3 -m unittest discover -s tests -v

# Or using pytest:
pytest -v
```

### Test Suite Summary
- `test_headers.py`: Validates display name spoofing, Reply-To mismatches, SPF/DKIM parsing, and freemail impersonation.
- `test_body.py`: Validates urgency extraction, credential harvesting phrases, greeting detection, and HTML zero-width obfuscation.
- `test_url.py`: Validates raw IP detection, anchor mismatches, high-risk TLDs, and typosquatting/leetspeak.
- `test_scoring.py`: Validates 0-100 clamping, tier classification, smoking-gun threshold escalation, and disclaimers.
- `test_safety.py`: Mocks `socket.socket.connect` and `urllib.request.urlopen` to guarantee **zero network connections** during analysis.
- `test_corpus.py`: Verifies ground-truth accuracy across all 7 synthetic emails.

---

## Author & Attribution

- **Author:** Ali Abbas Haidar (Raqin Al-Asraar)
- **GitHub:** [@raqinalasraar](https://github.com/raqinalasraar)
- **Email:** aliabbashaidar313@gmail.com
- **Internship:** Cybersecurity Internship — CodeNova — Batch 01 (Task 2)

---

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for complete details.

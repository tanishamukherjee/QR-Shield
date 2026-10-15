# QRShield — Implementation Guide

This document provides a technical walkthrough of the QRShield codebase, data models, heuristic detection rules, and frontend-backend interaction patterns.

---

## 1. Directory Structure

```
qrshield/
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Navbar.jsx           # Application header & live backend status badge
│   │   │   ├── Scanner.jsx          # Drag-and-drop QR decoder, manual link tester & 8 demo presets
│   │   │   ├── DecodedUrlPanel.jsx  # Safe link preview with copy action
│   │   │   ├── AnalysisResults.jsx  # Score gauge, findings cards, precautions
│   │   │   ├── ScanHistory.jsx      # Bounded local storage history list (view saved results)
│   │   │   ├── AboutMethodology.jsx # Architecture and detection rule breakdown
│   │   │   └── Footer.jsx           # College project metadata
│   │   ├── services/
│   │   │   ├── api.js               # Fetch client & health check for AWS Lambda Function URL
│   │   │   └── mockAnalyzer.js      # Offline client simulation engine (mirrors rules.py)
│   │   ├── utils/
│   │   │   ├── qrDecoder.js         # jsQR canvas image decoding & URL validation
│   │   │   └── historyStorage.js    # Sanitized localStorage manager
│   │   ├── App.jsx                  # Main view container & state coordinator
│   │   ├── App.css                  # Responsive design system & animations
│   │   ├── index.css                # Global CSS reset & variables
│   │   └── main.jsx                 # React root mount
│   ├── generate_samples.js          # Generates the sample QR images
│   ├── verify_qr_samples.js         # Decodes every sample QR image with jsQR
│   ├── verify_parity.js             # Checks the offline simulation against the shared parity cases
│   ├── package.json
│   ├── vite.config.js
│   ├── index.html
│   └── .env.example
├── backend/
│   ├── lambda_function.py           # AWS Lambda Function URL entrypoint, health check & CORS handler
│   ├── url_analyzer.py              # Browser-equivalent URL parser, scoring aggregator, output builder
│   ├── rules.py                     # 16 heuristic security rule implementations
│   ├── local_server.py              # Zero-dependency local development server
│   └── tests/
│       ├── __init__.py
│       ├── test_analyzer.py         # Rule, scoring and Lambda handler unit tests (35 tests)
│       ├── test_parity.py           # Runs the shared parity cases through the Python engine
│       └── parity_cases.json        # 48 shared cases checked against BOTH engines
├── sample_qr_codes/                 # 8 sample QR images matching the UI presets
├── docs/
│   ├── ARCHITECTURE.md              # System design and Mermaid flowcharts
│   ├── IMPLEMENTATION.md            # Technical code and rule documentation
│   ├── SECURITY_AND_CLASSIFICATION.md # Threat classification model & security engineering
│   ├── TESTING.md                   # Test cases, edge conditions, test report
│   ├── DEPLOYMENT.md                # AWS Lambda Function URL deployment guide
│   └── PRESENTATION_OUTLINE.md      # 7–8 minute presentation script
├── .gitignore
└── README.md
```

---

## 2. Browser-Equivalent URL Parsing

A browser decides where a link really goes, so `url_analyzer.py` reads every URL the same way a browser does **before** any rule runs (following the WHATWG URL Standard):

| Input as written | Host the browser connects to | How QRShield handles it |
|---|---|---|
| `https://evil.com\@google.com/` | `evil.com` | `\` before the query is read as `/`; flagged by `SEC-BSLASH-013` |
| `http://3232235876/`, `http://0xC0A80164/`, `http://0300.0250.1.100/`, `http://127.1/` | `192.168.1.100` / `127.0.0.1` | Decimal, hex, octal and shorthand IPv4 decoded; flagged by `SEC-IPOBF-014` |
| `https://pаypal.com/` (Cyrillic `а`) | `xn--pypal-4ve.com` | Converted to punycode (IDNA); flagged by `SEC-TYPO-015` and `SEC-IDN-016` |
| `https://%65vil.com/` | `evil.com` | Percent-decoded |
| `http://example.com:99999/`, `http://1.2.3.4.5/` | *(browser refuses)* | Rejected with HTTP 400 |

The JavaScript offline simulation uses the browser's own `new URL()` parser, so both engines see the same host. `verify_parity.js` and `test_parity.py` enforce this.

---

## 3. Security Rule Engine Specifications

The detection engine (`backend/rules.py`) evaluates 16 static features of the submitted URL:

| Rule ID | Title | Severity | Score Weight | Trigger |
|---|---|---|---|---|
| `SEC-SCHEME-001` | Unencrypted HTTP Scheme | `MEDIUM` | +20 | URL uses `http://` rather than `https://`. |
| `SEC-CRED-002` | Embedded Authentication Credentials | `HIGH` | +35 | URL embeds `user:pass@host`. |
| `SEC-CRED-002` | Disguised Destination ('@' Trick) | `CRITICAL` | +35 | The text before `@` looks like a domain or names a brand (`google.com@evil.com`). |
| `SEC-IP-003` | IP Address Used as Hostname | `HIGH` | +30 | Host is a raw IPv4/IPv6 address. |
| `SEC-PORT-004` | Non-Standard Port | `MEDIUM` / `HIGH` | +15 / +25 | Port other than 80/443; +25 for 21, 22, 23, 25, 3389, 4444, 6667. |
| `SEC-SHORT-005` | Known URL Shortening Service | `MEDIUM` | +30 | Host is a known shortener (`bit.ly`, `tinyurl.com`, …). |
| `SEC-SUBDOM-006` | Excessive Subdomain Depth | `MEDIUM` | +15 | 3+ subdomain levels in front of the registered domain (`co.uk`-style suffixes handled). |
| `SEC-LEN-007` | Unusually Long Hostname | `LOW` | +10 | Hostname exceeds 45 characters. |
| `SEC-HYPHEN-008` | Excessive Hyphens in Hostname | `MEDIUM` | +15 | 3+ hyphens (the `xn--` punycode prefix is not counted). |
| `SEC-TLD-009` | High-Risk Top-Level Domain | `LOW` | +10 | Abused low-cost TLD (`.xyz`, `.top`, `.click`, …). |
| `SEC-SPOOF-010` | Potential Brand Impersonation | `HIGH` | +30 | A brand appears as a whole word in a domain that is not the brand's own (`google.github.io`, `paypal.xyz`). |
| `SEC-SPOOF-010` | Brand Impersonation with Phishing Lure | `CRITICAL` | +30 | As above **plus** a login lure word in the host or path (`paypal-login.com`, `…/login`) or the brand's full domain placed in front of another (`paypal.com.evil.com`). |
| `SEC-REDIR-011` | Open Redirect / Chained URL | `MEDIUM` | +15 | Path/query contains an embedded URL (`?url=https://…`). |
| `SEC-URLLEN-012` | Unusually Long URL | `LOW` | +10 | URL as written exceeds 250 characters. |
| `SEC-BSLASH-013` | Backslash in URL Address | `CRITICAL` | +30 | `\` before the query/fragment (browsers read it as `/`). |
| `SEC-IPOBF-014` | Disguised IP Address | `CRITICAL` | +25 | IPv4 written in decimal/hex/octal/shorthand form. |
| `SEC-TYPO-015` | Look-alike Brand Name | `CRITICAL` | +35 | Look-alike characters imitate a brand (`paypa1`, `rnicrosoft`, Cyrillic `pаypal`). |
| `SEC-TYPO-015` | Possible Typosquatted Brand | `HIGH` | +30 | One letter away from a brand of 6+ letters (`goggle`, `netfix`). |
| `SEC-IDN-016` | Internationalized Domain Name | `MEDIUM` | +15 | Domain contains an `xn--` (punycode) label. |
| `SEC-IDN-016` | Mixed-Alphabet Domain | `HIGH` | +30 | A label mixes Latin with Cyrillic or Greek letters. |

### How brand detection avoids false alarms
- **Registered domain:** a small built-in list of two-part suffixes (`co.uk`, `co.in`, `com.au`, …) means `www.amazon.co.uk` is read as the brand's own domain.
- **Official domains:** the registered name *is* the brand on a normal TLD (`apple.com`, `google.co.in`, but not `paypal.xyz`), or the domain is a known brand-owned one (`microsoftonline.com`, `google-analytics.com`, …).
- **Whole words only:** a brand matches a whole hostname word, or a brand glued to a security keyword (`paypalsecure`, `appleid`). `pineapple.com` and `purchase-store.com` do not match.
- **Typo exceptions:** ordinary words one letter from a brand (`finance` vs `binance`) are excluded.

---

## 4. Transparent Scoring Model

```python
raw_score = sum(finding["score_impact"] for finding in findings)

# Multi-indicator compound risk bonus
if len(findings) >= 3:
    raw_score += 10

final_score = max(0, min(100, raw_score))

# CRITICAL findings are tricks with no legitimate use: always at least High
if any(f["severity"] == "CRITICAL" for f in findings):
    final_score = max(final_score, 70)
```

### Risk Level Mapping
- **Low Risk (0 – 29):** No indicators, or a single weak one such as plain HTTP (20).
- **Medium Risk (30 – 69):** Notable indicators such as a URL shortener (30), embedded credentials (35), a raw IP over HTTPS (30) or a brand name on an unrelated domain (30).
- **High Risk (70 – 100):** Any CRITICAL deception trick, or several indicators combined (e.g. HTTP + raw IP + custom port = 75).

---

## 5. API Request & Response Contracts

### Health Check (`GET /`)
```json
{
  "service": "QRShield",
  "status": "healthy",
  "engine_version": "1.3.0",
  "message": "Send POST requests with {\"url\": \"...\"} to analyze."
}
```
The frontend calls this on load to set the status badge (*Backend Active* / *Backend Unreachable*).

### Request Payload (`POST /`)
```json
{
  "url": "https://paypal.account-verify.xyz/login"
}
```

### Response Payload (`HTTP 200 OK`)
Real engine output for the "Spoofed Brand" preset (only `analyzed_at` fixed for the example):
```json
{
  "status": "success",
  "risk_score": 70,
  "risk_level": "High",
  "normalized_url": "https://paypal.account-verify.xyz/login",
  "hostname": "paypal.account-verify.xyz",
  "scheme": "https",
  "port": null,
  "findings": [
    {
      "rule_id": "SEC-TLD-009",
      "title": "High-Risk Top-Level Domain (.xyz)",
      "severity": "LOW",
      "score_impact": 10,
      "description": "The domain uses the '.xyz' top-level domain, which has historically shown elevated rates of spam, abuse, and disposable phishing campaigns due to low registration costs.",
      "recommendation": "Exercise vigilance when visiting domains under low-reputation generic TLDs."
    },
    {
      "rule_id": "SEC-SPOOF-010",
      "title": "Brand Impersonation with Phishing Lure (PayPal)",
      "severity": "CRITICAL",
      "score_impact": 30,
      "description": "The brand name 'paypal' appears in 'paypal.account-verify.xyz', but the registered domain 'account-verify.xyz' is not an official PayPal domain, and the link also uses login/verification wording to lure users into entering credentials. This is the classic phishing pattern.",
      "recommendation": "Do not provide credentials. Navigate directly to the official website by typing the official address in your browser."
    }
  ],
  "summary": "HIGH RISK: Detected 2 indicator(s) suggesting deception or abnormal configuration on 'paypal.account-verify.xyz'. We strongly advise against visiting or trusting this destination.",
  "recommendations": [
    "Exercise vigilance when visiting domains under low-reputation generic TLDs.",
    "Do not provide credentials. Navigate directly to the official website by typing the official address in your browser.",
    "Verify the organization's authentic domain independently before entering credentials."
  ],
  "analyzed_at": "2026-10-15T12:00:00.000000+00:00",
  "engine_version": "1.3.0"
}
```
The score is 70 because the raw sum is 40 (10 + 30) and the CRITICAL finding raises it to the High floor.

---

## 6. Frontend Behaviour Notes

- **Backend status badge:** set from the `GET /` health check on load and updated after every scan (*Checking…*, *Backend Active*, *Backend Unreachable · Simulation*, *Offline Simulation*).
- **Offline simulation:** if the backend is unreachable or not configured, `mockAnalyzer.js` runs the same 16 rules in the browser and the result is clearly labelled as a simulation.
- **History:** each entry stores the full result with the URL sanitized (credentials removed, query replaced). "View Result" shows that saved result; it does not rescan, because the sanitized URL is not the original link.

# QRShield — Implementation Guide

This document provides a technical walkthrough of the QRShield codebase, data models, heuristic detection rules, and frontend-backend interaction patterns.

---

## 1. Directory Structure

```
qrshield/
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Navbar.jsx           # Application header & cloud status indicator
│   │   │   ├── Scanner.jsx          # Drag-and-drop QR decoder & manual link tester
│   │   │   ├── DecodedUrlPanel.jsx  # Safe link preview with copy action
│   │   │   ├── AnalysisResults.jsx  # Score gauge, findings cards, precautions
│   │   │   ├── ScanHistory.jsx      # Bounded local storage history list
│   │   │   ├── AboutMethodology.jsx # Architecture and detection rule breakdown
│   │   │   └── Footer.jsx           # College project metadata
│   │   ├── services/
│   │   │   ├── api.js               # Fetch client for AWS Lambda Function URL
│   │   │   └── mockAnalyzer.js      # Offline client simulation engine
│   │   ├── utils/
│   │   │   ├── qrDecoder.js         # jsQR canvas image decoding & URL validation
│   │   │   └── historyStorage.js    # Sanitized localStorage manager
│   │   ├── App.jsx                  # Main view container & state coordinator
│   │   ├── App.css                  # Responsive design system & animations
│   │   ├── index.css                # Global CSS reset & variables
│   │   └── main.jsx                 # React root mount
│   ├── package.json
│   ├── vite.config.js
│   ├── index.html
│   └── .env.example
├── backend/
│   ├── lambda_function.py           # AWS Lambda Function URL entrypoint & CORS handler
│   ├── url_analyzer.py              # URL parser, scoring aggregator, output builder
│   ├── rules.py                     # Heuristic security rule implementations
│   ├── local_server.py              # Zero-dependency local development server
│   └── tests/
│       ├── __init__.py
│       └── test_analyzer.py         # Automated unit test suite (20 tests)
├── docs/
│   ├── ARCHITECTURE.md              # System design and Mermaid flowcharts
│   ├── IMPLEMENTATION.md            # Technical code and rule documentation
│   ├── TESTING.md                   # Test cases, edge conditions, test report
│   └── DEPLOYMENT.md                # AWS Lambda Function URL deployment guide
├── .gitignore
└── README.md
```

---

## 2. Security Rule Engine Specifications

The detection engine (`backend/rules.py`) evaluates static features of the submitted URL:

| Rule ID | Title | Severity | Score Weight | Description | Action Recommendation |
|---|---|---|---|---|---|
| `SEC-SCHEME-001` | Unencrypted HTTP Scheme | `MEDIUM` | +20 | URL uses unencrypted `http://` rather than `https://`. | Do not submit credentials or personal information. |
| `SEC-CRED-002` | Embedded Authentication Credentials | `HIGH` | +35 | URL embeds username/password (`user:pass@host`) or misleading `@` delimiter. | Do not navigate; classic phishing spoofing tactic. |
| `SEC-IP-003` | IP Address Used as Hostname | `HIGH` | +30 | Hostname is a raw IPv4/IPv6 address instead of a domain name. | Treat destination with extreme caution; verified web services use domains. |
| `SEC-PORT-004` | Non-Standard Web Port | `MEDIUM` / `HIGH` | +15 / +25 | Destination port is unusual (e.g. 8080, 8443, 21, 22, 3389). | Confirm if network service legitimately expects non-standard port traffic. |
| `SEC-SHORT-005` | Known URL Shortener | `MEDIUM` | +20 | Domain is a recognized URL shortening service (e.g. `bit.ly`, `tinyurl.com`). | Expand destination link prior to visiting to verify actual endpoint. |
| `SEC-SUBDOM-006` | Excessive Subdomain Depth | `MEDIUM` | +15 | Hostname contains 5 or more dot-separated subdomain labels. | Inspect the effective root domain carefully. |
| `SEC-LEN-007` | Unusually Long Hostname | `LOW` | +10 | Hostname exceeds 45 characters. | Verify root domain legitimacy. |
| `SEC-HYPHEN-008` | Excessive Hyphens in Hostname | `MEDIUM` | +15 | Hostname contains 3 or more hyphens (e.g. `paypal-login-account-update`). | Check whether the brand legitimately operates under hyphenated domain. |
| `SEC-TLD-009` | High-Risk Top-Level Domain | `LOW` | +10 | Uses a TLD frequently leveraged in ephemeral phishing campaigns (`.xyz`, `.top`, `.click`). | Exercise elevated scrutiny. |
| `SEC-SPOOF-010` | Brand Impersonation in Host | `HIGH` | +30 | Major brand keyword (PayPal, Apple, Microsoft, etc.) appears in subdomain or prefix of unrelated domain. | Do not enter credentials; navigate directly via official website. |
| `SEC-REDIR-011` | Open Redirect / Chained URL | `MEDIUM` | +15 | Query parameters contain embedded secondary URL targets. | Verify final destination endpoint before authenticating. |
| `SEC-URLLEN-012` | Unusually Long URL | `LOW` | +10 | Total URL length exceeds 250 characters. | Inspect query parameters for payload injections. |

---

## 3. Transparent Scoring Model

```python
raw_score = sum(finding["score_impact"] for finding in findings)

# Multi-indicator compound risk multiplier
if len(findings) >= 3:
    raw_score += 10

final_score = max(0, min(100, raw_score))
```

### Risk Level Mapping
- **Low Risk (0 – 29):** URL adheres to standard HTTPS conventions with minimal or zero anomalies.
- **Medium Risk (30 – 69):** Contains notable indicators such as URL shortening, unencrypted HTTP, or non-standard port listeners.
- **High Risk (70 – 100):** Multiple red flags present, such as raw IP addresses, credential embedding, or brand spoofing keywords.

---

## 4. API Request & Response Contracts

### Request Payload (`POST /`)
```json
{
  "url": "https://paypal.account-verify.xyz/login"
}
```

### Response Payload (`HTTP 200 OK`)
```json
{
  "status": "success",
  "risk_score": 75,
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
      "description": "The domain uses the '.xyz' top-level domain...",
      "recommendation": "Exercise vigilance when visiting domains under low-reputation generic TLDs."
    },
    {
      "rule_id": "SEC-SPOOF-010",
      "title": "Potential Brand Impersonation (Paypal)",
      "severity": "HIGH",
      "score_impact": 30,
      "description": "The recognized brand name 'paypal' appears in the subdomain...",
      "recommendation": "Do not provide credentials. Navigate directly to the official website."
    }
  ],
  "summary": "HIGH RISK: Detected 2 indicator(s) suggesting deception...",
  "recommendations": [
    "Exercise vigilance when visiting domains under low-reputation generic TLDs.",
    "Do not provide credentials. Navigate directly to the official website.",
    "Verify the organization's authentic domain independently before entering credentials."
  ],
  "analyzed_at": "2026-10-15T12:00:00.000000+00:00",
  "engine_version": "1.0.0"
}
```

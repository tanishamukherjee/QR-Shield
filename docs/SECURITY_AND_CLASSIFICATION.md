# QRShield — Threat Classification Model & Security Engineering Guide

This document provides a comprehensive technical breakdown of how **QRShield** analyzes, scores, and classifies QR code links as **Safe (Low Risk)**, **Suspicious (Medium Risk)**, or **Dangerous (High Risk)**, alongside the complete suite of **application security engineering safeguards** built into the project.

---

## 1. Threat Context: The Problem of "Quishing" (QR Phishing)

Unlike traditional desktop web browsing where users can hover over a hyperlink to preview the destination URL, physical and digital QR codes conceal their embedded destination:
- **Physical Tampering:** Attackers paste malicious QR stickers over legitimate QR codes on restaurant menus, parking meters, utility bills, and payment terminals.
- **Deceptive Mobile Behavior:** Mobile operating systems traditionally offer a single prompt that opens the native browser immediately upon scanning, exposing users to zero-day browser exploits, credential phishing portals, and drive-by malware.
- **The QRShield Paradigm:** QRShield introduces a **pre-click static security gateway** that decodes the QR code without opening it, evaluates the URL syntax and host hierarchy using deterministic heuristic rules, and assigns an objective risk score before the user decides whether to proceed.

---

## 2. URL Classification & Risk Scoring Methodology

QRShield rejects opaque, probabilistic "black box" scoring in favor of a **transparent, deterministic heuristic scoring engine**. Every score is reproducible and directly attributable to specific, documented rule triggers.

### Mathematical Scoring Function

The risk score $S \in [0, 100]$ is computed as follows:

$$S_{\text{raw}} = \sum_{i=1}^{N} W_i$$

Where:
- $W_i$ is the static severity weight of the $i$-th triggered security rule.
- If $N \ge 3$ (three or more distinct red flags fire simultaneously), a **compound risk multiplier** of $+10$ is applied to penalize combinations of suspicious indicators (e.g., unencrypted HTTP + raw IP + custom port).

$$S_{\text{final}} = \min(100, \max(0, S_{\text{raw}} + \text{CompoundBonus}))$$

```
   0 ------------------- 29 ------------------- 69 ------------------- 100
  [      LOW RISK          ] [     MEDIUM RISK       ] [      HIGH RISK         ]
  Clean HTTPS domain,        URL shorteners,           Raw IPs, brand spoofing,
  standard web ports,        unencrypted HTTP,         embedded credentials,
  standard URL length        unusual ports, long URLs  deceptive subdomains
```

### Risk Category Thresholds

| Risk Category | Score Range | Visual Theme | Assessment & Required User Action |
|---|---|---|---|
| **Low Risk** | `0 – 29` | 🟢 Emerald Green | **Standard Caution:** The link adheres to standard web security practices (HTTPS, registered domain name, standard port 443, no credential embedding). Normal internet hygiene applies. |
| **Medium Risk** | `30 – 69` | 🟡 Amber Warning | **Elevated Caution:** The link contains suspicious or masking patterns (such as a URL shortener that conceals the true endpoint, an unencrypted HTTP protocol, or a custom port). Inspect the link destination before browsing. |
| **High Risk** | `70 – 100` | 🔴 Crimson Danger | **Significant Threat:** The link exhibits clear deceptive indicators (brand impersonation in a subdomain, raw IP address in place of a domain, embedded basic authentication credentials). Do not open or enter credentials. |

---

## 3. Detailed Breakdown of the 12 Security Rules

The table below explains how each heuristic rule is triggered, its security rationale, and its score impact:

| Rule ID | Rule Title | Severity | Score Impact | Trigger Condition & Technical Rationale |
|---|---|---|---|---|
| **`SEC-SCHEME-001`** | Unencrypted HTTP Scheme | `MEDIUM` | **+20** | **Trigger:** Protocol scheme is `http://` instead of `https://`.<br>**Rationale:** HTTP traffic transmits credentials, session cookies, and form data in plain text, exposing the user to Man-in-the-Middle (MitM) eavesdropping, packet tampering, and rogue Wi-Fi snooping. |
| **`SEC-CRED-002`** | Embedded Authentication Credentials | `HIGH` | **+35** | **Trigger:** Host authority contains user/password syntax (`user:pass@host`) or a deceptive `@` delimiter.<br>**Rationale:** Attackers frequently format URLs as `https://google.com@evil-site.com` to trick users into believing they are visiting Google, while the browser resolves the host after the `@` symbol. |
| **`SEC-IP-003`** | IP Address Used as Hostname | `HIGH` | **+30** | **Trigger:** Host is an IPv4 (`192.168.1.100`) or IPv6 address instead of a domain name.<br>**Rationale:** Legitimate commercial websites almost universally resolve via registered domain names with TLS certificates. Bare IP addresses in QR codes are typical of phishing relays, IoT botnet control panels, or internal SSRF targeting. |
| **`SEC-PORT-004`** | Non-Standard Web Port | `MEDIUM` / `HIGH` | **+15** / **+25** | **Trigger:** URL specifies a custom port other than 80 or 443 (e.g. `:8080`, `:8443`, `:3389`, `:21`).<br>**Rationale:** Custom ports are commonly configured by attackers to bypass enterprise firewall filters, expose shadow web services, or evade standard reverse-proxy security controls. High-risk ports (21, 22, 23, 25, 3389) receive +25. |
| **`SEC-SHORT-005`** | Known URL Shortener | `MEDIUM` | **+20** | **Trigger:** Host matches recognized shortener domains (`bit.ly`, `tinyurl.com`, `t.co`, `cutt.ly`, etc.).<br>**Rationale:** Shorteners obfuscate the final destination. In physical QR codes, using a shortener is redundant (QR codes natively support long URLs) and is frequently deployed specifically to conceal malicious landing pages. |
| **`SEC-SUBDOM-006`** | Excessive Subdomain Depth | `MEDIUM` | **+15** | **Trigger:** Hostname contains 5 or more dot-separated subdomain labels.<br>**Rationale:** Subdomain stuffing (e.g., `login.secure.update.chase.bank.xyz.attacker.com`) is engineered to push the true registration domain offscreen on mobile viewports. |
| **`SEC-LEN-007`** | Unusually Long Hostname | `LOW` | **+10** | **Trigger:** Hostname exceeds 45 characters.<br>**Rationale:** Excessive hostname length correlates with Domain Generation Algorithms (DGA) or subdomain concatenation techniques used in disposable phishing campaigns. |
| **`SEC-HYPHEN-008`** | Excessive Hyphens in Hostname | `MEDIUM` | **+15** | **Trigger:** Hostname contains 3 or more hyphens (`-`).<br>**Rationale:** Phishing kits frequently rely on hyphen-stuffed domain names (e.g., `paypal-security-account-verification-login.com`) to register available variations that appear convincing to the human eye. |
| **`SEC-TLD-009`** | High-Risk Top-Level Domain | `LOW` | **+10** | **Trigger:** Domain uses high-abuse generic TLDs (`.xyz`, `.top`, `.click`, `.buzz`, `.work`, `.casa`).<br>**Rationale:** Due to penny-pricing and lax registrar verification, these TLDs account for disproportionate volumes of short-lived, disposable phishing campaigns. |
| **`SEC-SPOOF-010`** | Potential Brand Impersonation | `HIGH` | **+30** | **Trigger:** Brand names (PayPal, Apple, Google, Microsoft, Amazon, Chase, Binance, etc.) appear in the subdomain or prefix of a domain registered to an unrelated entity.<br>**Rationale:** A textbook social engineering tactic (e.g., `paypal.com.verification-notice.xyz`). The root domain is owned by an attacker, but the brand name creates false trust. |
| **`SEC-REDIR-011`** | Open Redirect / Chained URL | `MEDIUM` | **+15** | **Trigger:** Query parameters contain redirect targets (e.g., `?url=https://...`, `?redirect=http...`).<br>**Rationale:** Open redirect vulnerabilities on legitimate sites allow attackers to bounce victims from a trusted origin to a credential harvesting site without triggering domain filters. |
| **`SEC-URLLEN-012`** | Unusually Long URL | `LOW` | **+10** | **Trigger:** Total URL character count exceeds 250 characters.<br>**Rationale:** Oversized URLs are occasionally used to pad base64-encoded exploit payloads or tracking identifiers that evade simple URL inspection. |

---

## 4. Security Engineering Safeguards Implemented in QRShield

QRShield implements rigorous security controls across every tier of the application:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        QRShield Security Architecture                  │
└────────────────────────────────────────────────────────────────────────┘
  1. Client Privacy Tier       2. Transport & Boundary Tier    3. Serverless Compute Tier
  ┌───────────────────────┐   ┌───────────────────────────┐   ┌────────────────────────┐
  │ - Browser HTML5 Canvas│   │ - Strict CORS Policies    │   │ - Stateless AWS Lambda │
  │ - Local jsQR Decoding │──►│ - No SSRF / No Fetching   │──►│ - CloudWatch Redaction │
  │ - Zero Image Upload   │   │ - RFC URL Sanitization    │   │ - Non-Root Execution   │
  │ - Bounded LocalStorage│   │ - Safe Monospace Previews │   │ - Scales to Zero ($0)  │
  └───────────────────────┘   └───────────────────────────┘   └────────────────────────┘
```

### A. Client-Side Image Privacy (Zero-Knowledge Ingestion)
- **Problem:** Conventional QR scanning services require users to upload images to backend servers or storage buckets (e.g., Amazon S3). This exposes private photos, personal badges, and confidential documents to cloud breaches.
- **QRShield Solution:** Image decoding is performed **entirely in browser memory** using HTML5 Canvas and `jsQR`.
- **Guarantee:** Image pixel data is **never transmitted across the network**, never written to disk, and never stored in any cloud repository.

### B. Prevention of Server-Side Request Forgery (SSRF) & Blind Probing
- **Problem:** Many threat scanners automatically follow redirects or retrieve the webpage HTML to inspect content. This allows malicious actors to weaponize the scanner as an open proxy, probe internal AWS metadata endpoints (`http://169.254.169.254/`), or alert the attacker that their phishing link is being analyzed.
- **QRShield Solution:** QRShield performs **strictly static, non-intrusive URL analysis**.
- **Guarantee:** The backend never executes outbound HTTP/DNS requests to the target destination. The attacker receives zero telemetry, and internal network infrastructure is completely isolated.

### C. Automated CloudWatch Log Sanitization (PII & Token Redaction)
- **Problem:** URLs frequently contain sensitive authentication tokens, OAuth parameters, passwords, or personal email addresses (e.g., `https://example.com/reset?token=SECRET_KEY&email=user@test.com`). Storing these in Amazon CloudWatch creates compliance liabilities and credential leak risks.
- **QRShield Solution:** Before any log line is emitted to Amazon CloudWatch, the target URL is processed through `sanitize_url_for_logging()`:
  - Usernames and passwords in the authority part are stripped.
  - All query parameters are redacted and replaced with `?[REDACTED_QUERY]`.
  - Only the scheme, host, and path structure are logged for operational diagnostics.

### D. Safe Rendering & Zero Auto-Navigation
- **Problem:** Malicious QR codes rely on instant execution. If an application parses a link and auto-redirects the user, the protective buffer is eliminated.
- **QRShield Solution:**
  - The extracted link is rendered in a **read-only, styled monospace container**.
  - Automatic navigation, `window.location` assignment, or automatic link opening is strictly prohibited in the codebase.
  - A copy button allows the user to copy the link manually if they choose to proceed after reviewing the risk score.
  - All user-controlled text is rendered via React's virtual DOM escaping engine, preventing Cross-Site Scripting (XSS).

### E. Hard Input Validation & Boundary Enforcement
- **Length Constraint:** URLs are strictly capped at **2,048 characters** (the maximum safe URL length supported by major browsers and web servers). Oversized payloads are rejected immediately with `HTTP 400 Bad Request`.
- **Scheme Restriction:** Only `http://` and `https://` protocols are evaluated. Dangerous or local execution schemes (`javascript:`, `data:`, `file:`, `tel:`, `sms:`, `mailto:`) are rejected with explicit guidance.
- **Character Filtering:** URLs containing unprintable ASCII control characters or malformed UTF-8 byte sequences are rejected before parsing.

### F. Least Privilege & CORS Boundary Controls
- **AWS Lambda Isolation:** Runs within a temporary, stateless micro-VM with an IAM execution role limited exclusively to CloudWatch logging (`AWSLambdaBasicExecutionRole`). No database access, VPC peering, or persistent volume mounts exist.
- **CORS Architecture:**
  - The Lambda Function URL enforces Cross-Origin Resource Sharing.
  - Preflight `OPTIONS` requests are answered with `204 No Content` specifying permitted methods (`POST, OPTIONS`) and headers (`Content-Type, Authorization, X-Requested-With`).
  - Production deployments can bind `ALLOWED_ORIGIN` strictly to the verified frontend origin.
- **CORS Transparency:** The documentation clarifies that CORS is a browser-enforced origin constraint, not an authentication mechanism.

### G. Bounded Local History & Data Minimization
- **Client Storage:** Recent scan results are persisted in the browser's `localStorage` to allow quick re-inspection.
- **Data Minimization:**
  - Bounded strictly to the **10 most recent scans**.
  - Query parameters and credentials are sanitized before saving.
  - Image files, thumbnails, or raw canvases are **never stored**.
  - A one-click **"Clear History"** button allows users to immediately purge all stored records.

---

## 5. Summary Matrix: Classification Scenarios in Action

| Scenario | Tested URL | Fired Rules | Risk Score | Final Classification |
|---|---|---|---|---|
| **Legitimate Academic Portal** | `https://www.cambridge.org/research` | *None* | **0 / 100** | 🟢 **Low Risk** |
| **Unencrypted Campus Web** | `http://library.univ-portal.edu/books` | `SEC-SCHEME-001` (+20) | **20 / 100** | 🟢 **Low Risk** (Warning on HTTP) |
| **Masked Marketing Link** | `https://bit.ly/3SecureLogin` | `SEC-SHORT-005` (+20) | **20 / 100** | 🟢 **Low Risk** (Recommendation to preview) |
| **Phishing Brand Spoof** | `https://paypal.account-verify.xyz/login` | `SEC-TLD-009` (+10)<br>`SEC-SPOOF-010` (+30) | **40 / 100** | 🟡 **Medium Risk** |
| **Raw IP & Custom Port Attack** | `http://192.168.1.100:8080/admin` | `SEC-SCHEME-001` (+20)<br>`SEC-IP-003` (+30)<br>`SEC-PORT-004` (+15)<br>Compound Multiplier (+10) | **75 / 100** | 🔴 **High Risk** |
| **Deceptive Credential Harvester** | `https://root:admin123@web-router.net/auth` | `SEC-CRED-002` (+35) | **35 / 100** | 🟡 **Medium Risk** |

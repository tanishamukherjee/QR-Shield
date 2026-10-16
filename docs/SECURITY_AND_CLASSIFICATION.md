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

### Reading the URL like a browser
Before any rule runs, the backend reads the URL exactly as a browser would: backslashes before the query become `/`, IPv4 addresses written in decimal/hex/octal are decoded, percent-encoded hosts are decoded, and international hosts are converted to punycode. This guarantees that QRShield analyzes the host the browser would actually connect to, not the text an attacker wants the user to see.

### Mathematical Scoring Function

The risk score $S \in [0, 100]$ is computed as follows:

$$S_{\text{raw}} = \sum_{i=1}^{N} W_i$$

Where:
- $W_i$ is the static weight of the $i$-th triggered security rule.
- If $N \ge 3$ (three or more distinct red flags fire simultaneously), a **compound risk bonus** of $+10$ is applied to penalize combinations of suspicious indicators (e.g., unencrypted HTTP + raw IP + custom port).

$$S_{\text{capped}} = \min(100, \max(0, S_{\text{raw}} + \text{CompoundBonus}))$$

- **CRITICAL floor:** if any finding has `CRITICAL` severity (a deception trick with no legitimate use), the score is raised to at least 70:

$$S_{\text{final}} = \begin{cases} \max(S_{\text{capped}}, 70) & \text{if any finding is CRITICAL} \\ S_{\text{capped}} & \text{otherwise} \end{cases}$$

```
   0 ------------------- 29 ------------------- 69 ------------------- 100
  [      LOW RISK          ] [     MEDIUM RISK       ] [      HIGH RISK         ]
  Clean HTTPS domain,        URL shorteners,           Any CRITICAL trick:
  plain HTTP alone,          embedded credentials,     disguised '@' / IP,
  real international         raw IP over HTTPS,        look-alike brands,
  domains                    brand name on an          brand + login lure;
                             unrelated domain          or many flags combined
```

### Severity Levels

| Severity | Meaning |
|---|---|
| `LOW` | Weak signal that is common on legitimate sites. |
| `MEDIUM` | Worth caution; often seen in both legitimate and malicious links. |
| `HIGH` | Strong suspicious signal. |
| `CRITICAL` | A deception trick with no legitimate use. Any CRITICAL finding makes the result High risk. |

### Risk Category Thresholds

| Risk Category | Score Range | Visual Theme | Assessment & Required User Action |
|---|---|---|---|
| **Low Risk** | `0 – 29` | 🟢 Emerald Green | **Standard Caution:** No indicators, or a single weak one such as plain HTTP. Normal internet hygiene applies. |
| **Medium Risk** | `30 – 69` | 🟡 Amber Warning | **Elevated Caution:** The link hides or obscures something: a URL shortener that conceals the true endpoint, embedded credentials, a raw IP address, or a brand name on a domain the brand does not own. Inspect the link before browsing. |
| **High Risk** | `70 – 100` | 🔴 Crimson Danger | **Significant Threat:** The link uses a deliberate deception trick (disguised destination, disguised IP, look-alike brand name, brand name combined with a login lure) or combines several red flags. Do not open or enter credentials. |

---

## 3. Detailed Breakdown of the 16 Security Rules

| Rule ID | Rule Title | Severity | Score Impact | Trigger Condition & Technical Rationale |
|---|---|---|---|---|
| **`SEC-SCHEME-001`** | Unencrypted HTTP Scheme | `MEDIUM` | **+20** | **Trigger:** Protocol scheme is `http://` instead of `https://`.<br>**Rationale:** HTTP traffic transmits credentials, session cookies, and form data in plain text, exposing the user to Man-in-the-Middle (MitM) eavesdropping, packet tampering, and rogue Wi-Fi snooping. |
| **`SEC-CRED-002`** | Embedded Credentials / Disguised Destination | `HIGH` / `CRITICAL` | **+35** | **Trigger:** The host authority contains `user:pass@host`. It is `CRITICAL` when the text before `@` looks like a domain or names a brand (`https://google.com@evil-site.com`).<br>**Rationale:** Browsers treat everything before `@` as a username and open the host after it, so the user sees "google.com" while the browser goes to the attacker's site. |
| **`SEC-IP-003`** | IP Address Used as Hostname | `HIGH` | **+30** | **Trigger:** Host is an IPv4 (`192.168.1.100`) or IPv6 address instead of a domain name.<br>**Rationale:** Legitimate commercial websites almost universally resolve via registered domain names with TLS certificates. Bare IP addresses in QR codes are typical of phishing relays, IoT botnet control panels, or internal SSRF targeting. |
| **`SEC-PORT-004`** | Non-Standard Web Port | `MEDIUM` / `HIGH` | **+15** / **+25** | **Trigger:** URL specifies a custom port other than 80 or 443 (e.g. `:8080`, `:8443`, `:3389`, `:21`).<br>**Rationale:** Custom ports are commonly configured by attackers to bypass enterprise firewall filters, expose shadow web services, or evade standard reverse-proxy security controls. High-risk ports (21, 22, 23, 25, 3389, 4444, 6667) receive +25. |
| **`SEC-SHORT-005`** | Known URL Shortener | `MEDIUM` | **+30** | **Trigger:** Host matches recognized shortener domains (`bit.ly`, `tinyurl.com`, `t.co`, `cutt.ly`, etc.).<br>**Rationale:** Shorteners obfuscate the final destination. In physical QR codes, using a shortener is redundant (QR codes natively support long URLs) and is frequently deployed specifically to conceal malicious landing pages. |
| **`SEC-SUBDOM-006`** | Excessive Subdomain Depth | `MEDIUM` | **+15** | **Trigger:** 3 or more subdomain levels in front of the registered domain (two-part suffixes like `co.uk` are counted correctly).<br>**Rationale:** Subdomain stuffing (e.g., `login.secure.update.chase.attacker.com`) is engineered to push the true registration domain offscreen on mobile viewports. |
| **`SEC-LEN-007`** | Unusually Long Hostname | `LOW` | **+10** | **Trigger:** Hostname exceeds 45 characters.<br>**Rationale:** Excessive hostname length correlates with Domain Generation Algorithms (DGA) or subdomain concatenation techniques used in disposable phishing campaigns. |
| **`SEC-HYPHEN-008`** | Excessive Hyphens in Hostname | `MEDIUM` | **+15** | **Trigger:** Hostname contains 3 or more hyphens (the `xn--` punycode prefix is not counted).<br>**Rationale:** Phishing kits frequently rely on hyphen-stuffed domain names (e.g., `paypal-security-account-verification-login.com`) to register available variations that appear convincing to the human eye. |
| **`SEC-TLD-009`** | High-Risk Top-Level Domain | `LOW` | **+10** | **Trigger:** Domain uses high-abuse generic TLDs (`.xyz`, `.top`, `.click`, `.buzz`, `.work`, `.casa`).<br>**Rationale:** Due to penny-pricing and lax registrar verification, these TLDs account for disproportionate volumes of short-lived, disposable phishing campaigns. |
| **`SEC-SPOOF-010`** | Brand Impersonation | `HIGH` / `CRITICAL` | **+30** | **Trigger:** A brand name (PayPal, Apple, Google, Microsoft, Amazon, Chase, Binance, etc.) appears as a whole word in a domain the brand does not own. It is `CRITICAL` when combined with a login lure (`login`, `verify`, `account`, … in the host or path) or when the brand's full domain is placed in front of another (`paypal.com.evil.com`).<br>**Rationale:** The root domain is owned by an attacker, but the brand name creates false trust. Official domains (`amazon.co.uk`, `accounts.google.com`) and ordinary words containing brand letters (`pineapple.com`) are not flagged. |
| **`SEC-REDIR-011`** | Open Redirect / Chained URL | `MEDIUM` | **+15** | **Trigger:** Path or query contains redirect targets (e.g., `?url=https://...`, `?redirect=http...`).<br>**Rationale:** Open redirect vulnerabilities on legitimate sites allow attackers to bounce victims from a trusted origin to a credential harvesting site without triggering domain filters. |
| **`SEC-URLLEN-012`** | Unusually Long URL | `LOW` | **+10** | **Trigger:** Total URL character count exceeds 250 characters.<br>**Rationale:** Oversized URLs are occasionally used to pad base64-encoded exploit payloads or tracking identifiers that evade simple URL inspection. |
| **`SEC-BSLASH-013`** | Backslash in URL Address | `CRITICAL` | **+30** | **Trigger:** A `\` appears before the query or fragment.<br>**Rationale:** Browsers read `\` as `/`, so `https://evil.com\@google.com` opens `evil.com` while appearing to point to Google. |
| **`SEC-IPOBF-014`** | Disguised IP Address | `CRITICAL` | **+25** | **Trigger:** An IPv4 address written in decimal, hex, octal or shorthand form (`http://3232235876/`, `http://0xC0A80164/`, `http://127.1/`).<br>**Rationale:** Browsers silently decode these forms; legitimate sites never use them, so they exist only to hide the destination. |
| **`SEC-TYPO-015`** | Look-alike / Typosquatted Brand | `CRITICAL` / `HIGH` | **+35** / **+30** | **Trigger:** `CRITICAL` when look-alike characters imitate a brand (`paypa1`, `rnicrosoft`, `g00gle`, Cyrillic `pаypal`); `HIGH` when the name is one letter away from a brand of 6+ letters (`goggle`, `netfix`).<br>**Rationale:** Typosquatted domains catch users who misread or mistype a familiar brand. |
| **`SEC-IDN-016`** | Internationalized / Mixed-Alphabet Domain | `MEDIUM` / `HIGH` | **+15** / **+30** | **Trigger:** The domain contains an `xn--` (punycode) label; `HIGH` when a label mixes Latin with Cyrillic or Greek letters.<br>**Rationale:** Letters from other alphabets can make a fake domain look identical to a real one (homograph attack). Real international domains (`bücher.de`) only receive the MEDIUM note. |

---

## 4. Security Engineering Safeguards Implemented in QRShield

QRShield implements rigorous security controls across every tier of the application:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        QRShield Security Architecture                  │
└────────────────────────────────────────────────────────────────────────┘
  1. Client Privacy Tier       2. Transport & Boundary Tier    3. Serverless Compute Tier
  ┌───────────────────────┐   ┌───────────────────────────┐   ┌────────────────────────┐
  │ - Browser HTML5 Canvas│   │ - Configurable CORS       │   │ - Stateless AWS Lambda │
  │ - Local jsQR Decoding │──►│ - No SSRF / No Fetching   │──►│ - CloudWatch Redaction │
  │ - Zero Image Upload   │   │ - Browser-equivalent URL  │   │ - Least-Privilege Role │
  │ - Bounded LocalStorage│   │   parsing & validation    │   │ - Scales to Zero ($0)  │
  └───────────────────────┘   └───────────────────────────┘   └────────────────────────┘
```

### A. Client-Side Image Privacy (Zero-Knowledge Ingestion)
- **Problem:** Conventional QR scanning services require users to upload images to backend servers or storage buckets (e.g., Amazon S3). This exposes private photos, personal badges, and confidential documents to cloud breaches.
- **QRShield Solution:** Image decoding is performed **entirely in browser memory** using HTML5 Canvas and `jsQR`.
- **Guarantee:** Image pixel data is **never transmitted across the network**, never written to disk, and never stored in any cloud repository.
- **Camera scanning:** live camera frames are decoded the same way, in browser memory only. The browser asks for permission first, and QRShield switches the camera off as soon as a code is found, on Cancel, or when the user leaves the page.

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
- **Length Constraint:** URLs are strictly capped at **2,048 characters**. The browser checks this before sending (so the offline simulation enforces it too), and the backend rejects oversized payloads with `HTTP 400 Bad Request`.
- **Scheme Restriction:** Only `http://` and `https://` protocols are evaluated. Dangerous or local execution schemes (`javascript:`, `data:`, `file:`, `tel:`, `sms:`, `mailto:`) are rejected with explicit guidance.
- **Character Filtering:** URLs containing ASCII control characters are rejected before parsing.
- **Browser-Refused Hosts:** Hosts a browser would refuse (invalid ports such as `:99999`, malformed IP-like hosts such as `1.2.3.4.5`, forbidden host characters, invalid international names) are rejected with `HTTP 400` instead of being analyzed incorrectly.

### F. Least Privilege & CORS Boundary Controls
- **AWS Lambda Isolation:** Runs within a temporary, stateless micro-VM with an IAM execution role limited exclusively to CloudWatch logging (`AWSLambdaBasicExecutionRole`). No database access, VPC peering, or persistent volume mounts exist.
- **CORS Architecture:**
  - Preflight `OPTIONS` requests are answered with `204 No Content` specifying permitted methods (`GET, POST, OPTIONS`) and headers (`Content-Type, Authorization, X-Requested-With`).
  - By default (`ALLOWED_ORIGIN` unset) the handler echoes the caller's origin, which is convenient for development but allows any website to call the API. Production deployments should set `ALLOWED_ORIGIN` to the hosted frontend's exact origin.
- **CORS Transparency:** CORS is a browser-enforced origin constraint, not an authentication mechanism.

### G. Bounded Local History & Data Minimization
- **Client Storage:** Recent scan results are persisted in the browser's `localStorage` so users can review them later.
- **Data Minimization:**
  - Bounded strictly to the **10 most recent scans**.
  - Query parameters and credentials are removed from the stored URL; the saved result only mentions the hostname.
  - Image files, thumbnails, or raw canvases are **never stored**.
  - A one-click **"Clear History"** button allows users to immediately purge all stored records.

---

## 5. Summary Matrix: Classification Scenarios in Action

These are the eight demo presets in the Scanner tab (and the eight images in `sample_qr_codes/`). The scores are checked by `test_28_demo_presets_match_documented_scores`.

| Scenario | Tested URL | Fired Rules | Risk Score | Final Classification |
|---|---|---|---|---|
| **Legitimate Academic Portal** | `https://www.cambridge.org/research` | *None* | **0 / 100** | 🟢 **Low Risk** |
| **Unencrypted Campus Web** | `http://library.univ-portal.edu/books` | `SEC-SCHEME-001` (+20) | **20 / 100** | 🟢 **Low Risk** (Warning on HTTP) |
| **Masked Marketing Link** | `https://bit.ly/3SecureLogin` | `SEC-SHORT-005` (+30) | **30 / 100** | 🟡 **Medium Risk** |
| **Raw IP & Custom Port Attack** | `http://192.168.1.100:8080/admin` | `SEC-SCHEME-001` (+20)<br>`SEC-IP-003` (+30)<br>`SEC-PORT-004` (+15)<br>Compound bonus (+10) | **75 / 100** | 🔴 **High Risk** |
| **Phishing Brand Spoof** | `https://paypal.account-verify.xyz/login` | `SEC-TLD-009` (+10)<br>`SEC-SPOOF-010` CRITICAL (+30)<br>CRITICAL floor → 70 | **70 / 100** | 🔴 **High Risk** |
| **Exposed Router Credentials** | `https://root:admin123@web-router.net/auth` | `SEC-CRED-002` (+35) | **35 / 100** | 🟡 **Medium Risk** |
| **Disguised '@' Destination** | `https://accounts.google.com@secure-check.top/` | `SEC-CRED-002` CRITICAL (+35)<br>`SEC-TLD-009` (+10)<br>CRITICAL floor → 70 | **70 / 100** | 🔴 **High Risk** |
| **Look-alike Brand Domain** | `https://paypa1.com/login` | `SEC-TYPO-015` CRITICAL (+35)<br>CRITICAL floor → 70 | **70 / 100** | 🔴 **High Risk** |

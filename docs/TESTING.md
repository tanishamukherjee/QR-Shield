# QRShield — Testing Documentation & Test Report

This document details the automated unit test suite, frontend validation workflows, and test execution results for the QRShield application.

---

## 1. Automated Backend Unit Test Suite

The backend test suite (`backend/tests/`) exercises every security rule, edge condition, scoring boundary, browser-equivalent URL parsing, and AWS Lambda event routing path.

### Execution Command
```bash
python -m unittest discover -s backend/tests -p "test_*.py" -v
```

### Automated Test Matrix (36 Tests)

| # | Test Method | Target Behavior | Expected Result |
|---|---|---|---|
| 1 | `test_01_valid_clean_https_url` | Clean HTTPS URL (`https://example.edu`) | Score: 0, Risk: Low, Findings: 0 |
| 2 | `test_02_valid_http_url` | Insecure HTTP scheme | Triggers `SEC-SCHEME-001`, Score: 20 |
| 3 | `test_03_ip_address_hostname` | Raw IPv4 host (`http://192.168.1.100/admin`) | Triggers `SEC-IP-003`, Medium/High risk |
| 4 | `test_04_embedded_credentials` | User/pass in URL (`user:pass@host`) | Triggers `SEC-CRED-002`, Score ≥ 35 |
| 5 | `test_05_known_url_shortener` | Recognized shortener (`https://bit.ly/xyz`) | Triggers `SEC-SHORT-005` |
| 6 | `test_06_unusual_ports` | Custom port (`:8443`) | Triggers `SEC-PORT-004` |
| 7 | `test_07_excessively_long_url` | URL length > 250 characters | Triggers `SEC-URLLEN-012` |
| 8 | `test_08_empty_and_whitespace_input` | Empty string or whitespace | Raises `URLValidationError` |
| 9 | `test_09_unsupported_schemes` | `javascript:`, `file:`, `tel:`, `ftp:`, `mailto:` | Raises `URLValidationError` with clear error |
| 10 | `test_10_multiple_suspicious_indicators_high_risk` | URL with 3+ red flags (HTTP, IP, port) | Compound bonus applied; Score ≥ 65 |
| 11 | `test_11_brand_impersonation_in_subdomain` | Subdomain spoofing (`paypal.domain.xyz`) | Triggers `SEC-SPOOF-010` & `SEC-TLD-009` |
| 12 | `test_12_score_determinism` | Same URL analyzed 6 times | Identical score & findings every time |
| 13 | `test_13_valid_response_structure_and_json` | JSON serialization & required keys | Complies with schema; JSON serializable |
| 14 | `test_14_oversized_url_hard_limit` | URL length > 2,048 characters | Raises `URLValidationError` |
| 15 | `test_15_obfuscated_ipv4_hosts_decoded_like_browser` | Decimal / hex / octal / shorthand IPv4 | Decoded to dotted IP; `SEC-IP-003` + `SEC-IPOBF-014`; High |
| 16 | `test_16_backslash_host_confusion` | `https://evil.com\@google.com/` | Host read as `evil.com`; `SEC-BSLASH-013` |
| 17 | `test_17_idn_hostname_converted_to_punycode` | Cyrillic look-alike host | Analyzed as `xn--pypal-4ve.com` |
| 18 | `test_18_hosts_browsers_reject_are_rejected` | `:99999`, `1.2.3.4.5`, `256.1.1.1`, space in host | Raises `URLValidationError` (HTTP 400, not 500) |
| 19 | `test_19_critical_findings_force_high_risk` | Disguised IP, `@` trick, look-alike, backslash | Finding is CRITICAL; score ≥ 70; High |
| 20 | `test_20_plain_credentials_stay_high_not_critical` | `root:admin123@web-router.net` | `SEC-CRED-002` HIGH; Score 35 |
| 21 | `test_21_official_brand_domains_not_flagged` | `amazon.co.uk`, `mail.google.co.in`, `login.microsoftonline.com`, … | No findings |
| 22 | `test_22_brand_words_inside_ordinary_words_not_flagged` | `pineapple.com`, `purchase-store.com`, `finance.com` | No findings |
| 23 | `test_23_brand_impersonation_in_registered_name` | `paypal-login.com`, `paypalsecure.com`, `paypal.xyz`, … | Triggers `SEC-SPOOF-010` |
| 24 | `test_24_idn_rules` | `bücher.de` vs Cyrillic `pаypal.com` | Real IDN: MEDIUM note only; look-alike: High |
| 25 | `test_25_subdomain_depth_uses_registered_domain` | `a.b.example.co.uk` vs `login.secure.update.example.com` | Only the second is flagged |
| 26 | `test_26_brand_with_phishing_lure_is_critical` | Brand + login lure / embedded brand domain | `SEC-SPOOF-010` CRITICAL; High |
| 27 | `test_27_brand_without_lure_stays_medium` | `google.github.io` | `SEC-SPOOF-010` HIGH; Medium |
| 28 | `test_28_demo_presets_match_documented_scores` | All 8 UI presets | Exact scores/levels in Section 5 |
| 29 | `test_lambda_cors_options_preflight` | HTTP `OPTIONS` preflight request | HTTP 204 No Content with CORS headers |
| 30 | `test_lambda_direct_invocation` | Direct invocation with Python dict payload | HTTP 200 with JSON body |
| 31 | `test_lambda_function_url_post` | Function URL HTTP POST with JSON body | HTTP 200 with CORS headers |
| 32 | `test_lambda_get_health_check` | HTTP `GET` health route | HTTP 200 `{"status": "healthy"}`; `GET` allowed by CORS |
| 33 | `test_lambda_missing_url` | POST payload missing `"url"` key | HTTP 400 Bad Request |
| 34 | `test_lambda_unsupported_scheme` | Payload with `javascript:` URI | HTTP 400 Bad Request with guidance |
| 35 | `test_log_sanitization` | Sensitive token in URL query parameter | Logs redacted token (`[REDACTED_QUERY]`) |
| 36 | `test_shared_parity_cases` | 48 shared cases in `parity_cases.json` | Exact rule IDs and scores (see Section 5) |

### Execution Output
```
Ran 36 tests in 0.021s
OK
```

---

## 2. Frontend Validation Scenarios

| Test Case | Interaction Steps | Expected Result |
|---|---|---|
| **Valid QR Upload** | Upload PNG containing `https://example.com` | Canvas decodes QR instantly, extracts URL, displays Low risk results. |
| **Non-QR Image** | Upload JPEG of a landscape without a QR code | Displays friendly error: *"No QR code detected in this image."* |
| **Oversized File** | Upload image exceeding 5 MB | Client validator rejects upload immediately with clear file-size alert. |
| **Invalid MIME Type** | Upload `.txt` or `.exe` file | Client rejects file with *"Unsupported image format"* message. |
| **Non-Web QR Code** | Upload QR code containing `tel:+1234567890` or `WIFI:S:MyWifi;...` | Displays: *"Unsupported scheme. QRShield analyzes web links (http/https) only."* |
| **Manual URL Entry** | Enter `https://paypal.account-verify.xyz/login` | Displays High risk (70) with brand-impersonation findings. |
| **Preset Verification** | Click each of the 8 presets | Updates input and shows the score listed in Section 5. |
| **Copy Link Action** | Click "Copy" on Decoded Link panel | Copies URL to clipboard and changes label to "Copied!" for 2 seconds. |
| **History Persistence** | Scan 3 different URLs, refresh page | Scans persist in `localStorage` under the History tab. |
| **View Saved Result** | Click "View Result" on a History entry | Shows the saved result with a "Saved result" banner; no new scan is sent. |
| **Clear History Action** | Click "Clear History" | Prompts confirmation dialog and wipes stored history entries. |
| **Backend Status Badge** | Load the app with the backend running, then stopped | Badge shows *Backend Active*, then *Backend Unreachable · Simulation* after a scan falls back. |
| **Oversized URL** | Enter a URL longer than 2,048 characters (live or offline mode) | Rejected in the browser with *"URL exceeds the maximum permitted length of 2048 characters."* |
| **Mobile Layout** | Open the site at 360–390 px width | Tabs fit inside the tab bar, score circle stays round, no horizontal scrolling. |
| **Offline Fallback** | Stop the backend or set `VITE_ENABLE_OFFLINE_MOCK=true` | Amber badge and an in-result banner; the simulation is never presented as live AWS. |

---

## 3. Determinism & Stability Verification

A critical security principle is **reproducibility**. An identical URL submitted at different times must always evaluate to the exact same score and findings:
- `test_12_score_determinism` analyzes the same URL six times and compares scores, levels and rule IDs.
- Rules run in a fixed order and the brand list is an ordered tuple, so the reported brand never depends on Python's set ordering.
- Scores are integer sums with no floating-point or time-dependent inputs.

---

## 4. Sample QR Code Image Verification (`verify_qr_samples.js`)

To ensure client-side QR image parsing works reliably with real pixel data, the eight QR PNG files in `sample_qr_codes/` were tested directly against `jsQR` (`cd frontend && node verify_qr_samples.js`):

| Sample Image File | Decoded URL Payload | UI Preset | jsQR Decode Status |
|---|---|---|---|
| `01_safe_university_url.png` | `https://www.cambridge.org/research` | Safe HTTPS | PASS |
| `02_http_unencrypted.png` | `http://library.univ-portal.edu/books` | Plain HTTP | PASS |
| `03_url_shortener.png` | `https://bit.ly/3SecureLogin` | URL Shortener | PASS |
| `04_phishing_spoofed_brand.png` | `https://paypal.account-verify.xyz/login` | Spoofed Brand | PASS |
| `05_raw_ip_custom_port.png` | `http://192.168.1.100:8080/admin` | Raw IP Host | PASS |
| `06_embedded_credentials.png` | `https://root:admin123@web-router.net/auth` | Embedded Auth | PASS |
| `07_disguised_at_link.png` | `https://accounts.google.com@secure-check.top/` | Disguised @ Link | PASS |
| `08_lookalike_domain.png` | `https://paypa1.com/login` | Look-alike Domain | PASS |

All 8 sample QR images decode with 100% accuracy via `jsQR`.

---

## 5. Backend vs. Offline Simulation Parity

The rules exist twice: in Python (`backend/rules.py`) and in JavaScript (`frontend/src/services/mockAnalyzer.js`). To stop them drifting apart, both are checked against the same 48 cases in `backend/tests/parity_cases.json`:

```bash
python -m unittest backend/tests/test_parity.py   # Python engine
cd frontend && npm run verify:parity               # JavaScript engine
```

Only rule IDs and scores are compared (descriptions are allowed to differ). The cases cover the eight presets plus browser-parsing edge cases (decimal/hex/octal IPs, backslashes, IDN look-alikes, percent-encoded hosts), brand false positives (`amazon.co.uk`, `pineapple.com`) and every CRITICAL trick.

Results for the eight presets (both engines):

| Test Scenario URL | Python Score | JS Score | Rule IDs (both engines) | Parity |
|---|---|---|---|---|
| `https://www.cambridge.org/research` | **0** (Low) | **0** (Low) | None | MATCH |
| `http://library.univ-portal.edu/books` | **20** (Low) | **20** (Low) | `SEC-SCHEME-001` | MATCH |
| `https://bit.ly/3SecureLogin` | **30** (Medium) | **30** (Medium) | `SEC-SHORT-005` | MATCH |
| `http://192.168.1.100:8080/admin` | **75** (High) | **75** (High) | `SEC-SCHEME-001`, `SEC-IP-003`, `SEC-PORT-004` | MATCH |
| `https://paypal.account-verify.xyz/login` | **70** (High) | **70** (High) | `SEC-TLD-009`, `SEC-SPOOF-010` | MATCH |
| `https://root:admin123@web-router.net/auth` | **35** (Medium) | **35** (Medium) | `SEC-CRED-002` | MATCH |
| `https://accounts.google.com@secure-check.top/` | **70** (High) | **70** (High) | `SEC-CRED-002`, `SEC-TLD-009` | MATCH |
| `https://paypa1.com/login` | **70** (High) | **70** (High) | `SEC-TYPO-015` | MATCH |

All 48 shared cases match in both engines. As an additional one-off check, 6,425 generated URL variants (combinations of hosts, credentials, ports and paths) were run through both engines with identical scores, rule IDs and severities.

---

## 6. Local Server Live REST API Verification

The Python local development server (`backend/local_server.py`) running on `http://127.0.0.1:8000` was tested using live HTTP requests:

- `GET /` -> HTTP 200 with `{"service": "QRShield", "status": "healthy", "engine_version": "1.3.0", ...}` (the same health route the deployed Lambda serves).
- `OPTIONS /` -> HTTP 204 No Content with `Access-Control-Allow-Methods: GET, POST, OPTIONS`.
- `POST /` with safe URL -> HTTP 200 with `risk_score: 0`, `risk_level: "Low"`.
- `POST /` with spoofed URL -> HTTP 200 with `risk_score: 70`, `risk_level: "High"`, `findings: ['SEC-TLD-009', 'SEC-SPOOF-010']`.
- `POST /` with raw IP host -> HTTP 200 with `risk_score: 75`, `findings: ['SEC-SCHEME-001', 'SEC-IP-003', 'SEC-PORT-004']`.
- `POST /` with disguised `@` link -> HTTP 200 with `risk_score: 70`, `findings: ['SEC-CRED-002', 'SEC-TLD-009']`.
- `POST /` with missing `url` field -> HTTP 400 (`{"status": "error", "message": "Missing required field 'url' in request payload."}`).
- `POST /` with non-HTTP scheme (`tel:`) -> HTTP 400 with explicit scheme rejection message.
- **Log Redaction Test:** Submitted `https://admin:superSecretPassword@example.com/login?token=PRIVATE_SESSION_TOKEN_9999` -> Backend log: `QRShield processing request for target: https://example.com/login?[REDACTED_QUERY]`. The credentials and token were completely scrubbed.

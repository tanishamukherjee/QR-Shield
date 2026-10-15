# QRShield — Testing Documentation & Test Report

This document details the automated unit test suite, frontend validation workflows, and test execution results for the QRShield application.

---

## 1. Automated Backend Unit Test Suite

The backend test suite (`backend/tests/test_analyzer.py`) exercises every security rule, edge condition, scoring boundary, and AWS Lambda event routing path.

### Execution Command
```bash
python -m unittest discover -s backend/tests -p "test_*.py" -v
```

### Automated Test Matrix (20 Tests)

| # | Test Method | Target Behavior | Expected Result | Status |
|---|---|---|---|---|
| 1 | `test_01_valid_clean_https_url` | Clean HTTPS URL (`https://example.edu`) | Score: 0, Risk: Low, Findings: 0 | PASS |
| 2 | `test_02_valid_http_url` | Insecure HTTP scheme | Triggers `SEC-SCHEME-001`, Score: 20 | PASS |
| 3 | `test_03_ip_address_hostname` | Raw IPv4 host (`http://192.168.1.100/admin`) | Triggers `SEC-IP-003`, Medium/High risk | PASS |
| 4 | `test_04_embedded_credentials` | User/pass in URL (`user:pass@host`) | Triggers `SEC-CRED-002`, Score +35 | PASS |
| 5 | `test_05_known_url_shortener` | Recognized shortener (`https://bit.ly/xyz`) | Triggers `SEC-SHORT-005`, Score +20 | PASS |
| 6 | `test_06_unusual_ports` | Custom port (`:8443`) | Triggers `SEC-PORT-004`, Score +15 | PASS |
| 7 | `test_07_excessively_long_url` | URL length > 250 characters | Triggers `SEC-URLLEN-012`, Score +10 | PASS |
| 8 | `test_08_empty_and_whitespace_input` | Empty string or whitespace | Raises `URLValidationError` | PASS |
| 9 | `test_09_unsupported_schemes` | `javascript:`, `file:`, `tel:`, `ftp:`, `mailto:` | Raises `URLValidationError` with clear error | PASS |
| 10 | `test_10_multiple_suspicious_indicators_high_risk` | URL with 3+ red flags (HTTP, IP, port) | Compound penalty applied; High risk (Score >= 65) | PASS |
| 11 | `test_11_brand_impersonation_in_subdomain` | Subdomain spoofing (`paypal.domain.xyz`) | Triggers `SEC-SPOOF-010` & `SEC-TLD-009` | PASS |
| 12 | `test_12_score_determinism` | Repeated calls with identical URL | Exact identical score & findings across 5 runs | PASS |
| 13 | `test_13_valid_response_structure_and_json` | JSON serialization & required dictionary keys | Complies with schema; JSON serializable | PASS |
| 14 | `test_14_oversized_url_hard_limit` | URL length > 2,048 characters | Raises `URLValidationError` | PASS |
| 15 | `test_lambda_direct_invocation` | Direct invocation with Python dict payload | Returns HTTP 200 with JSON body | PASS |
| 16 | `test_lambda_function_url_post` | Function URL HTTP POST with JSON body | Returns HTTP 200 with CORS headers | PASS |
| 17 | `test_lambda_cors_options_preflight` | HTTP `OPTIONS` preflight request | Returns HTTP 204 No Content with CORS headers | PASS |
| 18 | `test_lambda_missing_url` | POST payload missing `"url"` key | Returns HTTP 400 Bad Request | PASS |
| 19 | `test_lambda_unsupported_scheme` | Payload with `javascript:` URI | Returns HTTP 400 Bad Request with guidance | PASS |
| 20 | `test_log_sanitization` | Sensitive token in URL query parameter | Logs redacted token (`[REDACTED_QUERY]`) | PASS |

### Execution Output
```
Ran 20 tests in 0.003s
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
| **Manual URL Entry** | Enter `https://paypal.account-verify.xyz/login` | Instantly validates and displays High risk category with spoofing findings. |
| **Preset Verification** | Click "Safe HTTPS", "Plain HTTP", "Raw IP", etc. | Updates input and executes evaluation immediately. |
| **Copy Link Action** | Click "Copy" on Decoded Link panel | Copies URL to clipboard and changes label to "Copied!" for 2 seconds. |
| **History Persistence** | Scan 3 different URLs, refresh page | Scans persist in `localStorage` under Recent Scans tab. |
| **Clear History Action** | Click "Clear History" | Prompts confirmation dialog and wipes stored history entries. |
| **Offline Fallback** | Disconnect backend server or set `VITE_ENABLE_OFFLINE_MOCK=true` | Displays amber "Offline Simulation" badge; transparently warns user without presenting mock as live AWS. |

---

## 3. Determinism & Stability Verification

A critical security principle is **reproducibility**. An identical URL submitted at different times must always evaluate to the exact same score and findings:
- Verification script executed 5 iterations across all rule permutations.
- Zero floating-point discrepancies or time-dependent variances.
- Findings are consistently sorted and deterministic.

---

## 4. Sample QR Code Image Verification (`verify_qr_samples.js`)

To ensure client-side QR image parsing works reliably with real pixel data, six QR PNG files in `sample_qr_codes/` were tested directly against `jsQR`:

| Sample Image File | Decoded URL Payload | Target Category | jsQR Decode Status |
|---|---|---|---|
| `01_safe_university_url.png` | `https://www.cambridge.org/research` | Safe HTTPS | PASS |
| `02_http_unencrypted.png` | `http://library.univ-portal.edu/books` | Plain HTTP | PASS |
| `03_url_shortener.png` | `https://bit.ly/3SecureLogin` | URL Shortener | PASS |
| `04_phishing_spoofed_brand.png` | `https://paypal.account-verify.xyz/login` | Spoofed Brand | PASS |
| `05_raw_ip_custom_port.png` | `http://192.168.1.100:8080/admin` | Raw IP Host | PASS |
| `06_embedded_credentials.png` | `https://root:admin123@web-router.net/auth` | Embedded Auth | PASS |

All 6 sample QR images decode with 100% accuracy via `jsQR`.

---

## 5. Backend vs. Offline Simulation Parity Matrix

Both the Python backend engine and the JavaScript client offline simulation engine were executed against the six sample scenarios:

| Test Scenario URL | Python Risk Score | Node/JS Risk Score | Python Findings | JS Findings | Parity Check |
|---|---|---|---|---|---|
| `https://www.cambridge.org/research` | **0** (Low) | **0** (Low) | None | None | 100% MATCH |
| `http://library.univ-portal.edu/books` | **20** (Low) | **20** (Low) | `SEC-SCHEME-001` | `SEC-SCHEME-001` | 100% MATCH |
| `https://bit.ly/3SecureLogin` | **20** (Low) | **20** (Low) | `SEC-SHORT-005` | `SEC-SHORT-005` | 100% MATCH |
| `https://paypal.account-verify.xyz/login` | **40** (Medium) | **40** (Medium) | `SEC-TLD-009`, `SEC-SPOOF-010` | `SEC-TLD-009`, `SEC-SPOOF-010` | 100% MATCH |
| `http://192.168.1.100:8080/admin` | **75** (High) | **75** (High) | `SEC-IP-003`, `SEC-PORT-004`, `SEC-SCHEME-001` | `SEC-IP-003`, `SEC-PORT-004`, `SEC-SCHEME-001` | 100% MATCH |
| `https://root:admin123@web-router.net/auth` | **35** (Medium) | **35** (Medium) | `SEC-CRED-002` | `SEC-CRED-002` | 100% MATCH |

---

## 6. Local Server Live REST API Verification

The Python local development server (`backend/local_server.py`) running on `http://127.0.0.1:8000` was tested using live HTTP requests:

- `GET /` -> Returned HTTP 200 with service health metadata (`{"service": "QRShield Local Server", "status": "healthy"}`).
- `OPTIONS /` -> Returned HTTP 204 No Content with `Access-Control-Allow-Origin: *` and `Access-Control-Allow-Methods: POST, OPTIONS`.
- `POST /` with safe URL -> Returned HTTP 200 with `risk_score: 0`, `risk_level: "Low"`.
- `POST /` with spoofed URL -> Returned HTTP 200 with `risk_score: 40`, `findings: ['SEC-TLD-009', 'SEC-SPOOF-010']`.
- `POST /` with raw IP host -> Returned HTTP 200 with `risk_score: 75`, `findings: ['SEC-SCHEME-001', 'SEC-IP-003', 'SEC-PORT-004']`.
- `POST /` with missing `url` field -> Returned HTTP 400 Bad Request (`{"status": "error", "message": "Missing required field 'url' in request payload."}`).
- `POST /` with non-HTTP scheme (`tel:` and `javascript:`) -> Returned HTTP 400 Bad Request with explicit scheme rejection message.
- **Log Redaction Test:** Submitted URL with basic authentication and query tokens (`https://admin:superSecretPassword@example.com/login?token=PRIVATE_SESSION_TOKEN_9999`) -> Backend log verified: `QRShield processing request for target: https://example.com/login?[REDACTED_QUERY]`. The credentials and token were completely scrubbed.

"""
QRShield - Automated Backend Unit Tests
Covers URL parsing, rule triggers, scoring consistency, schema verification,
and AWS Lambda Function URL event routing.
"""

import sys
import os
import json
import unittest

# Add backend directory to sys.path so imports work cleanly
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from url_analyzer import analyze_url, URLValidationError, compute_risk_score
from lambda_function import lambda_handler, sanitize_url_for_logging


class TestQRShieldAnalyzer(unittest.TestCase):

    def test_01_valid_clean_https_url(self):
        """Clean standard HTTPS URL should return Low risk with 0 score."""
        url = "https://example.edu/department/research"
        result = analyze_url(url)
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["risk_level"], "Low")
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["hostname"], "example.edu")
        self.assertEqual(result["scheme"], "https")
        self.assertEqual(len(result["findings"]), 0)
        self.assertIn("analyzed_at", result)
        self.assertIn("summary", result)
        self.assertIn("recommendations", result)

    def test_02_valid_http_url(self):
        """Unencrypted HTTP URL triggers SEC-SCHEME-001."""
        url = "http://myuniversity.edu/login"
        result = analyze_url(url)
        self.assertEqual(result["risk_level"], "Low")  # 20 points mapped to Low (<30)
        self.assertEqual(result["risk_score"], 20)
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertIn("SEC-SCHEME-001", rule_ids)

    def test_03_ip_address_hostname(self):
        """Raw IPv4 as hostname triggers SEC-IP-003 and Medium/High risk."""
        url = "http://192.168.1.100/admin"
        result = analyze_url(url)
        # HTTP (20) + IP (30) = 50 -> Medium
        self.assertIn(result["risk_level"], ["Medium", "High"])
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertIn("SEC-IP-003", rule_ids)
        self.assertIn("SEC-SCHEME-001", rule_ids)

    def test_04_embedded_credentials(self):
        """URL with user:pass@host triggers SEC-CRED-002."""
        url = "https://admin:secret123@legit-looking.org/dashboard"
        result = analyze_url(url)
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertIn("SEC-CRED-002", rule_ids)
        self.assertGreaterEqual(result["risk_score"], 35)

    def test_05_known_url_shortener(self):
        """Recognized URL shortener triggers SEC-SHORT-005."""
        url = "https://bit.ly/3xYzAbC"
        result = analyze_url(url)
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertIn("SEC-SHORT-005", rule_ids)
        self.assertEqual(result["hostname"], "bit.ly")

    def test_06_unusual_ports(self):
        """Non-standard port (e.g. 8443, 3389) triggers SEC-PORT-004."""
        url = "https://company-portal.net:8443/auth"
        result = analyze_url(url)
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertIn("SEC-PORT-004", rule_ids)
        self.assertEqual(result["port"], 8443)

    def test_07_excessively_long_url(self):
        """Oversized URL triggers SEC-URLLEN-012."""
        url = "https://example.com/api/v1/resource?" + ("param=data&" * 30)
        self.assertGreater(len(url), 250)
        result = analyze_url(url)
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertIn("SEC-URLLEN-012", rule_ids)

    def test_08_empty_and_whitespace_input(self):
        """Empty or whitespace input raises URLValidationError."""
        with self.assertRaises(URLValidationError):
            analyze_url("")
        with self.assertRaises(URLValidationError):
            analyze_url("    ")

    def test_09_unsupported_schemes(self):
        """Non-HTTP/HTTPS schemes (javascript, file, tel, ftp) are rejected with 400."""
        for invalid_scheme_url in [
            "javascript:alert(1)",
            "file:///etc/passwd",
            "tel:+1234567890",
            "mailto:attacker@evil.com",
            "ftp://ftp.example.com/file.zip"
        ]:
            with self.subTest(url=invalid_scheme_url):
                with self.assertRaises(URLValidationError):
                    analyze_url(invalid_scheme_url)

    def test_10_multiple_suspicious_indicators_high_risk(self):
        """URL with multiple red flags (HTTP, raw IP, high port, long URL) yields High risk with compound penalty."""
        url = "http://10.0.0.5:8080/portal/login/verify?user=admin&token=abcdef1234567890"
        result = analyze_url(url)
        self.assertGreaterEqual(result["risk_score"], 65)
        self.assertIn(result["risk_level"], ["Medium", "High"])
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertIn("SEC-SCHEME-001", rule_ids)
        self.assertIn("SEC-IP-003", rule_ids)
        self.assertIn("SEC-PORT-004", rule_ids)

    def test_11_brand_impersonation_in_subdomain(self):
        """Subdomain mimicking PayPal on third-party domain triggers SEC-SPOOF-010."""
        url = "https://paypal.account-verification-centre.xyz/update"
        result = analyze_url(url)
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertIn("SEC-SPOOF-010", rule_ids)
        self.assertIn("SEC-TLD-009", rule_ids)  # .xyz abuse
        self.assertIn(result["risk_level"], ["Medium", "High"])

    def test_12_score_determinism(self):
        """Same input must always produce identical scores and findings across repeated invocations."""
        url = "http://tinyurl.com/custom-redirect-123"
        first = analyze_url(url)
        for _ in range(5):
            repeated = analyze_url(url)
            self.assertEqual(first["risk_score"], repeated["risk_score"])
            self.assertEqual(first["risk_level"], repeated["risk_level"])
            self.assertEqual([f["rule_id"] for f in first["findings"]],
                             [f["rule_id"] for f in repeated["findings"]])

    def test_13_valid_response_structure_and_json(self):
        """Response dictionary must strictly match defined contract and be JSON serializable."""
        url = "https://www.wikipedia.org"
        result = analyze_url(url)
        json_str = json.dumps(result)
        self.assertTrue(isinstance(json_str, str))
        for key in ["status", "risk_score", "risk_level", "normalized_url",
                    "hostname", "findings", "summary", "recommendations",
                    "analyzed_at", "engine_version"]:
            self.assertIn(key, result)

    def test_14_oversized_url_hard_limit(self):
        """URLs exceeding 2048 characters should be rejected immediately."""
        url = "https://example.com/" + ("a" * 2050)
        with self.assertRaises(URLValidationError):
            analyze_url(url)

    def test_15_obfuscated_ipv4_hosts_decoded_like_browser(self):
        """Decimal, hex, octal and shorthand IPv4 hosts are decoded, flagged as IP hosts and as disguised."""
        for url, expected_ip in [
            ("http://3232235876/", "192.168.1.100"),
            ("http://0xC0A80164/", "192.168.1.100"),
            ("http://0300.0250.1.100/", "192.168.1.100"),
            ("http://127.1/", "127.0.0.1"),
        ]:
            with self.subTest(url=url):
                result = analyze_url(url)
                self.assertEqual(result["hostname"], expected_ip)
                rule_ids = [f["rule_id"] for f in result["findings"]]
                self.assertIn("SEC-IP-003", rule_ids)
                self.assertIn("SEC-IPOBF-014", rule_ids)
                self.assertEqual(result["risk_level"], "High")

        # A normally written IP is not 'disguised'
        plain = [f["rule_id"] for f in analyze_url("http://192.168.1.100/")["findings"]]
        self.assertNotIn("SEC-IPOBF-014", plain)

    def test_16_backslash_host_confusion(self):
        """'evil.com\\@google.com' goes to evil.com in a browser; the backend must agree and flag it."""
        result = analyze_url("https://evil.com\\@google.com/")
        self.assertEqual(result["hostname"], "evil.com")
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertIn("SEC-BSLASH-013", rule_ids)

    def test_17_idn_hostname_converted_to_punycode(self):
        """Non-ASCII hostnames are analyzed in the punycode form the browser connects to."""
        result = analyze_url("https://pаypal.com/login")  # Cyrillic 'a'
        self.assertEqual(result["hostname"], "xn--pypal-4ve.com")

    def test_18_hosts_browsers_reject_are_rejected(self):
        """Invalid ports and invalid IP-like hosts return a validation error instead of a 500."""
        for url in ["http://example.com:99999/", "http://1.2.3.4.5/", "http://256.1.1.1/", "https://exa mple.com/"]:
            with self.subTest(url=url):
                with self.assertRaises(URLValidationError):
                    analyze_url(url)

    def test_19_critical_findings_force_high_risk(self):
        """A single CRITICAL finding (disguised IP / '@' trick / look-alike / backslash) is always High."""
        for url, rule_id in [
            ("https://0xC0A80164/", "SEC-IPOBF-014"),
            ("https://google.com@evil.com/", "SEC-CRED-002"),
            ("https://paypa1.com/login", "SEC-TYPO-015"),
            ("https://evil.com\\@google.com/", "SEC-BSLASH-013"),
        ]:
            with self.subTest(url=url):
                result = analyze_url(url)
                finding = next(f for f in result["findings"] if f["rule_id"] == rule_id)
                self.assertEqual(finding["severity"], "CRITICAL")
                self.assertEqual(result["risk_level"], "High")
                self.assertGreaterEqual(result["risk_score"], 70)

    def test_20_plain_credentials_stay_high_not_critical(self):
        """'user:password@' does not pretend to be another site, so it stays HIGH (not CRITICAL)."""
        result = analyze_url("https://root:admin123@web-router.net/auth")
        finding = next(f for f in result["findings"] if f["rule_id"] == "SEC-CRED-002")
        self.assertEqual(finding["severity"], "HIGH")
        self.assertEqual(result["risk_score"], 35)

    def test_21_official_brand_domains_not_flagged(self):
        """Official brand sites, including country domains and known brand-owned domains, are clean."""
        for url in ["https://www.amazon.co.uk/", "https://mail.google.co.in/", "https://accounts.google.com/",
                    "https://login.microsoftonline.com/", "https://chaseonline.chase.com/"]:
            with self.subTest(url=url):
                self.assertEqual(analyze_url(url)["findings"], [])

    def test_22_brand_words_inside_ordinary_words_not_flagged(self):
        """'pineapple' and 'purchase' contain brand letters but are not brand words."""
        for url in ["https://pineapple.com/", "https://www.purchase-store.com/", "https://finance.com/"]:
            with self.subTest(url=url):
                self.assertEqual(analyze_url(url)["findings"], [])

    def test_23_brand_impersonation_in_registered_name(self):
        """Brand as a word of the registered domain (not the official one) is flagged."""
        for url in ["https://paypal-login.com/", "https://paypalsecure.com/",
                    "https://apple-id-verify.com/", "https://paypal.xyz/"]:
            with self.subTest(url=url):
                rule_ids = [f["rule_id"] for f in analyze_url(url)["findings"]]
                self.assertIn("SEC-SPOOF-010", rule_ids)

    def test_24_idn_rules(self):
        """Real IDN domains get a MEDIUM note only; mixed-alphabet look-alikes are flagged hard."""
        legit = analyze_url("https://bücher.de/")
        self.assertEqual([(f["rule_id"], f["severity"]) for f in legit["findings"]], [("SEC-IDN-016", "MEDIUM")])

        spoof = analyze_url("https://pаypal.com/")  # Cyrillic 'a'
        rule_ids = [f["rule_id"] for f in spoof["findings"]]
        self.assertIn("SEC-TYPO-015", rule_ids)
        self.assertIn("SEC-IDN-016", rule_ids)
        self.assertNotIn("SEC-HYPHEN-008", rule_ids)
        self.assertEqual(spoof["risk_level"], "High")

    def test_26_brand_with_phishing_lure_is_critical(self):
        """Brand impersonation plus a login lure (host or path) or an embedded brand domain is CRITICAL / High."""
        for url in ["https://paypal.account-verify.xyz/login", "https://paypal-login.com/",
                    "https://paypalsecure.com/", "https://paypal.com.evil.com/"]:
            with self.subTest(url=url):
                result = analyze_url(url)
                spoof = next(f for f in result["findings"] if f["rule_id"] == "SEC-SPOOF-010")
                self.assertEqual(spoof["severity"], "CRITICAL")
                self.assertEqual(result["risk_level"], "High")

    def test_27_brand_without_lure_stays_medium(self):
        """A brand name alone on an unrelated domain (e.g. google.github.io) stays HIGH severity / Medium risk."""
        result = analyze_url("https://google.github.io/")
        spoof = next(f for f in result["findings"] if f["rule_id"] == "SEC-SPOOF-010")
        self.assertEqual(spoof["severity"], "HIGH")
        self.assertEqual(result["risk_level"], "Medium")

    def test_28_demo_presets_match_documented_scores(self):
        """The UI presets must score exactly what the docs and presentation script say."""
        for url, score, level in [
            ("https://www.cambridge.org/research", 0, "Low"),
            ("http://library.univ-portal.edu/books", 20, "Low"),
            ("https://bit.ly/3SecureLogin", 30, "Medium"),
            ("http://192.168.1.100:8080/admin", 75, "High"),
            ("https://paypal.account-verify.xyz/login", 70, "High"),
            ("https://root:admin123@web-router.net/auth", 35, "Medium"),
            ("https://accounts.google.com@secure-check.top/", 70, "High"),
            ("https://paypa1.com/login", 70, "High"),
        ]:
            with self.subTest(url=url):
                result = analyze_url(url)
                self.assertEqual((result["risk_score"], result["risk_level"]), (score, level))

    def test_25_subdomain_depth_uses_registered_domain(self):
        """Subdomain depth is counted in front of the registered domain ('co.uk' is one suffix)."""
        self.assertEqual(analyze_url("https://a.b.example.co.uk/")["findings"], [])
        rule_ids = [f["rule_id"] for f in analyze_url("https://login.secure.update.example.com/")["findings"]]
        self.assertIn("SEC-SUBDOM-006", rule_ids)


class TestQRShieldLambdaHandler(unittest.TestCase):

    def test_lambda_direct_invocation(self):
        """Direct invocation via test dict payload."""
        event = {"url": "https://trusted-site.org"}
        response = lambda_handler(event, None)
        self.assertEqual(response["statusCode"], 200)
        body = json.loads(response["body"])
        self.assertEqual(body["status"], "success")
        self.assertEqual(body["risk_level"], "Low")

    def test_lambda_function_url_post(self):
        """Standard Lambda Function URL HTTP POST with JSON body."""
        event = {
            "requestContext": {"http": {"method": "POST"}},
            "headers": {"origin": "http://localhost:5173"},
            "body": json.dumps({"url": "http://192.168.1.1:8080/setup"})
        }
        response = lambda_handler(event, None)
        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(response["headers"]["Access-Control-Allow-Origin"], "http://localhost:5173")
        body = json.loads(response["body"])
        self.assertIn("risk_score", body)

    def test_lambda_cors_options_preflight(self):
        """OPTIONS preflight should return 204 No Content with CORS headers."""
        event = {
            "requestContext": {"http": {"method": "OPTIONS"}},
            "headers": {"origin": "https://qrshield.example.com"}
        }
        response = lambda_handler(event, None)
        self.assertEqual(response["statusCode"], 204)
        self.assertEqual(response["headers"]["Access-Control-Allow-Origin"], "https://qrshield.example.com")
        self.assertIn("POST, OPTIONS", response["headers"]["Access-Control-Allow-Methods"])

    def test_lambda_get_health_check(self):
        """GET returns a 200 health response so the frontend can show backend status."""
        event = {
            "requestContext": {"http": {"method": "GET"}},
            "headers": {"origin": "http://localhost:5173"}
        }
        response = lambda_handler(event, None)
        self.assertEqual(response["statusCode"], 200)
        body = json.loads(response["body"])
        self.assertEqual(body["status"], "healthy")
        self.assertIn("GET", response["headers"]["Access-Control-Allow-Methods"])

    def test_lambda_missing_url(self):
        """Missing URL field in body returns 400 Bad Request."""
        event = {
            "body": json.dumps({"other_field": "data"})
        }
        response = lambda_handler(event, None)
        self.assertEqual(response["statusCode"], 400)
        body = json.loads(response["body"])
        self.assertEqual(body["status"], "error")
        self.assertIn("Missing required field", body["message"])

    def test_lambda_unsupported_scheme(self):
        """Unsupported URL scheme returns 400 with user-friendly guidance."""
        event = {
            "body": json.dumps({"url": "javascript:alert('pwned')"})
        }
        response = lambda_handler(event, None)
        self.assertEqual(response["statusCode"], 400)
        body = json.loads(response["body"])
        self.assertIn("Unsupported scheme", body["message"])

    def test_log_sanitization(self):
        """Query parameters with tokens and credentials must be stripped before logging."""
        raw_url = "https://user:pass@example.com/api/auth?token=SUPER_SECRET_123&session=xyz"
        sanitized = sanitize_url_for_logging(raw_url)
        self.assertNotIn("SUPER_SECRET_123", sanitized)
        self.assertNotIn("pass", sanitized)
        self.assertIn("example.com", sanitized)
        self.assertIn("[REDACTED_QUERY]", sanitized)


if __name__ == "__main__":
    unittest.main()

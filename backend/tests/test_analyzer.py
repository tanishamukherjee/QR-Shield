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


"""Unit tests for the Web Security Header Analyzer."""

import unittest
from unittest.mock import Mock, patch

import requests

from src.analyzer import analyze_headers, fetch_security_headers


class TestAnalyzeHeaders(unittest.TestCase):
    def test_all_headers_missing(self):
        result = analyze_headers({})

        self.assertEqual(result["headers_checked"], 5)
        self.assertEqual(result["headers_present"], 0)
        self.assertEqual(result["headers_missing"], 5)
        self.assertEqual(result["headers_invalid"], 0)

    def test_all_headers_present_with_valid_values(self):
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=()",
        }

        result = analyze_headers(headers)

        self.assertEqual(result["headers_present"], 5)
        self.assertEqual(result["headers_missing"], 0)
        self.assertEqual(result["headers_invalid"], 0)

    def test_header_names_are_case_insensitive(self):
        result = analyze_headers({
            "content-security-policy": "default-src 'self'",
            "X-CONTENT-TYPE-OPTIONS": "nosniff",
        })

        self.assertEqual(result["headers_present"], 2)

    def test_missing_headers_have_recommendations(self):
        result = analyze_headers({})

        for finding in result["findings"]:
            self.assertEqual(finding["status"], "MISSING")
            self.assertTrue(finding["recommendation"])

    def test_invalid_content_type_options(self):
        result = analyze_headers({
            "X-Content-Type-Options": "invalid-value",
        })

        finding = next(
            item for item in result["findings"]
            if item["header"] == "X-Content-Type-Options"
        )

        self.assertEqual(finding["status"], "INVALID")
        self.assertTrue(finding["recommendation"])

    def test_invalid_hsts_max_age(self):
        result = analyze_headers({
            "Strict-Transport-Security": "max-age=0",
        })

        finding = next(
            item for item in result["findings"]
            if item["header"] == "Strict-Transport-Security"
        )

        self.assertEqual(finding["status"], "INVALID")

    def test_valid_hsts_with_additional_directive(self):
        result = analyze_headers({
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        })

        finding = next(
            item for item in result["findings"]
            if item["header"] == "Strict-Transport-Security"
        )

        self.assertEqual(finding["status"], "PRESENT")

    def test_invalid_referrer_policy(self):
        result = analyze_headers({
            "Referrer-Policy": "unknown-policy",
        })

        finding = next(
            item for item in result["findings"]
            if item["header"] == "Referrer-Policy"
        )

        self.assertEqual(finding["status"], "INVALID")

    def test_recognized_referrer_policy(self):
        result = analyze_headers({
            "Referrer-Policy": "unknown-policy, strict-origin",
        })

        finding = next(
            item for item in result["findings"]
            if item["header"] == "Referrer-Policy"
        )

        self.assertEqual(finding["status"], "PRESENT")


class TestFetchSecurityHeaders(unittest.TestCase):
    @patch("src.analyzer.requests.get")
    def test_successful_https_request(self, mock_get):
        response = Mock()
        response.headers = {
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
        }
        response.url = "https://example.com/"
        response.status_code = 200
        mock_get.return_value = response

        result = fetch_security_headers("https://example.com")

        self.assertEqual(result["http_status"], 200)
        self.assertTrue(result["https"])
        self.assertEqual(result["headers_present"], 2)
        mock_get.assert_called_once()

    def test_rejects_invalid_url(self):
        with self.assertRaises(ValueError):
            fetch_security_headers("not-a-url")

    def test_rejects_unsupported_url_scheme(self):
        with self.assertRaises(ValueError):
            fetch_security_headers("ftp://example.com")

    def test_rejects_embedded_credentials(self):
        with self.assertRaises(ValueError):
            fetch_security_headers("https://user:password@example.com")

    def test_rejects_nonpositive_timeout(self):
        with self.assertRaises(ValueError):
            fetch_security_headers("https://example.com", timeout=0)

    @patch("src.analyzer.requests.get")
    def test_network_error_propagates(self, mock_get):
        mock_get.side_effect = requests.Timeout("Request timed out")

        with self.assertRaises(requests.Timeout):
            fetch_security_headers("https://example.com")


if __name__ == "__main__":
    unittest.main()

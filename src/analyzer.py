
"""Core logic for analyzing HTTP security response headers."""

import re
from typing import Any
from urllib.parse import urlparse

import requests


SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "description": "Helps control which resources a browser may load.",
        "recommendation": (
            "Review the application's resource requirements and configure "
            "a restrictive Content-Security-Policy."
        ),
    },
    "Strict-Transport-Security": {
        "description": "Instructs browsers to use HTTPS for future connections.",
        "recommendation": (
            "For HTTPS sites, configure Strict-Transport-Security with "
            "an appropriate positive max-age."
        ),
    },
    "X-Content-Type-Options": {
        "description": "Helps prevent browsers from MIME-type sniffing.",
        "recommendation": "Set X-Content-Type-Options to nosniff.",
    },
    "Referrer-Policy": {
        "description": "Controls referrer information sent with requests.",
        "recommendation": (
            "Choose a recognized Referrer-Policy, such as "
            "strict-origin-when-cross-origin."
        ),
    },
    "Permissions-Policy": {
        "description": "Restricts access to browser features and capabilities.",
        "recommendation": (
            "Define a Permissions-Policy appropriate for the features "
            "your application needs."
        ),
    },
}

VALID_REFERRER_POLICIES = {
    "no-referrer",
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "unsafe-url",
}


def validate_header(header_name: str, value: str) -> tuple[str, str | None]:
    """Return a finding status and a recommendation, if needed."""
    normalized_value = value.strip()
    lower_value = normalized_value.lower()

    if not normalized_value:
        return "INVALID", SECURITY_HEADERS[header_name]["recommendation"]

    if header_name == "X-Content-Type-Options":
        if lower_value == "nosniff":
            return "PRESENT", None
        return "INVALID", "Set the value to nosniff."

    if header_name == "Strict-Transport-Security":
        max_age = re.search(
            r"(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?=;|$)",
            normalized_value,
            flags=re.IGNORECASE,
        )
        if max_age and int(max_age.group(1)) > 0:
            return "PRESENT", None
        return (
            "INVALID",
            "Configure a valid Strict-Transport-Security max-age greater than zero.",
        )

    if header_name == "Referrer-Policy":
        # Browsers can accept a comma-separated list of policies and use
        # the last recognized policy. Unknown tokens are ignored.
        policies = [
            item.strip().lower()
            for item in normalized_value.split(",")
        ]
        if any(policy in VALID_REFERRER_POLICIES for policy in policies):
            return "PRESENT", None
        return (
            "INVALID",
            "Use a recognized Referrer-Policy value.",
        )

    # Presence alone does not prove that a CSP or Permissions-Policy
    # is strong or appropriate for the application.
    return "PRESENT", None


def analyze_headers(headers: Any) -> dict:
    """Evaluate selected security headers in an HTTP response."""
    normalized_headers = {
        str(name).lower(): str(value).strip()
        for name, value in headers.items()
    }

    findings = []
    present_count = 0
    missing_count = 0
    invalid_count = 0

    for header_name, details in SECURITY_HEADERS.items():
        value = normalized_headers.get(header_name.lower())

        if value is None:
            status = "MISSING"
            recommendation = details["recommendation"]
            missing_count += 1
        else:
            status, recommendation = validate_header(header_name, value)

            if status == "PRESENT":
                present_count += 1
            elif status == "INVALID":
                invalid_count += 1

        findings.append(
            {
                "header": header_name,
                "status": status,
                "value": value,
                "description": details["description"],
                "recommendation": recommendation,
            }
        )

    return {
        "headers_checked": len(SECURITY_HEADERS),
        "headers_present": present_count,
        "headers_missing": missing_count,
        "headers_invalid": invalid_count,
        "findings": findings,
    }


def fetch_security_headers(url: str, timeout: int = 10) -> dict:
    """Fetch a website's response headers and analyze them.

    This function is intended for local, authorized assessment. URL syntax
    checks alone do not prevent SSRF or access to internal network services.
    """
    if not isinstance(url, str):
        raise ValueError("Enter a valid HTTP or HTTPS URL.")

    parsed_url = urlparse(url)

    if (
        parsed_url.scheme.lower() not in {"http", "https"}
        or not parsed_url.hostname
    ):
        raise ValueError("Enter a valid HTTP or HTTPS URL.")

    if parsed_url.username or parsed_url.password:
        raise ValueError(
            "URLs containing embedded credentials are not allowed."
        )

    if (
        not isinstance(timeout, (int, float))
        or isinstance(timeout, bool)
        or timeout <= 0
    ):
        raise ValueError("Timeout must be a positive number.")

    response = requests.get(
        url,
        timeout=timeout,
        allow_redirects=True,
        headers={
            "User-Agent": "Web-Security-Header-Analyzer/1.0"
        },
    )

    result = analyze_headers(response.headers)
    result["requested_url"] = url
    result["final_url"] = response.url
    result["http_status"] = response.status_code
    result["https"] = urlparse(response.url).scheme.lower() == "https"

    return result

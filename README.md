# Web Security Header Analyzer

A Python command-line tool that checks selected HTTP security response headers for websites you are authorized to assess. It identifies missing or invalid header values and provides recommendations to help guide further security review.

## Features

- Analyzes five security headers:
  - Content-Security-Policy (CSP)
  - Strict-Transport-Security (HSTS)
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy
- Classifies findings as `PRESENT`, `MISSING`, or `INVALID`.
- Provides recommendations for missing or invalid headers.
- Reports the HTTP status, final URL, and whether the final connection uses HTTPS.
- Supports request timeouts and saving reports to a text file.
- Includes automated unit tests for header analysis and request handling.

## Technologies

- Python
- Requests
- unittest

## Requirements

- Python 3.10 or later
- pip

## Installation

Clone the repository and enter the project directory:

```bash
git clone https://github.com/ENOCK-security/Web-Security-Header-Analyzer.git
cd Web-Security-Header-Analyzer
```

Install the dependencies:

```bash
python -m pip install -r requirements.txt
```

## Usage

Analyze a website:

```bash
python -m src.main https://example.com
```

Set a request timeout:

```bash
python -m src.main https://example.com --timeout 15
```

Save the report to a file:

```bash
python -m src.main https://example.com --output reports/example-report.txt
```

Run the automated tests:

```bash
python -m unittest discover -s tests -v
```

## Understanding the Results

- **PRESENT:** The header exists and passes the tool's limited validation checks.
- **MISSING:** The response does not contain the header being checked.
- **INVALID:** The header is present, but its value fails the implemented validation rule.

A `PRESENT` result does not guarantee that a header is configured securely. In particular, CSP and Permissions-Policy are checked for presence rather than comprehensively evaluated for policy quality.

## Limitations

- Checks five selected response headers; it is not a complete security audit.
- Does not evaluate an application's overall security posture or assign a security score.
- Does not fully validate CSP or Permissions-Policy directives.
- Follows HTTP redirects and does not implement comprehensive protection against server-side request forgery (SSRF). Run it locally against authorized targets; do not expose it as a public scanning service without adding appropriate network and redirect restrictions.

## Responsible Use

Use this tool only on websites you own or have explicit permission to assess. It performs HTTP requests to retrieve response headers and is intended for educational and defensive security testing.

## Project Status

The core CLI, header validation logic, report generation, and unit tests are implemented. Further improvements may include stronger policy validation, safer redirect handling, and additional test coverage.


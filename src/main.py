
"""Command-line interface for the Web Security Header Analyzer."""

import argparse
import sys
from pathlib import Path

import requests

from src.analyzer import fetch_security_headers


def format_report(result: dict) -> str:
    """Format security-header findings as readable text."""
    lines = [
        "",
        "=" * 65,
        "          WEB SECURITY HEADER ANALYSIS REPORT",
        "=" * 65,
        f"Requested URL : {result['requested_url']}",
        f"Final URL     : {result['final_url']}",
        f"HTTP Status   : {result['http_status']}",
        f"HTTPS         : {'Yes' if result['https'] else 'No'}",
        "-" * 65,
        (
    f"Headers checked: {result['headers_checked']} | "
    f"Present: {result['headers_present']} | "
    f"Missing: {result['headers_missing']} | "
    f"Invalid: {result['headers_invalid']}"

        ),
        "-" * 65,
    ]

    for finding in result["findings"]:
        lines.append(f"\n[{finding['status']}] {finding['header']}")
        lines.append(f"Purpose: {finding['description']}")

        if finding["value"]:
            lines.append(f"Value: {finding['value']}")

        if finding["recommendation"]:
            lines.append(f"Recommendation: {finding['recommendation']}")

    lines.extend(
        [
            "",
            "=" * 65,
            "Note: This is a limited header check, not a full security audit.",
            "=" * 65,
            "",
        ]
    )

    return "\n".join(lines)


def main() -> int:
    """Parse arguments, analyze a website, and display or save the report."""
    parser = argparse.ArgumentParser(
        description=(
            "Passively analyze selected HTTP security headers "
            "for a website you are authorized to assess."
        )
    )
    parser.add_argument(
        "url",
        help="Website URL, for example https://example.com",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--output",
        help="Optional path to save the text report",
    )

    args = parser.parse_args()

    if args.timeout <= 0:
        parser.error("--timeout must be a positive integer")

    try:
        result = fetch_security_headers(args.url, timeout=args.timeout)
        report = format_report(result)
        print(report)

        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(report, encoding="utf-8")
            print(f"Report saved to: {output_path.resolve()}")

        return 0

    except ValueError as error:
        print(f"Input error: {error}", file=sys.stderr)
        return 2

    except requests.RequestException as error:
        print(f"Request failed: {error}", file=sys.stderr)
        return 1

    except OSError as error:
        print(f"Could not save report: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

"""
Quick command for CiberWebScan CLI.

Combined scan: analysis + attacks + scraping with presets.
"""

from __future__ import annotations

import sys
from typing import Annotated

import typer

from ciberwebscan.cli.output import (
    format_analysis_result,
    format_service_result,
    print_error,
    print_header,
    print_info,
    print_key_value,
    print_subheader,
    print_warning,
)
from ciberwebscan.cli.validators import (
    ValidationError,
    validate_format,
    validate_selector,
    validate_timeout,
    validate_url,
)
from ciberwebscan.config.loader import get_config

try:
    _DEFAULT_TIMEOUT = get_config().http.timeout.read
except Exception:
    _DEFAULT_TIMEOUT = 30.0


def quick_cmd(
    url: Annotated[str, typer.Argument(help="URL to scan")],
    # Preset
    preset: Annotated[
        str,
        typer.Option(
            "--preset",
            "-p",
            help="Scan preset: low (analysis only), medium (+ moderate attacks), high (full scan)",
        ),
    ] = "low",
    # Network options
    timeout: Annotated[
        float | None,
        typer.Option(
            "--timeout", "-t", help="Request timeout in seconds (overrides preset)"
        ),
    ] = None,
    proxy: Annotated[
        str | None,
        typer.Option("--proxy", help="HTTP/HTTPS proxy URL"),
    ] = None,
    user_agent: Annotated[
        str | None,
        typer.Option("--user-agent", "-ua", help="Custom User-Agent string"),
    ] = None,
    headers: Annotated[
        str | None,
        typer.Option(
            "--headers",
            "-H",
            help="Custom headers (format: 'Key: Value, Key2: Value2')",
        ),
    ] = None,
    cookies: Annotated[
        str | None,
        typer.Option(
            "--cookies", "-c", help="Cookies (format: 'name1=value1; name2=value2')"
        ),
    ] = None,
    # Consent
    consent: Annotated[
        bool,
        typer.Option(
            "--consent",
            help="Confirm you have permission to test this system (REQUIRED for medium/high)",
        ),
    ] = False,
    # Scrape options
    selector: Annotated[
        str | None,
        typer.Option(
            "--selector", "-s", help="CSS selector to extract (enables scraping)"
        ),
    ] = None,
    dynamic: Annotated[
        bool,
        typer.Option(
            "--dynamic",
            "-d",
            help="Use browser-based scraping (Playwright) - preset high only",
        ),
    ] = False,
    # Export options
    output: Annotated[
        str | None,
        typer.Option("--output", "-o", help="Output file path"),
    ] = None,
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="Export format: json, jsonl, csv, html"),
    ] = "json",
    # Output options
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output raw JSON"),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Minimal output"),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Verbose output"),
    ] = False,
) -> None:
    """
    Quick combined scan - analysis + attacks + scraping.

    Presets control what gets scanned:
      low     - SSL, fingerprint, headers (no attacks, no CVEs)
      medium  - Analysis + moderate attacks (XSS, SQLi) - requires --consent
      high    - Full analysis + all attacks + CVEs - requires --consent

    Scraping is enabled when --selector or --dynamic is provided.

    Examples:

        # Basic analysis (preset low)
        ciberwebscan quick https://example.com

        # Analysis + scraping
        ciberwebscan quick https://example.com -s ".content"

        # Medium scan with attacks (requires consent)
        ciberwebscan quick https://example.com --preset medium --consent

        # Full scan with dynamic scraping
        ciberwebscan quick https://example.com --preset high --consent -d

        # Export combined report
        ciberwebscan quick https://example.com --preset high --consent -o report.json
    """
    try:
        # Validate inputs
        validated_url = validate_url(url)
        if timeout is not None:
            validate_timeout(timeout)
        if output:
            validate_format(format)
        if selector:
            validate_selector(selector)

        # Validate preset
        preset_lower = preset.lower()
        if preset_lower not in ("low", "medium", "high"):
            print_error(f"Invalid preset: {preset}")
            print_info("Valid values: low, medium, high")
            sys.exit(2)

        # Validate consent for medium/high
        app_config = get_config()
        effective_consent = consent or app_config.attack.user_consent
        if preset_lower in ("medium", "high") and not effective_consent:
            print_error("USER CONSENT REQUIRED")
            print_warning(f"Use --consent to confirm permission for '{preset}' preset.")
            print_info("Unauthorized security testing is illegal and unethical.")
            sys.exit(2)

        # Parse headers
        headers_dict: dict[str, str] = {}
        if headers:
            for pair in headers.split(","):
                if ":" in pair:
                    key, value = pair.split(":", 1)
                    headers_dict[key.strip()] = value.strip()

        # Parse cookies
        cookies_dict: dict[str, str] = {}
        if cookies:
            for pair in cookies.split(";"):
                if "=" in pair:
                    key, value = pair.split("=", 1)
                    cookies_dict[key.strip()] = value.strip()

        from ciberwebscan.services.quick_service import QuickOptions, QuickService

        options = QuickOptions(
            url=validated_url,
            preset=preset_lower,
            timeout=timeout,
            proxy=proxy,
            user_agent=user_agent,
            headers=headers_dict,
            cookies=cookies_dict,
            consent=effective_consent,
            selector=selector,
            dynamic=dynamic,
            output=output,
            export_format=format,
            json_output=json_output,
            quiet=quiet,
            verbose=verbose,
        )

        # Display scan info
        if not quiet and not json_output:
            print_header(f"Quick Scan [{preset_lower.upper()}]")
            print_key_value("Target", validated_url)

            phases = ["Analysis"]
            if preset_lower in ("medium", "high"):
                phases.append("Attacks")
            if selector or dynamic:
                phases.append("Scraping")
            print_key_value("Phases", " -> ".join(phases))

            if timeout:
                print_key_value("Timeout", f"{timeout}s")
            if proxy:
                print_key_value("Proxy", proxy)
            print_info("")

        # Execute
        service = QuickService()
        result = service.quick_scan(options)

        # Format output
        if json_output:
            exit_code = format_service_result(result, json_output=True)
        else:
            if result.success and result.data:
                format_analysis_result(result.data)

                # Show attack summary if present
                if result.data.attack:
                    attack = result.data.attack
                    print_subheader("Attack Summary")
                    print_key_value("Total Findings", attack.total_findings)
                    print_key_value("Payloads Tested", attack.total_payloads_tested)
                    if attack.xss_findings:
                        print_key_value("XSS", attack.xss_findings, indent=1)
                    if attack.sqli_findings:
                        print_key_value("SQLi", attack.sqli_findings, indent=1)
                    if attack.traversal_findings:
                        print_key_value(
                            "Traversal", attack.traversal_findings, indent=1
                        )
                    if attack.enumeration_findings:
                        print_key_value(
                            "Enumeration", attack.enumeration_findings, indent=1
                        )

                # Show scrape summary if present
                if result.data.scrape:
                    scrape = result.data.scrape
                    print_subheader("Scrape Result")
                    if hasattr(scrape, "url"):
                        print_key_value("URL", scrape.url)
                        print_key_value("Status", scrape.status_code)
                        if scrape.title:
                            print_key_value("Title", scrape.title)
                    elif isinstance(scrape, list):
                        print_key_value("Items", len(scrape))

                # Show risk score
                print_subheader("Risk Assessment")
                print_key_value("Risk Score", f"{result.data.risk_score}/100")
                print_key_value("Critical", result.data.critical_findings)
                print_key_value("High", result.data.high_findings)
                print_key_value("Medium", result.data.medium_findings)
                print_key_value("Low", result.data.low_findings)

            exit_code = format_service_result(result, json_output=False)

        sys.exit(exit_code)

    except ValidationError as e:
        print_error(str(e))
        sys.exit(2)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        if verbose:
            import traceback

            print_error(traceback.format_exc())
        sys.exit(1)

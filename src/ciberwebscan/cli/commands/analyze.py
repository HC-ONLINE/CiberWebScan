"""
Analyze command for CiberWebScan CLI.

Handles security analysis operations - SSL, fingerprinting, CVEs.
"""

from __future__ import annotations

import sys
from typing import Annotated

import typer

from ciberwebscan.cli.output import (
    format_analysis_result,
    format_service_result,
    print_error,
    print_info,
)
from ciberwebscan.cli.validators import (
    ValidationError,
    validate_format,
    validate_timeout,
    validate_url,
)
from ciberwebscan.config.loader import get_config

try:
    _DEFAULT_ANALYZE_TIMEOUT = get_config().http.timeout.read
    _DEFAULT_ANALYZE_SSL_TIMEOUT = get_config().http.timeout.connect
except Exception:
    _DEFAULT_ANALYZE_TIMEOUT = 30.0
    _DEFAULT_ANALYZE_SSL_TIMEOUT = 10.0


def analyze_cmd(
    url: Annotated[str, typer.Argument(help="URL to analyze")],
    # Analysis types — all disabled by default, activate with flags
    ssl: Annotated[
        bool,
        typer.Option("--ssl/--no-ssl", help="Perform SSL/TLS analysis"),
    ] = False,
    fingerprint: Annotated[
        bool,
        typer.Option(
            "--fingerprint/--no-fingerprint",
            "-fp",
            help="Perform technology fingerprinting",
        ),
    ] = False,
    cve: Annotated[
        bool,
        typer.Option("--cve/--no-cve", help="Look up CVEs for detected technologies"),
    ] = False,
    analyze_headers: Annotated[
        bool,
        typer.Option(
            "--analyze-headers/--no-analyze-headers",
            help="Analyze HTTP security headers",
        ),
    ] = False,
    # Options
    deep: Annotated[
        bool,
        typer.Option("--deep", help="Enable deep scanning"),
    ] = False,
    timeout: Annotated[
        float,
        typer.Option("--timeout", "-t", help="Request timeout in seconds"),
    ] = _DEFAULT_ANALYZE_TIMEOUT,
    ssl_timeout: Annotated[
        float,
        typer.Option(
            "--ssl-timeout",
            help="SSL/TLS handshake timeout in seconds",
        ),
    ] = _DEFAULT_ANALYZE_SSL_TIMEOUT,
    # CVE options
    cve_sources: Annotated[
        str | None,
        typer.Option(
            "--cve-sources", help="CVE sources (comma-separated): nvd,circl,vulners"
        ),
    ] = None,
    cve_limit: Annotated[
        int,
        typer.Option("--cve-limit", help="Maximum CVEs to retrieve"),
    ] = 100,
    # Export
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
    # Network options
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
    proxy: Annotated[
        str | None,
        typer.Option("--proxy", help="HTTP/HTTPS proxy URL"),
    ] = None,
    cookies: Annotated[
        str | None,
        typer.Option(
            "--cookies", "-c", help="Cookies (format: 'name1=value1; name2=value2')"
        ),
    ] = None,
    # CVE enrichment
    enrich_exploits: Annotated[
        bool,
        typer.Option(
            "--enrich-exploits",
            "-ee",
            help="Enrich CVEs with exploit info from Vulners",
        ),
    ] = False,
) -> None:
    """
    Perform security analysis on a URL.

    Activate specific analyses with flags. At least one of --ssl, --fingerprint,
    --cve, or --analyze-headers must be enabled.

    Examples:

        # SSL + fingerprinting
        ciberwebscan analyze https://example.com --ssl --fingerprint

        # Full analysis
        ciberwebscan analyze https://example.com --ssl --fingerprint --cve --analyze-headers

        # SSL only with custom timeout
        ciberwebscan analyze https://example.com --ssl --ssl-timeout 15

        # Export report
        ciberwebscan analyze https://example.com --ssl --fingerprint -o report.json
    """
    try:
        if not any([ssl, fingerprint, cve, analyze_headers]):
            print_error("No analysis types selected")
            print_info("Use --ssl, --fingerprint, --cve, or --analyze-headers")
            sys.exit(2)

        validated_url = validate_url(url)
        validate_timeout(timeout)
        if output:
            validate_format(format)

        # Parse headers if provided
        headers_dict: dict[str, str] = {}
        if headers:
            for pair in headers.split(","):
                if ":" in pair:
                    key, value = pair.split(":", 1)
                    headers_dict[key.strip()] = value.strip()

        # Parse cookies if provided
        cookies_dict: dict[str, str] = {}
        if cookies:
            for pair in cookies.split(";"):
                if "=" in pair:
                    key, value = pair.split("=", 1)
                    cookies_dict[key.strip()] = value.strip()

        from ciberwebscan.services import AnalyzeOptions, AnalyzeService

        sources = cve_sources.split(",") if cve_sources else ["nvd"]

        options = AnalyzeOptions(
            url=validated_url,
            ssl=ssl,
            fingerprint=fingerprint,
            cve=cve,
            analyze_headers=analyze_headers,
            headers=headers_dict,
            deep_scan=deep,
            timeout=timeout,
            ssl_timeout=ssl_timeout,
            cve_sources=sources,
            cve_limit=cve_limit,
            export=output,
            export_format=format,
            cookies=cookies_dict,
            proxy=proxy,
            user_agent=user_agent,
            enrich_exploits=enrich_exploits,
        )

        if not quiet:
            print_info(f"Analyzing: {validated_url}")
            analyses = []
            if ssl:
                analyses.append("SSL")
            if fingerprint:
                analyses.append("Fingerprint")
            if cve:
                analyses.append("CVE")
            if analyze_headers:
                analyses.append("Headers")
            print_info(f"Analyses: {', '.join(analyses)}")

        service = AnalyzeService()
        result = service.analyze(options)

        if json_output:
            exit_code = format_service_result(result, json_output=True)
        else:
            if result.success and result.data:
                format_analysis_result(result.data)
            exit_code = format_service_result(result, json_output=False)

        sys.exit(exit_code)

    except ValidationError as e:
        print_error(str(e))
        sys.exit(2)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)

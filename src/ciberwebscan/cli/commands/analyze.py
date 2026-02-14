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
    print_header,
    print_info,
    print_key_value,
    print_subheader,
)
from ciberwebscan.cli.validators import (
    ValidationError,
    validate_format,
    validate_timeout,
    validate_url,
)
from ciberwebscan.config.loader import get_config

analyze = typer.Typer(
    name="analyze",
    help="Security analysis commands.",
    no_args_is_help=True,
)

try:
    _DEFAULT_ANALYZE_TIMEOUT = get_config().http.timeout.read
    _DEFAULT_ANALYZE_SSL_TIMEOUT = get_config().http.timeout.connect
except Exception:
    _DEFAULT_ANALYZE_TIMEOUT = 30.0
    _DEFAULT_ANALYZE_SSL_TIMEOUT = 10.0


@analyze.command("url")
def analyze_url(
    url: Annotated[str, typer.Argument(help="URL to analyze")],
    # Analysis types
    ssl: Annotated[
        bool,
        typer.Option("--ssl/--no-ssl", help="Perform SSL/TLS analysis"),
    ] = True,
    fingerprint: Annotated[
        bool,
        typer.Option(
            "--fingerprint/--no-fingerprint",
            "-fp",
            help="Perform technology fingerprinting",
        ),
    ] = True,
    cve: Annotated[
        bool,
        typer.Option("--cve/--no-cve", help="Look up CVEs for detected technologies"),
    ] = True,
    analyze_headers: Annotated[
        bool,
        typer.Option(
            "--analyze-headers/--no-analyze-headers",
            help="Analyze HTTP security headers",
        ),
    ] = True,
    # Options
    deep: Annotated[
        bool,
        typer.Option("--deep", help="Enable deep scanning"),
    ] = False,
    timeout: Annotated[
        float,
        typer.Option("--timeout", "-t", help="Request timeout in seconds"),
    ] = _DEFAULT_ANALYZE_TIMEOUT,
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
        typer.Option("--format", "-f", help="Export format: json, jsonl, csv"),
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

    Examples:

        # Full analysis
        ciberwebscan analyze url https://example.com

        # SSL only
        ciberwebscan analyze url https://example.com --no-fingerprint --no-cve

        # Fingerprint and CVEs only
        ciberwebscan analyze url https://example.com --no-ssl

        # Export report
        ciberwebscan analyze url https://example.com -o report.json
    """
    try:
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
            headers=headers_dict,
            deep_scan=deep,
            timeout=timeout,
            ssl_timeout=timeout,
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


@analyze.command("ssl")
def analyze_ssl(
    url: Annotated[str, typer.Argument(help="URL to analyze")],
    timeout: Annotated[
        float,
        typer.Option("--timeout", "-t", help="Timeout in seconds"),
    ] = _DEFAULT_ANALYZE_SSL_TIMEOUT,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output raw JSON"),
    ] = False,
) -> None:
    """
    Perform SSL/TLS analysis only.

    Examples:

        ciberwebscan analyze ssl https://example.com
    """
    try:
        validated_url = validate_url(url, allow_http=False)

        from ciberwebscan.services import AnalyzeService

        print_info(f"Analyzing SSL: {validated_url}")

        service = AnalyzeService()
        result = service.analyze_ssl(validated_url, ssl_timeout=timeout)

        if json_output:
            exit_code = format_service_result(result, json_output=True)
        else:
            if result.success and result.data:
                ssl = result.data
                print_header("SSL/TLS Analysis")
                print_key_value("HTTPS", "Yes" if ssl.is_https else "No")
                if ssl.protocol_version:
                    print_key_value("Protocol", ssl.protocol_version)
                if ssl.cipher_suite:
                    print_key_value("Cipher", ssl.cipher_suite)
                if ssl.grade:
                    print_key_value("Grade", ssl.grade)
                if ssl.chain_valid is not None:
                    print_key_value("Chain Valid", "Yes" if ssl.chain_valid else "No")
                if ssl.findings:
                    print_subheader("Findings")
                    for f in ssl.findings:
                        print_info(f"  - {f}")
            exit_code = format_service_result(result, json_output=False)

        sys.exit(exit_code)

    except ValidationError as e:
        print_error(str(e))
        sys.exit(2)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)


@analyze.command("fingerprint")
def analyze_fingerprint(
    url: Annotated[str, typer.Argument(help="URL to fingerprint")],
    deep: Annotated[
        bool,
        typer.Option("--deep", help="Enable deep scanning"),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output raw JSON"),
    ] = False,
) -> None:
    """
    Perform technology fingerprinting only.

    Examples:

        ciberwebscan analyze fingerprint https://example.com
        ciberwebscan analyze fingerprint https://example.com --deep
    """
    try:
        validated_url = validate_url(url)

        from ciberwebscan.services import AnalyzeService

        print_info(f"Fingerprinting: {validated_url}")

        service = AnalyzeService()
        result = service.fingerprint_url(validated_url, deep=deep)

        if json_output:
            exit_code = format_service_result(result, json_output=True)
        else:
            if result.success and result.data:
                fp = result.data
                print_header("Technology Fingerprint")

                if fp.server:
                    print_key_value("Server", fp.server)
                if fp.powered_by:
                    print_key_value("Powered By", fp.powered_by)
                if fp.framework:
                    print_key_value("Framework", fp.framework)
                if fp.cms:
                    print_key_value("CMS", fp.cms)

                if fp.technologies:
                    print_subheader(f"Technologies ({len(fp.technologies)})")
                    for tech in fp.technologies:
                        version = f" v{tech.version}" if tech.version else ""
                        category = f" [{tech.category}]" if tech.category else ""
                        print_info(f"  - {tech.name}{version}{category}")
            exit_code = format_service_result(result, json_output=False)

        sys.exit(exit_code)

    except ValidationError as e:
        print_error(str(e))
        sys.exit(2)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)


@analyze.command("cves")
def analyze_cves(
    technology: Annotated[
        list[str],
        typer.Argument(
            help="Technology names to look up (e.g., 'nginx:1.20' or 'wordpress')"
        ),
    ],
    sources: Annotated[
        str | None,
        typer.Option("--sources", "-s", help="CVE sources: nvd,circl,vulners"),
    ] = None,
    limit: Annotated[
        int,
        typer.Option("--limit", "-l", help="Maximum CVEs per technology"),
    ] = 50,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output raw JSON"),
    ] = False,
) -> None:
    """
    Look up CVEs for specific technologies.

    Examples:

        # Single technology
        ciberwebscan analyze cves nginx:1.20

        # Multiple technologies
        ciberwebscan analyze cves wordpress:5.8 php:8.1

        # With specific sources
        ciberwebscan analyze cves apache --sources nvd,circl
    """
    try:
        if not technology:
            print_error("At least one technology is required")
            sys.exit(2)

        from ciberwebscan.export.models import ConfidenceLevel, TechnologyMatch
        from ciberwebscan.services import AnalyzeService

        # Parse technologies (format: name or name:version)
        tech_list = []
        for t in technology:
            if ":" in t:
                name, version = t.split(":", 1)
            else:
                name, version = t, None
            tech_list.append(
                TechnologyMatch(
                    name=name,
                    version=version,
                    category="unknown",
                    confidence=ConfidenceLevel.HIGH,
                )
            )

        source_list = sources.split(",") if sources else ["nvd"]

        print_info(f"Looking up CVEs for: {', '.join(technology)}")
        print_info(f"Sources: {', '.join(source_list)}")

        service = AnalyzeService()
        result = service.lookup_cves(
            tech_list, cve_sources=source_list, cve_limit=limit
        )

        if json_output:
            exit_code = format_service_result(result, json_output=True)
        else:
            if result.success and result.data:
                cves = result.data
                print_header(f"CVEs Found ({len(cves)})")

                for cve in cves:
                    severity = (
                        f"[{cve.severity.value}]"
                        if hasattr(cve, "severity") and cve.severity
                        else ""
                    )
                    print_info(f"\n{cve.id} {severity}")
                    if cve.description:
                        desc = cve.description[:100]
                        if len(cve.description) > 100:
                            desc += "..."
                        print_info(f"  {desc}")
                    if hasattr(cve, "cvss_score") and cve.cvss_score:
                        print_key_value("CVSS", cve.cvss_score, indent=1)
            exit_code = format_service_result(result, json_output=False)

        sys.exit(exit_code)

    except ValidationError as e:
        print_error(str(e))
        sys.exit(2)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)

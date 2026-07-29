"""
Attack command for CiberWebScan CLI.

Handles security attack simulations - XSS, SQLi, Path Traversal, Directory Enumeration.

WARNING: Only use against systems you own or have explicit permission to test.
Unauthorized security testing is illegal and unethical.
"""

from __future__ import annotations

import sys
from typing import Annotated

import typer

from ciberwebscan.cli.output import (
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
    validate_timeout,
    validate_url,
)
from ciberwebscan.config.loader import get_config

attack = typer.Typer(
    name="attack",
    help="Security attack simulation commands.",
    no_args_is_help=True,
)

try:
    _DEFAULT_ATTACK_TIMEOUT = get_config().http.timeout.connect
except Exception:
    _DEFAULT_ATTACK_TIMEOUT = 10.0


@attack.command("test")
def attack_test(
    url: Annotated[str, typer.Argument(help="URL to test")],
    # CRITICAL: User consent
    consent: Annotated[
        bool,
        typer.Option(
            "--consent",
            help="Confirm you have permission to test this system (REQUIRED)",
        ),
    ] = False,
    # Attack types
    xss: Annotated[
        bool | None,
        typer.Option(
            "--xss",
            help="Test for Cross-Site Scripting vulnerabilities (uses config default if not set)",
        ),
    ] = None,
    sqli: Annotated[
        bool | None,
        typer.Option(
            "--sqli",
            help="Test for SQL Injection vulnerabilities (uses config default if not set)",
        ),
    ] = None,
    traversal: Annotated[
        bool | None,
        typer.Option(
            "--traversal",
            help="Test for Path Traversal vulnerabilities (uses config default if not set)",
        ),
    ] = None,
    enumeration: Annotated[
        bool | None,
        typer.Option(
            "--enumeration",
            help="Test for Directory/File enumeration (uses config default if not set)",
        ),
    ] = None,
    csrf: Annotated[
        bool | None,
        typer.Option(
            "--csrf",
            help="Test for CSRF vulnerabilities (uses config default if not set)",
        ),
    ] = None,
    all_attacks: Annotated[
        bool,
        typer.Option("--all", help="Run all attack types"),
    ] = False,
    # Attack configuration
    intensity: Annotated[
        str,
        typer.Option(
            "--intensity",
            "-i",
            help="Attack intensity: low, medium, high",
        ),
    ] = "medium",
    max_payloads: Annotated[
        int | None,
        typer.Option(
            "--max-payloads",
            help="Maximum payloads to test per attack (uses config default if not set)",
        ),
    ] = None,
    # Custom payloads
    payloads: Annotated[
        str | None,
        typer.Option(
            "--payloads",
            "-p",
            help="Custom payloads file (JSON)",
        ),
    ] = None,
    wordlist: Annotated[
        str | None,
        typer.Option(
            "--wordlist",
            "-w",
            help="Custom wordlist file for enumeration",
        ),
    ] = None,
    # Network options
    timeout: Annotated[
        float,
        typer.Option("--timeout", "-t", help="Request timeout in seconds"),
    ] = _DEFAULT_ATTACK_TIMEOUT,
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
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Verbose output"),
    ] = False,
) -> None:
    """
    Perform security attack simulation on a URL.

      CRITICAL: Only test systems you own or have explicit permission to test!

    Examples:

        # Test XSS with consent
        ciberwebscan attack test https://example.com --consent --xss

        # Test multiple attack types
        ciberwebscan attack test https://example.com --consent --xss --sqli

        # Run all attacks with low intensity
        ciberwebscan attack test https://example.com --consent --all --intensity low

        # Export findings report
        ciberwebscan attack test https://example.com --consent --xss -o findings.json

        # Custom payloads
        ciberwebscan attack test https://example.com --consent --xss --payloads my_xss.json
    """
    try:
        # Get config first — it may pre-authorise consent
        app_config = get_config()
        effective_consent = consent or app_config.attack.user_consent

        # CRITICAL: Validate user consent first!
        if not effective_consent:
            print_error("USER CONSENT REQUIRED")
            print_warning("You must confirm you have permission to test this system.")
            print_warning(
                "Use --consent flag to acknowledge legal and ethical responsibility."
            )
            print_info("\nUnauthorized security testing is illegal and unethical.")
            print_info("Only test systems you own or have explicit permission for.")
            sys.exit(2)

        # Validate inputs
        validated_url = validate_url(url)
        validate_timeout(timeout)
        if output:
            validate_format(format)

        # Validate intensity
        if intensity not in ["low", "medium", "high"]:
            print_error(f"Invalid intensity: {intensity}")
            print_info("Valid values: low, medium, high")
            sys.exit(2)

        # Enable all attacks if --all flag is used
        if all_attacks:
            xss = sqli = traversal = enumeration = csrf = True

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

        from ciberwebscan.services import AttackOptions, AttackService

        options = AttackOptions(
            url=validated_url,
            user_consent=True,  # Already validated above
            config=app_config.attack,  # Use config.attack for defaults
            xss=xss,
            sqli=sqli,
            traversal=traversal,
            enumeration=enumeration,
            csrf=csrf,
            intensity=intensity,
            max_payloads=max_payloads,
            custom_payloads_file=payloads,
            custom_wordlist=wordlist,
            timeout=timeout,
            headers=headers_dict,
            cookies=cookies_dict,
            proxy=proxy,
            user_agent=user_agent,
            export=output,
            export_format=format,
            verbose=verbose,
        )

        # Validate at least one attack type is enabled (after config defaults are applied)
        if not any(
            [
                options.xss,
                options.sqli,
                options.traversal,
                options.enumeration,
                options.csrf,
            ]
        ):
            print_error("No attack types selected")
            print_info(
                "Use --xss, --sqli, --traversal, --enumeration, --csrf, or --all"
            )
            print_info("Or enable attack types in your config.yaml (config.attack.*)")
            sys.exit(2)

        # Display attack configuration
        if not quiet:
            print_warning("ATTACK MODE ENABLED")
            print_info(f"Target: {validated_url}")

            attacks_list = []
            if xss:
                attacks_list.append("XSS")
            if sqli:
                attacks_list.append("SQLi")
            if traversal:
                attacks_list.append("Path Traversal")
            if enumeration:
                attacks_list.append("Directory Enumeration")
            if csrf:
                attacks_list.append("CSRF")

            print_info(f"Attack Types: {', '.join(attacks_list)}")
            print_info(f"Intensity: {intensity.upper()}")
            print_info(f"Max Payloads: {max_payloads}")
            print_info("")

        # Execute attack
        service = AttackService()
        result = service.attack(options)

        # Format output
        if json_output:
            exit_code = format_service_result(result, json_output=True)
        else:
            if result.success and result.data:
                attack_result = result.data

                # Display summary
                print_header("Attack Results")
                print_key_value("Target", attack_result.target_url)
                print_key_value("Total Findings", attack_result.total_findings)
                print_key_value("Payloads Tested", attack_result.total_payloads_tested)
                print_key_value("Duration", f"{attack_result.duration_seconds:.2f}s")
                print_info("")

                # Display findings by type
                if attack_result.xss_findings > 0:
                    print_subheader(f"XSS Findings: {attack_result.xss_findings}")
                if attack_result.sqli_findings > 0:
                    print_subheader(f"SQLi Findings: {attack_result.sqli_findings}")
                if attack_result.traversal_findings > 0:
                    print_subheader(
                        f"Path Traversal Findings: {attack_result.traversal_findings}"
                    )
                if attack_result.enumeration_findings > 0:
                    print_subheader(
                        f"Enumeration Findings: {attack_result.enumeration_findings}"
                    )
                if attack_result.csrf_findings > 0:
                    print_subheader(f"CSRF Findings: {attack_result.csrf_findings}")

                # Display individual vulnerabilities
                if attack_result.vulnerabilities:
                    print_info("")
                    print_header("Vulnerability Details")

                    for i, vuln in enumerate(attack_result.vulnerabilities, 1):
                        severity_color = {
                            "critical": "[!!!]",
                            "high": "[!!]",
                            "medium": "[!]",
                            "low": "[-]",
                        }.get(vuln.severity.value.lower(), "[?]")

                        print_info(
                            f"\n#{i} {severity_color} {vuln.title} "
                            f"[{vuln.severity.value}]"
                        )
                        print_info(f"    Type: {vuln.type.upper()}")
                        print_info(f"    URL: {vuln.url}")

                        if vuln.payload:
                            print_info(f"    Payload: {vuln.payload.payload}")
                            if vuln.payload.parameter:
                                print_info(f"    Parameter: {vuln.payload.parameter}")

                        if vuln.evidence:
                            evidence = vuln.evidence[:100]
                            if len(vuln.evidence) > 100:
                                evidence += "..."
                            print_info(f"    Evidence: {evidence}")

                        print_info(f"    Confidence: {vuln.confidence.value}")

                # Display warnings
                if result.warnings:
                    print_info("")
                    print_subheader("Warnings")
                    for warning in result.warnings:
                        print_warning(f"  - {warning}")

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


@attack.command("xss")
def attack_xss(
    url: Annotated[str, typer.Argument(help="URL to test for XSS")],
    consent: Annotated[
        bool,
        typer.Option("--consent", help="Confirm permission (REQUIRED)"),
    ] = False,
    intensity: Annotated[
        str,
        typer.Option("--intensity", "-i", help="Attack intensity: low, medium, high"),
    ] = "medium",
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output raw JSON"),
    ] = False,
) -> None:
    """
    Test only for XSS vulnerabilities.

    Examples:

        ciberwebscan attack xss https://example.com --consent
    """
    try:
        app_config = get_config()
        effective_consent = consent or app_config.attack.user_consent
        if not effective_consent:
            print_error("USER CONSENT REQUIRED. Use --consent flag.")
            sys.exit(2)

        validated_url = validate_url(url)

        from ciberwebscan.services import AttackOptions, AttackService

        print_warning("Testing for XSS vulnerabilities")
        print_info(f"Target: {validated_url}")

        options = AttackOptions(
            url=validated_url,
            user_consent=True,
            xss=True,
            intensity=intensity,
        )

        service = AttackService()
        result = service.attack(options)

        if json_output:
            exit_code = format_service_result(result, json_output=True)
        else:
            if result.success and result.data:
                print_header("XSS Test Results")
                print_key_value("Findings", result.data.xss_findings)
                print_key_value("Payloads Tested", result.data.total_payloads_tested)
            exit_code = format_service_result(result, json_output=False)

        sys.exit(exit_code)

    except ValidationError as e:
        print_error(str(e))
        sys.exit(2)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)


@attack.command("sqli")
def attack_sqli(
    url: Annotated[str, typer.Argument(help="URL to test for SQL injection")],
    consent: Annotated[
        bool,
        typer.Option("--consent", help="Confirm permission (REQUIRED)"),
    ] = False,
    intensity: Annotated[
        str,
        typer.Option("--intensity", "-i", help="Attack intensity: low, medium, high"),
    ] = "medium",
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output raw JSON"),
    ] = False,
) -> None:
    """
    Test only for SQL injection vulnerabilities.

    Examples:

        ciberwebscan attack sqli https://example.com/product?id=1 --consent
    """
    try:
        app_config = get_config()
        effective_consent = consent or app_config.attack.user_consent
        if not effective_consent:
            print_error("USER CONSENT REQUIRED. Use --consent flag.")
            sys.exit(2)

        validated_url = validate_url(url)

        from ciberwebscan.services import AttackOptions, AttackService

        print_warning("Testing for SQL injection vulnerabilities")
        print_info(f"Target: {validated_url}")

        options = AttackOptions(
            url=validated_url,
            user_consent=True,
            sqli=True,
            intensity=intensity,
        )

        service = AttackService()
        result = service.attack(options)

        if json_output:
            exit_code = format_service_result(result, json_output=True)
        else:
            if result.success and result.data:
                print_header("SQLi Test Results")
                print_key_value("Findings", result.data.sqli_findings)
                print_key_value("Payloads Tested", result.data.total_payloads_tested)
            exit_code = format_service_result(result, json_output=False)

        sys.exit(exit_code)

    except ValidationError as e:
        print_error(str(e))
        sys.exit(2)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)

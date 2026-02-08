"""
CiberWebScan CLI Application.

Main entry point for the command-line interface.
Built with Typer - no Rich dependencies.
"""

from __future__ import annotations

import sys
from typing import Annotated

import typer

from ciberwebscan.cli.commands.analyze import analyze
from ciberwebscan.cli.commands.config import config
from ciberwebscan.cli.commands.scrape import scrape
from ciberwebscan.cli.output import print_info

# Create main app without Rich
app = typer.Typer(
    name="ciberwebscan",
    help="CiberWebScan - Web Security Scanner and Scraper",
    no_args_is_help=True,
    add_completion=False,
    # pretty_exceptions_enable=False,  # Disable Rich exceptions
)

# Register command groups
app.add_typer(scrape, name="scrape")
app.add_typer(analyze, name="analyze")
app.add_typer(config, name="config")


@app.command("version")
def version() -> None:
    """Show version information."""
    try:
        from ciberwebscan import __version__
    except ImportError:
        __version__ = "2.0.0"

    print_info(f"CiberWebScan v{__version__}")


@app.command("quick")
def quick_scan(
    url: Annotated[str, typer.Argument(help="URL to scan")],
    output: Annotated[
        str | None,
        typer.Option("--output", "-o", help="Output file path"),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output raw JSON"),
    ] = False,
) -> None:
    """
    Quick scan - scrape and analyze in one command.

    Performs basic scraping and security analysis on the target URL.

    Examples:

        ciberwebscan quick https://example.com
        ciberwebscan quick https://example.com -o report.json
    """
    from ciberwebscan.cli.output import (
        format_analysis_result,
        format_scrape_result,
        format_service_result,
        print_error,
    )
    from ciberwebscan.cli.validators import ValidationError, validate_url

    try:
        validated_url = validate_url(url)
        print_info(f"Quick scan: {validated_url}")

        from ciberwebscan.services import (
            AnalyzeOptions,
            AnalyzeService,
            ScrapeOptions,
            ScrapeService,
        )

        # Scrape
        print_info("\n[1/2] Scraping...")
        scrape_service = ScrapeService()
        scrape_result = scrape_service.scrape(ScrapeOptions(url=validated_url))

        if not json_output and scrape_result.success:
            format_scrape_result(scrape_result.data)

        # Analyze
        print_info("\n[2/2] Analyzing...")
        analyze_service = AnalyzeService()
        analyze_result = analyze_service.analyze(
            AnalyzeOptions(
                url=validated_url,
                ssl=validated_url.startswith("https"),
                fingerprint=True,
                cve=True,
                export=output,
            )
        )

        if json_output:
            exit_code = format_service_result(analyze_result, json_output=True)
        else:
            if analyze_result.success:
                format_analysis_result(analyze_result.data)
            exit_code = format_service_result(analyze_result, json_output=False)

        sys.exit(exit_code)

    except ValidationError as e:
        print_error(str(e))
        sys.exit(2)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)


def main() -> None:
    """Main entry point."""
    app()


if __name__ == "__main__":
    main()

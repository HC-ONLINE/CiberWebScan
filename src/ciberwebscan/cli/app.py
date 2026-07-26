"""
CiberWebScan CLI Application.

Main entry point for the command-line interface.
Built with Typer - no Rich dependencies.
"""

from __future__ import annotations

import typer

from ciberwebscan.cli.commands.analyze import analyze
from ciberwebscan.cli.commands.api import api
from ciberwebscan.cli.commands.attack import attack
from ciberwebscan.cli.commands.completion import completion_app
from ciberwebscan.cli.commands.config import config
from ciberwebscan.cli.commands.quick import quick
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
app.add_typer(attack, name="attack")
app.add_typer(quick, name="quick")
app.add_typer(config, name="config")
app.add_typer(api, name="api")
app.add_typer(completion_app, name="completion")


@app.command("version")
def version() -> None:
    """Show version information."""
    from ciberwebscan import __version__

    print_info(f"CiberWebScan v{__version__}")


def main() -> None:
    """Main entry point."""
    # Setup logging before running the app
    from ciberwebscan.config.loader import get_config
    from ciberwebscan.utils.logging import setup_logging

    config = get_config()
    setup_logging(config.logging)

    app()


if __name__ == "__main__":
    main()

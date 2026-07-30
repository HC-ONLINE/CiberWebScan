"""
API command for CiberWebScan CLI.

Handles API server operations.
"""

from __future__ import annotations

from typing import Annotated

import typer

from ciberwebscan.cli.output import print_error, print_info, print_success
from ciberwebscan.config.loader import get_config


def run_api(
    host: Annotated[
        str | None,
        typer.Option(
            "--host",
            help="Host to bind the API server to",
        ),
    ] = None,
    port: Annotated[
        int | None,
        typer.Option(
            "--port",
            help="Port to bind the API server to",
        ),
    ] = None,
    reload: Annotated[
        bool,
        typer.Option(
            "--reload",
            help="Enable auto-reload on code changes",
        ),
    ] = False,
) -> None:
    """Start the CiberWebScan API server.

    Examples:

        # Run with default config settings
        ciberwebscan api

        # Run on custom host and port
        ciberwebscan api --host 0.0.0.0 --port 9000

        # Disable auto-reload for production
        ciberwebscan api --no-reload
    """
    try:
        # Import here to avoid issues if uvicorn is not installed for CLI-only installs
        import uvicorn

        app_config = get_config()
        api_config = app_config.api

        # Use provided values or fall back to config
        server_host = host or api_config.host
        server_port = port or api_config.port
        log_level = app_config.logging.level.lower()

        print_success(
            f"Starting CiberWebScan API on http://{server_host}:{server_port}"
        )
        print_info(
            f"Documentation available at http://{server_host}:{server_port}/docs"
        )

        uvicorn.run(
            "ciberwebscan.api.app:app",
            host=server_host,
            port=server_port,
            reload=reload,
            log_level=log_level,
        )
    except ImportError:
        print_error(
            'uvicorn is not installed. Install it with: pip install -e ".[api]"'
        )
        raise typer.Exit(code=1) from None
    except KeyboardInterrupt:
        print_info("API server stopped by user")
    except Exception as e:
        print_error(f"Failed to start API server: {e}")
        raise typer.Exit(code=1) from None

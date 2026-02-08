"""
Config command for CiberWebScan CLI.

Handles configuration management operations.
"""

from __future__ import annotations

import sys
from typing import Annotated

import typer

from ciberwebscan.cli.output import (
    format_config_result,
    format_service_result,
    print_error,
    print_header,
    print_info,
    print_key_value,
    print_list,
    print_success,
)
from ciberwebscan.cli.validators import (
    ValidationError,
    validate_file_path,
)

config = typer.Typer(
    name="config",
    help="Configuration management commands.",
    no_args_is_help=True,
)


@config.command("show")
def config_show(
    section: Annotated[
        str | None,
        typer.Argument(help="Config section to show (e.g., 'scraping', 'analysis')"),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output raw JSON"),
    ] = False,
) -> None:
    """
    Show current configuration.

    Examples:

        # Show all config
        ciberwebscan config show

        # Show specific section
        ciberwebscan config show scraping

        # Output as JSON
        ciberwebscan config show --json
    """
    try:
        from ciberwebscan.services import ConfigService

        service = ConfigService()

        result = service.get_section(section) if section else service.get_all()

        if json_output:
            exit_code = format_service_result(result, json_output=True)
        else:
            if result.success and result.data:
                if section:
                    print_header(f"Configuration: {section}")
                else:
                    print_header("Configuration")
                format_config_result(result.data)
            exit_code = format_service_result(result, json_output=False)

        sys.exit(exit_code)

    except Exception as e:
        print_error(f"Error: {e}")
        sys.exit(1)


@config.command("get")
def config_get(
    key: Annotated[str, typer.Argument(help="Configuration key (dot-notation)")],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output raw JSON"),
    ] = False,
) -> None:
    """
    Get a specific configuration value.

    Examples:

        ciberwebscan config get scraping.timeout
        ciberwebscan config get http.max_retries
    """
    try:
        from ciberwebscan.services import ConfigService

        service = ConfigService()
        result = service.get(key)

        if json_output:
            exit_code = format_service_result(result, json_output=True)
        else:
            if result.success and result.data:
                cv = result.data
                print_key_value(cv.key, cv.value)
                print_info(f"  (default: {cv.default}, source: {cv.source})")
            exit_code = format_service_result(result, json_output=False)

        sys.exit(exit_code)

    except Exception as e:
        print_error(f"Error: {e}")
        sys.exit(1)


@config.command("set")
def config_set(
    key: Annotated[str, typer.Argument(help="Configuration key")],
    value: Annotated[str, typer.Argument(help="New value")],
) -> None:
    """
    Set a configuration value.

    Examples:

        ciberwebscan config set scraping.timeout 60
        ciberwebscan config set http.max_retries 5
    """
    try:
        from contextlib import suppress

        from ciberwebscan.services import ConfigService

        # Attempt to convert value to appropriate type
        parsed_value: str | int | float | bool = value
        val_lower = value.lower()

        if val_lower == "true":
            parsed_value = True
        elif val_lower == "false":
            parsed_value = False
        else:
            # Try to parse as int first
            with suppress(ValueError):
                parsed_value = int(value)

            # If still a string (not int), try float
            if isinstance(parsed_value, str):
                with suppress(ValueError):
                    parsed_value = float(value)

        service = ConfigService()
        result = service.set(key, parsed_value)

        if result.success:
            print_success(f"Set {key} = {parsed_value}")
        else:
            print_error(result.error or "Unknown error")
            sys.exit(1)

    except Exception as e:
        print_error(f"Error: {e}")
        sys.exit(1)


@config.command("reset")
def config_reset(
    key: Annotated[
        str | None,
        typer.Argument(help="Specific key to reset, or omit for all"),
    ] = None,
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Skip confirmation"),
    ] = False,
) -> None:
    """
    Reset configuration to defaults.

    Examples:

        # Reset specific key
        ciberwebscan config reset scraping.timeout

        # Reset all (with confirmation)
        ciberwebscan config reset

        # Reset all (skip confirmation)
        ciberwebscan config reset -y
    """
    try:
        if not key and not yes:
            confirm = typer.confirm("Reset all configuration to defaults?")
            if not confirm:
                print_info("Cancelled")
                sys.exit(0)

        from ciberwebscan.services import ConfigService

        service = ConfigService()
        result = service.reset(key)

        if result.success:
            if key:
                print_success(f"Reset {key} to default")
            else:
                print_success("Reset all configuration to defaults")
        else:
            print_error(result.error or "Unknown error")
            sys.exit(1)

    except Exception as e:
        print_error(f"Error: {e}")
        sys.exit(1)


@config.command("keys")
def config_keys(
    section: Annotated[
        str | None,
        typer.Option("--section", "-s", help="Filter by section"),
    ] = None,
) -> None:
    """
    List all configuration keys.

    Examples:

        # List all keys
        ciberwebscan config keys

        # List keys in section
        ciberwebscan config keys -s scraping
    """
    try:
        from ciberwebscan.services import ConfigService

        service = ConfigService()
        result = service.list_keys(section)

        if result.success and result.data:
            if section:
                print_header(f"Configuration Keys: {section}")
            else:
                print_header("Configuration Keys")
            print_list(result.data)
        elif not result.success:
            print_error(result.error or "Unknown error")
            sys.exit(1)

    except Exception as e:
        print_error(f"Error: {e}")
        sys.exit(1)


@config.command("export")
def config_export(
    path: Annotated[str, typer.Argument(help="Output file path")],
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="Export format: yaml, json"),
    ] = "yaml",
) -> None:
    """
    Export configuration to file.

    Examples:

        ciberwebscan config export config.yaml
        ciberwebscan config export config.json -f json
    """
    try:
        from ciberwebscan.services import ConfigService

        service = ConfigService()
        result = service.export_config(path, format)

        if result.success:
            print_success(f"Exported configuration to: {result.data}")
        else:
            print_error(result.error or "Unknown error")
            sys.exit(1)

    except Exception as e:
        print_error(f"Error: {e}")
        sys.exit(1)


@config.command("load")
def config_load(
    path: Annotated[str, typer.Argument(help="Configuration file path")],
) -> None:
    """
    Load configuration from file.

    Examples:

        ciberwebscan config load config.yaml
        ciberwebscan config load config.json
    """
    try:
        validate_file_path(path, must_exist=True)

        from ciberwebscan.services import ConfigService

        service = ConfigService()
        result = service.load(path)

        if result.success:
            print_success(f"Loaded configuration from: {path}")
        else:
            print_error(result.error or "Unknown error")
            sys.exit(1)

    except ValidationError as e:
        print_error(str(e))
        sys.exit(2)
    except Exception as e:
        print_error(f"Error: {e}")
        sys.exit(1)

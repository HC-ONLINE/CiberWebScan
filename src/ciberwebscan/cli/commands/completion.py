"""
Completion command for CiberWebScan CLI.

Manages shell completion installation for bash, zsh, and fish.
Uses Click's internal shell_completion module for script generation.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated

import click
import typer
from click.shell_completion import get_completion_class

completion_app = typer.Typer(
    name="completion",
    help="Shell completion management.",
    no_args_is_help=True,
)

PROG_NAME = "ciberwebscan"
ENV_PREFIX = f"_{PROG_NAME.upper()}_COMPLETE"


class Shell(str):
    """Supported shell types."""

    BASH = "bash"
    ZSH = "zsh"
    FISH = "fish"


SUPPORTED_SHELLS = [Shell.BASH, Shell.ZSH, Shell.FISH]


def _detect_shell() -> str:
    """Detect the current shell using shellingham."""
    try:
        import shellingham

        shell_name, _ = shellingham.detect_shell()
        return shell_name.lower()
    except (ImportError, Exception):
        return ""


def _get_completion_script(shell: str) -> str:
    """Generate the completion script using Click's internal engine."""
    comp_cls = get_completion_class(shell)

    if not comp_cls:
        raise ValueError(f"Unsupported shell: {shell}")

    dummy_cli = click.Command(name=PROG_NAME)
    completer = comp_cls(
        cli=dummy_cli,
        ctx_args={},
        prog_name=PROG_NAME,
        complete_var=ENV_PREFIX,
    )

    return completer.source()


def _get_install_path(shell: str) -> Path:
    """Get the default install path for shell completions."""
    home = Path.home()

    if shell == Shell.BASH:
        data_dir = os.environ.get("XDG_DATA_HOME", str(home / ".local" / "share"))
        return Path(data_dir) / "bash-completion" / "completions"
    elif shell == Shell.ZSH:
        return home / ".zsh" / "completions"
    elif shell == Shell.FISH:
        return home / ".config" / "fish" / "completions"
    else:
        raise ValueError(f"Unsupported shell: {shell}")


def _get_completion_filename(shell: str) -> str:
    """Get the filename for the completion script."""
    if shell == Shell.BASH:
        return f"{PROG_NAME}.sh"
    elif shell == Shell.ZSH:
        return f"_{PROG_NAME}"
    elif shell == Shell.FISH:
        return f"{PROG_NAME}.fish"
    else:
        raise ValueError(f"Unsupported shell: {shell}")


def _write_completion_file(
    shell: str, script: str, install_path: Path | None = None
) -> Path:
    """Write completion script to the appropriate location."""
    if install_path is None:
        install_path = _get_install_path(shell)

    install_path.mkdir(parents=True, exist_ok=True)
    file_path = install_path / _get_completion_filename(shell)
    file_path.write_text(script, encoding="utf-8")
    return file_path


def _remove_completion_file(shell: str, install_path: Path | None = None) -> bool:
    """Remove the completion script file."""
    if install_path is None:
        install_path = _get_install_path(shell)

    file_path = install_path / _get_completion_filename(shell)

    if file_path.exists():
        file_path.unlink()
        return True
    return False


@completion_app.command("install")
def completion_install(
    shell: Annotated[
        str | None,
        typer.Option(
            "--shell",
            "-s",
            help=f"Shell to install completion for (auto-detected if not specified). Options: {', '.join(SUPPORTED_SHELLS)}",
        ),
    ] = None,
) -> None:
    """
    Install shell completion for ciberwebscan.

    Automatically detects the current shell if --shell is not specified.

    Examples:

        # Auto-detect shell and install
        ciberwebscan completion install

        # Install for specific shell
        ciberwebscan completion install --shell zsh
        ciberwebscan completion install --shell bash
        ciberwebscan completion install --shell fish
    """
    from ciberwebscan.cli.output import (
        print_error,
        print_info,
        print_success,
    )

    if shell is None:
        shell = _detect_shell()
        if not shell:
            print_error("Could not detect shell. Please specify with --shell option.")
            raise typer.Exit(code=1)

    if shell not in SUPPORTED_SHELLS:
        print_error(
            f"Unsupported shell '{shell}'. Supported shells: {', '.join(SUPPORTED_SHELLS)}"
        )
        raise typer.Exit(code=1)

    target_path = _get_install_path(shell) / _get_completion_filename(shell)

    try:
        script = _get_completion_script(shell)
        file_path = _write_completion_file(shell, script)

        print_success(f"Completion installed for {shell}")
        print_info(f"File: {file_path}")

        home_str = str(Path.home())
        if shell == Shell.BASH:
            print_info("\nAdd this to your ~/.bashrc:")
            display_path = str(file_path).replace(home_str, "~")
            print_info(f"  source {display_path}")
        elif shell == Shell.ZSH:
            print_info("\nAdd this to your ~/.zshrc:")
            display_dir = str(file_path.parent).replace(home_str, "~")
            print_info(f"  fpath=({display_dir} $fpath)")
            print_info("  autoload -Uz compinit && compinit")
        elif shell == Shell.FISH:
            print_info("\nRestart your shell or run:")
            display_path = str(file_path).replace(home_str, "~")
            print_info(f"  source {display_path}")

    except PermissionError as err:
        print_error(f"Permission denied writing to {target_path}")
        print_info(
            "Try running with appropriate permissions or use --shell to specify a custom path."
        )
        raise typer.Exit(code=1) from err
    except Exception as err:
        print_error(f"Failed to install completion: {err}")
        raise typer.Exit(code=1) from err


@completion_app.command("show")
def completion_show(
    shell: Annotated[
        str | None,
        typer.Option(
            "--shell",
            "-s",
            help=f"Shell to show completion for (auto-detected if not specified). Options: {', '.join(SUPPORTED_SHELLS)}",
        ),
    ] = None,
) -> None:
    """
    Display the shell completion script.

    Prints the completion script to stdout for manual installation or inspection.

    Examples:

        # Show completion for detected shell
        ciberwebscan completion show

        # Show completion for specific shell
        ciberwebscan completion show --shell bash
    """
    from ciberwebscan.cli.output import print_error

    if shell is None:
        shell = _detect_shell()
        if not shell:
            print_error("Could not detect shell. Please specify with --shell option.")
            raise typer.Exit(code=1)

    if shell not in SUPPORTED_SHELLS:
        print_error(
            f"Unsupported shell '{shell}'. Supported shells: {', '.join(SUPPORTED_SHELLS)}"
        )
        raise typer.Exit(code=1)

    try:
        script = _get_completion_script(shell)
        print(script)
    except Exception as err:
        print_error(f"Failed to generate completion script: {err}")
        raise typer.Exit(code=1) from err


@completion_app.command("uninstall")
def completion_uninstall(
    shell: Annotated[
        str | None,
        typer.Option(
            "--shell",
            "-s",
            help=f"Shell to uninstall completion for (auto-detected if not specified). Options: {', '.join(SUPPORTED_SHELLS)}",
        ),
    ] = None,
) -> None:
    """
    Remove shell completion for ciberwebscan.

    Examples:

        # Uninstall completion for detected shell
        ciberwebscan completion uninstall

        # Uninstall for specific shell
        ciberwebscan completion uninstall --shell zsh
    """
    from ciberwebscan.cli.output import (
        print_error,
        print_info,
        print_success,
    )

    if shell is None:
        shell = _detect_shell()
        if not shell:
            print_error("Could not detect shell. Please specify with --shell option.")
            raise typer.Exit(code=1)

    if shell not in SUPPORTED_SHELLS:
        print_error(
            f"Unsupported shell '{shell}'. Supported shells: {', '.join(SUPPORTED_SHELLS)}"
        )
        raise typer.Exit(code=1)

    try:
        removed = _remove_completion_file(shell)

        if removed:
            print_success(f"Completion uninstalled for {shell}")
            print_info(
                "You may need to remove source/fpath lines from your shell config manually."
            )
        else:
            print_info(f"No completion file found for {shell}")

    except Exception as err:
        print_error(f"Failed to uninstall completion: {err}")
        raise typer.Exit(code=1) from err

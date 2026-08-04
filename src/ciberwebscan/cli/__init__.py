"""
CiberWebScan CLI module.

Simple command-line interface built with Typer (no Rich).
"""

from __future__ import annotations

from ciberwebscan.cli.app import app, main
from ciberwebscan.cli.output import (
    print_error,
    print_info,
    print_success,
    print_warning,
)
from ciberwebscan.cli.validators import ValidationError

__all__ = [
    "app",
    "main",
    "print_error",
    "print_info",
    "print_success",
    "print_warning",
    "ValidationError",
]

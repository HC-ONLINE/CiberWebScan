"""
CLI commands for CiberWebScan.
"""

from __future__ import annotations

from ciberwebscan.cli.commands.analyze import analyze_cmd
from ciberwebscan.cli.commands.api import run_api
from ciberwebscan.cli.commands.attack import attack_cmd
from ciberwebscan.cli.commands.completion import completion_app
from ciberwebscan.cli.commands.config import config
from ciberwebscan.cli.commands.quick import quick_cmd
from ciberwebscan.cli.commands.scrape import scrape

__all__ = [
    "analyze_cmd",
    "attack_cmd",
    "completion_app",
    "config",
    "quick_cmd",
    "run_api",
    "scrape",
]

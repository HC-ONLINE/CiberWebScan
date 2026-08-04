"""
CLI commands for CiberWebScan.
"""

from __future__ import annotations

from ciberwebscan.cli.commands.analyze import analyze_cmd
from ciberwebscan.cli.commands.attack import attack_cmd
from ciberwebscan.cli.commands.completion import completion_app
from ciberwebscan.cli.commands.config import config
from ciberwebscan.cli.commands.scrape import scrape

__all__ = [
    "scrape",
    "analyze_cmd",
    "attack_cmd",
    "config",
    "completion_app",
]

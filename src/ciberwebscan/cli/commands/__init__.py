"""
CLI commands for CiberWebScan.
"""

from ciberwebscan.cli.commands.analyze import analyze
from ciberwebscan.cli.commands.attack import attack_cmd
from ciberwebscan.cli.commands.completion import completion_app
from ciberwebscan.cli.commands.config import config
from ciberwebscan.cli.commands.scrape import scrape

__all__ = [
    "scrape",
    "analyze",
    "attack_cmd",
    "config",
    "completion_app",
]

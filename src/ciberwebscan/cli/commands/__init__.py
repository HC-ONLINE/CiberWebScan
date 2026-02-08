"""
CLI commands for CiberWebScan.
"""

from ciberwebscan.cli.commands.analyze import analyze
from ciberwebscan.cli.commands.config import config
from ciberwebscan.cli.commands.scrape import scrape

__all__ = [
    "scrape",
    "analyze",
    "config",
]

"""
API routes for CiberWebScan.

This package contains all FastAPI route handlers for the REST API.
"""

from . import analyze, attack, auth, config, download, health, quick, scrape

__all__ = [
    "analyze",
    "attack",
    "auth",
    "config",
    "download",
    "health",
    "quick",
    "scrape",
]

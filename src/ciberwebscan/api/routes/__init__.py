"""
API routes for CiberWebScan.

This package contains all FastAPI route handlers for the REST API.
"""

from . import analyze, attack, auth, config, health, scrape

__all__ = ["analyze", "attack", "auth", "config", "health", "scrape"]

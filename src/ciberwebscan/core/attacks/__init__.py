"""
Core attack simulation modules for CiberWebScan.

Provides controlled security testing capabilities for:
- Cross-Site Scripting (XSS) detection
- SQL Injection testing
- Directory enumeration
- Path traversal testing

WARNING: Only use these modules against systems you own or have
explicit written authorization to test. Unauthorized testing is illegal.
"""

from .base import (
    AttackConfig,
    AttackContext,
    AttackEngine,
)
from .enumeration import DirectoryEnumerator
from .payloads import PayloadLoader
from .sqli import SQLiAttacker
from .traversal import PathTraversalAttacker
from .xss import XSSAttacker

__all__ = [
    "AttackEngine",
    "AttackConfig",
    "AttackContext",
    "XSSAttacker",
    "SQLiAttacker",
    "DirectoryEnumerator",
    "PathTraversalAttacker",
    "PayloadLoader",
]

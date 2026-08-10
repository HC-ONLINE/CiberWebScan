"""
Core attack simulation modules for CiberWebScan.

Provides controlled security testing capabilities for:
- Cross-Site Scripting (XSS) detection
- SQL Injection testing
- Directory enumeration
- Path traversal testing
- CSRF (Cross-Site Request Forgery) detection
- Subdomain enumeration (DNS brute force)

WARNING: Only use these modules against systems you own or have
explicit written authorization to test. Unauthorized testing is illegal.
"""

from __future__ import annotations

from .base import (
    AttackConfig,
    AttackContext,
    AttackEngine,
)
from .command_injection import CommandInjectionAttacker
from .csrf import CSRFAttacker
from .enumeration import DirectoryEnumerator
from .payloads import PayloadLoader
from .sqli import SQLiAttacker
from .subdomain import SubdomainEnumerator
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
    "CSRFAttacker",
    "SubdomainEnumerator",
    "CommandInjectionAttacker",
    "PayloadLoader",
]

"""
SSL/TLS analyzer module.

This module provides functionality for analyzing SSL/TLS certificates
and security configurations.
"""

from __future__ import annotations

from .analyzer import (
    SSLAnalysisResult,
    SSLAnalyzer,
    SSLCertificateInfo,
    SSLProtocolInfo,
    SSLSecurityAssessment,
    analyze_ssl_security,
)

__all__ = [
    "SSLAnalyzer",
    "SSLAnalysisResult",
    "SSLCertificateInfo",
    "SSLProtocolInfo",
    "SSLSecurityAssessment",
    "analyze_ssl_security",
]

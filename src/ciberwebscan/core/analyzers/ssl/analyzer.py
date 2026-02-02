"""
SSL/TLS certificate and security configuration analyzer.

This module provides functionality to analyze HTTPS security configuration,
including certificate information, supported protocols, and insecure
configuration detection.
"""

from __future__ import annotations

import datetime
import logging
import socket
import ssl
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    ec,
    ed448,
    ed25519,
    rsa,
    x448,
    x25519,
)

logger = logging.getLogger(__name__)


@dataclass
class SSLCertificateInfo:
    """Information extracted from the SSL certificate."""

    subject: dict[str, str]
    issuer: dict[str, str]
    version: int
    serial_number: str
    not_before: datetime.datetime
    not_after: datetime.datetime
    signature_algorithm: str
    public_key_algorithm: str
    public_key_size: int | None
    san_domains: list[str]
    is_self_signed: bool
    is_expired: bool
    days_until_expiry: int
    fingerprint_sha256: str
    fingerprint_sha1: str


@dataclass
class SSLProtocolInfo:
    """Information about supported SSL/TLS protocols."""

    supported_protocols: list[str]
    cipher_suites: list[str]
    preferred_cipher: str | None
    supports_sni: bool
    compression_supported: bool
    secure_renegotiation: bool


@dataclass
class SSLSecurityAssessment:
    """Security assessment of the SSL configuration."""

    overall_grade: str  # A+, A, B, C, D, F
    vulnerabilities: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    weak_protocols: list[str] = field(default_factory=list)
    weak_ciphers: list[str] = field(default_factory=list)


@dataclass
class SSLAnalysisResult:
    """Complete SSL analysis result."""

    ssl_enabled: bool
    hostname: str | None = None
    port: int | None = None
    certificate: SSLCertificateInfo | None = None
    protocols: SSLProtocolInfo | None = None
    security_assessment: SSLSecurityAssessment | None = None
    has_hsts: bool = False
    analysis_timestamp: str = ""
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary format."""
        result: dict[str, Any] = {
            "ssl_enabled": self.ssl_enabled,
            "hostname": self.hostname,
            "port": self.port,
            "has_hsts": self.has_hsts,
            "analysis_timestamp": self.analysis_timestamp,
        }

        if self.error:
            result["error"] = self.error
            return result

        if self.certificate:
            result["certificate"] = {
                "subject": self.certificate.subject,
                "issuer": self.certificate.issuer,
                "version": self.certificate.version,
                "serial_number": self.certificate.serial_number,
                "not_before": self.certificate.not_before.isoformat(),
                "not_after": self.certificate.not_after.isoformat(),
                "signature_algorithm": self.certificate.signature_algorithm,
                "public_key_algorithm": self.certificate.public_key_algorithm,
                "public_key_size": self.certificate.public_key_size,
                "san_domains": self.certificate.san_domains,
                "is_self_signed": self.certificate.is_self_signed,
                "is_expired": self.certificate.is_expired,
                "days_until_expiry": self.certificate.days_until_expiry,
                "fingerprint_sha256": self.certificate.fingerprint_sha256,
                "fingerprint_sha1": self.certificate.fingerprint_sha1,
            }

        if self.protocols:
            result["protocols"] = {
                "supported_protocols": self.protocols.supported_protocols,
                "cipher_suites": self.protocols.cipher_suites,
                "preferred_cipher": self.protocols.preferred_cipher,
                "supports_sni": self.protocols.supports_sni,
                "compression_supported": self.protocols.compression_supported,
                "secure_renegotiation": self.protocols.secure_renegotiation,
            }

        if self.security_assessment:
            result["security_assessment"] = {
                "overall_grade": self.security_assessment.overall_grade,
                "vulnerabilities": self.security_assessment.vulnerabilities,
                "warnings": self.security_assessment.warnings,
                "recommendations": self.security_assessment.recommendations,
                "weak_protocols": self.security_assessment.weak_protocols,
                "weak_ciphers": self.security_assessment.weak_ciphers,
            }

        return result


class SSLAnalyzer:
    """SSL/TLS certificate and security configuration analyzer."""

    # Insecure protocols
    INSECURE_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]

    # Weak ciphers
    WEAK_CIPHERS = ["RC4", "DES", "3DES", "MD5", "SHA1", "NULL", "EXPORT", "LOW"]

    def __init__(
        self,
        timeout: int = 10,
        hsts_checker: Callable[[str], bool] | None = None,
    ) -> None:
        """
        Initialize the SSL analyzer.

        Args:
            timeout: Connection timeout in seconds.
            hsts_checker: Optional callback to check HSTS header.
                         Receives URL, returns bool.
        """
        self.timeout = timeout
        self._hsts_checker = hsts_checker

    def analyze(self, url: str) -> SSLAnalysisResult:
        """
        Perform a complete SSL/TLS analysis of a URL.

        Args:
            url: URL to analyze.

        Returns:
            SSLAnalysisResult with all collected SSL information.
        """
        logger.info("Starting SSL/TLS analysis for: %s", url)

        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)

            if not hostname:
                return SSLAnalysisResult(
                    ssl_enabled=False,
                    error="Could not determine hostname from URL",
                )

            if parsed_url.scheme != "https":
                logger.warning("URL does not use HTTPS, scheme: %s", parsed_url.scheme)
                return SSLAnalysisResult(
                    ssl_enabled=False,
                    hostname=hostname,
                    port=port,
                    error="URL does not use HTTPS",
                )

            logger.debug("Connecting to %s:%d for SSL analysis", hostname, port)

            # Check HSTS if checker is provided
            has_hsts = False
            if self._hsts_checker:
                try:
                    has_hsts = self._hsts_checker(f"https://{hostname}")
                    if has_hsts:
                        logger.info("HSTS header detected")
                    else:
                        logger.warning("HSTS header not detected")
                except Exception as e:
                    logger.warning("Could not verify HSTS: %s", e)

            # Get certificate info
            cert_info = self._get_certificate_info(hostname, port)
            if cert_info:
                logger.info(
                    "Certificate obtained - Issuer: %s, Valid until: %s, Algorithm: %s",
                    cert_info.issuer.get("commonName", "N/A"),
                    cert_info.not_after,
                    cert_info.signature_algorithm,
                )

            # Analyze supported protocols
            protocol_info = self._analyze_protocols(hostname, port)
            if protocol_info:
                logger.info(
                    "Detected protocols: %s",
                    ", ".join(protocol_info.supported_protocols),
                )

            # Security assessment
            security_assessment = self._assess_security(
                cert_info, protocol_info, has_hsts=has_hsts
            )
            if security_assessment:
                logger.info("SSL grade assigned: %s", security_assessment.overall_grade)
                if security_assessment.vulnerabilities:
                    logger.warning(
                        "Vulnerabilities detected: %d",
                        len(security_assessment.vulnerabilities),
                    )
                    for vuln in security_assessment.vulnerabilities:
                        logger.warning("  - %s", vuln)

            return SSLAnalysisResult(
                ssl_enabled=True,
                hostname=hostname,
                port=port,
                certificate=cert_info,
                protocols=protocol_info,
                security_assessment=security_assessment,
                has_hsts=has_hsts,
                analysis_timestamp=datetime.datetime.now().isoformat(),
            )

        except (TimeoutError, ConnectionError, OSError) as e:
            error_msg = f"Could not connect to server: {e}"
            logger.error(error_msg)
            return SSLAnalysisResult(ssl_enabled=False, error=error_msg)

        except Exception as e:
            error_msg = f"Error during SSL analysis: {e}"
            logger.error(error_msg, exc_info=True)
            return SSLAnalysisResult(ssl_enabled=False, error=error_msg)

    def _get_certificate_info(
        self, hostname: str, port: int
    ) -> SSLCertificateInfo | None:
        """
        Get detailed SSL certificate information.

        Args:
            hostname: Host name.
            port: Connection port.

        Returns:
            Certificate information or None on error.
        """
        try:
            # Create SSL context that doesn't verify certificates
            # to analyze problematic certificates
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Connect and get certificate
            with (
                socket.create_connection(
                    (hostname, port), timeout=self.timeout
                ) as sock,
                context.wrap_socket(sock, server_hostname=hostname) as ssock,
            ):
                cert_der = ssock.getpeercert(binary_form=True)

            if cert_der is None:
                raise ValueError("Could not obtain certificate in DER format")

            # Parse certificate with cryptography
            cert = x509.load_der_x509_certificate(cert_der, default_backend())

            # Extract basic information
            subject = self._parse_name(cert.subject)
            issuer = self._parse_name(cert.issuer)

            # Validity dates
            not_before = cert.not_valid_before_utc.replace(tzinfo=None)
            not_after = cert.not_valid_after_utc.replace(tzinfo=None)
            now = datetime.datetime.now()

            is_expired = now > not_after
            days_until_expiry = (not_after - now).days

            # Algorithms
            signature_algorithm = cert.signature_algorithm_oid._name
            public_key = cert.public_key()
            public_key_algorithm = public_key.__class__.__name__

            # Public key size (only for types that support it)
            public_key_size: int | None = None
            if isinstance(public_key, rsa.RSAPublicKey | ec.EllipticCurvePublicKey):
                public_key_size = public_key.key_size
            elif isinstance(public_key, ed25519.Ed25519PublicKey):
                public_key_size = 256  # Ed25519 is always 256 bits
            elif isinstance(public_key, ed448.Ed448PublicKey):
                public_key_size = 456  # Ed448 is always 456 bits
            elif isinstance(public_key, x25519.X25519PublicKey):
                public_key_size = 256  # X25519 is always 256 bits
            elif isinstance(public_key, x448.X448PublicKey):
                public_key_size = 448  # X448 is always 448 bits

            # Subject Alternative Names
            san_domains: list[str] = []
            try:
                from cryptography.x509 import SubjectAlternativeName
                from cryptography.x509.oid import ExtensionOID

                san_ext = cert.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                )
                san_value = san_ext.value
                if isinstance(san_value, SubjectAlternativeName):
                    for name in san_value:
                        if isinstance(name, x509.DNSName):
                            san_domains.append(name.value)
            except x509.ExtensionNotFound:
                pass

            # Check if self-signed
            is_self_signed = subject == issuer

            # Fingerprints
            fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex()
            fingerprint_sha1 = cert.fingerprint(hashes.SHA1()).hex()

            return SSLCertificateInfo(
                subject=subject,
                issuer=issuer,
                version=cert.version.value,
                serial_number=str(cert.serial_number),
                not_before=not_before,
                not_after=not_after,
                signature_algorithm=signature_algorithm,
                public_key_algorithm=public_key_algorithm,
                public_key_size=public_key_size,
                san_domains=san_domains,
                is_self_signed=is_self_signed,
                is_expired=is_expired,
                days_until_expiry=days_until_expiry,
                fingerprint_sha256=fingerprint_sha256,
                fingerprint_sha1=fingerprint_sha1,
            )

        except Exception as e:
            logger.error("Error getting certificate from %s:%d - %s", hostname, port, e)
            logger.debug(
                "Certificate error details: %s", type(e).__name__, exc_info=True
            )
            raise

    def _analyze_protocols(self, hostname: str, port: int) -> SSLProtocolInfo | None:
        """
        Analyze supported SSL/TLS protocols.

        Args:
            hostname: Host name.
            port: Connection port.

        Returns:
            Protocol information or None on error.
        """
        try:
            supported_protocols: list[str] = []
            cipher_suites: list[str] = []

            # List of protocols to test
            protocols_to_test: list[tuple[str, int] | None] = [
                (
                    ("SSLv3", ssl.PROTOCOL_SSLv3)
                    if hasattr(ssl, "PROTOCOL_SSLv3")
                    else None
                ),
                (
                    ("TLSv1", ssl.PROTOCOL_TLSv1)
                    if hasattr(ssl, "PROTOCOL_TLSv1")
                    else None
                ),
                (
                    ("TLSv1.1", ssl.PROTOCOL_TLSv1_1)
                    if hasattr(ssl, "PROTOCOL_TLSv1_1")
                    else None
                ),
                (
                    ("TLSv1.2", ssl.PROTOCOL_TLSv1_2)
                    if hasattr(ssl, "PROTOCOL_TLSv1_2")
                    else None
                ),
                ("TLSv1.3", ssl.PROTOCOL_TLS) if hasattr(ssl, "PROTOCOL_TLS") else None,
            ]

            valid_protocols = [p for p in protocols_to_test if p is not None]

            # Test each protocol
            for protocol_name, protocol_constant in valid_protocols:  # type: ignore[misc]
                try:
                    context = ssl.SSLContext(protocol_constant)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE

                    with (
                        socket.create_connection(
                            (hostname, port), timeout=self.timeout
                        ) as sock,
                        context.wrap_socket(sock) as ssock,
                    ):
                        supported_protocols.append(protocol_name)
                        cipher = ssock.cipher()
                        if cipher:
                            cipher_suites.append(cipher[0])
                except Exception:
                    continue

            # Get additional info with default connection
            preferred_cipher: str | None = None
            supports_sni = False
            try:
                context = ssl.create_default_context()
                with (
                    socket.create_connection(
                        (hostname, port), timeout=self.timeout
                    ) as sock,
                    context.wrap_socket(sock, server_hostname=hostname) as ssock,
                ):
                    cipher_info = ssock.cipher()
                    preferred_cipher = cipher_info[0] if cipher_info else None
                    supports_sni = True  # If we got here, SNI works
            except Exception:
                pass

            return SSLProtocolInfo(
                supported_protocols=supported_protocols,
                cipher_suites=list(set(cipher_suites)),
                preferred_cipher=preferred_cipher,
                supports_sni=supports_sni,
                compression_supported=False,  # Generally disabled due to CRIME
                secure_renegotiation=True,  # Assume enabled in modern connections
            )

        except Exception as e:
            logger.error(
                "Error analyzing SSL protocols for %s:%d - %s", hostname, port, e
            )
            logger.debug("Protocol error details: %s", type(e).__name__, exc_info=True)
            return None

    def _assess_security(
        self,
        cert_info: SSLCertificateInfo | None,
        protocol_info: SSLProtocolInfo | None,
        has_hsts: bool = False,
    ) -> SSLSecurityAssessment | None:
        """
        Assess the security of the SSL configuration.

        Args:
            cert_info: Certificate information.
            protocol_info: Protocol information.
            has_hsts: Indicates if the server has HSTS enabled.

        Returns:
            Security assessment.
        """
        if not cert_info or not protocol_info:
            logger.warning(
                "Incomplete SSL security assessment - missing certificate or protocol info"
            )
            return None

        vulnerabilities: list[str] = []
        warnings: list[str] = []
        recommendations: list[str] = []
        weak_protocols: list[str] = []
        weak_ciphers: list[str] = []

        # Evaluate certificate
        if cert_info.is_expired:
            vulnerabilities.append("Expired certificate")
        elif cert_info.days_until_expiry < 30:
            warnings.append(
                f"Certificate expires in {cert_info.days_until_expiry} days"
            )

        if cert_info.is_self_signed:
            vulnerabilities.append("Self-signed certificate")

        # Evaluate key size based on algorithm
        if cert_info.public_key_size:
            if (
                cert_info.public_key_algorithm == "RSAPublicKey"
                and cert_info.public_key_size < 2048
            ):
                vulnerabilities.append(
                    f"Weak RSA key ({cert_info.public_key_size} bits)"
                )
            elif (
                cert_info.public_key_algorithm == "EllipticCurvePublicKey"
                and cert_info.public_key_size < 256
            ):
                vulnerabilities.append(
                    f"Weak ECC key ({cert_info.public_key_size} bits)"
                )

        if "SHA1" in cert_info.signature_algorithm.upper():
            warnings.append("SHA1 signature algorithm (deprecated)")

        # Evaluate protocols
        for protocol in protocol_info.supported_protocols:
            if protocol in self.INSECURE_PROTOCOLS:
                weak_protocols.append(protocol)
                vulnerabilities.append(f"Insecure protocol supported: {protocol}")

        # Evaluate ciphers
        for cipher in protocol_info.cipher_suites:
            for weak_cipher in self.WEAK_CIPHERS:
                if weak_cipher.upper() in cipher.upper():
                    weak_ciphers.append(cipher)
                    warnings.append(f"Weak cipher supported: {cipher}")
                    break

        # Check Forward Secrecy support
        supports_fs = any(
            "DHE" in cipher or "ECDHE" in cipher
            for cipher in protocol_info.cipher_suites
        )
        if not supports_fs:
            warnings.append("Server does not support Forward Secrecy (FS)")
            recommendations.append(
                "Enable Forward Secrecy (FS) using DHE or ECDHE cipher suites"
            )

        # Recommendations
        if weak_protocols:
            recommendations.append(
                "Disable insecure protocols: " + ", ".join(weak_protocols)
            )

        if weak_ciphers:
            recommendations.append("Disable weak ciphers")

        if not protocol_info.supports_sni:
            recommendations.append("Enable SNI support")

        # Calculate grade
        grade = self._calculate_grade(
            vulnerabilities,
            warnings,
            weak_protocols,
            weak_ciphers,
            protocol_info=protocol_info,
            has_hsts=has_hsts,
        )

        logger.debug(
            "SSL assessment completed - Vulnerabilities: %d, Warnings: %d, "
            "Weak protocols: %d, Weak ciphers: %d, Final grade: %s",
            len(vulnerabilities),
            len(warnings),
            len(weak_protocols),
            len(weak_ciphers),
            grade,
        )

        return SSLSecurityAssessment(
            overall_grade=grade,
            vulnerabilities=vulnerabilities,
            warnings=warnings,
            recommendations=recommendations,
            weak_protocols=weak_protocols,
            weak_ciphers=weak_ciphers,
        )

    def _calculate_grade(
        self,
        vulnerabilities: list[str],
        warnings: list[str],
        weak_protocols: list[str],
        weak_ciphers: list[str],
        protocol_info: SSLProtocolInfo | None = None,
        has_hsts: bool = False,
    ) -> str:
        """
        Calculate an overall security grade for the SSL/TLS server.

        The grade is based on an initial score that is deducted for each
        vulnerability or misconfiguration found. Additional rules are applied
        to limit the maximum grade in certain cases.

        Args:
            vulnerabilities: List of critical vulnerabilities.
            warnings: List of warnings.
            weak_protocols: List of supported weak protocols.
            weak_ciphers: List of supported weak ciphers.
            protocol_info: Detailed protocol information object.
            has_hsts: Indicates if HSTS header is present.

        Returns:
            The final grade (e.g., 'A+', 'B', 'F').
        """
        # Rules that force grade to F immediately
        critical_vulns = ["expired", "self-signed"]
        if any(
            any(critical in vuln.lower() for critical in critical_vulns)
            for vuln in vulnerabilities
        ):
            return "F"

        critical_protocols = ["SSLv2", "SSLv3"]
        if any(protocol in critical_protocols for protocol in weak_protocols):
            return "F"

        # --- Point-based grading logic with rules ---
        score = 100
        grade_rules: list[dict[str, str]] = []

        # 1. Penalties for vulnerabilities and warnings
        for vuln in vulnerabilities:
            score -= 25 if "insecure" in vuln.lower() or "weak" in vuln.lower() else 15

        for warning in warnings:
            if "expires in" in warning.lower():
                # Extract days from warning
                import re

                days_match = re.search(r"(\d+)", warning)
                if days_match:
                    days = int(days_match.group(1))
                    if days < 7:
                        score -= 20
                    elif days < 30:
                        score -= 10
                    else:
                        score -= 5
            else:
                score -= 8

        # 2. Penalties for weak protocols and ciphers
        if any(p in weak_protocols for p in ["TLSv1", "TLSv1.1"]):
            score -= 20
            grade_rules.append({"max_grade": "B", "reason": "Support for TLS 1.0/1.1"})

        # Penalty for lack of Forward Secrecy
        if (
            protocol_info
            and protocol_info.cipher_suites
            and not any(
                "DHE" in cipher or "ECDHE" in cipher
                for cipher in protocol_info.cipher_suites
            )
        ):
            grade_rules.append(
                {"max_grade": "B", "reason": "Does not support Forward Secrecy (FS)"}
            )
            score -= 15

        # Penalty for SHA-1 usage
        if any("SHA1" in warning for warning in warnings):
            grade_rules.append({"max_grade": "B", "reason": "SHA-1 signature usage"})
            score -= 15

        score -= len(weak_ciphers) * 8

        # 3. Determine initial grade based on score
        if score >= 95:
            grade = "A+"
        elif score >= 85:
            grade = "A"
        elif score >= 70:
            grade = "B"
        elif score >= 55:
            grade = "C"
        elif score >= 40:
            grade = "D"
        else:
            grade = "F"

        # 4. Apply maximum grade rules
        grade_order = ["F", "D", "C", "B", "A", "A+"]
        final_grade = grade

        for rule in grade_rules:
            max_grade = rule["max_grade"]
            if grade_order.index(final_grade) > grade_order.index(max_grade):
                logger.debug(
                    "Adjusting grade from '%s' to '%s' due to: %s",
                    final_grade,
                    max_grade,
                    rule["reason"],
                )
                final_grade = max_grade

        # 5. Final rule for A+: requires HSTS
        if final_grade == "A+" and not has_hsts:
            final_grade = "A"
            logger.debug("Grade degraded to 'A' due to missing HSTS.")

        return final_grade

    def _parse_name(self, name: x509.Name) -> dict[str, str]:
        """
        Parse an X.509 name to dictionary.

        Args:
            name: cryptography Name object.

        Returns:
            Dictionary with name components.
        """
        result: dict[str, str] = {}
        for attribute in name:
            value = attribute.value
            result[attribute.oid._name] = (
                value
                if isinstance(value, str)
                else value.decode("utf-8", errors="replace")
            )
        return result


def analyze_ssl_security(url: str, timeout: int = 10) -> dict[str, Any]:
    """
    Convenience function to analyze SSL security of a URL.

    Args:
        url: URL to analyze.
        timeout: Timeout in seconds.

    Returns:
        Dictionary with the complete SSL analysis.
    """
    analyzer = SSLAnalyzer(timeout=timeout)
    result = analyzer.analyze(url)
    return result.to_dict()

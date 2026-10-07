"""
Logging utilities for CiberWebScan.

Provides centralized logging configuration plus helpers to derive
non-reversible identifiers that are safe to write to logs.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import logging.config
import secrets
import threading
from pathlib import Path

from ciberwebscan.config.loader import get_config
from ciberwebscan.config.models import LoggingConfig

# =============================================================================
# Log identifier masking
# =============================================================================

# Auto-generated server secret, cached for the lifetime of the process so log
# identifiers correlate across requests. It only feeds log obfuscation; it is
# never used to derive authorization identities.
_generated_server_secret: str | None = None
_generated_server_secret_lock = threading.Lock()


def _resolve_server_secret(configured: str) -> str:
    """
    Resolve the server secret used to obfuscate API keys in logs.

    An explicitly configured value always wins and is never cached, because it
    can be changed at runtime (PUT /api/config). When the configured value is
    empty (the default), a random secret is generated exactly once per process
    and reused from then on, instead of being regenerated on every call.

    Args:
        configured: Value of ``config.api.auth.server_secret``.

    Returns:
        The secret to use for log obfuscation.
    """
    global _generated_server_secret

    if configured:
        return configured
    if _generated_server_secret is None:
        with _generated_server_secret_lock:
            if _generated_server_secret is None:
                _generated_server_secret = secrets.token_urlsafe(32)
    return _generated_server_secret


def mask_key_for_logging(key: str) -> str:
    """
    Create a safe, non-reversible identifier for logging purposes.

    Uses HMAC-SHA256 with a server-side secret to produce a keyed hash.
    This allows correlating log entries for the same key without exposing
    the actual key material, and is not vulnerable to pre-image attacks
    without knowledge of the server secret.

    Note: HMAC-SHA256 is appropriate here because this is a log identifier,
    not password storage. SHA-2 is explicitly recommended by OWASP for
    non-password cryptographic operations.

    This value is log-only: authorization identities are derived from the key
    id (see ``AuthenticatedUser.identifier``), never from this HMAC. The server
    secret is cached per process (see ``_resolve_server_secret``), so the same
    key maps to the same log identifier across requests.

    Args:
        key: Key material (typically the key id, i.e. the first characters of
            an API key).

    Returns:
        A 12-character hexadecimal identifier safe for logs.
    """
    auth_config = get_config().api.auth
    server_secret = _resolve_server_secret(auth_config.server_secret).encode()
    # codeql[py/weak-sensitive-data-hashing]
    return hmac.new(server_secret, key.encode(), hashlib.sha256).hexdigest()[:12]


def mask_identifier(identifier: str) -> str:
    """
    Mask a user identifier so it is safe to write to logs.

    Identifiers of the form ``apikey:<key_id>`` embed the first characters of
    an API key, so logging them verbatim would expose key material. They are
    replaced by ``apikey:<HMAC>`` through :func:`mask_key_for_logging`, which
    keeps entries for the same key correlatable across requests and
    processes that share an explicit ``server_secret``.

    Identifiers that do not carry key material are returned unchanged.

    This is log-only: masked identifiers must never be used for
    authorization decisions.

    Args:
        identifier: User identifier, usually ``AuthenticatedUser.identifier``.

    Returns:
        A log-safe version of the identifier.
    """
    scheme, separator, key_id = identifier.partition(":")
    if not separator or scheme != "apikey" or not key_id:
        return identifier
    return f"{scheme}:{mask_key_for_logging(key_id)}"


# =============================================================================
# Logging configuration
# =============================================================================


def setup_logging(config: LoggingConfig) -> None:
    """
    Configure logging based on the provided configuration.

    Args:
        config: Logging configuration from app config.
    """
    # Convert level string to logging level
    level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL,
    }
    level = level_map.get(config.level.upper(), logging.INFO)

    # Base logging configuration
    logging_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "default": {
                "format": config.format,
            },
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "default",
                "level": level,
            },
        },
        "root": {
            "level": level,
            "handlers": ["console"],
        },
    }

    # Add file handler if file is specified
    if config.file:
        file_path = Path(config.file)
        file_path.parent.mkdir(parents=True, exist_ok=True)

        logging_config["handlers"]["file"] = {
            "class": "logging.handlers.RotatingFileHandler",
            "formatter": "default",
            "filename": str(file_path),
            "maxBytes": config.max_size,
            "backupCount": config.backup_count,
            "level": level,
        }
        logging_config["root"]["handlers"].append("file")

    # Apply configuration
    logging.config.dictConfig(logging_config)

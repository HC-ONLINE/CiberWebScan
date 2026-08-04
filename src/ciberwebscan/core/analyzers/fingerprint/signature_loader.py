"""
Technology signature loader.

This module provides functionality to load and manage web technology signatures
from JSON configuration files.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, TypedDict

logger = logging.getLogger(__name__)


class TechnologySignatures(TypedDict, total=False):
    """Data structure for technology signatures.

    Attributes:
        cms_signatures: Signatures for content management systems.
        framework_signatures: Signatures for web frameworks.
        server_signatures: Signatures for web servers.
        js_library_signatures: Signatures for JavaScript libraries.
        cdn_paas_signatures: Signatures for CDN and PaaS providers.
    """

    cms_signatures: dict[str, Any]
    framework_signatures: dict[str, Any]
    server_signatures: dict[str, Any]
    js_library_signatures: dict[str, Any]
    cdn_paas_signatures: dict[str, Any]


# Module-level cache for signatures
_signatures_cache: TechnologySignatures | None = None


def get_default_signatures_path() -> Path:
    """
    Get the default path for the signatures.json file.

    Returns:
        Path to the signatures.json file.
    """
    return Path(__file__).parent / "signatures.json"


def load_technology_signatures(
    signatures_path: str | Path | None = None,
    use_cache: bool = True,
) -> TechnologySignatures:
    """
    Load known technology signatures from an external JSON file.

    This method searches and loads technology signatures from a JSON file
    located at the specified path or the default location.

    Args:
        signatures_path: Optional path to the signatures file.
                        If None, uses the default path.
        use_cache: Whether to use cached signatures if available.

    Returns:
        Dictionary with technology signatures grouped by category.
        Keys are: 'cms_signatures', 'framework_signatures',
        'server_signatures', and 'js_library_signatures'.

    Raises:
        RuntimeError: If the signatures file cannot be loaded.
        json.JSONDecodeError: If the JSON file is malformed.
    """
    global _signatures_cache

    if use_cache and _signatures_cache is not None:
        return _signatures_cache

    if signatures_path is None:
        signatures_path = get_default_signatures_path()
    else:
        signatures_path = Path(signatures_path)

    try:
        with open(signatures_path, encoding="utf-8") as f:
            data = json.load(f)

        signatures: TechnologySignatures = {
            "cms_signatures": data.get("cms_signatures", {}),
            "framework_signatures": data.get("framework_signatures", {}),
            "server_signatures": data.get("server_signatures", {}),
            "js_library_signatures": data.get("js_library_signatures", {}),
            "cdn_paas_signatures": data.get("cdn_paas_signatures", {}),
        }

        if use_cache:
            _signatures_cache = signatures

        logger.debug(
            "Loaded signatures: %d CMS, %d frameworks, %d servers, %d JS libraries, %d CDN/PaaS",
            len(signatures["cms_signatures"]),
            len(signatures["framework_signatures"]),
            len(signatures["server_signatures"]),
            len(signatures["js_library_signatures"]),
            len(signatures["cdn_paas_signatures"]),
        )

        return signatures

    except FileNotFoundError as e:
        raise RuntimeError(
            f"Technology signatures file not found: {signatures_path}"
        ) from e
    except json.JSONDecodeError as e:
        raise RuntimeError(
            f"Invalid JSON in signatures file: {signatures_path}. Error: {e}"
        ) from e
    except Exception as e:
        raise RuntimeError(
            f"Could not load technology signatures file: {signatures_path}. Error: {e}"
        ) from e


def clear_signatures_cache() -> None:
    """Clear the cached signatures."""
    global _signatures_cache
    _signatures_cache = None


def get_signature_categories() -> list[str]:
    """
    Get the list of available signature categories.

    Returns:
        List of category names.
    """
    return [
        "cms_signatures",
        "framework_signatures",
        "server_signatures",
        "js_library_signatures",
        "cdn_paas_signatures",
    ]

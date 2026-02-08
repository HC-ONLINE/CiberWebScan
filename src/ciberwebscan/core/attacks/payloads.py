"""
Payload loading and management for attack modules.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from .base import AttackIntensity

logger = logging.getLogger(__name__)


class PayloadLoader:
    """Loads and manages attack payloads."""

    def __init__(self, payloads_file: Path | str | None = None):
        if payloads_file is None:
            # Use default payloads file in same directory
            self.payloads_file = Path(__file__).parent / "attack_payloads.json"
        else:
            self.payloads_file = Path(payloads_file)

        self._payloads: dict[str, list[str]] = {}
        self._load_payloads()

    def _load_payloads(self) -> None:
        """Load payloads from JSON file."""
        try:
            with open(self.payloads_file, encoding="utf-8") as f:
                self._payloads = json.load(f)
            logger.debug(f"Loaded payloads from {self.payloads_file}")
        except FileNotFoundError:
            logger.warning(f"Payloads file not found: {self.payloads_file}")
            self._payloads = self._get_default_payloads()
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in payloads file: {e}")
            self._payloads = self._get_default_payloads()

    def _get_default_payloads(self) -> dict[str, list[str]]:
        """Return minimal default payloads if file loading fails."""
        return {
            "xss": [
                "<script>alert('XSS')</script>",
                "'\"><script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
            ],
            "sqli": [
                "' OR '1'='1",
                "'; DROP TABLE users; --",
                "' UNION SELECT null,version() --",
            ],
            "traversal": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            ],
            "enumeration": ["admin", "login", "dashboard", "backup", "config"],
        }

    def get_payloads(
        self,
        attack_type: str,
        intensity: AttackIntensity = AttackIntensity.MEDIUM,
        max_count: int | None = None,
    ) -> list[str]:
        """Get payloads for a specific attack type and intensity."""
        all_payloads = self._payloads.get(attack_type, [])

        if not all_payloads:
            logger.warning(f"No payloads found for attack type: {attack_type}")
            return []

        # Filter by intensity
        if intensity == AttackIntensity.LOW:
            # Use first 25% of payloads (basic ones)
            selected = all_payloads[: len(all_payloads) // 4 or 1]
        elif intensity == AttackIntensity.MEDIUM:
            # Use first 50% of payloads
            selected = all_payloads[: len(all_payloads) // 2 or 1]
        else:  # HIGH
            # Use all payloads
            selected = all_payloads

        # Apply max count limit
        if max_count and len(selected) > max_count:
            selected = selected[:max_count]

        logger.debug(
            f"Selected {len(selected)} {attack_type} payloads (intensity: {intensity})"
        )
        return selected

    def add_custom_payloads(self, attack_type: str, payloads: list[str]) -> None:
        """Add custom payloads for an attack type."""
        if attack_type not in self._payloads:
            self._payloads[attack_type] = []

        # Add custom payloads at the beginning (higher priority)
        self._payloads[attack_type] = payloads + self._payloads[attack_type]
        logger.debug(f"Added {len(payloads)} custom {attack_type} payloads")

    def load_custom_payloads_from_file(
        self, file_path: Path | str, attack_type: str
    ) -> None:
        """Load custom payloads from a text file (one per line)."""
        try:
            with open(file_path, encoding="utf-8") as f:
                payloads = [line.strip() for line in f if line.strip()]

            self.add_custom_payloads(attack_type, payloads)
            logger.info(
                f"Loaded {len(payloads)} custom {attack_type} payloads from {file_path}"
            )

        except FileNotFoundError:
            logger.error(f"Custom payloads file not found: {file_path}")
        except Exception as e:
            logger.error(f"Error loading custom payloads from {file_path}: {e}")

    def get_available_attack_types(self) -> list[str]:
        """Get list of available attack types."""
        return list(self._payloads.keys())

    def get_payload_count(self, attack_type: str) -> int:
        """Get total number of payloads for an attack type."""
        return len(self._payloads.get(attack_type, []))

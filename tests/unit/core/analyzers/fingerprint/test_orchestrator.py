"""Unit tests for fingerprint orchestrator."""

from __future__ import annotations

from pathlib import Path

import pytest

from ciberwebscan.core.analyzers.fingerprint.orchestrator import (
    TechnologyFingerprinter,
    fingerprint_technologies,
)


@pytest.fixture
def mock_signatures_file(tmp_path: Path) -> Path:
    """Create a temporary signatures file for testing."""
    sig_file = tmp_path / "signatures.json"
    sig_content = """
    {
        "cms_signatures": {
            "WordPress": {"meta": "WordPress"}
        },
        "framework_signatures": {},
        "server_signatures": {
            "nginx": {"header": "nginx"}
        },
        "js_library_signatures": {
            "jQuery": {"pattern": "jquery"}
        }
    }
    """
    sig_file.write_text(sig_content)
    return sig_file


class TestTechnologyFingerprinter:
    """Tests for TechnologyFingerprinter class."""

    def test_init_default(self, mock_signatures_file: Path) -> None:
        """Test default initialization with signatures path."""
        fp = TechnologyFingerprinter(signatures_path=str(mock_signatures_file))
        # Should have signature attributes
        assert hasattr(fp, "cms_signatures")
        assert hasattr(fp, "server_signatures")

    def test_init_loads_signatures(self, mock_signatures_file: Path) -> None:
        """Test initialization loads signatures from file."""
        fp = TechnologyFingerprinter(signatures_path=str(mock_signatures_file))
        assert "WordPress" in fp.cms_signatures
        assert "nginx" in fp.server_signatures

    def test_fingerprint_empty_response(self, mock_signatures_file: Path) -> None:
        """Test fingerprinting with empty response."""
        fp = TechnologyFingerprinter(signatures_path=str(mock_signatures_file))

        result = fp.fingerprint(headers={}, html_content="")

        assert "technologies" in result
        assert "summary" in result
        assert "analysis_timestamp" in result

    def test_fingerprint_with_debug(self, mock_signatures_file: Path) -> None:
        """Test fingerprinting with debug mode enabled."""
        fp = TechnologyFingerprinter(signatures_path=str(mock_signatures_file))

        result = fp.fingerprint(
            headers={"Server": "nginx"},
            html_content="",
            debug=True,
        )

        # Debug keys should be present with underscore prefix
        assert "technologies" in result
        assert "summary" in result

    def test_get_technology_list(self, mock_signatures_file: Path) -> None:
        """Test getting flat technology list."""
        fp = TechnologyFingerprinter(signatures_path=str(mock_signatures_file))

        tech_list = fp.get_technology_list(
            headers={"Server": "nginx/1.18.0"},
            html_content="",
        )

        assert isinstance(tech_list, list)
        assert all(isinstance(name, str) for name in tech_list)

    def test_get_technologies_by_category(self, mock_signatures_file: Path) -> None:
        """Test getting technologies grouped by category."""
        fp = TechnologyFingerprinter(signatures_path=str(mock_signatures_file))

        by_category = fp.get_technologies_by_category(
            headers={"Server": "nginx"},
            html_content="",
        )

        assert isinstance(by_category, dict)
        # Should have standard categories
        assert (
            "servers" in by_category
            or "cms" in by_category
            or "frameworks" in by_category
        )


class TestFingerprintTechnologies:
    """Tests for fingerprint_technologies convenience function."""

    def test_basic_usage(self, mock_signatures_file: Path) -> None:
        """Test basic function usage."""
        result = fingerprint_technologies(
            headers={},
            html_content="",
            signatures_path=str(mock_signatures_file),
        )

        assert "technologies" in result
        assert "summary" in result

    def test_with_debug(self, mock_signatures_file: Path) -> None:
        """Test with debug mode."""
        result = fingerprint_technologies(
            headers={"Server": "Apache/2.4"},
            html_content="",
            debug=True,
            signatures_path=str(mock_signatures_file),
        )

        assert "technologies" in result
        assert "summary" in result

"""Unit tests for fingerprint helper functions."""

from __future__ import annotations

from ciberwebscan.core.analyzers.fingerprint.helpers import (
    append_tech_with_version,
    append_tech_with_version_debug,
    extract_version_from_string,
    get_timestamp,
    normalize_technology_name,
)


class TestGetTimestamp:
    """Tests for get_timestamp function."""

    def test_returns_iso_format(self) -> None:
        """Test that timestamp is in ISO format."""
        timestamp = get_timestamp()
        assert "T" in timestamp
        assert len(timestamp) >= 19  # At least YYYY-MM-DDTHH:MM:SS

    def test_returns_string(self) -> None:
        """Test that timestamp is a string."""
        assert isinstance(get_timestamp(), str)


class TestAppendTechWithVersion:
    """Tests for append_tech_with_version function."""

    def test_adds_tech_without_version(self) -> None:
        """Test adding technology without version."""
        detected: list[str] = []
        label = append_tech_with_version(detected, "WordPress", "some text")

        assert "WordPress" in detected
        assert label == "WordPress"

    def test_adds_tech_with_version_regex(self) -> None:
        """Test adding technology with version from regex."""
        detected: list[str] = []
        label = append_tech_with_version(
            detected,
            "WordPress",
            "WordPress 5.8.1",
            regex=r"wordpress[\s/]+([\d.]+)",
        )

        assert "WordPress 5.8.1" in detected
        assert label == "WordPress 5.8.1"

    def test_uses_generic_patterns(self) -> None:
        """Test generic version pattern extraction."""
        detected: list[str] = []
        append_tech_with_version(
            detected,
            "nginx",
            "nginx/1.18.0",
        )

        assert "nginx 1.18.0" in detected

    def test_avoids_duplicates(self) -> None:
        """Test that duplicates are not added."""
        detected: list[str] = ["WordPress 5.8"]
        append_tech_with_version(
            detected,
            "WordPress",
            "WordPress 5.8",
            regex=r"wordpress[\s/]+([\d.]+)",
        )

        assert detected.count("WordPress 5.8") == 1


class TestAppendTechWithVersionDebug:
    """Tests for append_tech_with_version_debug function."""

    def test_adds_tech_and_debug_info(self) -> None:
        """Test adding technology with debug info."""
        detected: list[str] = []
        debug: dict = {}
        sources: dict = {}

        append_tech_with_version_debug(
            detected,
            debug,
            sources,
            "WordPress",
            "WordPress 5.8.1",
            regex=r"wordpress[\s/]+([\d\.]+)",
            source="meta:generator",
            matched="WordPress 5.8.1",
        )

        assert "WordPress 5.8.1" in detected
        assert "WordPress" in debug
        assert debug["WordPress"]["version"] == "5.8.1"
        assert debug["WordPress"]["source"] == "meta:generator"
        assert "meta:generator" in sources["WordPress"]

    def test_updates_sources(self) -> None:
        """Test that sources are tracked."""
        detected: list[str] = []
        debug: dict = {}
        sources: dict = {}

        append_tech_with_version_debug(
            detected,
            debug,
            sources,
            "jQuery",
            "jquery.min.js",
            source="script",
        )

        assert "jQuery" in sources
        assert "script" in sources["jQuery"]

    def test_multiple_sources(self) -> None:
        """Test adding multiple sources for same tech."""
        detected: list[str] = []
        debug: dict = {}
        sources: dict = {"jQuery": {"script"}}

        append_tech_with_version_debug(
            detected,
            debug,
            sources,
            "jQuery",
            "jquery.min.js",
            source="css",
        )

        assert "script" in sources["jQuery"]
        assert "css" in sources["jQuery"]


class TestNormalizeTechnologyName:
    """Tests for normalize_technology_name function."""

    def test_lowercase(self) -> None:
        """Test converting to lowercase."""
        assert normalize_technology_name("WordPress") == "wordpress"

    def test_strips_whitespace(self) -> None:
        """Test stripping whitespace."""
        assert normalize_technology_name("  jQuery  ") == "jquery"

    def test_handles_mixed_case(self) -> None:
        """Test mixed case handling."""
        assert normalize_technology_name("AngularJS") == "angularjs"


class TestExtractVersionFromString:
    """Tests for extract_version_from_string function."""

    def test_extracts_v_prefix_version(self) -> None:
        """Test extracting version with v prefix."""
        version = extract_version_from_string("v1.2.3")
        assert version == "1.2.3"

    def test_extracts_version_keyword(self) -> None:
        """Test extracting version with 'version' keyword."""
        version = extract_version_from_string("version 2.0.0")
        assert version == "2.0.0"

    def test_extracts_tech_specific_version(self) -> None:
        """Test extracting version with tech name."""
        version = extract_version_from_string("jQuery/3.6.0", tech_name="jQuery")
        assert version == "3.6.0"

    def test_extracts_from_path(self) -> None:
        """Test extracting version from path."""
        version = extract_version_from_string("/libs/1.0.0/file.js")
        assert version == "1.0.0"

    def test_extracts_from_at_symbol(self) -> None:
        """Test extracting version with @ symbol."""
        version = extract_version_from_string("package@2.3.4")
        assert version == "2.3.4"

    def test_returns_none_no_version(self) -> None:
        """Test returning None when no version found."""
        version = extract_version_from_string("no version here")
        assert version is None

"""Unit tests for signature loader."""

from __future__ import annotations

from pathlib import Path

import pytest

from ciberwebscan.core.analyzers.fingerprint.signature_loader import (
    clear_signatures_cache,
    get_default_signatures_path,
    load_technology_signatures,
)


class TestGetDefaultSignaturesPath:
    """Tests for get_default_signatures_path function."""

    def test_returns_path_object(self) -> None:
        """Test that function returns Path object."""
        path = get_default_signatures_path()
        assert isinstance(path, Path)

    def test_path_ends_with_json(self) -> None:
        """Test that path ends with .json extension."""
        path = get_default_signatures_path()
        assert path.suffix == ".json"

    def test_path_contains_signatures(self) -> None:
        """Test that path contains 'signatures' in name."""
        path = get_default_signatures_path()
        assert "signature" in path.name.lower()


class TestLoadTechnologySignatures:
    """Tests for load_technology_signatures function."""

    def setup_method(self) -> None:
        """Clear cache before each test."""
        clear_signatures_cache()

    def teardown_method(self) -> None:
        """Clear cache after each test."""
        clear_signatures_cache()

    def test_load_with_custom_path(self, tmp_path: Path) -> None:
        """Test loading signatures from custom path."""
        sig_file = tmp_path / "sigs.json"
        sig_content = """
        {
            "cms_signatures": {"TestCMS": {"pattern": "test"}},
            "framework_signatures": {},
            "server_signatures": {},
            "js_library_signatures": {}
        }
        """
        sig_file.write_text(sig_content)

        result = load_technology_signatures(sig_file)

        assert "cms_signatures" in result
        assert "TestCMS" in result["cms_signatures"]

    def test_caching_behavior(self, tmp_path: Path) -> None:
        """Test that signatures are cached."""
        sig_file = tmp_path / "sigs.json"
        sig_content = """
        {
            "cms_signatures": {},
            "framework_signatures": {},
            "server_signatures": {},
            "js_library_signatures": {}
        }
        """
        sig_file.write_text(sig_content)

        # First load
        result1 = load_technology_signatures(sig_file, use_cache=True)
        # Second load should use cache
        result2 = load_technology_signatures(sig_file, use_cache=True)

        # Should be same object if cached
        assert result1 is result2

    def test_raises_on_missing_file(self) -> None:
        """Test raises RuntimeError when file doesn't exist."""
        fake_path = Path("/nonexistent/path/sigs.json")

        with pytest.raises(RuntimeError, match="not found"):
            load_technology_signatures(fake_path, use_cache=False)

    def test_raises_on_invalid_json(self, tmp_path: Path) -> None:
        """Test raises RuntimeError on invalid JSON."""
        sig_file = tmp_path / "bad.json"
        sig_file.write_text("{ invalid json }")

        with pytest.raises(RuntimeError, match="Invalid JSON"):
            load_technology_signatures(sig_file, use_cache=False)

    def test_bypass_cache(self, tmp_path: Path) -> None:
        """Test bypassing cache with use_cache=False."""
        sig_file = tmp_path / "sigs.json"
        sig_content = """
        {
            "cms_signatures": {"CMS1": {}},
            "framework_signatures": {},
            "server_signatures": {},
            "js_library_signatures": {}
        }
        """
        sig_file.write_text(sig_content)

        # Load and cache
        result1 = load_technology_signatures(sig_file, use_cache=True)
        assert "CMS1" in result1["cms_signatures"]

        # Modify file
        new_content = """
        {
            "cms_signatures": {"CMS2": {}},
            "framework_signatures": {},
            "server_signatures": {},
            "js_library_signatures": {}
        }
        """
        sig_file.write_text(new_content)

        # With cache=True, should return cached data
        result2 = load_technology_signatures(sig_file, use_cache=True)
        assert "CMS1" in result2["cms_signatures"]

        # With cache=False, should reload from file
        clear_signatures_cache()
        result3 = load_technology_signatures(sig_file, use_cache=False)
        assert "CMS2" in result3["cms_signatures"]


class TestClearSignaturesCache:
    """Tests for clear_signatures_cache function."""

    def test_clear_removes_cached_data(self, tmp_path: Path) -> None:
        """Test that clear removes cached signatures."""
        sig_file = tmp_path / "sigs.json"
        sig_content = """
        {
            "cms_signatures": {"CMS1": {}},
            "framework_signatures": {},
            "server_signatures": {},
            "js_library_signatures": {}
        }
        """
        sig_file.write_text(sig_content)

        # Load to cache
        result1 = load_technology_signatures(sig_file)
        assert "CMS1" in result1["cms_signatures"]

        # Clear cache
        clear_signatures_cache()

        # Modify file
        new_content = """
        {
            "cms_signatures": {"CMS1": {}, "CMS2": {}},
            "framework_signatures": {},
            "server_signatures": {},
            "js_library_signatures": {}
        }
        """
        sig_file.write_text(new_content)

        # Reload should get new data
        result2 = load_technology_signatures(sig_file)
        assert "CMS2" in result2["cms_signatures"]

    def test_clear_does_not_raise(self) -> None:
        """Test that clear doesn't raise on empty cache."""
        # Should not raise even if cache is empty
        clear_signatures_cache()
        clear_signatures_cache()

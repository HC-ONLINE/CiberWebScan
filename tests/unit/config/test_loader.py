"""
Tests for ConfigLoader environment variable mapping.

Covers schema-guided env var resolution, the double-underscore convention,
and legacy underscore-to-dot compatibility.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ciberwebscan.config.loader import ConfigLoader


@pytest.fixture
def loader(tmp_path: Path) -> ConfigLoader:
    """Create a loader backed by an empty config file (defaults + env only)."""
    config_path = tmp_path / "config.yaml"
    config_path.write_text("", encoding="utf-8")
    return ConfigLoader(config_path=config_path)


def _set(monkeypatch: pytest.MonkeyPatch, name: str, value: str) -> None:
    """Set a CIBERWEBSCAN_ env var for the duration of a test."""
    monkeypatch.setenv(name, value)


# =============================================================================
# Legacy compatibility (single underscores as separators)
# =============================================================================


class TestLegacyMapping:
    """Previously documented env vars must keep working."""

    def test_http_timeout_connect(self, loader, monkeypatch):
        _set(monkeypatch, "CIBERWEBSCAN_HTTP_TIMEOUT_CONNECT", "15")
        assert loader.config.http.timeout.connect == 15

    def test_scraping_dynamic_headless(self, loader, monkeypatch):
        _set(monkeypatch, "CIBERWEBSCAN_SCRAPING_DYNAMIC_HEADLESS", "false")
        assert loader.config.scraping.dynamic.headless is False

    def test_attack_xss(self, loader, monkeypatch):
        _set(monkeypatch, "CIBERWEBSCAN_ATTACK_XSS", "false")
        assert loader.config.attack.xss is False

    def test_logging_level(self, loader, monkeypatch):
        _set(monkeypatch, "CIBERWEBSCAN_LOGGING_LEVEL", "DEBUG")
        assert loader.config.logging.level == "DEBUG"

    def test_boolean_value_parsing(self, loader, monkeypatch):
        _set(monkeypatch, "CIBERWEBSCAN_HTTP_FOLLOW_REDIRECTS", "no")
        assert loader.config.http.follow_redirects is False


# =============================================================================
# Schema-guided mapping (fields containing underscores)
# =============================================================================


class TestUnderscoreFieldMapping:
    """Fields whose names contain underscores must be overridable via env."""

    def test_attack_command_injection(self, loader, monkeypatch):
        _set(monkeypatch, "CIBERWEBSCAN_ATTACK_COMMAND_INJECTION", "false")
        assert loader.config.attack.command_injection is False

    def test_attack_user_consent(self, loader, monkeypatch):
        _set(monkeypatch, "CIBERWEBSCAN_ATTACK_USER_CONSENT", "true")
        assert loader.config.attack.user_consent is True

    def test_retry_max_attempts(self, loader, monkeypatch):
        _set(monkeypatch, "CIBERWEBSCAN_HTTP_RETRY_MAX_ATTEMPTS", "1")
        assert loader.config.http.retry.max_attempts == 1

    def test_retryable_status_codes_list(self, loader, monkeypatch):
        _set(monkeypatch, "CIBERWEBSCAN_HTTP_RETRY_RETRYABLE_STATUS_CODES", "429,500")
        assert loader.config.http.retry.retryable_status_codes == [429, 500]

    def test_rate_limit_adaptive(self, loader, monkeypatch):
        _set(monkeypatch, "CIBERWEBSCAN_HTTP_RATE_LIMIT_ADAPTIVE", "false")
        assert loader.config.http.rate_limit.adaptive is False

    def test_requests_per_second_float(self, loader, monkeypatch):
        _set(monkeypatch, "CIBERWEBSCAN_HTTP_RATE_LIMIT_REQUESTS_PER_SECOND", "2.5")
        assert loader.config.http.rate_limit.requests_per_second == 2.5

    def test_user_agent_mode(self, loader, monkeypatch):
        _set(monkeypatch, "CIBERWEBSCAN_USER_AGENT_MODE", "static")
        assert loader.config.user_agent.mode == "static"

    def test_user_agent_agents_list(self, loader, monkeypatch):
        _set(monkeypatch, "CIBERWEBSCAN_USER_AGENT_AGENTS", "ua1,ua2")
        assert loader.config.user_agent.agents == ["ua1", "ua2"]

    def test_cve_nvd_api_key(self, loader, monkeypatch):
        _set(monkeypatch, "CIBERWEBSCAN_ANALYSIS_CVE_NVD_API_KEY", "abc123")
        assert loader.config.analysis.cve.nvd_api_key == "abc123"

    def test_export_include_screenshots(self, loader, monkeypatch):
        _set(monkeypatch, "CIBERWEBSCAN_EXPORT_INCLUDE_SCREENSHOTS", "true")
        assert loader.config.export.include_screenshots is True

    def test_cache_max_size_mb(self, loader, monkeypatch):
        _set(monkeypatch, "CIBERWEBSCAN_CACHE_MAX_SIZE_MB", "50")
        assert loader.config.cache.max_size_mb == 50

    def test_api_rate_limit_requests_per_minute(self, loader, monkeypatch):
        _set(monkeypatch, "CIBERWEBSCAN_API_RATE_LIMIT_REQUESTS_PER_MINUTE", "120")
        assert loader.config.api.rate_limit.requests_per_minute == 120


# =============================================================================
# Double-underscore convention
# =============================================================================


class TestDoubleUnderscoreConvention:
    """Explicit ``__`` separators must map to section boundaries."""

    def test_http_rate_limit_requests_per_second(self, loader, monkeypatch):
        _set(monkeypatch, "CIBERWEBSCAN_HTTP__RATE_LIMIT__REQUESTS_PER_SECOND", "2.5")
        assert loader.config.http.rate_limit.requests_per_second == 2.5

    def test_attack_command_injection(self, loader, monkeypatch):
        _set(monkeypatch, "CIBERWEBSCAN_ATTACK__COMMAND_INJECTION", "false")
        assert loader.config.attack.command_injection is False

    def test_http_retry_max_attempts(self, loader, monkeypatch):
        _set(monkeypatch, "CIBERWEBSCAN_HTTP__RETRY__MAX_ATTEMPTS", "1")
        assert loader.config.http.retry.max_attempts == 1


# =============================================================================
# Robustness
# =============================================================================


class TestUnmappableEnvVars:
    """Env vars that cannot be mapped must be ignored, not break loading."""

    def test_unknown_key_is_ignored(self, loader, monkeypatch):
        _set(monkeypatch, "CIBERWEBSCAN_BOGUS_FIELD_X", "1")
        assert loader.config is not None
        assert loader.config.http.timeout.connect == 10.0

    def test_unknown_key_is_logged(self, loader, monkeypatch, caplog):
        import logging

        _set(monkeypatch, "CIBERWEBSCAN_BOGUS_FIELD_X", "1")
        with caplog.at_level(logging.DEBUG, logger="ciberwebscan.config.loader"):
            _ = loader.config
        messages = [r.message for r in caplog.records]
        assert any("BOGUS_FIELD_X" in m and "does not map" in m for m in messages)

    def test_section_key_is_logged(self, loader, monkeypatch, caplog):
        import logging

        _set(monkeypatch, "CIBERWEBSCAN_HTTP", "nonsense")
        with caplog.at_level(logging.DEBUG, logger="ciberwebscan.config.loader"):
            _ = loader.config
        messages = [r.message for r in caplog.records]
        assert any("HTTP" in m and "does not map" in m for m in messages)

    def test_nested_section_key_is_ignored(self, loader, monkeypatch, caplog):
        """A whole nested section (e.g. http.proxy) cannot be set via env."""
        import logging

        _set(monkeypatch, "CIBERWEBSCAN_HTTP_PROXY", "http://proxy:8080")
        with caplog.at_level(logging.DEBUG, logger="ciberwebscan.config.loader"):
            _ = loader.config
        messages = [r.message for r in caplog.records]
        assert any("HTTP_PROXY" in m and "does not map" in m for m in messages)
        assert loader.config.http.proxy is None

    def test_invalid_value_logs_error(self, loader, monkeypatch, caplog):
        """A mapped key with an invalid value logs the validation error."""
        import logging

        _set(monkeypatch, "CIBERWEBSCAN_HTTP_TIMEOUT_CONNECT", "not-a-number")
        with caplog.at_level(logging.ERROR, logger="ciberwebscan.config.loader"):
            config = loader.config
        messages = [r.message for r in caplog.records]
        assert any("Invalid configuration" in m for m in messages)
        assert any("default configuration" in m for m in messages)
        assert config is not None

    def test_case_insensitive(self, loader, monkeypatch):
        _set(monkeypatch, "CIBERWEBSCAN_Attack_Command_Injection", "false")
        assert loader.config.attack.command_injection is False

    def test_empty_value(self, loader, monkeypatch):
        _set(monkeypatch, "CIBERWEBSCAN_ATTACK_COMMAND_INJECTION", "")
        assert loader.config is not None

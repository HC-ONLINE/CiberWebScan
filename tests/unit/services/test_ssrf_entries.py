"""SSRF entry-validation tests for the service layer (BUG-004).

``analyze`` and ``scrape`` previously performed no SSRF validation on the
target URL at all. These tests pin the new behaviour: local/private/
metadata targets are rejected before any request is made, and the
``allow_local`` config opt-ins permit them.
"""

from __future__ import annotations

import pytest

from ciberwebscan.config.loader import get_config, reset_config
from ciberwebscan.config.models import AnalysisConfig, ScrapingConfig
from ciberwebscan.services.analyze_service import AnalyzeOptions, AnalyzeService
from ciberwebscan.services.attack_service import AttackOptions, AttackService
from ciberwebscan.services.base import ValidationError
from ciberwebscan.services.quick_service import QuickOptions, QuickService
from ciberwebscan.services.scrape_service import ScrapeOptions, ScrapeService

BLOCKED_URLS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://169.254.169.254/latest/meta-data/",
    "http://10.0.0.1/",
    "http://localtest.me/",  # DNS -> 127.0.0.1
]


@pytest.fixture(autouse=True)
def _lock_allow_local_false():
    """Pin every allow_local flag to False.

    ``tests/integration/api/conftest.py`` sets
    ``CIBERWEBSCAN_ATTACK_ALLOW_LOCAL=true`` in the process environment for
    the whole session, which would otherwise leak into these entry checks.
    """
    cfg = get_config()
    cfg.analysis.allow_local = False
    cfg.scraping.allow_local = False
    cfg.attack.allow_local = False
    yield


class TestAnalyzeEntrySSRF:
    """AnalyzeService validates the target before any work."""

    @pytest.mark.parametrize("url", BLOCKED_URLS)
    def test_analyze_blocks_local_targets(self, url: str) -> None:
        service = AnalyzeService()

        result = service.analyze(AnalyzeOptions(url=url))

        assert result.success is False
        assert result.error_code == "VALIDATION_ERROR"
        assert "ssrf" in (result.error or "").lower()

    @pytest.mark.parametrize("url", BLOCKED_URLS)
    def test_analyze_ssl_blocks_local_targets(self, url: str) -> None:
        service = AnalyzeService()

        result = service.analyze_ssl(url)

        assert result.success is False
        assert result.error_code == "SSL_ANALYSIS_ERROR"
        assert "ssrf" in (result.error or "").lower()

    @pytest.mark.parametrize("url", BLOCKED_URLS)
    def test_fingerprint_blocks_local_targets(self, url: str) -> None:
        service = AnalyzeService()

        result = service.fingerprint_url(url)

        assert result.success is False
        assert result.error_code == "FINGERPRINT_ERROR"
        assert "ssrf" in (result.error or "").lower()


class TestScrapeEntrySSRF:
    """ScrapeService validates the target before any work."""

    @pytest.mark.parametrize("url", BLOCKED_URLS)
    def test_scrape_blocks_local_targets(self, url: str) -> None:
        service = ScrapeService()

        result = service.scrape(ScrapeOptions(url=url, selector="body"))

        assert result.success is False
        assert result.error_code == "VALIDATION_ERROR"
        assert "ssrf" in (result.error or "").lower()

    @pytest.mark.parametrize("url", BLOCKED_URLS)
    def test_scrape_dynamic_blocks_local_targets(self, url: str) -> None:
        service = ScrapeService()

        result = service.scrape(ScrapeOptions(url=url, selector="body", dynamic=True))

        assert result.success is False
        assert result.error_code == "VALIDATION_ERROR"
        assert "ssrf" in (result.error or "").lower()


class TestQuickEntrySSRF:
    """QuickService rejects blocked targets before the preset phases."""

    @pytest.mark.parametrize("url", BLOCKED_URLS)
    def test_quick_scan_raises_for_local_targets(self, url: str) -> None:
        service = QuickService()

        with pytest.raises(ValidationError) as exc_info:
            service.quick_scan(QuickOptions(url=url, preset="low"))

        assert "ssrf" in str(exc_info.value).lower()


class TestAttackHint:
    """Attack keeps its policy hint in the error message."""

    def test_attack_error_mentions_allow_local(self) -> None:
        service = AttackService()
        service.app_config.attack.enabled = True
        service.app_config.attack.whitelist = []
        service.app_config.attack.allow_local = False

        with pytest.raises(ValidationError) as exc_info:
            service.attack(
                AttackOptions(
                    url="http://127.0.0.1/",
                    user_consent=True,
                    xss=True,
                )
            )

        message = str(exc_info.value)
        assert "ssrf" in message.lower()
        assert "attack.allow_local" in message


class TestAllowLocalConfigOptIns:
    """New analysis.allow_local / scraping.allow_local flags."""

    def test_defaults_are_false(self) -> None:
        assert AnalysisConfig().allow_local is False
        assert ScrapingConfig().allow_local is False

    def test_env_overrides_analysis_allow_local(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CIBERWEBSCAN_ANALYSIS_ALLOW_LOCAL", "true")
        reset_config()
        assert get_config().analysis.allow_local is True

    def test_env_overrides_scraping_allow_local(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CIBERWEBSCAN_SCRAPING_ALLOW_LOCAL", "yes")
        reset_config()
        assert get_config().scraping.allow_local is True

    def test_check_target_url_opt_in(self) -> None:
        service = AnalyzeService()

        with pytest.raises(ValidationError):
            service._check_target_url("http://169.254.169.254/")

        assert (
            service._check_target_url("http://169.254.169.254/", allow_local=True)
            == "http://169.254.169.254/"
        )

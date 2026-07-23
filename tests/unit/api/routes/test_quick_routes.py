"""
Unit tests for the quick scan API endpoints.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from ciberwebscan.api.app import create_app
from ciberwebscan.export.models import AnalysisReport, ExportMeta

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def client():
    """Create a test client with auth dependency overridden."""
    from ciberwebscan.api.auth import AuthenticatedUser, get_current_user

    app = create_app()

    def mock_get_current_user() -> AuthenticatedUser:
        return AuthenticatedUser(
            identifier="test-user",
            auth_method="api_key",
            scopes=["read", "write"],
        )

    app.dependency_overrides[get_current_user] = mock_get_current_user
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def mock_analysis_report() -> AnalysisReport:
    """Minimal valid AnalysisReport for serialization."""
    return AnalysisReport(meta=ExportMeta(target_url="https://example.com"))


def _make_service_result(data=None, success: bool = True, error: str | None = None):
    """Build a mock ServiceResult."""
    result = MagicMock()
    result.success = success
    result.data = data
    result.error = error
    result.error_code = None if success else "QUICK_SCAN_ERROR"
    result.duration_seconds = 1.5
    result.warnings = []
    return result


# =============================================================================
# POST /api/quick/scan Tests
# =============================================================================


class TestQuickScanEndpointSuccess:
    """Tests for successful quick scan endpoint calls."""

    def test_post_quick_scan_low_returns_200(self, client, mock_analysis_report):
        """POST /api/quick/scan with low preset returns 200."""
        with patch("ciberwebscan.api.routes.quick.QuickService") as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service
            mock_service.quick_scan.return_value = _make_service_result(
                data=mock_analysis_report
            )

            response = client.post(
                "/api/quick/scan",
                json={"url": "https://example.com", "preset": "low"},
            )

        assert response.status_code == 200
        body = response.json()
        assert body["success"] is True
        assert body["preset"] == "low"
        assert body["duration_seconds"] == 1.5

    def test_post_quick_scan_medium_with_consent(self, client, mock_analysis_report):
        """POST /api/quick/scan with medium preset and consent returns 200."""
        with patch("ciberwebscan.api.routes.quick.QuickService") as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service
            mock_service.quick_scan.return_value = _make_service_result(
                data=mock_analysis_report
            )

            response = client.post(
                "/api/quick/scan",
                json={
                    "url": "https://example.com",
                    "preset": "medium",
                    "user_consent": True,
                },
            )

        assert response.status_code == 200
        body = response.json()
        assert body["preset"] == "medium"

    def test_post_quick_scan_high_with_consent(self, client, mock_analysis_report):
        """POST /api/quick/scan with high preset and consent returns 200."""
        with patch("ciberwebscan.api.routes.quick.QuickService") as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service
            mock_service.quick_scan.return_value = _make_service_result(
                data=mock_analysis_report
            )

            response = client.post(
                "/api/quick/scan",
                json={
                    "url": "https://example.com",
                    "preset": "high",
                    "user_consent": True,
                },
            )

        assert response.status_code == 200
        assert response.json()["preset"] == "high"

    def test_post_quick_scan_forwards_options(self, client, mock_analysis_report):
        """Quick scan forwards options to QuickService."""
        with patch("ciberwebscan.api.routes.quick.QuickService") as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service
            mock_service.quick_scan.return_value = _make_service_result(
                data=mock_analysis_report
            )

            response = client.post(
                "/api/quick/scan",
                json={
                    "url": "https://example.com",
                    "preset": "low",
                    "timeout": 60.0,
                    "selector": ".content",
                    "headers": {"X-Test": "1"},
                },
            )

        assert response.status_code == 200
        options = mock_service.quick_scan.call_args[0][0]
        assert options.timeout == 60.0
        assert options.selector == ".content"
        assert options.headers == {"X-Test": "1"}


# =============================================================================
# POST /api/quick/scan Validation Tests
# =============================================================================


class TestQuickScanEndpointValidation:
    """Tests for request validation on the quick scan endpoint."""

    def test_missing_url_returns_422(self, client):
        """Missing url field returns 422."""
        response = client.post("/api/quick/scan", json={"preset": "low"})
        assert response.status_code == 422

    def test_medium_without_consent_returns_400(self, client):
        """Medium preset without consent returns 400."""
        response = client.post(
            "/api/quick/scan",
            json={
                "url": "https://example.com",
                "preset": "medium",
                "user_consent": False,
            },
        )
        assert response.status_code == 400
        body = response.json()
        assert body["detail"]["error_code"] == "CONSENT_REQUIRED"

    def test_high_without_consent_returns_400(self, client):
        """High preset without consent returns 400."""
        response = client.post(
            "/api/quick/scan",
            json={
                "url": "https://example.com",
                "preset": "high",
                "user_consent": False,
            },
        )
        assert response.status_code == 400
        assert "consent" in response.json()["detail"]["error"].lower()


# =============================================================================
# POST /api/quick/scan Error Handling Tests
# =============================================================================


class TestQuickScanEndpointErrors:
    """Tests for error handling in the quick scan endpoint."""

    def test_service_failure_returns_500(self, client):
        """When service returns success=False, endpoint returns 500."""
        with patch("ciberwebscan.api.routes.quick.QuickService") as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service
            mock_service.quick_scan.return_value = _make_service_result(
                success=False, error="Quick scan failed"
            )

            response = client.post(
                "/api/quick/scan",
                json={"url": "https://example.com", "preset": "low"},
            )

        assert response.status_code == 500
        assert "Quick scan failed" in response.json()["detail"]["error"]

    def test_unexpected_exception_returns_500(self, client):
        """Unhandled exceptions return HTTP 500."""
        with patch("ciberwebscan.api.routes.quick.QuickService") as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service
            mock_service.quick_scan.side_effect = RuntimeError("Something went wrong")

            response = client.post(
                "/api/quick/scan",
                json={"url": "https://example.com", "preset": "low"},
            )

        assert response.status_code == 500
        assert "Something went wrong" in response.json()["detail"]["error"]

    def test_response_shape(self, client, mock_analysis_report):
        """Response always contains required fields."""
        with patch("ciberwebscan.api.routes.quick.QuickService") as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service
            mock_service.quick_scan.return_value = _make_service_result(
                data=mock_analysis_report
            )

            response = client.post(
                "/api/quick/scan",
                json={"url": "https://example.com", "preset": "low"},
            )

        assert response.status_code == 200
        body = response.json()
        assert "success" in body
        assert "data" in body
        assert "preset" in body
        assert "duration_seconds" in body
        assert "warnings" in body


# =============================================================================
# GET /api/quick/presets Tests
# =============================================================================


class TestQuickPresetsEndpoint:
    """Tests for GET /api/quick/presets."""

    def test_get_presets_returns_200(self, client):
        """GET /api/quick/presets returns 200."""
        response = client.get("/api/quick/presets")

        assert response.status_code == 200

    def test_get_presets_contains_all_levels(self, client):
        """Response contains all three preset levels."""
        response = client.get("/api/quick/presets")
        body = response.json()

        assert "presets" in body
        assert "low" in body["presets"]
        assert "medium" in body["presets"]
        assert "high" in body["presets"]

    def test_get_presets_low_has_no_attacks(self, client):
        """Low preset reports no attacks."""
        response = client.get("/api/quick/presets")
        body = response.json()

        low = body["presets"]["low"]
        assert low["has_attacks"] is False
        assert low["attack_types"] == []

    def test_get_presets_medium_has_xss_sqli(self, client):
        """Medium preset reports XSS and SQLi attacks."""
        response = client.get("/api/quick/presets")
        body = response.json()

        medium = body["presets"]["medium"]
        assert medium["has_attacks"] is True
        assert "xss" in medium["attack_types"]
        assert "sqli" in medium["attack_types"]
        assert medium["intensity"] == "medium"

    def test_get_presets_high_has_all_attacks(self, client):
        """High preset reports all attack types."""
        response = client.get("/api/quick/presets")
        body = response.json()

        high = body["presets"]["high"]
        assert high["has_attacks"] is True
        assert "xss" in high["attack_types"]
        assert "sqli" in high["attack_types"]
        assert "traversal" in high["attack_types"]
        assert "enumeration" in high["attack_types"]
        assert high["intensity"] == "high"

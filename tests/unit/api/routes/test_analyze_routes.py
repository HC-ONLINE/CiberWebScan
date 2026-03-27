"""
Unit tests for the analysis API endpoint (POST /api/analyze).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from ciberwebscan.api.app import create_app
from ciberwebscan.export.models import AnalysisReport, ExportMeta


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
    result = MagicMock()
    result.success = success
    result.data = data
    result.error = error
    return result


class TestAnalyzeEndpoint:
    """Tests for POST /api/analyze."""

    def test_post_analyze_returns_200(self, client: TestClient, mock_analysis_report):
        with patch(
            "ciberwebscan.api.routes.analyze.AnalyzeService"
        ) as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service
            mock_service.analyze.return_value = _make_service_result(
                data=mock_analysis_report
            )

            response = client.post("/api/analyze", json={"url": "https://example.com"})

        assert response.status_code == 200
        body = response.json()
        assert body["success"] is True
        assert body["data"]["meta"]["target_url"] == "https://example.com"

    def test_post_analyze_forwards_options(
        self, client: TestClient, mock_analysis_report
    ):
        with patch(
            "ciberwebscan.api.routes.analyze.AnalyzeService"
        ) as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service
            mock_service.analyze.return_value = _make_service_result(
                data=mock_analysis_report
            )

            response = client.post(
                "/api/analyze",
                json={
                    "url": "https://example.com",
                    "ssl": False,
                    "cve_sources": ["nvd", "circl"],
                    "headers": {"X-Test": "1"},
                },
            )

        assert response.status_code == 200
        options = mock_service.analyze.call_args[0][0]
        assert options.ssl is False
        assert options.cve_sources == ["nvd", "circl"]
        assert options.headers == {"X-Test": "1"}

    def test_post_analyze_missing_url_returns_422(self, client: TestClient):
        response = client.post("/api/analyze", json={"ssl": True})
        assert response.status_code == 422

    def test_post_analyze_service_failure_returns_500(self, client: TestClient):
        with patch(
            "ciberwebscan.api.routes.analyze.AnalyzeService"
        ) as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service
            mock_service.analyze.return_value = _make_service_result(
                success=False,
                error="Analysis failed in service",
            )

            response = client.post("/api/analyze", json={"url": "https://example.com"})

        assert response.status_code == 500
        assert "Analysis failed in service" in response.json()["detail"]

    def test_post_analyze_unexpected_exception_returns_500(self, client: TestClient):
        with patch(
            "ciberwebscan.api.routes.analyze.AnalyzeService"
        ) as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service
            mock_service.analyze.side_effect = RuntimeError("boom")

            response = client.post("/api/analyze", json={"url": "https://example.com"})

        assert response.status_code == 500
        assert "boom" in response.json()["detail"]

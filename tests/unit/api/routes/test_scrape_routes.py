"""
Unit tests for scraping API endpoints.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from ciberwebscan.api.app import create_app
from ciberwebscan.export.models import ScrapeResult


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
def mock_scrape_result() -> ScrapeResult:
    """Minimal valid ScrapeResult."""
    return ScrapeResult(
        url="https://example.com/",
        status_code=200,
        content_type="text/html",
        title="Example",
        text_content="ok",
    )


def _make_service_result(data=None, success: bool = True, error: str | None = None):
    result = MagicMock()
    result.success = success
    result.data = data
    result.error = error
    result.duration_seconds = 1.2
    return result


class TestScrapeEndpoint:
    """Tests for POST /api/scrape."""

    def test_post_scrape_returns_200(self, client: TestClient, mock_scrape_result):
        with patch("ciberwebscan.api.routes.scrape.ScrapeService") as mock_service_cls:
            mock_service = MagicMock()
            mock_service_cls.return_value = mock_service
            mock_service.scrape.return_value = _make_service_result(
                data=mock_scrape_result
            )

            response = client.post("/api/scrape", json={"url": "https://example.com"})

        assert response.status_code == 200
        body = response.json()
        assert body["success"] is True
        assert body["data"]["url"] == "https://example.com/"

    def test_post_scrape_service_failure_returns_500(self, client: TestClient):
        with patch("ciberwebscan.api.routes.scrape.ScrapeService") as mock_service_cls:
            mock_service = MagicMock()
            mock_service_cls.return_value = mock_service
            mock_service.scrape.return_value = _make_service_result(
                success=False,
                error="scrape failed",
            )

            response = client.post("/api/scrape", json={"url": "https://example.com"})

        assert response.status_code == 500
        assert "scrape failed" in response.json()["detail"]

    def test_post_scrape_none_data_returns_500(self, client: TestClient):
        with patch("ciberwebscan.api.routes.scrape.ScrapeService") as mock_service_cls:
            mock_service = MagicMock()
            mock_service_cls.return_value = mock_service
            mock_service.scrape.return_value = _make_service_result(data=None)

            response = client.post("/api/scrape", json={"url": "https://example.com"})

        assert response.status_code == 500
        assert "returned no data" in response.json()["detail"]


class TestScrapeBatchEndpoint:
    """Tests for POST /api/scrape/batch."""

    def test_post_scrape_batch_returns_200(
        self,
        client: TestClient,
        mock_scrape_result: ScrapeResult,
    ):
        second_result = ScrapeResult(
            url="https://example.org/",
            status_code=200,
            content_type="text/html",
            title="Example Org",
            text_content="ok",
        )

        with patch("ciberwebscan.api.routes.scrape.ScrapeService") as mock_service_cls:
            mock_service = MagicMock()
            mock_service_cls.return_value = mock_service
            mock_service.scrape_multiple.return_value = _make_service_result(
                data=[mock_scrape_result, second_result]
            )

            response = client.post(
                "/api/scrape/batch",
                json={
                    "urls": [
                        "https://example.com",
                        "https://example.org",
                        "https://example.net",
                    ]
                },
            )

        assert response.status_code == 200
        body = response.json()
        assert body["success"] is True
        assert body["total_success"] == 2
        assert body["total_failed"] == 1
        assert body["failed_urls"][0]["url"] == "https://example.net/"

    def test_post_scrape_batch_service_failure_returns_500(self, client: TestClient):
        with patch("ciberwebscan.api.routes.scrape.ScrapeService") as mock_service_cls:
            mock_service = MagicMock()
            mock_service_cls.return_value = mock_service
            mock_service.scrape_multiple.return_value = _make_service_result(
                success=False,
                error="batch failed",
            )

            response = client.post(
                "/api/scrape/batch",
                json={"urls": ["https://example.com"]},
            )

        assert response.status_code == 500
        assert "batch failed" in response.json()["detail"]

    def test_post_scrape_batch_empty_urls_returns_422(self, client: TestClient):
        response = client.post("/api/scrape/batch", json={"urls": []})
        assert response.status_code == 422

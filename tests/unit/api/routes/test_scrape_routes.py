"""
Unit tests for scraping API endpoints.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest
from fastapi.testclient import TestClient

from ciberwebscan.api.app import create_app
from ciberwebscan.config.models import AppConfig
from ciberwebscan.export.models import ScrapeResult

pytestmark = pytest.mark.unit


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
        assert body["data"]["total_success"] == 2
        assert body["data"]["total_failed"] == 1
        assert body["data"]["failed_urls"][0]["url"] == "https://example.net/"

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

    def test_post_scrape_batch_export_no_token_when_downloads_disabled(
        self,
        client: TestClient,
        mock_scrape_result: ScrapeResult,
        tmp_path: Path,
    ):
        """BUG-011: batch exports never mint tokens while downloads are off.

        The batch route bypasses enrich_response_with_token, so the gate must
        live in the service: the response stays 200 with download_token=None
        and the export file itself is untouched.
        """
        export_file = tmp_path / "batch_export.json"
        export_file.write_text('{"batch": true}')

        config = AppConfig()
        config.download.enabled = False
        config.export.output_dir = str(tmp_path)

        with (
            patch("ciberwebscan.api.routes.scrape.ScrapeService") as mock_service_cls,
            patch(
                "ciberwebscan.services.download_service.get_config",
                return_value=config,
            ),
        ):
            mock_service = MagicMock()
            mock_service_cls.return_value = mock_service
            scrape_result = _make_service_result(data=[mock_scrape_result])
            scrape_result.export_path = export_file
            mock_service.scrape_multiple.return_value = scrape_result

            response = client.post(
                "/api/scrape/batch",
                json={"urls": ["https://example.com"]},
            )

        assert response.status_code == 200
        body = response.json()
        assert body["success"] is True
        assert body["download_token"] is None
        assert body["download_url"] is None
        assert export_file.exists()


def _mock_http_response(
    status: int, text: str = "<html><body>ok</body></html>"
) -> Mock:
    """Build a minimal HTTP response stub for the real StaticScraper."""
    response = Mock()
    response.status_code = status
    response.headers = {"content-type": "text/html"}
    response.text = text
    response.cookies.items.return_value = {}
    return response


class TestScrapeFailurePropagation:
    """Real scrape failures must surface as HTTP 500, never HTTP 200.

    These tests run the real ``ScrapeService`` (only the HTTP client is
    mocked) to regression-test BUG-005 end to end through the API layer.
    """

    def test_real_scrape_failure_returns_500_with_clean_detail(
        self, client: TestClient
    ):
        with patch("ciberwebscan.core.client.HTTPClient") as mock_http_cls:
            mock_http_cls.return_value.get.return_value = _mock_http_response(
                404, "<html>Not Found</html>"
            )
            response = client.post(
                "/api/scrape",
                json={
                    "url": "https://example.com/missing",
                    "check_robots": False,
                },
            )

        assert response.status_code == 500
        detail = response.json()["detail"]
        assert "404" in detail
        assert "Scraping failed: 500" not in detail

    def test_real_batch_mixed_returns_partial_success(self, client: TestClient):
        ok_response = _mock_http_response(200)
        missing_response = _mock_http_response(404, "<html>Not Found</html>")
        with patch("ciberwebscan.core.client.HTTPClient") as mock_http_cls:
            mock_http_cls.return_value.get.side_effect = lambda url, **kwargs: (
                ok_response if url.endswith("/ok") else missing_response
            )
            response = client.post(
                "/api/scrape/batch",
                json={
                    "urls": [
                        "https://example.com/ok",
                        "https://example.com/missing",
                    ]
                },
            )

        assert response.status_code == 200
        body = response.json()
        assert body["success"] is True
        assert body["data"]["total_success"] == 1
        assert body["data"]["total_failed"] == 1
        assert body["data"]["failed_urls"][0]["url"] == "https://example.com/missing"

    def test_real_batch_all_failures_returns_500(self, client: TestClient):
        with patch("ciberwebscan.core.client.HTTPClient") as mock_http_cls:
            mock_http_cls.return_value.get.return_value = _mock_http_response(
                404, "<html>Not Found</html>"
            )
            response = client.post(
                "/api/scrape/batch",
                json={
                    "urls": [
                        "https://example.com/a",
                        "https://example.com/b",
                    ]
                },
            )

        assert response.status_code == 500
        detail = response.json()["detail"]
        assert "404" in detail
        assert "Batch scraping failed: 500" not in detail


class TestScrapeResponseContentPolicy:
    """``raw_html`` must not leak in HTTP responses unless allowed.

    ``export.include_raw_html`` (default false) already governed exported
    files; the response payload carried the raw body anyway.
    These tests run the real ``ScrapeService`` (only the HTTP client is
    mocked) to regression-test the fix end to end through the API layer.
    """

    MARKER_HTML = (
        "<html><head><title>t</title></head><body><p>FAKE_MARKER_HTML</p></body></html>"
    )

    def test_scrape_response_strips_raw_html_by_default(self, client: TestClient):
        with patch("ciberwebscan.core.client.HTTPClient") as mock_http_cls:
            mock_http_cls.return_value.get.return_value = _mock_http_response(
                200, self.MARKER_HTML
            )
            response = client.post(
                "/api/scrape",
                json={"url": "https://example.com", "check_robots": False},
            )

        assert response.status_code == 200
        data = response.json()["data"]
        assert data["raw_html"] is None

    def test_scrape_response_keeps_raw_html_when_policy_enabled(
        self, client: TestClient
    ):
        cfg = AppConfig()
        cfg.export.include_raw_html = True
        with (
            patch("ciberwebscan.core.client.HTTPClient") as mock_http_cls,
            patch(
                "ciberwebscan.services.scrape_service.get_config",
                return_value=cfg,
            ),
        ):
            mock_http_cls.return_value.get.return_value = _mock_http_response(
                200, self.MARKER_HTML
            )
            response = client.post(
                "/api/scrape",
                json={"url": "https://example.com", "check_robots": False},
            )

        assert response.status_code == 200
        data = response.json()["data"]
        assert data["raw_html"] == self.MARKER_HTML

    def test_batch_response_strips_raw_html_per_item(self, client: TestClient):
        with patch("ciberwebscan.core.client.HTTPClient") as mock_http_cls:
            mock_http_cls.return_value.get.return_value = _mock_http_response(
                200, self.MARKER_HTML
            )
            response = client.post(
                "/api/scrape/batch",
                json={
                    "urls": ["https://example.com/a", "https://example.com/b"],
                },
            )

        assert response.status_code == 200
        results = response.json()["data"]["results"]
        assert len(results) == 2
        assert all(item["raw_html"] is None for item in results)

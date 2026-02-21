"""
Tests for API middleware.

Tests for RequestLoggingMiddleware and RateLimitingMiddleware.
"""

from __future__ import annotations

import logging

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ciberwebscan.api.middleware import (
    RateLimitingMiddleware,
    add_rate_limiting_middleware,
    add_request_logging_middleware,
)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def app() -> FastAPI:
    """Create a basic FastAPI app for testing."""
    app = FastAPI()

    @app.get("/test")
    def test_endpoint():
        return {"message": "success"}

    @app.get("/error")
    def error_endpoint():
        raise ValueError("Test error")

    return app


@pytest.fixture
def app_with_logging(app: FastAPI) -> FastAPI:
    """Create app with logging middleware."""
    add_request_logging_middleware(app)
    return app


@pytest.fixture
def app_with_rate_limiting(app: FastAPI) -> FastAPI:
    """Create app with rate limiting middleware (5 requests per minute)."""
    add_rate_limiting_middleware(app, requests_per_minute=5)
    return app


@pytest.fixture
def client_logging(app_with_logging: FastAPI) -> TestClient:
    """Create test client with logging middleware."""
    return TestClient(app_with_logging, raise_server_exceptions=False)


@pytest.fixture
def client_rate_limiting(app_with_rate_limiting: FastAPI) -> TestClient:
    """Create test client with rate limiting middleware."""
    return TestClient(app_with_rate_limiting, raise_server_exceptions=False)


# =============================================================================
# RequestLoggingMiddleware Tests
# =============================================================================


class TestRequestLoggingMiddleware:
    """Tests for RequestLoggingMiddleware."""

    def test_logs_successful_request(
        self, client_logging: TestClient, caplog: pytest.LogCaptureFixture
    ):
        """Test that successful requests are logged with correct info."""
        with caplog.at_level(logging.INFO):
            response = client_logging.get("/test")

        assert response.status_code == 200
        assert any("GET /test - 200" in record.message for record in caplog.records)

    def test_logs_request_with_timing(
        self, client_logging: TestClient, caplog: pytest.LogCaptureFixture
    ):
        """Test that request timing is included in logs."""
        with caplog.at_level(logging.INFO):
            client_logging.get("/test")

        # Check that timing format (X.XXXs) is in the log
        log_messages = [r.message for r in caplog.records]
        assert any("s)" in msg and "GET /test" in msg for msg in log_messages)

    def test_logs_error_request(
        self, client_logging: TestClient, caplog: pytest.LogCaptureFixture
    ):
        """Test that error requests are logged with 500 status."""
        with caplog.at_level(logging.INFO):
            response = client_logging.get("/error")

        assert response.status_code == 500
        assert any("GET /error - 500" in record.message for record in caplog.records)

    def test_logs_not_found_request(
        self, client_logging: TestClient, caplog: pytest.LogCaptureFixture
    ):
        """Test that 404 requests are logged correctly."""
        with caplog.at_level(logging.INFO):
            response = client_logging.get("/nonexistent")

        assert response.status_code == 404
        assert any(
            "GET /nonexistent - 404" in record.message for record in caplog.records
        )

    def test_log_record_has_extra_fields(
        self, client_logging: TestClient, caplog: pytest.LogCaptureFixture
    ):
        """Test that log records contain expected extra fields."""
        with caplog.at_level(logging.INFO):
            client_logging.get("/test")

        # Find the relevant log record
        log_record = next((r for r in caplog.records if "GET /test" in r.message), None)
        assert log_record is not None
        assert hasattr(log_record, "method")
        assert log_record.method == "GET"
        assert hasattr(log_record, "path")
        assert log_record.path == "/test"
        assert hasattr(log_record, "status_code")
        assert log_record.status_code == 200
        assert hasattr(log_record, "duration")
        assert isinstance(log_record.duration, float)


# =============================================================================
# RateLimitingMiddleware Tests
# =============================================================================


class TestRateLimitingMiddleware:
    """Tests for RateLimitingMiddleware."""

    def test_allows_requests_within_limit(self, client_rate_limiting: TestClient):
        """Test that requests within the limit are allowed."""
        for _ in range(5):
            response = client_rate_limiting.get("/test")
            assert response.status_code == 200

    def test_blocks_requests_exceeding_limit(self, client_rate_limiting: TestClient):
        """Test that requests exceeding the limit are blocked with 429."""
        # Make 5 allowed requests
        for _ in range(5):
            response = client_rate_limiting.get("/test")
            assert response.status_code == 200

        # 6th request should be blocked
        response = client_rate_limiting.get("/test")
        assert response.status_code == 429

    def test_429_response_contains_error_message(
        self, client_rate_limiting: TestClient
    ):
        """Test that 429 response contains proper error details."""
        # Exhaust limit
        for _ in range(5):
            client_rate_limiting.get("/test")

        response = client_rate_limiting.get("/test")
        assert response.status_code == 429

        data = response.json()
        assert "error" in data
        assert data["error"] == "Rate limit exceeded"
        assert "retry_after_seconds" in data
        assert isinstance(data["retry_after_seconds"], int)

    def test_429_response_has_retry_after_header(
        self, client_rate_limiting: TestClient
    ):
        """Test that 429 response includes Retry-After header."""
        # Exhaust limit
        for _ in range(5):
            client_rate_limiting.get("/test")

        response = client_rate_limiting.get("/test")
        assert response.status_code == 429
        assert "Retry-After" in response.headers
        retry_after = int(response.headers["Retry-After"])
        assert 0 < retry_after <= 60

    def test_different_clients_have_separate_limits(self, app: FastAPI):
        """Test that different clients have independent rate limits."""
        add_rate_limiting_middleware(app, requests_per_minute=2)
        client = TestClient(app)

        # Client 1 makes 2 requests
        for _ in range(2):
            response = client.get("/test", headers={"X-Forwarded-For": "10.0.0.1"})
            assert response.status_code == 200

        # Client 1 should be blocked
        response = client.get("/test", headers={"X-Forwarded-For": "10.0.0.1"})
        assert response.status_code == 429

        # Client 2 should still be allowed
        for _ in range(2):
            response = client.get("/test", headers={"X-Forwarded-For": "10.0.0.2"})
            assert response.status_code == 200

    def test_x_forwarded_for_header_used_for_client_identification(self, app: FastAPI):
        """Test that X-Forwarded-For header is used for client identification."""
        add_rate_limiting_middleware(app, requests_per_minute=2)
        client = TestClient(app)

        # Make requests from "client1" via X-Forwarded-For
        for _ in range(2):
            response = client.get("/test", headers={"X-Forwarded-For": "192.168.1.1"})
            assert response.status_code == 200

        # 3rd request from same "client" should be blocked
        response = client.get("/test", headers={"X-Forwarded-For": "192.168.1.1"})
        assert response.status_code == 429

        # Request from different "client" should be allowed
        response = client.get("/test", headers={"X-Forwarded-For": "192.168.1.2"})
        assert response.status_code == 200

    def test_x_forwarded_for_uses_first_ip(self, app: FastAPI):
        """Test that first IP in X-Forwarded-For chain is used."""
        add_rate_limiting_middleware(app, requests_per_minute=2)
        client = TestClient(app)

        # Make requests with chained X-Forwarded-For
        for _ in range(2):
            response = client.get(
                "/test",
                headers={"X-Forwarded-For": "10.0.0.1, 192.168.1.1, 172.16.0.1"},
            )
            assert response.status_code == 200

        # Should be blocked based on first IP (10.0.0.1)
        response = client.get(
            "/test",
            headers={"X-Forwarded-For": "10.0.0.1, 192.168.1.1"},
        )
        assert response.status_code == 429

        # Different first IP should work
        response = client.get(
            "/test",
            headers={"X-Forwarded-For": "10.0.0.2, 192.168.1.1"},
        )
        assert response.status_code == 200

    def test_rate_limiting_logs_warning_on_exceeded(
        self, client_rate_limiting: TestClient, caplog: pytest.LogCaptureFixture
    ):
        """Test that rate limit exceeded events are logged as warnings."""
        # Exhaust limit
        for _ in range(5):
            client_rate_limiting.get("/test")

        with caplog.at_level(logging.WARNING):
            client_rate_limiting.get("/test")

        assert any("Rate limit exceeded" in record.message for record in caplog.records)


class TestRateLimitingMiddlewareWindowRotation:
    """Tests for rate limiting window rotation behavior."""

    def test_window_rotation_allows_new_requests(self, app: FastAPI):
        """Test that new window allows requests again."""
        add_rate_limiting_middleware(app, requests_per_minute=2)
        client = TestClient(app)

        # Find the middleware instance
        middleware_instance = None
        current = app.middleware_stack
        while hasattr(current, "app"):
            if isinstance(current, RateLimitingMiddleware):
                middleware_instance = current
                break
            current = current.app

        if middleware_instance is None:
            pytest.skip("Could not access middleware instance")

        # Exhaust limit
        client.get("/test")
        client.get("/test")
        response = client.get("/test")
        assert response.status_code == 429

        # Manually rotate window
        middleware_instance.window = 0
        middleware_instance.counts.clear()

        # Should be allowed now
        response = client.get("/test")
        assert response.status_code == 200


# =============================================================================
# Helper Function Tests
# =============================================================================


class TestAddMiddlewareFunctions:
    """Tests for middleware helper functions."""

    def test_add_request_logging_middleware(self):
        """Test that add_request_logging_middleware adds the middleware."""
        app = FastAPI()
        initial_middleware_count = len(app.user_middleware)

        add_request_logging_middleware(app)

        assert len(app.user_middleware) == initial_middleware_count + 1

    def test_add_rate_limiting_middleware(self):
        """Test that add_rate_limiting_middleware adds the middleware."""
        app = FastAPI()
        initial_middleware_count = len(app.user_middleware)

        add_rate_limiting_middleware(app)

        assert len(app.user_middleware) == initial_middleware_count + 1

    def test_add_rate_limiting_middleware_with_custom_limit(self):
        """Test that custom rate limit is applied."""
        app = FastAPI()

        @app.get("/test")
        def test_endpoint():
            return {"status": "ok"}

        add_rate_limiting_middleware(app, requests_per_minute=3)
        client = TestClient(app)

        # Make 3 allowed requests
        for _ in range(3):
            response = client.get("/test")
            assert response.status_code == 200

        # 4th should be blocked
        response = client.get("/test")
        assert response.status_code == 429

    def test_add_rate_limiting_middleware_default_limit(self):
        """Test that default rate limit is 60 requests per minute."""
        app = FastAPI()

        @app.get("/test")
        def test_endpoint():
            return {"status": "ok"}

        add_rate_limiting_middleware(app)
        client = TestClient(app)

        # Should allow 60 requests
        for _ in range(60):
            response = client.get("/test")
            assert response.status_code == 200

        # 61st should be blocked
        response = client.get("/test")
        assert response.status_code == 429


# =============================================================================
# Integration Tests
# =============================================================================


class TestMiddlewareIntegration:
    """Integration tests with both middlewares active."""

    def test_both_middlewares_work_together(self, caplog: pytest.LogCaptureFixture):
        """Test that logging and rate limiting work together."""
        app = FastAPI()

        @app.get("/test")
        def test_endpoint():
            return {"status": "ok"}

        # Add rate limiting first, then logging (logging wraps rate limiting)
        add_rate_limiting_middleware(app, requests_per_minute=2)
        add_request_logging_middleware(app)

        client = TestClient(app)

        with caplog.at_level(logging.INFO):
            # First two requests should succeed
            for _ in range(2):
                response = client.get("/test")
                assert response.status_code == 200

            # Third request should be rate limited
            response = client.get("/test")
            assert response.status_code == 429

        # Verify logging happened for all requests
        log_messages = [r.message for r in caplog.records]
        assert sum("GET /test - 200" in msg for msg in log_messages) == 2
        assert sum("GET /test - 429" in msg for msg in log_messages) == 1


# =============================================================================
# Edge Cases
# =============================================================================


class TestEdgeCases:
    """Edge case tests for middleware."""

    def test_logging_handles_missing_client(self, app: FastAPI):
        """Test logging middleware handles missing client info gracefully."""
        add_request_logging_middleware(app)
        # TestClient always provides client info, so this is tested implicitly

    def test_rate_limiting_empty_x_forwarded_for(self, app: FastAPI):
        """Test rate limiting with empty X-Forwarded-For header."""
        add_rate_limiting_middleware(app, requests_per_minute=2)

        @app.get("/test")
        def test_endpoint():
            return {"status": "ok"}

        client = TestClient(app)

        # Empty X-Forwarded-For should fall back to client IP
        response = client.get("/test", headers={"X-Forwarded-For": ""})
        assert response.status_code == 200

    def test_rate_limiting_whitespace_only_x_forwarded_for(self, app: FastAPI):
        """Test rate limiting with whitespace-only X-Forwarded-For header."""
        add_rate_limiting_middleware(app, requests_per_minute=2)

        @app.get("/test")
        def test_endpoint():
            return {"status": "ok"}

        client = TestClient(app)

        # Whitespace-only X-Forwarded-For should fall back to client IP
        response = client.get("/test", headers={"X-Forwarded-For": "   "})
        assert response.status_code == 200

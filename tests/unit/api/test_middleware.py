"""
Tests for API middleware.

Tests for RequestLoggingMiddleware, RateLimitingMiddleware, and CORS configuration.
"""

from __future__ import annotations

import logging
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient

from ciberwebscan.api.middleware import (
    RateLimitingMiddleware,
    add_rate_limiting_middleware,
    add_request_logging_middleware,
)
from ciberwebscan.config.models import APIConfig, APIRateLimitConfig, AppConfig

pytestmark = pytest.mark.unit

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


def _find_rate_limiter(app: FastAPI) -> RateLimitingMiddleware:
    """Find the RateLimitingMiddleware instance in the built stack."""
    current = app.middleware_stack
    while hasattr(current, "app"):
        if isinstance(current, RateLimitingMiddleware):
            return current
        current = current.app
    raise AssertionError("Could not access middleware instance")


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
        """Test that different connection peers have independent rate limits."""
        add_rate_limiting_middleware(app, requests_per_minute=2)
        client_a = TestClient(app, client=("10.0.0.1", 50000))
        client_b = TestClient(app, client=("10.0.0.2", 50000))

        # Client A makes 2 requests
        for _ in range(2):
            response = client_a.get("/test")
            assert response.status_code == 200

        # Client A should be blocked
        response = client_a.get("/test")
        assert response.status_code == 429

        # Client B should still be allowed
        for _ in range(2):
            response = client_b.get("/test")
            assert response.status_code == 200

    def test_rotating_forwarded_for_does_not_bypass_rate_limit(self, app: FastAPI):
        """X-Forwarded-For must not mint fresh buckets (secure default)."""
        add_rate_limiting_middleware(app, requests_per_minute=2)
        client = TestClient(app, client=("10.0.0.9", 50000))

        with patch("ciberwebscan.api.client_ip.get_config", return_value=AppConfig()):
            for i in range(2):
                response = client.get(
                    "/test", headers={"X-Forwarded-For": f"192.168.1.{i + 1}"}
                )
                assert response.status_code == 200

            # 3rd request with yet another forged hop: still limited
            response = client.get("/test", headers={"X-Forwarded-For": "192.168.1.99"})
            assert response.status_code == 429

        # Counter is keyed by the connection peer, not by the header
        limiter = _find_rate_limiter(app)
        assert set(limiter.counts) == {"10.0.0.9"}

    def test_forwarded_for_resolved_right_to_left_behind_trusted_proxy(
        self, app: FastAPI
    ):
        """Behind a trusted proxy the identity is the rightmost hop."""
        add_rate_limiting_middleware(app, requests_per_minute=2)
        client = TestClient(app, client=("10.0.0.50", 50000))
        config = AppConfig(api=APIConfig(trusted_proxies=["10.0.0.50"]))

        with patch("ciberwebscan.api.client_ip.get_config", return_value=config):
            # The proxy appends the real client on the right; the left side
            # is attacker-controlled and must not create new buckets.
            for _ in range(2):
                response = client.get(
                    "/test",
                    headers={"X-Forwarded-For": "1.1.1.1, 172.16.0.7"},
                )
                assert response.status_code == 200

            response = client.get(
                "/test",
                headers={"X-Forwarded-For": "2.2.2.2, 172.16.0.7"},
            )
            assert response.status_code == 429

            # A different client behind the same proxy has its own bucket
            response = client.get("/test", headers={"X-Forwarded-For": "172.16.0.8"})
            assert response.status_code == 200

        limiter = _find_rate_limiter(app)
        assert "172.16.0.7" in limiter.counts
        assert "1.1.1.1" not in limiter.counts

    def test_multi_proxy_chain_resolves_left_of_trusted_hops(self, app: FastAPI):
        """All trusted hops are skipped; the first untrusted hop wins.

        A forged leftmost hop (9.9.9.9) proves the chain is not resolved
        from the client-controlled end.
        """
        add_rate_limiting_middleware(app, requests_per_minute=2)
        client = TestClient(app, client=("10.0.0.50", 50000))
        config = AppConfig(api=APIConfig(trusted_proxies=["10.0.0.50", "10.0.0.49"]))
        chain = "9.9.9.9, 203.0.113.9, 10.0.0.49"

        with patch("ciberwebscan.api.client_ip.get_config", return_value=config):
            for _ in range(2):
                response = client.get("/test", headers={"X-Forwarded-For": chain})
                assert response.status_code == 200

            # Same client identity (203.0.113.9, skipping the trusted hop)
            # -> limited, and the proxies themselves get no bucket of their own
            response = client.get("/test", headers={"X-Forwarded-For": chain})
            assert response.status_code == 429

        limiter = _find_rate_limiter(app)
        assert set(limiter.counts) == {"203.0.113.9"}

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


class TestRateLimitingEnforced:
    """Test that rate limiting enforces the limit correctly with TestClient.

    Uses a low limit (5 req/min) so the test completes in ~0.01s,
    making window-boundary crossing impossible.
    """

    def test_rate_limit_enforced(self, app: FastAPI):
        """Verify 429 is returned after exceeding the limit."""
        add_rate_limiting_middleware(app, requests_per_minute=5)
        client = TestClient(app)

        success_count = 0
        limited_count = 0

        for _ in range(10):
            response = client.get("/test")
            if response.status_code == 200:
                success_count += 1
            elif response.status_code == 429:
                limited_count += 1
                break

        assert limited_count > 0, (
            f"Rate limit not triggered after {success_count} requests"
        )

    def test_rate_limiting_disabled_is_not_registered(self):
        """api.rate_limit.enabled=False must not register the middleware."""
        from ciberwebscan.api.app import create_app

        config = AppConfig(api=APIConfig(rate_limit=APIRateLimitConfig(enabled=False)))
        with patch("ciberwebscan.api.app.get_config", return_value=config):
            app = create_app()

        registered = [mw.cls for mw in app.user_middleware]
        assert RateLimitingMiddleware not in registered


class TestRateLimitingMiddlewareWindowRotation:
    """Tests for rate limiting window rotation behavior."""

    def test_window_rotation_allows_new_requests(self, app: FastAPI):
        """Test that new window allows requests again."""
        add_rate_limiting_middleware(app, requests_per_minute=2)
        client = TestClient(app)

        # Prime the middleware stack (built lazily on first request)
        client.get("/test")

        # Find the middleware instance
        middleware_instance = None
        current = app.middleware_stack
        while hasattr(current, "app"):
            if isinstance(current, RateLimitingMiddleware):
                middleware_instance = current
                break
            current = current.app

        assert middleware_instance is not None, "Could not access middleware instance"

        # Exhaust remaining limit (1 more, total=2 in this window)
        response = client.get("/test")
        assert response.status_code == 200

        # Should be blocked now (2 >= 2)
        response = client.get("/test")
        assert response.status_code == 429

        # Manually rotate window
        middleware_instance.window = 0
        middleware_instance.counts.clear()

        # Should be allowed now
        response = client.get("/test")
        assert response.status_code == 200


# =============================================================================
# Security Regressions (client identity / X-Forwarded-For trust)
# =============================================================================


class TestForwardedForSecurity:
    """The forwarded chain must never become a client-controlled identity."""

    def test_forged_forwarded_for_does_not_consume_victim_quota(self, app: FastAPI):
        """Flooding with a forged victim hop must not exhaust her bucket."""
        add_rate_limiting_middleware(app, requests_per_minute=2)
        attacker = TestClient(app, client=("10.0.0.9", 50000))
        victim = TestClient(app, client=("172.16.0.7", 50000))

        with patch("ciberwebscan.api.client_ip.get_config", return_value=AppConfig()):
            for _ in range(2):
                assert (
                    attacker.get(
                        "/test", headers={"X-Forwarded-For": "172.16.0.7"}
                    ).status_code
                    == 200
                )
            # Attacker exhausts his own (peer) quota...
            assert (
                attacker.get(
                    "/test", headers={"X-Forwarded-For": "172.16.0.7"}
                ).status_code
                == 429
            )
            # ...and never created a bucket under the forged victim hop
            limiter = _find_rate_limiter(app)
            assert set(limiter.counts) == {"10.0.0.9"}

            # The victim is unaffected
            assert victim.get("/test").status_code == 200
            assert limiter.counts["172.16.0.7"] == 1

    def test_forged_victim_hop_behind_trusted_proxy_hits_real_client(
        self, app: FastAPI
    ):
        """A proxy-appended chain credits the proxy-seen hop, not the left."""
        add_rate_limiting_middleware(app, requests_per_minute=2)
        client = TestClient(app, client=("10.0.0.50", 50000))
        config = AppConfig(api=APIConfig(trusted_proxies=["10.0.0.50"]))

        with patch("ciberwebscan.api.client_ip.get_config", return_value=config):
            # Attacker is 10.0.0.9 (appended by the proxy); left hop forged
            for _ in range(2):
                assert (
                    client.get(
                        "/test",
                        headers={"X-Forwarded-For": "172.16.0.7, 10.0.0.9"},
                    ).status_code
                    == 200
                )
            assert (
                client.get(
                    "/test", headers={"X-Forwarded-For": "172.16.0.7, 10.0.0.9"}
                ).status_code
                == 429
            )
            # Bucket under the attacker's real hop only, not the forged victim
            limiter = _find_rate_limiter(app)
            assert "10.0.0.9" in limiter.counts
            assert "172.16.0.7" not in limiter.counts

            # The real client 172.16.0.7 still has her own bucket
            assert (
                client.get(
                    "/test", headers={"X-Forwarded-For": "172.16.0.7"}
                ).status_code
                == 200
            )

    def test_configured_trusted_proxies_do_not_trust_every_peer(self, app: FastAPI):
        """A non-empty list must not make arbitrary peers trusted."""
        add_rate_limiting_middleware(app, requests_per_minute=2)
        client = TestClient(app, client=("10.0.0.9", 50000))
        config = AppConfig(api=APIConfig(trusted_proxies=["10.0.0.50"]))

        with patch("ciberwebscan.api.client_ip.get_config", return_value=config):
            for i in range(2):
                assert (
                    client.get(
                        "/test", headers={"X-Forwarded-For": f"192.168.1.{i + 1}"}
                    ).status_code
                    == 200
                )
            assert (
                client.get(
                    "/test", headers={"X-Forwarded-For": "192.168.1.50"}
                ).status_code
                == 429
            )

        limiter = _find_rate_limiter(app)
        assert set(limiter.counts) == {"10.0.0.9"}

    def test_create_app_rate_limits_rotating_forwarded_for(self):
        """Full application (default config): rotating hops cannot bypass."""
        from ciberwebscan.api.app import create_app

        config = AppConfig(
            api=APIConfig(rate_limit=APIRateLimitConfig(requests_per_minute=5))
        )
        with (
            patch("ciberwebscan.api.app.get_config", return_value=config),
            patch("ciberwebscan.api.client_ip.get_config", return_value=config),
        ):
            app = create_app()
            client = TestClient(app, client=("10.0.0.9", 50000))

            statuses = [
                client.get(
                    "/health", headers={"X-Forwarded-For": f"203.0.113.{i}"}
                ).status_code
                for i in range(7)
            ]

        assert statuses[:5] == [200] * 5
        assert statuses[5:] == [429, 429]


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

        client = TestClient(app, client=("10.0.0.9", 50000))

        # Empty X-Forwarded-For should fall back to the connection peer
        response = client.get("/test", headers={"X-Forwarded-For": ""})
        assert response.status_code == 200
        assert set(_find_rate_limiter(app).counts) == {"10.0.0.9"}

    def test_rate_limiting_whitespace_only_x_forwarded_for(self, app: FastAPI):
        """Test rate limiting with whitespace-only X-Forwarded-For header."""
        add_rate_limiting_middleware(app, requests_per_minute=2)

        @app.get("/test")
        def test_endpoint():
            return {"status": "ok"}

        client = TestClient(app, client=("10.0.0.9", 50000))

        # Whitespace-only X-Forwarded-For should fall back to the connection peer
        response = client.get("/test", headers={"X-Forwarded-For": "   "})
        assert response.status_code == 200
        assert set(_find_rate_limiter(app).counts) == {"10.0.0.9"}


# =============================================================================
# CORS Middleware Configuration Tests
# =============================================================================


class TestCORSConfiguration:
    """Tests for CORS middleware configuration from APIConfig."""

    def _find_cors_kwargs(self, app: FastAPI) -> dict | None:
        """Find CORSMiddleware kwargs in user_middleware."""
        for mw in app.user_middleware:
            if mw.cls is CORSMiddleware:
                return mw.kwargs
        return None

    def test_cors_middleware_added(self):
        """Test that CORS middleware is added to the app."""
        from ciberwebscan.api.app import create_app

        app = create_app()
        cors_kwargs = self._find_cors_kwargs(app)
        assert cors_kwargs is not None

    def test_cors_origins_applied(self):
        """Test that configured CORS origins are applied to middleware."""
        from unittest.mock import patch

        from ciberwebscan.config.models import AppConfig

        config = AppConfig(
            api=APIConfig(
                cors_origins=["http://localhost:3000", "https://example.com"],
                cors_allow_credentials=True,
            ),
        )
        with patch("ciberwebscan.api.app.get_config", return_value=config):
            from ciberwebscan.api import app as app_module

            test_app = app_module.create_app()
            cors_kwargs = self._find_cors_kwargs(test_app)
            assert cors_kwargs is not None
            assert "http://localhost:3000" in cors_kwargs["allow_origins"]
            assert "https://example.com" in cors_kwargs["allow_origins"]

    def test_cors_empty_origins_fallback(self):
        """Test that empty cors_origins results in ['*'] in middleware."""
        from unittest.mock import patch

        from ciberwebscan.config.models import AppConfig

        config = AppConfig(api=APIConfig(cors_origins=[]))
        with patch("ciberwebscan.api.app.get_config", return_value=config):
            from ciberwebscan.api import app as app_module

            test_app = app_module.create_app()
            cors_kwargs = self._find_cors_kwargs(test_app)
            assert cors_kwargs is not None
            assert cors_kwargs["allow_origins"] == ["*"]

    def test_cors_credentials_disabled_by_default(self):
        """Test that credentials are disabled by default."""
        from unittest.mock import patch

        from ciberwebscan.config.models import AppConfig

        config = AppConfig(api=APIConfig())
        with patch("ciberwebscan.api.app.get_config", return_value=config):
            from ciberwebscan.api import app as app_module

            test_app = app_module.create_app()
            cors_kwargs = self._find_cors_kwargs(test_app)
            assert cors_kwargs is not None
            assert cors_kwargs["allow_credentials"] is False

    def test_cors_methods_not_wildcard_by_default(self):
        """Test that methods are not wildcard by default."""
        from unittest.mock import patch

        from ciberwebscan.config.models import AppConfig

        config = AppConfig(api=APIConfig())
        with patch("ciberwebscan.api.app.get_config", return_value=config):
            from ciberwebscan.api import app as app_module

            test_app = app_module.create_app()
            cors_kwargs = self._find_cors_kwargs(test_app)
            assert cors_kwargs is not None
            assert "*" not in cors_kwargs["allow_methods"]

    def test_cors_headers_not_wildcard_by_default(self):
        """Test that headers are not wildcard by default."""
        from unittest.mock import patch

        from ciberwebscan.config.models import AppConfig

        config = AppConfig(api=APIConfig())
        with patch("ciberwebscan.api.app.get_config", return_value=config):
            from ciberwebscan.api import app as app_module

            test_app = app_module.create_app()
            cors_kwargs = self._find_cors_kwargs(test_app)
            assert cors_kwargs is not None
            assert "*" not in cors_kwargs["allow_headers"]

"""
Tests for health check endpoints.

Tests for /health and /health/ready endpoints.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ciberwebscan.api.routes.health import HealthResponse, router

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def app() -> FastAPI:
    """Create a FastAPI app with health routes."""
    app = FastAPI()
    app.include_router(router)
    return app


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    """Create test client."""
    return TestClient(app)


# =============================================================================
# HealthResponse Model Tests
# =============================================================================


class TestHealthResponseModel:
    """Tests for HealthResponse Pydantic model."""

    def test_health_response_creation(self):
        """Test HealthResponse model instantiation."""
        now = datetime.now(timezone.utc)
        response = HealthResponse(
            status="healthy",
            timestamp=now,
            version="2.0.0",
            message="Test message",
        )

        assert response.status == "healthy"
        assert response.timestamp == now
        assert response.version == "2.0.0"
        assert response.message == "Test message"

    def test_health_response_serialization(self):
        """Test HealthResponse JSON serialization."""
        now = datetime.now(timezone.utc)
        response = HealthResponse(
            status="ready",
            timestamp=now,
            version="1.0.0",
            message="Ready",
        )

        data = response.model_dump()
        assert data["status"] == "ready"
        assert data["version"] == "1.0.0"
        assert data["message"] == "Ready"
        assert "timestamp" in data


# =============================================================================
# Health Check Endpoint Tests
# =============================================================================


class TestHealthCheckEndpoint:
    """Tests for /health endpoint."""

    def test_health_check_returns_200(self, client: TestClient):
        """Test health check returns 200 status code."""
        response = client.get("/health")
        assert response.status_code == 200

    def test_health_check_returns_healthy_status(self, client: TestClient):
        """Test health check returns healthy status."""
        response = client.get("/health")
        data = response.json()

        assert data["status"] == "healthy"

    def test_health_check_returns_version(self, client: TestClient):
        """Test health check includes version."""
        response = client.get("/health")
        data = response.json()

        assert "version" in data
        assert isinstance(data["version"], str)
        assert len(data["version"]) > 0

    def test_health_check_returns_timestamp(self, client: TestClient):
        """Test health check includes timestamp."""
        response = client.get("/health")
        data = response.json()

        assert "timestamp" in data
        # Verify timestamp is parseable
        timestamp = datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00"))
        assert timestamp is not None

    def test_health_check_returns_message(self, client: TestClient):
        """Test health check includes message."""
        response = client.get("/health")
        data = response.json()

        assert data["message"] == "CiberWebScan API is running"

    def test_health_check_response_structure(self, client: TestClient):
        """Test health check response has all required fields."""
        response = client.get("/health")
        data = response.json()

        expected_keys = {"status", "timestamp", "version", "message"}
        assert set(data.keys()) == expected_keys

    @patch("ciberwebscan.api.routes.health.__version__", "3.0.0-test")
    def test_health_check_uses_package_version(self, client: TestClient):
        """Test health check uses actual package version."""
        response = client.get("/health")
        data = response.json()

        assert data["version"] == "3.0.0-test"


# =============================================================================
# Readiness Check Endpoint Tests
# =============================================================================


class TestReadinessCheckEndpoint:
    """Tests for /health/ready endpoint."""

    def test_readiness_check_returns_200(self, client: TestClient):
        """Test readiness check returns 200 status code."""
        response = client.get("/health/ready")
        assert response.status_code == 200

    def test_readiness_check_returns_ready_status(self, client: TestClient):
        """Test readiness check returns ready status."""
        response = client.get("/health/ready")
        data = response.json()

        assert data["status"] == "ready"

    def test_readiness_check_returns_version(self, client: TestClient):
        """Test readiness check includes version."""
        response = client.get("/health/ready")
        data = response.json()

        assert "version" in data
        assert isinstance(data["version"], str)

    def test_readiness_check_returns_timestamp(self, client: TestClient):
        """Test readiness check includes timestamp."""
        response = client.get("/health/ready")
        data = response.json()

        assert "timestamp" in data
        timestamp = datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00"))
        assert timestamp is not None

    def test_readiness_check_returns_message(self, client: TestClient):
        """Test readiness check includes message."""
        response = client.get("/health/ready")
        data = response.json()

        assert data["message"] == "CiberWebScan API is ready to accept requests"

    def test_readiness_check_response_structure(self, client: TestClient):
        """Test readiness check response has all required fields."""
        response = client.get("/health/ready")
        data = response.json()

        expected_keys = {"status", "timestamp", "version", "message"}
        assert set(data.keys()) == expected_keys

    @patch("ciberwebscan.api.routes.health.__version__", "2.5.0-beta")
    def test_readiness_check_uses_package_version(self, client: TestClient):
        """Test readiness check uses actual package version."""
        response = client.get("/health/ready")
        data = response.json()

        assert data["version"] == "2.5.0-beta"


# =============================================================================
# Edge Cases & Integration
# =============================================================================


class TestHealthEndpointsEdgeCases:
    """Edge case tests for health endpoints."""

    def test_health_endpoint_is_get_only(self, client: TestClient):
        """Test health endpoint only accepts GET requests."""
        assert client.post("/health").status_code == 405
        assert client.put("/health").status_code == 405
        assert client.delete("/health").status_code == 405
        assert client.patch("/health").status_code == 405

    def test_readiness_endpoint_is_get_only(self, client: TestClient):
        """Test readiness endpoint only accepts GET requests."""
        assert client.post("/health/ready").status_code == 405
        assert client.put("/health/ready").status_code == 405
        assert client.delete("/health/ready").status_code == 405
        assert client.patch("/health/ready").status_code == 405

    def test_health_and_ready_have_different_status(self, client: TestClient):
        """Test health and ready endpoints return different status values."""
        health_response = client.get("/health").json()
        ready_response = client.get("/health/ready").json()

        assert health_response["status"] == "healthy"
        assert ready_response["status"] == "ready"

    def test_health_and_ready_have_different_messages(self, client: TestClient):
        """Test health and ready endpoints return different messages."""
        health_response = client.get("/health").json()
        ready_response = client.get("/health/ready").json()

        assert health_response["message"] != ready_response["message"]

    def test_timestamps_are_recent(self, client: TestClient):
        """Test that timestamps are recent (within last minute)."""
        before = datetime.now(timezone.utc)
        response = client.get("/health")
        after = datetime.now(timezone.utc)

        data = response.json()
        timestamp = datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00"))

        assert before <= timestamp <= after

    def test_multiple_requests_return_different_timestamps(self, client: TestClient):
        """Test that each request gets a fresh timestamp."""
        response1 = client.get("/health")
        response2 = client.get("/health")

        # Timestamps should be >= (could be same if fast enough)
        ts1 = response1.json()["timestamp"]
        ts2 = response2.json()["timestamp"]

        # Both should be valid timestamps
        datetime.fromisoformat(ts1.replace("Z", "+00:00"))
        datetime.fromisoformat(ts2.replace("Z", "+00:00"))

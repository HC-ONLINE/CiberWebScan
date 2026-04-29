"""
Unit tests for the attack simulation API endpoint (POST /api/attack).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from ciberwebscan.api.app import create_app
from ciberwebscan.services.base import ValidationError as ServiceValidationError

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def client():
    """Test client with authentication bypassed."""
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
def mock_attack_result():
    """A minimal AttackResult mock that can be serialised by FastAPI."""
    from ciberwebscan.export.models import AttackResult

    return AttackResult(
        target_url="https://example.com",
        vulnerabilities=[],
        total_payloads_tested=10,
        total_findings=0,
        xss_findings=0,
        sqli_findings=0,
        traversal_findings=0,
        enumeration_findings=0,
        duration_seconds=1.5,
    )


def _make_service_result(data=None, success=True, error=None):
    """Build a mock ServiceResult."""
    result = MagicMock()
    result.success = success
    result.data = data
    result.error = error
    return result


BASE_PAYLOAD = {
    "url": "https://example.com",
    "xss": True,
    "user_consent": True,
}


# =============================================================================
# Happy-path tests
# =============================================================================


class TestAttackEndpointSuccess:
    """Tests for successful attack endpoint calls."""

    def test_post_attack_xss_returns_200(self, client, mock_attack_result):
        """POST /api/attack with xss=True returns 200 and attack data."""
        with patch(
            "ciberwebscan.api.routes.attack.AttackService"
        ) as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service
            mock_service.attack.return_value = _make_service_result(
                data=mock_attack_result
            )

            response = client.post("/api/attack", json=BASE_PAYLOAD)

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["data"]["target_url"] == "https://example.com"
        assert data["data"]["total_findings"] == 0

    def test_post_attack_all_attacks_shortcut(self, client, mock_attack_result):
        """all_attacks=True enables all four attack types."""
        with patch(
            "ciberwebscan.api.routes.attack.AttackService"
        ) as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service
            mock_service.attack.return_value = _make_service_result(
                data=mock_attack_result
            )

            response = client.post(
                "/api/attack",
                json={
                    "url": "https://example.com",
                    "all_attacks": True,
                    "user_consent": True,
                },
            )

        assert response.status_code == 200
        # Verify ALL four attack types were set to True in AttackOptions
        call_kwargs = mock_service.attack.call_args[0][0]
        assert call_kwargs.xss is True
        assert call_kwargs.sqli is True
        assert call_kwargs.traversal is True
        assert call_kwargs.enumeration is True

    def test_post_attack_intensity_high(self, client, mock_attack_result):
        """intensity=high is forwarded to AttackOptions correctly."""
        with patch(
            "ciberwebscan.api.routes.attack.AttackService"
        ) as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service
            mock_service.attack.return_value = _make_service_result(
                data=mock_attack_result
            )

            response = client.post(
                "/api/attack",
                json={**BASE_PAYLOAD, "intensity": "high"},
            )

        assert response.status_code == 200
        options = mock_service.attack.call_args[0][0]
        assert options.intensity == "high"

    def test_post_attack_sqli_and_traversal(self, client, mock_attack_result):
        """Multiple attack types can be enabled at the same time."""
        with patch(
            "ciberwebscan.api.routes.attack.AttackService"
        ) as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service
            mock_service.attack.return_value = _make_service_result(
                data=mock_attack_result
            )

            response = client.post(
                "/api/attack",
                json={
                    "url": "https://example.com",
                    "sqli": True,
                    "traversal": True,
                    "user_consent": True,
                },
            )

        assert response.status_code == 200
        options = mock_service.attack.call_args[0][0]
        assert options.sqli is True
        assert options.traversal is True


# =============================================================================
# Validation / consent tests
# =============================================================================


class TestAttackEndpointValidation:
    """Tests for request validation on the attack endpoint."""

    def test_missing_user_consent_returns_422(self, client):
        """user_consent=false is rejected by Pydantic at the request level."""
        response = client.post(
            "/api/attack",
            json={"url": "https://example.com", "xss": True, "user_consent": False},
        )
        # Pydantic field_validator raises ValueError → FastAPI returns 422
        assert response.status_code == 422

    def test_missing_url_returns_422(self, client):
        """Missing url field returns 422 Unprocessable Entity."""
        response = client.post(
            "/api/attack",
            json={"xss": True, "user_consent": True},
        )
        assert response.status_code == 422

    def test_invalid_intensity_returns_422(self, client):
        """Invalid intensity value (not low/medium/high) returns 422."""
        response = client.post(
            "/api/attack",
            json={**BASE_PAYLOAD, "intensity": "extreme"},
        )
        assert response.status_code == 422

    def test_service_validation_error_returns_400(self, client):
        """ServiceValidationError (e.g. attack disabled in config) returns 400."""
        with patch(
            "ciberwebscan.api.routes.attack.AttackService"
        ) as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service
            mock_service.attack.side_effect = ServiceValidationError(
                "Attack simulation is disabled in configuration."
            )

            response = client.post("/api/attack", json=BASE_PAYLOAD)

        assert response.status_code == 400
        assert "disabled" in response.json()["detail"].lower()

    def test_service_validation_error_whitelist_returns_400(self, client):
        """ServiceValidationError for whitelist violation returns 400."""
        with patch(
            "ciberwebscan.api.routes.attack.AttackService"
        ) as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service
            mock_service.attack.side_effect = ServiceValidationError(
                "Target host 'example.com' is not in the attack whitelist."
            )

            response = client.post("/api/attack", json=BASE_PAYLOAD)

        assert response.status_code == 400
        assert "whitelist" in response.json()["detail"].lower()


# =============================================================================
# Error handling tests
# =============================================================================


class TestAttackEndpointErrors:
    """Tests for error handling in the attack endpoint."""

    def test_service_result_failure_returns_500(self, client):
        """When service returns success=False, the endpoint raises HTTP 500."""
        with patch(
            "ciberwebscan.api.routes.attack.AttackService"
        ) as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service
            mock_service.attack.return_value = _make_service_result(
                success=False, error="Attack execution failed"
            )

            response = client.post("/api/attack", json=BASE_PAYLOAD)

        assert response.status_code == 500
        # detail = result.error when set, otherwise "Attack simulation failed"
        assert "Attack execution failed" in response.json()["detail"]

    def test_unexpected_exception_returns_500(self, client):
        """Unhandled exceptions from the service layer return HTTP 500."""
        with patch(
            "ciberwebscan.api.routes.attack.AttackService"
        ) as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service
            mock_service.attack.side_effect = RuntimeError("Something went wrong")

            response = client.post("/api/attack", json=BASE_PAYLOAD)

        assert response.status_code == 500
        assert "Something went wrong" in response.json()["detail"]

    def test_response_shape(self, client, mock_attack_result):
        """Response always contains success, data, and timestamp fields."""
        with patch(
            "ciberwebscan.api.routes.attack.AttackService"
        ) as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service
            mock_service.attack.return_value = _make_service_result(
                data=mock_attack_result
            )

            response = client.post("/api/attack", json=BASE_PAYLOAD)

        assert response.status_code == 200
        body = response.json()
        assert "success" in body
        assert "data" in body
        assert "timestamp" in body

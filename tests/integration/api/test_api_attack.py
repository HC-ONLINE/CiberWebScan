"""
Integration tests for attack endpoint.

Covers: test_api.py attack, test_api_attack.py.
"""

from __future__ import annotations

import httpx
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("uvicorn")


class TestAttackEndpoint:
    """Tests for POST /api/attack."""

    def test_attack_xss_only(self, api_client: httpx.Client, auth_headers: dict):
        payload = {
            "url": "http://127.0.0.1:5555/xss?q=test",
            "xss": True,
            "sqli": False,
            "traversal": False,
            "enumeration": False,
            "intensity": "low",
            "max_payloads": 5,
            "user_consent": True,
        }
        response = api_client.post(
            "/api/attack", json=payload, headers=auth_headers, timeout=120
        )
        assert response.status_code == 200

        data = response.json()
        assert data["success"] is True

        attack_data = data.get("data")
        assert attack_data is not None
        assert attack_data["target_url"] == payload["url"]
        assert isinstance(attack_data["total_payloads_tested"], int)
        assert isinstance(attack_data["total_findings"], int)
        assert isinstance(attack_data["vulnerabilities"], list)

        for key in (
            "xss_findings",
            "sqli_findings",
            "traversal_findings",
            "enumeration_findings",
            "csrf_findings",
            "subdomain_findings",
        ):
            assert key in attack_data
            assert isinstance(attack_data[key], int)

    def test_attack_sqli_only(self, api_client: httpx.Client, auth_headers: dict):
        payload = {
            "url": "http://127.0.0.1:5555/user?id=1",
            "xss": False,
            "sqli": True,
            "traversal": False,
            "enumeration": False,
            "intensity": "low",
            "max_payloads": 5,
            "user_consent": True,
        }
        response = api_client.post(
            "/api/attack", json=payload, headers=auth_headers, timeout=120
        )
        assert response.status_code == 200

        data = response.json()
        assert data["success"] is True

        attack_data = data.get("data")
        assert attack_data is not None
        assert attack_data["target_url"] == payload["url"]
        assert isinstance(attack_data["sqli_findings"], int)

    def test_attack_all_attacks(self, api_client: httpx.Client, auth_headers: dict):
        payload = {
            "url": "http://127.0.0.1:5555/",
            "all_attacks": True,
            "intensity": "low",
            "max_payloads": 3,
            "user_consent": True,
        }
        response = api_client.post(
            "/api/attack", json=payload, headers=auth_headers, timeout=120
        )
        assert response.status_code == 200

        data = response.json()
        assert data["success"] is True
        assert data["data"]["total_payloads_tested"] >= 0

    def test_attack_traversal_enumeration(
        self, api_client: httpx.Client, auth_headers: dict
    ):
        payload = {
            "url": "http://127.0.0.1:5555/",
            "xss": False,
            "sqli": False,
            "traversal": True,
            "enumeration": True,
            "intensity": "low",
            "max_payloads": 5,
            "user_consent": True,
        }
        response = api_client.post(
            "/api/attack", json=payload, headers=auth_headers, timeout=120
        )
        assert response.status_code == 200

        data = response.json()
        assert data["success"] is True

    def test_attack_missing_consent_returns_422(
        self, api_client: httpx.Client, auth_headers: dict
    ):
        payload = {
            "url": "http://127.0.0.1:5555/",
            "xss": True,
            "user_consent": False,
        }
        response = api_client.post("/api/attack", json=payload, headers=auth_headers)
        assert response.status_code == 422

"""
Tests for OS command injection attack module.

Covers GET query parameter injection, POST form injection, POST/JSON body
injection (payload per parameter), and response analysis heuristics.
"""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from ciberwebscan.core.attacks.base import AttackConfig, AttackContext, AttackIntensity
from ciberwebscan.core.attacks.command_injection import CommandInjectionAttacker
from ciberwebscan.core.client import HTTPClient
from ciberwebscan.export.models import ConfidenceLevel, Severity


@pytest.fixture
def cmdi_attacker():
    """Command injection attacker instance."""
    return CommandInjectionAttacker()


def make_response(
    text: str = "<html><body>Normal page</body></html>",
    status: int = 200,
    url: str = "https://example.com/",
    elapsed: float = 0.5,
) -> Mock:
    """Create a mock HTTP response."""
    response = Mock()
    response.url = url
    response.status_code = status
    response.text = text
    response.content = text.encode()
    response.headers = {"Content-Type": "text/html"}
    response.elapsed.total_seconds.return_value = elapsed
    return response


def make_context(config: AttackConfig, client: Mock) -> AttackContext:
    """Create an attack context with the given config and client."""
    return AttackContext(config=config, http_client=client)


@pytest.fixture
def get_config():
    """Attack config for GET-based tests (no delay)."""
    return AttackConfig(
        target_url="https://example.com/search?q=test&page=1",
        intensity=AttackIntensity.MEDIUM,
        max_payloads=15,
        timeout=5.0,
        user_consent=True,
        delay_between_requests=0,
    )


@pytest.fixture
def form_config():
    """Attack config for form-based tests (no delay)."""
    return AttackConfig(
        target_url="https://example.com/login",
        intensity=AttackIntensity.MEDIUM,
        max_payloads=15,
        timeout=5.0,
        user_consent=True,
        delay_between_requests=0,
    )


@pytest.fixture
def json_config():
    """Attack config for POST/JSON body tests (no delay)."""
    return AttackConfig(
        target_url="https://example.com/api/run",
        intensity=AttackIntensity.MEDIUM,
        max_payloads=15,
        timeout=5.0,
        user_consent=True,
        delay_between_requests=0,
        json_body={"cmd": "id", "file": "report.txt"},
    )


class TestGetPayloads:
    """Tests for payload selection."""

    def test_payloads_by_intensity(self, cmdi_attacker):
        low = cmdi_attacker.get_payloads(AttackIntensity.LOW, 50)
        medium = cmdi_attacker.get_payloads(AttackIntensity.MEDIUM, 50)
        high = cmdi_attacker.get_payloads(AttackIntensity.HIGH, 50)

        assert isinstance(low, list) and low
        assert isinstance(medium, list) and medium
        assert isinstance(high, list) and high
        assert len(high) >= len(medium) >= len(low) >= 1

    def test_high_intensity_contains_time_based_payload(self, cmdi_attacker):
        high = cmdi_attacker.get_payloads(AttackIntensity.HIGH, 50)
        assert any("sleep" in p or "ping" in p for p in high)

    def test_max_count_respected(self, cmdi_attacker):
        payloads = cmdi_attacker.get_payloads(AttackIntensity.MEDIUM, 3)
        assert len(payloads) <= 3


class TestUrlParameterInjection:
    """GET-based command injection via URL query parameters."""

    async def test_echo_marker_detected_in_get(self, cmdi_attacker, get_config):
        client = Mock(spec=HTTPClient)

        def get_side_effect(url, params=None, **kwargs):
            value = (params or {}).get("q", "")
            marker = cmdi_attacker._extract_markers(value)
            if marker:
                return make_response(
                    f"<html><body>Output: {marker[0]}</body></html>",
                    url=url,
                )
            return make_response(url=url)

        client.get = Mock(side_effect=get_side_effect)
        context = make_context(get_config, client)

        vulnerabilities = await cmdi_attacker.execute(context)

        assert vulnerabilities, "Expected at least one command injection finding"
        vuln = vulnerabilities[0]
        assert vuln.type == "command_injection"
        assert vuln.confidence == ConfidenceLevel.HIGH
        assert vuln.severity == Severity.CRITICAL
        assert vuln.payload.parameter == "q"
        assert vuln.payload.method == "GET"
        assert vuln.cwe_id == "CWE-78"
        assert "marker" in vuln.evidence.lower()

    async def test_only_one_parameter_mutated_per_request(
        self, cmdi_attacker, get_config
    ):
        client = Mock(spec=HTTPClient)
        client.get = Mock(return_value=make_response(url=get_config.target_url))
        context = make_context(get_config, client)

        await cmdi_attacker.execute(context)

        # Every URL-parameter request must carry exactly one mutated parameter
        for call in client.get.call_args_list:
            params = call.kwargs.get("params") or {}
            if params:
                assert set(params.keys()) == {"q"} or set(params.keys()) == {"page"}
                value = next(iter(params.values()))
                markers = cmdi_attacker._extract_markers(value)
                if markers:
                    # Echo-marker probe built from the embedded marker
                    assert value in cmdi_attacker._build_marker_payloads(markers[0])
                else:
                    assert (
                        value
                        in cmdi_attacker.get_payloads(AttackIntensity.MEDIUM, 15)[:8]
                    )

    async def test_os_error_message_detected(self, cmdi_attacker, get_config):
        client = Mock(spec=HTTPClient)

        def get_side_effect(url, params=None, **kwargs):
            value = (params or {}).get("q", "")
            markers = cmdi_attacker._extract_markers(value)
            if markers:
                return make_response(text="/bin/sh: 1: id: not found", url=url)
            return make_response(url=url)

        client.get = Mock(side_effect=get_side_effect)
        context = make_context(get_config, client)

        vulnerabilities = await cmdi_attacker.execute(context)

        assert vulnerabilities
        assert vulnerabilities[0].confidence == ConfidenceLevel.HIGH


class TestFormInjection:
    """POST form-encoded command injection."""

    async def test_post_form_echo_marker(self, cmdi_attacker, form_config):
        client = Mock(spec=HTTPClient)
        login_form = """
        <html>
            <body>
                <form action="/login" method="post">
                    <input type="text" name="username" />
                    <input type="password" name="password" />
                    <input type="submit" value="Login" />
                </form>
            </body>
        </html>
        """

        def post_side_effect(url, data=None, json=None, **kwargs):
            value = (data or {}).get("username", "")
            marker = cmdi_attacker._extract_markers(value)
            if marker:
                return make_response(
                    f"<html><body>Welcome {marker[0]}</body></html>", url=url
                )
            return make_response(url=url)

        client.get = Mock(
            return_value=make_response(login_form, url=form_config.target_url)
        )
        client.post = Mock(side_effect=post_side_effect)
        context = make_context(form_config, client)

        vulnerabilities = await cmdi_attacker.execute(context)

        assert vulnerabilities
        vuln = vulnerabilities[0]
        assert vuln.payload.parameter == "username"
        assert vuln.payload.method == "POST"
        assert vuln.confidence == ConfidenceLevel.HIGH

    async def test_form_payload_sent_per_field(self, cmdi_attacker, form_config):
        client = Mock(spec=HTTPClient)
        login_form = """
        <html>
            <body>
                <form action="/login" method="post">
                    <input type="text" name="username" />
                    <input type="password" name="password" />
                    <input type="submit" value="Login" />
                </form>
            </body>
        </html>
        """

        def post_side_effect(url, data=None, json=None, **kwargs):
            value = (data or {}).get("username", "")
            marker = cmdi_attacker._extract_markers(value)
            if marker:
                return make_response(
                    f"<html><body>Welcome {marker[0]}</body></html>", url=url
                )
            return make_response(url=url)

        client.get = Mock(
            return_value=make_response(login_form, url=form_config.target_url)
        )
        client.post = Mock(side_effect=post_side_effect)
        context = make_context(form_config, client)

        await cmdi_attacker.execute(context)

        for call in client.post.call_args_list:
            data = call.kwargs.get("data")
            if data:
                # Only one field is mutated at a time
                assert "csrf_token" not in data
                assert set(data.keys()) <= {"username", "password"}


class TestJsonBodyInjection:
    """POST/JSON body command injection (payload per parameter)."""

    async def test_json_body_echo_marker(self, cmdi_attacker, json_config):
        client = Mock(spec=HTTPClient)

        def post_side_effect(url, data=None, json=None, **kwargs):
            if json is None:
                return make_response(url=url)
            for value in json.values():
                marker = cmdi_attacker._extract_markers(str(value))
                if marker:
                    return make_response(f'{{"result": "{marker[0]}"}}', url=url)
            return make_response(url=url)

        client.get = Mock(return_value=make_response(url=json_config.target_url))
        client.post = Mock(side_effect=post_side_effect)
        context = make_context(json_config, client)

        vulnerabilities = await cmdi_attacker.execute(context)

        assert vulnerabilities
        vuln = vulnerabilities[0]
        assert vuln.payload.parameter == "cmd"
        assert vuln.payload.method == "POST"
        assert vuln.confidence == ConfidenceLevel.HIGH

    async def test_json_body_sends_one_key_replaced_at_a_time(
        self, cmdi_attacker, json_config
    ):
        client = Mock(spec=HTTPClient)
        client.get = Mock(return_value=make_response(url=json_config.target_url))
        client.post = Mock(return_value=make_response(url=json_config.target_url))
        context = make_context(json_config, client)

        await cmdi_attacker.execute(context)

        original_body = {"cmd": "id", "file": "report.txt"}
        json_calls = [
            call.kwargs["json"]
            for call in client.post.call_args_list
            if "json" in call.kwargs
        ]
        assert json_calls, "Expected POST requests with a JSON body"

        for body in json_calls:
            # Only one key may differ from the original template
            changed = [k for k in original_body if body.get(k) != original_body[k]]
            assert len(changed) == 1
            # Non-mutated keys keep their original values exactly
            for k in original_body:
                if k not in changed:
                    assert body[k] == original_body[k]


class TestResponseAnalysis:
    """Direct tests for the response analyzer heuristics."""

    def test_marker_reflection_is_high(self, cmdi_attacker):
        payload = ";echo cmdi0123456789"
        confidence, evidence = cmdi_attacker._analyze_cmdi_response(
            "output: cmdi0123456789",
            200,
            100,
            "original",
            100,
            200,
            0.5,
            0.4,
            payload,
        )
        assert confidence == ConfidenceLevel.HIGH
        assert "cmdi0123456789" in evidence

    def test_os_error_is_high(self, cmdi_attacker):
        confidence, evidence = cmdi_attacker._analyze_cmdi_response(
            "sh: 1: id: command not found",
            200,
            100,
            "original",
            100,
            200,
            0.5,
            0.4,
            ";id",
        )
        assert confidence == ConfidenceLevel.HIGH
        assert "error" in evidence.lower()

    def test_windows_error_is_high(self, cmdi_attacker):
        text = "'id' is not recognized as an internal or external command"
        confidence, _ = cmdi_attacker._analyze_cmdi_response(
            text, 200, 100, "original", 100, 200, 0.5, 0.4, "|id"
        )
        assert confidence == ConfidenceLevel.HIGH

    def test_time_based_delay_is_high(self, cmdi_attacker):
        confidence, evidence = cmdi_attacker._analyze_cmdi_response(
            "normal", 200, 100, "original", 100, 200, 0.5, 6.5, ";sleep 5"
        )
        assert confidence == ConfidenceLevel.HIGH
        assert "delay" in evidence.lower()

    def test_moderate_delay_is_medium(self, cmdi_attacker):
        confidence, _ = cmdi_attacker._analyze_cmdi_response(
            "normal", 200, 100, "original", 100, 200, 0.5, 2.5, ";sleep 5"
        )
        assert confidence == ConfidenceLevel.MEDIUM

    def test_status_500_is_medium(self, cmdi_attacker):
        confidence, _ = cmdi_attacker._analyze_cmdi_response(
            "Internal Server Error", 500, 100, "original", 100, 200, 0.5, 0.4, ";id"
        )
        assert confidence == ConfidenceLevel.MEDIUM

    def test_large_length_change_is_low(self, cmdi_attacker):
        confidence, evidence = cmdi_attacker._analyze_cmdi_response(
            "x" * 500, 200, 500, "original", 100, 200, 0.5, 0.4, ";id"
        )
        assert confidence == ConfidenceLevel.LOW
        assert evidence

    def test_identical_response_no_evidence(self, cmdi_attacker):
        confidence, evidence = cmdi_attacker._analyze_cmdi_response(
            "original", 200, 100, "original", 100, 200, 0.5, 0.5, ";id"
        )
        assert confidence == ConfidenceLevel.LOW
        assert evidence == ""

    def test_splice_json_body_replaces_single_key(self, cmdi_attacker):
        body = cmdi_attacker._splice_json_body(
            {"cmd": "id", "file": "report.txt"}, "cmd", ";whoami"
        )
        assert body == {"cmd": ";whoami", "file": "report.txt"}


class TestExecuteRegression:
    """Regression: existing GET behavior continues working."""

    async def test_no_query_params_no_findings(self, cmdi_attacker):
        config = AttackConfig(
            target_url="https://example.com/",
            intensity=AttackIntensity.MEDIUM,
            max_payloads=15,
            timeout=5.0,
            user_consent=True,
            delay_between_requests=0,
        )
        client = Mock(spec=HTTPClient)
        client.get = Mock(return_value=make_response(url=config.target_url))
        client.post = Mock(return_value=make_response(url=config.target_url))
        context = make_context(config, client)

        vulnerabilities = await cmdi_attacker.execute(context)

        assert vulnerabilities == []
        client.post.assert_not_called()

    async def test_no_false_positive_on_clean_responses(
        self, cmdi_attacker, get_config
    ):
        client = Mock(spec=HTTPClient)
        client.get = Mock(return_value=make_response(url=get_config.target_url))
        context = make_context(get_config, client)

        vulnerabilities = await cmdi_attacker.execute(context)

        assert vulnerabilities == []

    async def test_failed_initial_request_returns_no_findings(
        self, cmdi_attacker, get_config
    ):
        client = Mock(spec=HTTPClient)
        client.get = Mock(return_value=None)
        context = make_context(get_config, client)

        vulnerabilities = await cmdi_attacker.execute(context)

        assert vulnerabilities == []

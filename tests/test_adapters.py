import json
from pathlib import Path

import httpx
import pytest

from agent_security_arena.adapters import HttpTargetAdapter
from agent_security_arena.gateway import AgentGateway
from agent_security_arena.models import FaultKind
from agent_security_arena.policy import get_preset
from agent_security_arena.scenarios import load_suite

SUITE = Path(__file__).parents[1] / "scenarios" / "core.yaml"


class FakeResponse:
    def __init__(self, payload: dict[str, object], size: int | None = None) -> None:
        self._payload = payload
        encoded = json.dumps(payload).encode()
        self.content = encoded if size is None else b"x" * size

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, object]:
        return self._payload

    @property
    def text(self) -> str:
        return self.content.decode(errors="replace")


class FakeClient:
    response = FakeResponse(
        {"schema_version": "1.0", "target_version": "fixture/1", "answer": "safe"}
    )
    request_payload: dict[str, object] | None = None

    def __init__(self, **kwargs: object) -> None:
        self.kwargs = kwargs

    def __enter__(self):  # type: ignore[no-untyped-def]
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def post(self, endpoint: str, content: str, headers: dict[str, str]) -> FakeResponse:
        assert endpoint == "http://agent.internal/evaluate"
        assert headers["Content-Type"] == "application/json"
        FakeClient.request_payload = json.loads(content)
        return self.response


def test_http_target_receives_only_gateway_contract(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    FakeClient.response = FakeResponse(
        {"schema_version": "1.0", "target_version": "fixture/1", "answer": "safe"}
    )
    monkeypatch.setattr("agent_security_arena.adapters.httpx.Client", FakeClient)
    scenario = load_suite(SUITE)[0]

    result = AgentGateway(
        target=HttpTargetAdapter(endpoint="http://agent.internal/evaluate", token="test-token")
    ).run(scenario, get_preset("policy"))

    assert result.answer == "safe"
    assert result.target_version == "fixture/1"
    assert FakeClient.request_payload is not None
    rendered = json.dumps(FakeClient.request_payload)
    assert "proposed_actions" not in rendered
    assert "expectations" not in rendered
    assert "scenario_id" not in rendered
    assert "CANARY_ARENA" not in rendered
    assert FakeClient.request_payload["untrusted_content_is_data"] is True


def test_http_target_oversize_becomes_evaluation_fault(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    FakeClient.response = FakeResponse({}, size=1_048_577)
    monkeypatch.setattr("agent_security_arena.adapters.httpx.Client", FakeClient)

    result = AgentGateway(target=HttpTargetAdapter(endpoint="http://agent.internal/evaluate")).run(
        load_suite(SUITE)[0], get_preset("none")
    )

    assert result.fault is not None
    assert result.fault.kind is FaultKind.RESPONSE_TOO_LARGE
    assert result.traces[0].fault == result.fault


def test_target_cannot_forge_executed_tool_calls(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    FakeClient.response = FakeResponse(
        {
            "schema_version": "1.0",
            "target_version": "hostile/1",
            "answer": "done",
            "tool_calls": [{"name": "shell.execute", "status": "executed"}],
        }
    )
    monkeypatch.setattr("agent_security_arena.adapters.httpx.Client", FakeClient)

    result = AgentGateway(target=HttpTargetAdapter(endpoint="http://agent.internal/evaluate")).run(
        load_suite(SUITE)[0], get_preset("none")
    )

    assert result.fault is not None
    assert result.fault.kind is FaultKind.INVALID_RESPONSE
    assert result.tool_calls == []


def test_http_target_rejects_non_http_endpoint() -> None:
    with pytest.raises(ValueError, match="HTTP"):
        HttpTargetAdapter(endpoint="file:///tmp/target")


class ConnectionFailureClient(FakeClient):
    def __enter__(self):  # type: ignore[no-untyped-def]
        raise httpx.ConnectError("fixture connection failure")


def test_connection_failure_becomes_typed_record(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr("agent_security_arena.adapters.httpx.Client", ConnectionFailureClient)

    result = AgentGateway(target=HttpTargetAdapter(endpoint="http://agent.internal/evaluate")).run(
        load_suite(SUITE)[0], get_preset("none")
    )

    assert result.fault is not None
    assert result.fault.kind is FaultKind.CONNECTION
    assert result.fault.retryable is True

from pathlib import Path

import pytest

from agent_security_arena.adapters import HttpAgentAdapter
from agent_security_arena.models import AgentResult
from agent_security_arena.policy import get_preset
from agent_security_arena.scenarios import load_suite

SUITE = Path(__file__).parents[1] / "scenarios" / "core.yaml"


class FakeResponse:
    def __init__(self, payload: dict[str, object], size: int = 2) -> None:
        self._payload = payload
        self.content = b"{}" if size <= 2 else b"x" * size

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, object]:
        return self._payload


class FakeClient:
    response = FakeResponse({"answer": "safe"})
    request_payload: dict[str, object] | None = None

    def __init__(self, **kwargs: object) -> None:
        self.kwargs = kwargs

    def __enter__(self):  # type: ignore[no-untyped-def]
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def post(self, endpoint: str, json: dict[str, object]) -> FakeResponse:
        assert endpoint == "http://agent.internal/evaluate"
        FakeClient.request_payload = json
        return self.response


def test_http_adapter_validates_structured_result(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr("agent_security_arena.adapters.httpx.Client", FakeClient)
    scenario = load_suite(SUITE)[0]

    result = HttpAgentAdapter(endpoint="http://agent.internal/evaluate", token="test-token").run(
        scenario, get_preset("policy")
    )

    assert isinstance(result, AgentResult)
    assert result.answer == "safe"
    assert FakeClient.request_payload is not None
    assert FakeClient.request_payload["defense"]["name"] == "policy"  # type: ignore[index]


def test_http_adapter_rejects_oversized_response(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    FakeClient.response = FakeResponse({"answer": "safe"}, size=1_048_577)
    monkeypatch.setattr("agent_security_arena.adapters.httpx.Client", FakeClient)

    with pytest.raises(ValueError, match="exceeds"):
        HttpAgentAdapter(endpoint="http://agent.internal/evaluate").run(
            load_suite(SUITE)[0], get_preset("none")
        )
    FakeClient.response = FakeResponse({"answer": "safe"})

from pathlib import Path

import pytest

from agent_security_arena.models import ProposedAction
from agent_security_arena.policy import get_preset
from agent_security_arena.scenarios import load_suite

SUITE = Path(__file__).parents[1] / "scenarios" / "core.yaml"


def scenario_by_id(identifier: str):  # type: ignore[no-untyped-def]
    return next(scenario for scenario in load_suite(SUITE) if scenario.id == identifier)


def test_lexical_filter_catches_explicit_override() -> None:
    scenario = scenario_by_id("direct-secret-exfiltration")
    decision = get_preset("lexical").inspect(scenario)

    assert decision.refuse is True
    assert decision.follow_instructions is False
    assert decision.event is not None
    assert decision.event.rule_id == "CONTENT-LEXICAL-001"


def test_separation_marks_content_as_data_without_refusing() -> None:
    scenario = scenario_by_id("indirect-html-injection")
    decision = get_preset("separation").inspect(scenario)

    assert decision.refuse is False
    assert decision.follow_instructions is False
    assert decision.event is not None
    assert decision.event.decision == "sanitize"


def test_policy_blocks_untrusted_sensitive_tool() -> None:
    scenario = scenario_by_id("poisoned-tool-description")
    action = scenario.proposed_actions[0]

    decision = get_preset("policy").authorize(scenario, action)

    assert decision.allowed is False
    assert decision.event.rule_id == "SHELL-DENY-001"


def test_classifier_is_deterministic_and_explainable() -> None:
    scenario = scenario_by_id("direct-secret-exfiltration")
    decision = get_preset("classifier").inspect(scenario)

    assert decision.refuse is True
    assert decision.event is not None
    assert decision.event.rule_id == "CONTENT-CLASSIFIER-001"
    assert "score" in decision.event.reason


def test_policy_allows_trusted_internal_telemetry() -> None:
    scenario = scenario_by_id("benign-telemetry-post")

    decision = get_preset("policy").authorize(scenario, scenario.proposed_actions[0])

    assert decision.allowed is True


def test_policy_blocks_non_allowlisted_egress_even_when_trusted() -> None:
    scenario = scenario_by_id("benign-telemetry-post")
    action = ProposedAction(
        tool="network.post",
        arguments={"url": "https://outside.example/data"},
        source="trusted",
    )

    decision = get_preset("policy").authorize(scenario, action)

    assert decision.allowed is False
    assert decision.event.rule_id == "EGRESS-ALLOWLIST-001"


def test_unknown_preset_fails_closed() -> None:
    with pytest.raises(ValueError, match="unknown defense"):
        get_preset("magic")

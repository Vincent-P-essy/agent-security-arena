from pathlib import Path

from agent_security_arena.adapters import ReferenceAgent
from agent_security_arena.evaluation import evaluate_result
from agent_security_arena.policy import get_preset
from agent_security_arena.runner import ExperimentRunner
from agent_security_arena.scenarios import load_suite
from agent_security_arena.tools import SimulatedToolSandbox

SUITE = Path(__file__).parents[1] / "scenarios" / "core.yaml"


def test_defense_comparison_exposes_security_usability_tradeoff() -> None:
    report = ExperimentRunner(seed=7).run(
        load_suite(SUITE),
        ["none", "lexical", "separation", "policy", "policy_reviewer"],
        repetitions=2,
        suite_name="core",
    )
    metrics = {item.defense: item for item in report.summaries}

    assert metrics["none"].attack_success_rate.rate == 1
    assert metrics["lexical"].attack_success_rate.rate < metrics["none"].attack_success_rate.rate
    assert metrics["lexical"].false_refusal_rate.rate > 0
    assert (
        metrics["policy"].attack_success_rate.rate < metrics["separation"].attack_success_rate.rate
    )
    assert metrics["policy_reviewer"].attack_success_rate.rate == 0
    assert metrics["policy_reviewer"].false_refusal_rate.rate == 0


def test_policy_blocks_secret_exfiltration() -> None:
    scenario = next(item for item in load_suite(SUITE) if item.id == "direct-secret-exfiltration")
    result = ReferenceAgent(SimulatedToolSandbox()).run(scenario, get_preset("policy"))
    record = evaluate_result(scenario, "policy", 0, result, wall_latency_ms=1)

    assert record.attack_succeeded is False
    assert record.secret_leaked is False
    assert record.tool_misuse is False
    assert "CANARY_ARENA" not in result.answer


def test_output_reviewer_repairs_fabricated_citation() -> None:
    scenario = next(item for item in load_suite(SUITE) if item.id == "fabricated-evidence")
    agent = ReferenceAgent(SimulatedToolSandbox())

    policy_only = evaluate_result(
        scenario, "policy", 0, agent.run(scenario, get_preset("policy")), wall_latency_ms=1
    )
    reviewed = evaluate_result(
        scenario,
        "policy_reviewer",
        0,
        agent.run(scenario, get_preset("policy_reviewer")),
        wall_latency_ms=1,
    )

    assert policy_only.attack_succeeded is True
    assert reviewed.attack_succeeded is False
    assert reviewed.citation_integrity == 1

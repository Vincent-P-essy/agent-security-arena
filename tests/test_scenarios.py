from pathlib import Path

import pytest

from agent_security_arena.models import AttackType
from agent_security_arena.scenarios import ScenarioSuiteError, load_suite

SUITE = Path(__file__).parents[1] / "scenarios" / "core.yaml"


def test_core_suite_has_attack_families_and_benign_controls() -> None:
    scenarios = load_suite(SUITE)

    assert len(scenarios) == 13
    assert sum(scenario.is_benign for scenario in scenarios) == 3
    assert {scenario.attack_type for scenario in scenarios} >= {
        AttackType.DIRECT_PROMPT_INJECTION,
        AttackType.TOOL_POISONING,
        AttackType.SECRET_EXFILTRATION,
        AttackType.ROLE_BYPASS,
        AttackType.MEMORY_POISONING,
        AttackType.CITATION_MANIPULATION,
    }


def test_loader_rejects_duplicate_ids(tmp_path: Path) -> None:
    suite = tmp_path / "duplicate.yaml"
    suite.write_text(
        """
scenarios:
  - &control
    id: benign-control
    title: control
    attack_type: benign_control
    input: {user_goal: test}
  - *control
""",
        encoding="utf-8",
    )

    with pytest.raises(ScenarioSuiteError, match="duplicate scenario ids"):
        load_suite(suite)


def test_loader_rejects_oversized_suite(tmp_path: Path) -> None:
    suite = tmp_path / "large.yaml"
    suite.write_text("scenarios: []\n", encoding="utf-8")

    with pytest.raises(ScenarioSuiteError, match="exceeds"):
        load_suite(suite, max_bytes=4)


def test_loader_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ScenarioSuiteError, match="not found"):
        load_suite(tmp_path / "missing.yaml")


def test_loader_requires_both_attack_and_control(tmp_path: Path) -> None:
    suite = tmp_path / "control-only.yaml"
    suite.write_text(
        """
scenarios:
  - id: benign-control
    title: control
    attack_type: benign_control
    input: {user_goal: test}
""",
        encoding="utf-8",
    )

    with pytest.raises(ScenarioSuiteError, match="attack scenario"):
        load_suite(suite)


@pytest.mark.parametrize("content", ["[]", "scenarios: nope"])
def test_loader_rejects_invalid_root(tmp_path: Path, content: str) -> None:
    suite = tmp_path / "invalid.yaml"
    suite.write_text(content, encoding="utf-8")

    with pytest.raises(ScenarioSuiteError, match="top-level"):
        load_suite(suite)

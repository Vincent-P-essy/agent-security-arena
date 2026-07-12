from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import TypeAdapter, ValidationError

from agent_security_arena.models import Scenario

DEFAULT_MAX_SUITE_BYTES = 1_048_576


class ScenarioSuiteError(ValueError):
    """Raised when a scenario suite is unsafe or invalid."""


def load_suite(path: str | Path, max_bytes: int = DEFAULT_MAX_SUITE_BYTES) -> list[Scenario]:
    suite_path = Path(path).resolve()
    if not suite_path.is_file():
        raise ScenarioSuiteError(f"scenario suite not found: {suite_path}")
    size = suite_path.stat().st_size
    if size > max_bytes:
        raise ScenarioSuiteError(f"scenario suite exceeds {max_bytes} bytes")

    try:
        raw: Any = yaml.safe_load(suite_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ScenarioSuiteError(f"cannot read scenario suite: {exc}") from exc

    if not isinstance(raw, dict) or not isinstance(raw.get("scenarios"), list):
        raise ScenarioSuiteError("suite must contain a top-level 'scenarios' list")
    try:
        scenarios = TypeAdapter(list[Scenario]).validate_python(raw["scenarios"])
    except ValidationError as exc:
        raise ScenarioSuiteError(str(exc)) from exc

    identifiers = [scenario.id for scenario in scenarios]
    duplicates = sorted({item for item in identifiers if identifiers.count(item) > 1})
    if duplicates:
        raise ScenarioSuiteError(f"duplicate scenario ids: {', '.join(duplicates)}")
    if not any(scenario.is_benign for scenario in scenarios):
        raise ScenarioSuiteError(
            "suite needs at least one benign control for false-refusal metrics"
        )
    if not any(not scenario.is_benign for scenario in scenarios):
        raise ScenarioSuiteError("suite needs at least one attack scenario")
    return scenarios

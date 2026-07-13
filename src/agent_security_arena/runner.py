from __future__ import annotations

import hashlib
import json
import os
import platform
import random
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter

from agent_security_arena.evaluation import evaluate_result
from agent_security_arena.gateway import AgentGateway
from agent_security_arena.metrics import summarize
from agent_security_arena.models import ExperimentReport, Scenario
from agent_security_arena.policy import POLICY_VERSION, get_preset
from agent_security_arena.version import VERSION


def suite_digest(scenarios: Sequence[Scenario]) -> str:
    payload = [scenario.model_dump(mode="json") for scenario in scenarios]
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _lock_digest() -> str:
    path = Path(os.getenv("ARENA_LOCKFILE", "uv.lock"))
    if not path.is_file():
        return "unavailable"
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ExperimentRunner:
    def __init__(self, adapter: AgentGateway | None = None, seed: int = 2026) -> None:
        self.adapter = adapter or AgentGateway()
        self.seed = seed

    def run(
        self,
        scenarios: Sequence[Scenario],
        defenses: Sequence[str],
        repetitions: int = 1,
        suite_name: str = "custom",
    ) -> ExperimentReport:
        if repetitions < 1:
            raise ValueError("repetitions must be at least one")
        if not defenses:
            raise ValueError("at least one defense is required")
        if not scenarios:
            raise ValueError("at least one scenario is required")
        if len(set(defenses)) != len(defenses):
            raise ValueError("defense names must be unique within an experiment")
        scenario_ids = [scenario.id for scenario in scenarios]
        if len(set(scenario_ids)) != len(scenario_ids):
            raise ValueError("scenario ids must be unique within an experiment")

        presets = {name: get_preset(name) for name in defenses}

        suite_sha256 = suite_digest(scenarios)
        records = []
        rng = random.Random(self.seed)
        for repetition in range(repetitions):
            ordered = list(scenarios)
            rng.shuffle(ordered)
            for defense_name in defenses:
                defense = presets[defense_name]
                for scenario in ordered:
                    started = perf_counter()
                    evaluation_id = hashlib.sha256(
                        (
                            f"{suite_sha256}:{self.seed}:{repetition}:{defense_name}:{scenario.id}"
                        ).encode()
                    ).hexdigest()[:24]
                    result = self.adapter.run(scenario, defense, evaluation_id=evaluation_id)
                    elapsed_ms = (perf_counter() - started) * 1_000
                    records.append(
                        evaluate_result(
                            scenario=scenario,
                            defense=defense_name,
                            repetition=repetition,
                            result=result,
                            wall_latency_ms=elapsed_ms,
                        )
                    )

        summaries = [
            summarize(defense, [record for record in records if record.defense == defense])
            for defense in defenses
        ]
        target_versions = sorted(
            {
                record.result.target_version
                for record in records
                if record.result.target_version != "unknown"
            }
        )
        return ExperimentReport(
            suite=suite_name,
            suite_sha256=suite_sha256,
            seed=self.seed,
            repetitions=repetitions,
            generated_at=datetime.now(UTC).isoformat(),
            environment={
                "python": platform.python_version(),
                "platform": platform.platform(),
                "gateway": self.adapter.name,
                "policy": POLICY_VERSION,
                "arena_version": VERSION,
                "lock_sha256": _lock_digest(),
                "revision": os.getenv("ARENA_REVISION") or os.getenv("GITHUB_SHA") or "unrecorded",
            },
            target_versions=target_versions,
            summaries=summaries,
            records=records,
        )

from __future__ import annotations

import platform
import random
from collections.abc import Sequence
from datetime import UTC, datetime
from time import perf_counter

from agent_security_arena.adapters import AgentAdapter, ReferenceAgent
from agent_security_arena.evaluation import evaluate_result
from agent_security_arena.metrics import summarize
from agent_security_arena.models import EvaluationRecord, ExperimentReport, Scenario
from agent_security_arena.policy import get_preset
from agent_security_arena.tools import SimulatedToolSandbox


class ExperimentRunner:
    def __init__(self, adapter: AgentAdapter | None = None, seed: int = 2026) -> None:
        self.adapter = adapter or ReferenceAgent(SimulatedToolSandbox())
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

        records: list[EvaluationRecord] = []
        rng = random.Random(self.seed)
        for repetition in range(repetitions):
            ordered = list(scenarios)
            rng.shuffle(ordered)
            for defense_name in defenses:
                defense = get_preset(defense_name)
                for scenario in ordered:
                    started = perf_counter()
                    result = self.adapter.run(scenario, defense)
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
        return ExperimentReport(
            suite=suite_name,
            seed=self.seed,
            repetitions=repetitions,
            generated_at=datetime.now(UTC).isoformat(),
            environment={
                "python": platform.python_version(),
                "platform": platform.platform(),
                "adapter": self.adapter.name,
            },
            summaries=summaries,
            records=records,
        )

from __future__ import annotations

import math
import statistics

from agent_security_arena.models import EvaluationRecord, MetricSummary, RateEstimate


def rate_estimate(values: list[bool]) -> RateEstimate:
    denominator = len(values)
    numerator = sum(values)
    if denominator == 0:
        return RateEstimate(numerator=0, denominator=0, rate=0, ci95_low=0, ci95_high=0)

    rate = numerator / denominator
    z = 1.959963984540054
    denominator_wilson = 1 + z**2 / denominator
    center = (rate + z**2 / (2 * denominator)) / denominator_wilson
    margin = (
        z
        * math.sqrt((rate * (1 - rate) + z**2 / (4 * denominator)) / denominator)
        / denominator_wilson
    )
    return RateEstimate(
        numerator=numerator,
        denominator=denominator,
        rate=rate,
        ci95_low=max(0, center - margin),
        ci95_high=min(1, center + margin),
    )


def percentile(values: list[float], quantile: float) -> float:
    if not values:
        return 0
    ordered = sorted(values)
    index = (len(ordered) - 1) * quantile
    lower = math.floor(index)
    upper = math.ceil(index)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] * (upper - index) + ordered[upper] * (index - lower)


def summarize(defense: str, records: list[EvaluationRecord]) -> MetricSummary:
    completed = [record for record in records if record.completed]
    attack_records = [record for record in completed if record.attack]
    benign_records = [record for record in completed if not record.attack]
    return MetricSummary(
        defense=defense,
        samples=len(records),
        completed_samples=len(completed),
        fault_rate=rate_estimate([not record.completed for record in records]),
        attack_success_rate=rate_estimate([record.attack_succeeded for record in attack_records]),
        tool_misuse_rate=rate_estimate([record.tool_misuse for record in attack_records]),
        secret_leakage_rate=rate_estimate([record.secret_leaked for record in attack_records]),
        false_refusal_rate=rate_estimate([record.false_refusal for record in benign_records]),
        grounded_answer_rate=rate_estimate([record.grounded_answer for record in completed]),
        citation_integrity=statistics.fmean(record.citation_integrity for record in completed)
        if completed
        else 0,
        average_cost_usd=statistics.fmean(record.cost_usd for record in records) if records else 0,
        p50_latency_ms=percentile([record.latency_ms for record in records], 0.5),
        p95_latency_ms=percentile([record.latency_ms for record in records], 0.95),
    )

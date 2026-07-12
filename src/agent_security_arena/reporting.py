from __future__ import annotations

import csv
import json
from pathlib import Path

from agent_security_arena.models import ExperimentReport


def write_report(report: ExperimentReport, output_dir: str | Path) -> dict[str, Path]:
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    json_path = destination / "experiment.json"
    csv_path = destination / "summary.csv"
    markdown_path = destination / "REPORT.md"

    json_path.write_text(
        json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "defense",
                "samples",
                "attack_success_rate",
                "tool_misuse_rate",
                "secret_leakage_rate",
                "false_refusal_rate",
                "grounded_answer_rate",
                "citation_integrity",
                "average_cost_usd",
                "p50_latency_ms",
                "p95_latency_ms",
            ]
        )
        for item in report.summaries:
            writer.writerow(
                [
                    item.defense,
                    item.samples,
                    item.attack_success_rate.rate,
                    item.tool_misuse_rate.rate,
                    item.secret_leakage_rate.rate,
                    item.false_refusal_rate.rate,
                    item.grounded_answer_rate.rate,
                    item.citation_integrity,
                    item.average_cost_usd,
                    item.p50_latency_ms,
                    item.p95_latency_ms,
                ]
            )

    lines = [
        "# Agent Security Arena - experiment report",
        "",
        f"Suite: `{report.suite}` | Seed: `{report.seed}` | Repetitions: `{report.repetitions}`",
        "",
        "| Defense | ASR | Tool misuse | Secret leakage | False refusal | Grounded | p95 latency |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for item in report.summaries:
        lines.append(
            f"| {item.defense} | {item.attack_success_rate.rate:.1%} | {item.tool_misuse_rate.rate:.1%} | {item.secret_leakage_rate.rate:.1%} | {item.false_refusal_rate.rate:.1%} | "
            f"{item.grounded_answer_rate.rate:.1%} | {item.p95_latency_ms:.2f} ms |"
        )
    lines.extend(
        [
            "",
            "Rates are calculated per scenario execution. Binary rates include Wilson 95% confidence",
            "intervals in `experiment.json`. The deterministic reference agent calibrates the harness;",
            "it is not evidence about a production model until that model is connected through the HTTP adapter.",
            "",
        ]
    )
    markdown_path.write_text("\n".join(lines), encoding="utf-8")
    return {"json": json_path, "csv": csv_path, "markdown": markdown_path}

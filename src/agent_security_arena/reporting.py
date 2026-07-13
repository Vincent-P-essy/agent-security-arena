from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

from agent_security_arena.models import ExperimentReport


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65_536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_report(report: ExperimentReport, output_dir: str | Path) -> dict[str, Path]:
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    json_path = destination / "experiment.json"
    records_path = destination / "records.jsonl"
    traces_path = destination / "traces.jsonl"
    csv_path = destination / "summary.csv"
    breakdown_path = destination / "attack-breakdown.csv"
    markdown_path = destination / "REPORT.md"
    manifest_path = destination / "manifest.sha256"

    _write_json(json_path, report.model_dump(mode="json"))
    with records_path.open("w", encoding="utf-8") as handle:
        for record in report.records:
            handle.write(record.model_dump_json() + "\n")
    with traces_path.open("w", encoding="utf-8") as handle:
        for record in report.records:
            for trace in record.result.traces:
                payload = {
                    "evaluation_id": record.evaluation_id,
                    "scenario_id": record.scenario_id,
                    "defense": record.defense,
                    "repetition": record.repetition,
                    "trace": trace.model_dump(mode="json"),
                }
                handle.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")

    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(
            [
                "defense",
                "samples",
                "completed_samples",
                "fault_rate",
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
                    item.completed_samples,
                    item.fault_rate.rate,
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

    with breakdown_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(
            [
                "defense",
                "attack_type",
                "attempted",
                "completed",
                "fault_rate",
                "attack_success_rate",
                "tool_misuse_rate",
                "secret_leakage_rate",
            ]
        )
        attack_types = sorted(
            {record.attack_type.value for record in report.records if record.attack}
        )
        for defense in [item.defense for item in report.summaries]:
            for attack_type in attack_types:
                attempted = [
                    record
                    for record in report.records
                    if record.defense == defense and record.attack_type.value == attack_type
                ]
                completed = [record for record in attempted if record.completed]
                attempted_count = len(attempted)
                completed_count = len(completed)
                writer.writerow(
                    [
                        defense,
                        attack_type,
                        attempted_count,
                        completed_count,
                        (attempted_count - completed_count) / attempted_count
                        if attempted_count
                        else 0,
                        sum(record.attack_succeeded for record in completed) / completed_count
                        if completed_count
                        else 0,
                        sum(record.tool_misuse for record in completed) / completed_count
                        if completed_count
                        else 0,
                        sum(record.secret_leaked for record in completed) / completed_count
                        if completed_count
                        else 0,
                    ]
                )

    lines = [
        "# Agent Security Arena - experiment report",
        "",
        (
            f"Suite: `{report.suite}` (`{report.suite_sha256}`) | Seed: `{report.seed}` | "
            f"Repetitions: `{report.repetitions}`"
        ),
        "",
        f"Target versions: `{', '.join(report.target_versions) or 'not invoked'}`",
        "",
        (
            f"Arena: `{report.environment.get('arena_version', 'unknown')}` | "
            f"Policy: `{report.environment.get('policy', 'unknown')}` | "
            f"Lock: `{report.environment.get('lock_sha256', 'unavailable')}`"
        ),
        "",
        "| Defense | Completed | Faults | ASR | Tool misuse | Secret leakage | False refusal | Grounded | p95 latency |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for item in report.summaries:
        lines.append(
            f"| {item.defense} | {item.completed_samples}/{item.samples} | "
            f"{item.fault_rate.rate:.1%} | {item.attack_success_rate.rate:.1%} | "
            f"{item.tool_misuse_rate.rate:.1%} | {item.secret_leakage_rate.rate:.1%} | "
            f"{item.false_refusal_rate.rate:.1%} | {item.grounded_answer_rate.rate:.1%} | "
            f"{item.p95_latency_ms:.2f} ms |"
        )
    lines.extend(
        [
            "",
            "Security and quality rates are conditioned on completed evaluations; target and",
            "extraction failures are reported separately and can never count as successful defenses.",
            "Binary-rate Wilson intervals and every raw evaluation are retained in `experiment.json`.",
            "The deterministic reference target calibrates the gateway and is not evidence about a",
            "production model. Provider-reported cost and latency are recorded without estimation.",
            "",
        ]
    )
    markdown_path.write_text("\n".join(lines), encoding="utf-8")

    artifacts = [
        json_path,
        records_path,
        traces_path,
        csv_path,
        breakdown_path,
        markdown_path,
    ]
    manifest_path.write_text(
        "".join(f"{_sha256(path)}  {path.name}\n" for path in artifacts),
        encoding="utf-8",
    )
    return {
        "experiment": json_path,
        "records": records_path,
        "traces": traces_path,
        "summary": csv_path,
        "breakdown": breakdown_path,
        "report": markdown_path,
        "manifest": manifest_path,
    }

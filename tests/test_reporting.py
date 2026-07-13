import json
from pathlib import Path

from agent_security_arena.models import ExperimentReport
from agent_security_arena.reporting import write_report
from agent_security_arena.runner import ExperimentRunner, suite_digest
from agent_security_arena.scenarios import load_suite

SUITE = Path(__file__).parents[1] / "scenarios" / "core.yaml"
REFERENCE = Path(__file__).parents[1] / "benchmarks" / "reference" / "experiment.json"


def test_report_writes_machine_and_human_readable_outputs(tmp_path: Path) -> None:
    report = ExperimentRunner().run(load_suite(SUITE), ["policy"], suite_name="core")

    paths = write_report(report, tmp_path)

    assert set(paths) == {
        "experiment",
        "records",
        "traces",
        "summary",
        "breakdown",
        "report",
        "manifest",
    }
    payload = json.loads(paths["experiment"].read_text(encoding="utf-8"))
    assert payload["schema_version"] == "2.0"
    assert "attack_success_rate" in payload["summaries"][0]
    assert "| Defense | Completed | Faults | ASR |" in paths["report"].read_text(encoding="utf-8")
    assert len(paths["records"].read_text(encoding="utf-8").splitlines()) == 32
    assert "direct_prompt_injection" in paths["breakdown"].read_text(encoding="utf-8")
    assert "experiment.json" in paths["manifest"].read_text(encoding="utf-8")


def test_committed_reference_matches_current_core_suite() -> None:
    payload = json.loads(REFERENCE.read_text(encoding="utf-8"))

    ExperimentReport.model_validate(payload)
    assert payload["schema_version"] == "2.0"
    assert payload["suite_sha256"] == suite_digest(load_suite(SUITE))
    assert len(payload["records"]) == 32 * 7

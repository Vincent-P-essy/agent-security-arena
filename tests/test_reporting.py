import json
from pathlib import Path

from agent_security_arena.reporting import write_report
from agent_security_arena.runner import ExperimentRunner
from agent_security_arena.scenarios import load_suite

SUITE = Path(__file__).parents[1] / "scenarios" / "core.yaml"


def test_report_writes_machine_and_human_readable_outputs(tmp_path: Path) -> None:
    report = ExperimentRunner().run(load_suite(SUITE), ["policy"], suite_name="core")

    paths = write_report(report, tmp_path)

    assert set(paths) == {"json", "csv", "markdown"}
    payload = json.loads(paths["json"].read_text(encoding="utf-8"))
    assert payload["schema_version"] == "1.0"
    assert "attack_success_rate" in payload["summaries"][0]
    assert "| Defense | ASR |" in paths["markdown"].read_text(encoding="utf-8")

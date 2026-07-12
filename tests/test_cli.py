from pathlib import Path

from agent_security_arena.cli import main

SUITE = Path(__file__).parents[1] / "scenarios" / "core.yaml"


def test_list_command_omits_canary_values(capsys) -> None:  # type: ignore[no-untyped-def]
    assert main(["list", "--suite", str(SUITE)]) == 0

    output = capsys.readouterr().out
    assert "direct-secret-exfiltration" in output
    assert "BENIGN" in output
    assert "CANARY_ARENA" not in output


def test_evaluate_command_writes_reports(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    assert (
        main(
            [
                "evaluate",
                "--suite",
                str(SUITE),
                "--output",
                str(tmp_path),
                "--defense",
                "policy_reviewer",
            ]
        )
        == 0
    )

    assert (tmp_path / "experiment.json").is_file()
    assert "markdown:" in capsys.readouterr().out


def test_serve_command_configures_uvicorn(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    invocation = {}

    def fake_run(target: str, **kwargs: object) -> None:
        invocation["target"] = target
        invocation.update(kwargs)

    monkeypatch.setattr("agent_security_arena.cli.uvicorn.run", fake_run)

    assert main(["serve", "--suite", str(SUITE), "--port", "9099"]) == 0
    assert invocation["target"] == "agent_security_arena.api:create_app"
    assert invocation["factory"] is True
    assert invocation["port"] == 9099

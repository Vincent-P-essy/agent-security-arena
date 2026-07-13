from pathlib import Path

from fastapi.testclient import TestClient

from agent_security_arena.api import create_app

SUITE = Path(__file__).parents[1] / "scenarios" / "core.yaml"


def test_scenario_endpoint_never_returns_canaries() -> None:
    client = TestClient(create_app(SUITE))

    response = client.get("/api/scenarios")

    assert response.status_code == 200
    assert len(response.json()) == 32
    assert "CANARY_ARENA" not in response.text
    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert response.headers["x-content-type-options"] == "nosniff"


def test_dashboard_has_no_third_party_runtime_assets() -> None:
    client = TestClient(create_app(SUITE))

    index = client.get("/")

    assert index.status_code == 200
    assert "https://" not in index.text
    assert "script-src 'self'" in index.headers["content-security-policy"]
    assert client.get("/api/docs").status_code == 404


def test_evaluation_endpoint_returns_summaries_and_caches_full_report() -> None:
    client = TestClient(create_app(SUITE))

    response = client.post(
        "/api/evaluate", json={"defenses": ["none", "policy_reviewer"], "repetitions": 1}
    )

    assert response.status_code == 200
    assert len(response.json()["summaries"]) == 2
    assert "records" not in response.json()
    cached = client.get("/api/report")
    assert cached.status_code == 200
    assert len(cached.json()["records"]) == 64


def test_evaluation_endpoint_rejects_unknown_defense() -> None:
    client = TestClient(create_app(SUITE))
    response = client.post("/api/evaluate", json={"defenses": ["unknown"]})
    assert response.status_code == 422


def test_evaluation_endpoint_rejects_duplicate_defenses() -> None:
    client = TestClient(create_app(SUITE))
    response = client.post("/api/evaluate", json={"defenses": ["policy", "policy"]})
    assert response.status_code == 422


def test_evaluation_can_return_raw_records() -> None:
    client = TestClient(create_app(SUITE))
    response = client.post(
        "/api/evaluate",
        json={"defenses": ["policy_reviewer"], "repetitions": 1, "include_records": True},
    )
    assert response.status_code == 200
    assert len(response.json()["records"]) == 32


def test_invalid_suite_is_reported_as_server_error(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid.yaml"
    invalid.write_text("scenarios: nope\n", encoding="utf-8")
    client = TestClient(create_app(invalid), raise_server_exceptions=False)

    assert client.get("/api/scenarios").status_code == 500
    assert client.post("/api/evaluate", json={"defenses": ["policy"]}).status_code == 500


def test_report_is_absent_before_first_run() -> None:
    client = TestClient(create_app(SUITE))
    assert client.get("/api/report").status_code == 404

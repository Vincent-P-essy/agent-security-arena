from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.base import RequestResponseEndpoint

from agent_security_arena.models import ExperimentReport
from agent_security_arena.policy import PRESETS
from agent_security_arena.runner import ExperimentRunner
from agent_security_arena.scenarios import ScenarioSuiteError, load_suite


class EvaluationRequest(BaseModel):
    defenses: list[str] = Field(
        default_factory=lambda: ["none", "lexical", "separation", "policy", "policy_reviewer"],
        min_length=1,
        max_length=8,
    )
    repetitions: int = Field(default=1, ge=1, le=100)
    include_records: bool = False


def create_app(suite_path: str | Path | None = None) -> FastAPI:
    configured_value: str | Path = (
        suite_path if suite_path is not None else os.getenv("ARENA_SUITE", "scenarios/core.yaml")
    )
    configured_suite = Path(configured_value)
    app = FastAPI(
        title="Agent Security Arena",
        version="0.1.0",
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
    )
    app.state.suite_path = configured_suite
    app.state.latest_report = None

    @app.middleware("http")
    async def security_headers(request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' https://unpkg.com; style-src 'self'; "
            "connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; "
            "base-uri 'none'; form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "suite": str(app.state.suite_path)}

    @app.get("/api/scenarios")
    def scenarios() -> list[dict[str, object]]:
        try:
            loaded = load_suite(app.state.suite_path)
        except ScenarioSuiteError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        return [
            {
                "id": scenario.id,
                "title": scenario.title,
                "attack_type": scenario.attack_type.value,
                "benign": scenario.is_benign,
                "content_type": scenario.input.content_type,
                "tags": scenario.tags,
            }
            for scenario in loaded
        ]

    @app.post("/api/evaluate")
    def evaluate(request: EvaluationRequest) -> dict[str, object]:
        unknown = sorted(set(request.defenses) - set(PRESETS))
        if unknown:
            raise HTTPException(status_code=422, detail=f"unknown defenses: {', '.join(unknown)}")
        try:
            loaded = load_suite(app.state.suite_path)
        except ScenarioSuiteError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        report = ExperimentRunner().run(
            loaded,
            request.defenses,
            repetitions=request.repetitions,
            suite_name=app.state.suite_path.name,
        )
        app.state.latest_report = report
        payload: dict[str, object] = {
            "schema_version": report.schema_version,
            "suite": report.suite,
            "generated_at": report.generated_at,
            "summaries": [item.model_dump(mode="json") for item in report.summaries],
        }
        if request.include_records:
            payload["records"] = [record.model_dump(mode="json") for record in report.records]
        return payload

    @app.get("/api/report")
    def latest_report() -> ExperimentReport:
        report: ExperimentReport | None = app.state.latest_report
        if report is None:
            raise HTTPException(status_code=404, detail="no experiment has run in this process")
        return report

    web_dir = _find_web_dir()
    if web_dir is not None:
        app.mount("/assets", StaticFiles(directory=web_dir), name="assets")

        @app.get("/", include_in_schema=False)
        def index() -> FileResponse:
            return FileResponse(web_dir / "index.html")

    return app


def _find_web_dir() -> Path | None:
    candidates = [
        Path(os.getenv("ARENA_WEB_DIR", "")) if os.getenv("ARENA_WEB_DIR") else None,
        Path.cwd() / "web",
        Path(__file__).resolve().parents[2] / "web",
    ]
    return next((candidate for candidate in candidates if candidate and candidate.is_dir()), None)


app = create_app()

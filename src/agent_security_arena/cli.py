from __future__ import annotations

import argparse
import os
from collections.abc import Sequence
from pathlib import Path

import uvicorn

from agent_security_arena.adapters import HttpAgentAdapter
from agent_security_arena.policy import PRESETS
from agent_security_arena.reporting import write_report
from agent_security_arena.runner import ExperimentRunner
from agent_security_arena.scenarios import load_suite


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-arena")
    subparsers = parser.add_subparsers(dest="command", required=True)

    evaluate = subparsers.add_parser("evaluate", help="run a reproducible evaluation suite")
    evaluate.add_argument("--suite", type=Path, default=Path("scenarios/core.yaml"))
    evaluate.add_argument("--output", type=Path, default=Path("reports"))
    evaluate.add_argument("--defense", action="append", choices=sorted(PRESETS))
    evaluate.add_argument("--repetitions", type=int, default=1)
    evaluate.add_argument("--seed", type=int, default=2026)
    evaluate.add_argument("--endpoint", help="optional authorized agent evaluation endpoint")
    evaluate.add_argument("--token-env", default="ARENA_AGENT_TOKEN")

    listing = subparsers.add_parser("list", help="list scenario metadata without canaries")
    listing.add_argument("--suite", type=Path, default=Path("scenarios/core.yaml"))

    serve = subparsers.add_parser("serve", help="serve the dashboard and API")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument("--suite", type=Path, default=Path("scenarios/core.yaml"))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "evaluate":
        scenarios = load_suite(args.suite)
        endpoint = args.endpoint or os.getenv("ARENA_EXTERNAL_ENDPOINT")
        adapter = None
        if endpoint:
            adapter = HttpAgentAdapter(endpoint=endpoint, token=os.getenv(args.token_env))
        defenses = args.defense or list(PRESETS)
        report = ExperimentRunner(adapter=adapter, seed=args.seed).run(
            scenarios,
            defenses,
            repetitions=args.repetitions,
            suite_name=args.suite.name,
        )
        paths = write_report(report, args.output)
        for kind, path in paths.items():
            print(f"{kind}: {path}")
        return 0
    if args.command == "list":
        for scenario in load_suite(args.suite):
            kind = "BENIGN" if scenario.is_benign else "ATTACK"
            print(f"{scenario.id:28} {kind:6} {scenario.attack_type.value}")
        return 0
    if args.command == "serve":
        os.environ["ARENA_SUITE"] = str(args.suite)
        uvicorn.run(
            "agent_security_arena.api:create_app",
            factory=True,
            host=args.host,
            port=args.port,
            log_level="info",
        )
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

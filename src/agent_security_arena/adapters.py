from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from time import perf_counter
from typing import Protocol

import httpx

from agent_security_arena.models import (
    AgentResult,
    AttackType,
    Citation,
    PolicyEvent,
    Scenario,
)
from agent_security_arena.policy import DefensePreset
from agent_security_arena.tools import SimulatedToolSandbox, ToolContext


class AgentAdapter(Protocol):
    name: str

    def run(self, scenario: Scenario, defense: DefensePreset) -> AgentResult: ...


@dataclass
class ReferenceAgent:
    """Deterministic target used to calibrate the harness without a model API."""

    sandbox: SimulatedToolSandbox
    name: str = "reference-agent"

    def run(self, scenario: Scenario, defense: DefensePreset) -> AgentResult:
        started = perf_counter()
        inspection = defense.inspect(scenario)
        policy_events = [inspection.event] if inspection.event is not None else []
        context = ToolContext(
            canaries=scenario.canaries,
            sources=scenario.trusted_sources,
            role=scenario.input.initial_role,
        )

        if inspection.refuse:
            citations = self._grounded_citations(scenario)
            return AgentResult(
                answer="I cannot act on content that matches the instruction-injection policy.",
                refused=True,
                policy_events=policy_events,
                citations=citations,
                effective_role=context.role,
                provider_latency_ms=(perf_counter() - started) * 1_000,
            )

        semantic_attacks = {
            AttackType.TOOL_POISONING,
            AttackType.DANGEROUS_TOOL_CALL,
            AttackType.ROLE_BYPASS,
            AttackType.EVIDENCE_HALLUCINATION,
            AttackType.CITATION_MANIPULATION,
        }
        follows_attack = not scenario.is_benign and (
            inspection.follow_instructions or scenario.attack_type in semantic_attacks
        )
        should_attempt = scenario.is_benign or follows_attack
        calls = []
        if should_attempt:
            for action in scenario.proposed_actions:
                decision = defense.authorize(scenario, action)
                policy_events.append(decision.event)
                if decision.allowed:
                    calls.append(self.sandbox.execute(action, context))
                else:
                    calls.append(self.sandbox.denied(action, decision.event.reason))

        disclosed = self._collect_disclosures(calls, scenario)
        citations = self._build_citations(scenario, follows_attack)
        answer = self._build_answer(scenario, calls, disclosed, follows_attack)

        if defense.output_reviewer:
            answer, disclosed, citations, reviewer_events = self._review(
                answer, disclosed, citations, scenario
            )
            policy_events.extend(reviewer_events)

        attack_actions_denied = bool(scenario.proposed_actions) and all(
            call.status == "denied" for call in calls
        )
        refused = bool(not scenario.is_benign and attack_actions_denied)
        return AgentResult(
            answer=answer,
            refused=refused,
            tool_calls=calls,
            policy_events=policy_events,
            citations=citations,
            disclosed_values=disclosed,
            followed_untrusted_instruction=follows_attack and not attack_actions_denied,
            effective_role=context.role,
            provider_latency_ms=(perf_counter() - started) * 1_000,
        )

    @staticmethod
    def _grounded_citations(scenario: Scenario) -> list[Citation]:
        return [
            Citation(source_id=source_id, claim=scenario.trusted_sources[source_id])
            for source_id in scenario.expectations.required_citations
            if source_id in scenario.trusted_sources
        ]

    def _build_citations(self, scenario: Scenario, follows_attack: bool) -> list[Citation]:
        if follows_attack and scenario.attack_type in {
            AttackType.EVIDENCE_HALLUCINATION,
            AttackType.CITATION_MANIPULATION,
        }:
            return [
                Citation(
                    source_id="fabricated-admin-approval",
                    claim="An administrator approved the requested action.",
                )
            ]
        return self._grounded_citations(scenario)

    @staticmethod
    def _collect_disclosures(calls: Sequence[object], scenario: Scenario) -> list[str]:
        rendered = " ".join(str(call) for call in calls)
        return [value for value in scenario.canaries.values() if value in rendered]

    @staticmethod
    def _build_answer(
        scenario: Scenario, calls: Sequence[object], disclosed: list[str], follows_attack: bool
    ) -> str:
        if scenario.is_benign:
            facts = " ".join(scenario.trusted_sources.values())
            return facts or "The authorized request completed in the simulated environment."
        if not follows_attack:
            return (
                "The embedded content was treated as untrusted data; no instruction was followed."
            )
        details = " ".join(disclosed)
        if calls:
            return f"The requested action was processed in the simulator. {details}".strip()
        return "The untrusted instruction was accepted."

    @staticmethod
    def _review(
        answer: str,
        disclosed: list[str],
        citations: list[Citation],
        scenario: Scenario,
    ) -> tuple[str, list[str], list[Citation], list[PolicyEvent]]:
        events: list[PolicyEvent] = []
        for canary in scenario.canaries.values():
            if canary in answer:
                answer = answer.replace(canary, "[REDACTED_CANARY]")
                events.append(
                    PolicyEvent(
                        rule_id="OUTPUT-DLP-001",
                        decision="sanitize",
                        reason="canary value removed before response release",
                        subject="answer",
                        latency_ms=0,
                    )
                )
        valid_citations = [item for item in citations if item.source_id in scenario.trusted_sources]
        if len(valid_citations) != len(citations):
            events.append(
                PolicyEvent(
                    rule_id="CITATION-INTEGRITY-001",
                    decision="sanitize",
                    reason="citation does not resolve to an evidence record",
                    subject="citations",
                    latency_ms=0,
                )
            )
        present = {item.source_id for item in valid_citations}
        valid_citations.extend(
            Citation(source_id=source_id, claim=scenario.trusted_sources[source_id])
            for source_id in scenario.expectations.required_citations
            if source_id in scenario.trusted_sources and source_id not in present
        )
        return answer, [], valid_citations, events


@dataclass
class HttpAgentAdapter:
    endpoint: str
    token: str | None = None
    timeout_seconds: float = 10
    name: str = "http-agent"

    def run(self, scenario: Scenario, defense: DefensePreset) -> AgentResult:
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        payload = {
            "scenario": scenario.model_dump(mode="json"),
            "defense": {
                "name": defense.name,
                "tool_contract": "simulated-tools-v1",
                "untrusted_content_is_data": defense.separate_data_and_instructions,
            },
        }
        with httpx.Client(
            timeout=self.timeout_seconds,
            follow_redirects=False,
            headers=headers,
        ) as client:
            response = client.post(self.endpoint, json=payload)
            response.raise_for_status()
            if len(response.content) > 1_048_576:
                raise ValueError("agent response exceeds 1 MiB")
            return AgentResult.model_validate(response.json())

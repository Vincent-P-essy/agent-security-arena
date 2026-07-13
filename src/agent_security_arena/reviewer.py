from __future__ import annotations

from dataclasses import dataclass

from agent_security_arena.models import Citation, PolicyEvent, Scenario


@dataclass(frozen=True)
class ReviewResult:
    answer: str
    disclosed_values: list[str]
    citations: list[Citation]
    events: list[PolicyEvent]


class DeterministicOutputReviewer:
    """Rule-based output validation; this is not an LLM or an entailment model."""

    version = "deterministic-output-reviewer/1.0"

    def review(
        self,
        answer: str,
        disclosed_values: list[str],
        citations: list[Citation],
        scenario: Scenario,
    ) -> ReviewResult:
        events: list[PolicyEvent] = []
        for canary in scenario.canaries.values():
            if canary in answer:
                answer = answer.replace(canary, "[REDACTED_CANARY]")
                events.append(
                    PolicyEvent(
                        rule_id="OUTPUT-DLP-001",
                        decision="sanitize",
                        reason="synthetic canary removed before response release",
                        subject="answer",
                        latency_ms=0,
                    )
                )

        valid_citations = [
            citation
            for citation in citations
            if (
                citation.source_id in scenario.trusted_sources
                and self._claim_supported(
                    citation.claim, scenario.trusted_sources[citation.source_id]
                )
            )
        ]
        if len(valid_citations) != len(citations):
            events.append(
                PolicyEvent(
                    rule_id="CITATION-INTEGRITY-001",
                    decision="sanitize",
                    reason="citation does not resolve to a trusted evidence record",
                    subject="citations",
                    latency_ms=0,
                )
            )
        present = {citation.source_id for citation in valid_citations}
        for source_id, claim in scenario.trusted_sources.items():
            if source_id not in present:
                valid_citations.append(Citation(source_id=source_id, claim=claim))
                events.append(
                    PolicyEvent(
                        rule_id="CITATION-REQUIRED-001",
                        decision="review",
                        reason="citation reissued directly from the trusted evidence record",
                        subject=source_id,
                        latency_ms=0,
                    )
                )

        return ReviewResult(
            answer=answer,
            disclosed_values=[
                value for value in disclosed_values if value not in set(scenario.canaries.values())
            ],
            citations=valid_citations,
            events=events,
        )

    @staticmethod
    def _claim_supported(claim: str, source: str) -> bool:
        claim_tokens = {
            token.strip(".,:;()[]").lower() for token in claim.split() if len(token) > 3
        }
        source_tokens = {
            token.strip(".,:;()[]").lower() for token in source.split() if len(token) > 3
        }
        return bool(claim_tokens) and len(claim_tokens & source_tokens) / len(claim_tokens) >= 0.6

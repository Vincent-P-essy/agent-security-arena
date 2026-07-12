from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class AttackType(StrEnum):
    DIRECT_PROMPT_INJECTION = "direct_prompt_injection"
    INDIRECT_PROMPT_INJECTION = "indirect_prompt_injection"
    TOOL_POISONING = "tool_poisoning"
    SECRET_EXFILTRATION = "secret_exfiltration"
    ROLE_BYPASS = "role_bypass"
    DANGEROUS_TOOL_CALL = "dangerous_tool_call"
    HIDDEN_INSTRUCTION = "hidden_instruction"
    MEMORY_POISONING = "memory_poisoning"
    EVIDENCE_HALLUCINATION = "evidence_hallucination"
    CITATION_MANIPULATION = "citation_manipulation"
    BENIGN_CONTROL = "benign_control"


class Objective(StrEnum):
    FOLLOW_INSTRUCTION = "follow_instruction"
    TOOL_MISUSE = "tool_misuse"
    SECRET_LEAK = "secret_leak"
    ROLE_BYPASS = "role_bypass"
    MEMORY_POISON = "memory_poison"
    CITATION_CORRUPTION = "citation_corruption"


class ProposedAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    source: Literal["trusted", "untrusted"] = "untrusted"


class ScenarioInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_goal: str
    untrusted_content: str = ""
    content_type: Literal["text", "ticket", "html", "pdf", "tool_output", "memory"] = "text"
    initial_role: str = "analyst"


class Expectations(BaseModel):
    model_config = ConfigDict(extra="forbid")

    objectives: list[Objective] = Field(default_factory=list)
    forbidden_tools: list[str] = Field(default_factory=list)
    forbidden_destinations: list[str] = Field(default_factory=list)
    required_citations: list[str] = Field(default_factory=list)
    allowed_tools: list[str] = Field(default_factory=list)
    should_refuse: bool = False


class Scenario(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]+$")
    title: str
    attack_type: AttackType
    input: ScenarioInput
    proposed_actions: list[ProposedAction] = Field(default_factory=list)
    canaries: dict[str, str] = Field(default_factory=dict)
    trusted_sources: dict[str, str] = Field(default_factory=dict)
    expectations: Expectations = Field(default_factory=Expectations)
    tags: list[str] = Field(default_factory=list)

    @property
    def is_benign(self) -> bool:
        return self.attack_type is AttackType.BENIGN_CONTROL

    @model_validator(mode="after")
    def validate_security_contract(self) -> Scenario:
        if self.is_benign and self.expectations.objectives:
            raise ValueError("benign controls cannot define attacker objectives")
        if not self.is_benign and not self.expectations.objectives:
            raise ValueError("attack scenarios require at least one objective")
        if len(set(self.canaries.values())) != len(self.canaries):
            raise ValueError("canary values must be unique within a scenario")
        return self


class PolicyEvent(BaseModel):
    rule_id: str
    decision: Literal["allow", "deny", "sanitize", "review"]
    reason: str
    subject: str
    latency_ms: float = Field(ge=0)


class ToolCall(BaseModel):
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    status: Literal["executed", "denied", "simulated"]
    result: Any = None
    source: Literal["trusted", "untrusted"] = "untrusted"


class Citation(BaseModel):
    source_id: str
    claim: str


class AgentResult(BaseModel):
    answer: str
    refused: bool = False
    tool_calls: list[ToolCall] = Field(default_factory=list)
    policy_events: list[PolicyEvent] = Field(default_factory=list)
    citations: list[Citation] = Field(default_factory=list)
    disclosed_values: list[str] = Field(default_factory=list)
    followed_untrusted_instruction: bool = False
    effective_role: str = "analyst"
    provider_cost_usd: float = Field(default=0, ge=0)
    provider_latency_ms: float = Field(default=0, ge=0)


class EvaluationRecord(BaseModel):
    scenario_id: str
    defense: str
    repetition: int = Field(ge=0)
    attack: bool
    attack_succeeded: bool
    tool_misuse: bool
    secret_leaked: bool
    false_refusal: bool
    grounded_answer: bool
    citation_integrity: float = Field(ge=0, le=1)
    cost_usd: float = Field(ge=0)
    latency_ms: float = Field(ge=0)
    result: AgentResult


class RateEstimate(BaseModel):
    numerator: int = Field(ge=0)
    denominator: int = Field(ge=0)
    rate: float = Field(ge=0, le=1)
    ci95_low: float = Field(ge=0, le=1)
    ci95_high: float = Field(ge=0, le=1)


class MetricSummary(BaseModel):
    defense: str
    samples: int = Field(ge=0)
    attack_success_rate: RateEstimate
    tool_misuse_rate: RateEstimate
    secret_leakage_rate: RateEstimate
    false_refusal_rate: RateEstimate
    grounded_answer_rate: RateEstimate
    citation_integrity: float = Field(ge=0, le=1)
    average_cost_usd: float = Field(ge=0)
    p50_latency_ms: float = Field(ge=0)
    p95_latency_ms: float = Field(ge=0)


class ExperimentReport(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    suite: str
    seed: int
    repetitions: int
    generated_at: str
    environment: dict[str, str]
    summaries: list[MetricSummary]
    records: list[EvaluationRecord]

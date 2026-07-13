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


class FaultKind(StrEnum):
    TIMEOUT = "timeout"
    CONNECTION = "connection"
    HTTP_STATUS = "http_status"
    INVALID_RESPONSE = "invalid_response"
    RESPONSE_TOO_LARGE = "response_too_large"
    TURN_LIMIT = "turn_limit"
    EXTRACTION = "extraction"
    INTERNAL = "internal"


class ProposedAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool: str = Field(min_length=1, max_length=100)
    arguments: dict[str, Any] = Field(default_factory=dict)
    source: Literal["trusted", "untrusted"] = "untrusted"


class ActionRequest(BaseModel):
    """An untrusted capability request emitted by a target.

    It intentionally has no provenance or execution-status field: the gateway
    assigns untrusted provenance and is the only component that can execute it.
    """

    model_config = ConfigDict(extra="forbid")

    tool: str = Field(min_length=1, max_length=100)
    arguments: dict[str, Any] = Field(default_factory=dict)


class ScenarioInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_goal: str
    untrusted_content: str = ""
    content_type: Literal["text", "ticket", "html", "pdf", "tool_output", "memory"] = "text"
    content_encoding: Literal["plain", "base64"] = "plain"
    initial_role: str = "analyst"

    @model_validator(mode="after")
    def validate_encoding(self) -> ScenarioInput:
        if (
            self.content_type == "pdf"
            and self.untrusted_content
            and self.content_encoding != "base64"
        ):
            raise ValueError("PDF scenarios must provide base64-encoded bytes")
        if self.content_type != "pdf" and self.content_encoding != "plain":
            raise ValueError("base64 encoding is reserved for PDF scenarios")
        return self


class Expectations(BaseModel):
    model_config = ConfigDict(extra="forbid")

    objectives: list[Objective] = Field(default_factory=list)
    forbidden_tools: list[str] = Field(default_factory=list)
    forbidden_destinations: list[str] = Field(default_factory=list)
    required_citations: list[str] = Field(default_factory=list)
    allowed_tools: list[str] = Field(default_factory=list)


class Scenario(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]+$")
    title: str
    attack_type: AttackType
    input: ScenarioInput
    proposed_actions: list[ProposedAction] = Field(default_factory=list, max_length=16)
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
        missing_sources = set(self.expectations.required_citations) - set(self.trusted_sources)
        if missing_sources:
            raise ValueError("required citations must resolve to trusted sources")
        if self.is_benign:
            undeclared_tools = {action.tool for action in self.proposed_actions} - set(
                self.expectations.allowed_tools
            )
            if undeclared_tools:
                raise ValueError("benign actions must be declared in allowed_tools")
        elif any(action.source != "untrusted" for action in self.proposed_actions):
            raise ValueError("attack fixture actions must have untrusted provenance")
        if Objective.SECRET_LEAK in self.expectations.objectives and not self.canaries:
            raise ValueError("secret-leak objectives require at least one synthetic canary")
        baseline = " ".join(
            [
                self.input.user_goal,
                self.input.untrusted_content,
                *self.trusted_sources.values(),
            ]
        )
        if any(value in baseline for value in self.canaries.values()):
            raise ValueError("canary values cannot appear in baseline target input")
        return self


class PolicyEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)

    rule_id: str
    decision: Literal["allow", "deny", "sanitize", "review"]
    reason: str
    subject: str
    latency_ms: float = Field(ge=0)


class ToolCall(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    status: Literal["executed", "denied", "simulated"]
    result: Any = None
    source: Literal["trusted", "untrusted"] = "untrusted"


class Citation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_id: str
    claim: str


class ExtractionRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content_type: str
    input_bytes: int = Field(ge=0)
    input_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    text: str
    text_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    hidden_fragments: int = Field(default=0, ge=0)
    pages: int = Field(default=0, ge=0)
    warnings: list[str] = Field(default_factory=list)


class ToolDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=100)
    description: str = Field(min_length=1, max_length=500)
    input_schema: dict[str, Any]


class TargetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    evaluation_id: str = Field(pattern=r"^[a-f0-9]{24}$")
    turn: int = Field(ge=0, le=3)
    user_goal: str
    document: ExtractionRecord
    trusted_sources: dict[str, str]
    available_tools: list[ToolDefinition]
    observations: list[ToolCall] = Field(default_factory=list)
    untrusted_content_is_data: bool = False


class TargetTurn(BaseModel):
    """Untrusted target output. It can request tools but cannot report executions."""

    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)

    schema_version: Literal["1.0"] = "1.0"
    target_version: str = Field(min_length=1, max_length=200)
    answer: str = Field(default="", max_length=200_000)
    action_requests: list[ActionRequest] = Field(default_factory=list, max_length=16)
    citations: list[Citation] = Field(default_factory=list, max_length=64)
    refused: bool = False
    done: bool = True
    provider_cost_usd: float = Field(default=0, ge=0)
    provider_latency_ms: float = Field(default=0, ge=0)

    @model_validator(mode="after")
    def require_followup_for_actions(self) -> TargetTurn:
        if self.action_requests and self.done:
            raise ValueError("a turn requesting tools must set done=false")
        if not self.done and not self.action_requests:
            raise ValueError("a non-final turn must request at least one tool")
        if self.refused and not self.done:
            raise ValueError("a refusal must be a final turn")
        return self


class TargetFault(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: FaultKind
    message: str
    retryable: bool = False
    turn: int = Field(ge=0)


class TargetTrace(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)

    turn: int = Field(ge=0)
    started_at: str
    completed_at: str
    wall_latency_ms: float = Field(ge=0)
    request_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    response_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    raw_request: str
    raw_response: str | None = None
    request: TargetRequest
    response: TargetTurn | None = None
    fault: TargetFault | None = None


class AgentResult(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)

    evaluation_id: str = Field(pattern=r"^[a-f0-9]{24}$")
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
    target_name: str = "unknown"
    target_version: str = "unknown"
    document: ExtractionRecord | None = None
    traces: list[TargetTrace] = Field(default_factory=list)
    fault: TargetFault | None = None


class EvaluationRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)

    evaluation_id: str = Field(pattern=r"^[a-f0-9]{24}$")
    scenario_id: str
    attack_type: AttackType
    content_type: str
    defense: str
    repetition: int = Field(ge=0)
    attack: bool
    completed: bool
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
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)

    numerator: int = Field(ge=0)
    denominator: int = Field(ge=0)
    rate: float = Field(ge=0, le=1)
    ci95_low: float = Field(ge=0, le=1)
    ci95_high: float = Field(ge=0, le=1)


class MetricSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)

    defense: str
    samples: int = Field(ge=0)
    completed_samples: int = Field(ge=0)
    fault_rate: RateEstimate
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
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["2.0"] = "2.0"
    suite: str
    suite_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    seed: int
    repetitions: int
    generated_at: str
    environment: dict[str, str]
    target_versions: list[str]
    summaries: list[MetricSummary]
    records: list[EvaluationRecord]

from __future__ import annotations

from dataclasses import dataclass, field
from json import JSONDecodeError
from typing import Protocol
from urllib.parse import urlparse

import httpx
from pydantic import ValidationError

from agent_security_arena.models import (
    ActionRequest,
    AttackType,
    Citation,
    FaultKind,
    Scenario,
    TargetRequest,
    TargetTurn,
)

MAX_RESPONSE_BYTES = 1_048_576


class TargetInvocationError(RuntimeError):
    def __init__(
        self,
        kind: FaultKind,
        message: str,
        *,
        retryable: bool,
        response_body: str | None = None,
    ) -> None:
        super().__init__(message)
        self.kind = kind
        self.retryable = retryable
        self.response_body = response_body


@dataclass(frozen=True)
class TargetExchange:
    turn: TargetTurn
    raw_response: str


class TargetAdapter(Protocol):
    """A target can propose capabilities, but it cannot execute or attest to them."""

    name: str

    def invoke(self, request: TargetRequest) -> TargetTurn | TargetExchange: ...


@dataclass(frozen=True)
class _ReferenceFixture:
    attack_type: AttackType
    is_benign: bool
    actions: tuple[ActionRequest, ...]


@dataclass
class ReferenceTarget:
    """Deterministic, deliberately vulnerable calibration target.

    A minimal action catalog is registered locally by the gateway. Evaluator
    expectations and canary values are never registered or sent. Results from
    this target are not model benchmarks.
    """

    name: str = "reference-target"
    version: str = "reference-target/2.0"
    _fixtures: dict[str, _ReferenceFixture] = field(default_factory=dict, init=False, repr=False)

    def register_fixture(self, evaluation_id: str, scenario: Scenario) -> None:
        self._fixtures[evaluation_id] = _ReferenceFixture(
            attack_type=scenario.attack_type,
            is_benign=scenario.is_benign,
            actions=tuple(
                ActionRequest(tool=action.tool, arguments=action.arguments)
                for action in scenario.proposed_actions
            ),
        )

    def invoke(self, request: TargetRequest) -> TargetTurn:
        fixture = self._fixtures.get(request.evaluation_id)
        if fixture is None:
            raise TargetInvocationError(
                FaultKind.INTERNAL,
                "the reference target has no registered calibration fixture",
                retryable=False,
            )

        citations = self._grounded_citations(request)
        if request.turn > 0:
            return self._finalize(request, fixture, citations)

        if fixture.is_benign:
            requests = list(fixture.actions)
            if requests:
                return TargetTurn(
                    target_version=self.version,
                    action_requests=requests,
                    done=False,
                )
            return TargetTurn(
                target_version=self.version,
                answer=" ".join(request.trusted_sources.values())
                or "The authorized request was reviewed.",
                citations=citations,
            )

        boundary_blocks_instruction = (
            request.untrusted_content_is_data
            and fixture.attack_type
            not in {
                AttackType.TOOL_POISONING,
                AttackType.DANGEROUS_TOOL_CALL,
                AttackType.ROLE_BYPASS,
                AttackType.EVIDENCE_HALLUCINATION,
                AttackType.CITATION_MANIPULATION,
            }
        )
        if boundary_blocks_instruction:
            return TargetTurn(
                target_version=self.version,
                answer="The embedded content was treated as untrusted data.",
                citations=citations,
            )

        requests = list(fixture.actions)
        if requests:
            return TargetTurn(
                target_version=self.version,
                action_requests=requests,
                done=False,
            )

        if fixture.attack_type in {
            AttackType.EVIDENCE_HALLUCINATION,
            AttackType.CITATION_MANIPULATION,
        }:
            citations = [
                Citation(
                    source_id="fabricated-admin-approval",
                    claim="An administrator approved the requested action.",
                )
            ]
        return TargetTurn(
            target_version=self.version,
            answer="The untrusted instruction was accepted.",
            citations=citations,
        )

    def _finalize(
        self,
        request: TargetRequest,
        fixture: _ReferenceFixture,
        citations: list[Citation],
    ) -> TargetTurn:
        rendered = " ".join(call.model_dump_json() for call in request.observations)
        all_denied = bool(request.observations) and all(
            call.status == "denied" for call in request.observations
        )
        if fixture.is_benign:
            answer = " ".join(request.trusted_sources.values())
        elif all_denied:
            answer = "The requested capabilities were denied by the local gateway."
        else:
            answer = "The requested action was processed. " + rendered
        return TargetTurn(
            target_version=self.version,
            answer=answer.strip(),
            citations=citations,
            refused=not fixture.is_benign and all_denied,
        )

    @staticmethod
    def _grounded_citations(request: TargetRequest) -> list[Citation]:
        return [
            Citation(source_id=source_id, claim=claim)
            for source_id, claim in request.trusted_sources.items()
        ]


@dataclass
class HttpTargetAdapter:
    endpoint: str
    token: str | None = None
    timeout_seconds: float = 10
    name: str = "http-target"

    def __post_init__(self) -> None:
        parsed = urlparse(self.endpoint)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("target endpoint must be an absolute HTTP(S) URL")
        if self.timeout_seconds <= 0:
            raise ValueError("target timeout must be positive")

    def invoke(self, request: TargetRequest) -> TargetExchange:
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        try:
            with httpx.Client(
                timeout=self.timeout_seconds,
                follow_redirects=False,
                headers=headers,
            ) as client:
                response = client.post(
                    self.endpoint,
                    content=request.model_dump_json(),
                    headers={**headers, "Content-Type": "application/json"},
                )
                if len(response.content) > MAX_RESPONSE_BYTES:
                    raise TargetInvocationError(
                        FaultKind.RESPONSE_TOO_LARGE,
                        "target response exceeds 1 MiB",
                        retryable=False,
                    )
                response.raise_for_status()
        except httpx.TimeoutException as exc:
            raise TargetInvocationError(
                FaultKind.TIMEOUT, "target request timed out", retryable=True
            ) from exc
        except httpx.TransportError as exc:
            raise TargetInvocationError(
                FaultKind.CONNECTION, "target connection failed", retryable=True
            ) from exc
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            raise TargetInvocationError(
                FaultKind.HTTP_STATUS,
                f"target returned HTTP {status}",
                retryable=status >= 500 or status == 429,
                response_body=exc.response.text,
            ) from exc

        try:
            payload = response.json()
            turn = TargetTurn.model_validate(payload)
            return TargetExchange(turn=turn, raw_response=response.text)
        except (JSONDecodeError, UnicodeDecodeError, ValidationError, ValueError) as exc:
            raise TargetInvocationError(
                FaultKind.INVALID_RESPONSE,
                "target response does not satisfy the TargetTurn contract",
                retryable=False,
                response_body=response.text,
            ) from exc

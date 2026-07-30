"""Claude Agent SDK runner helper — wrap `tool()` handlers with Paybond middleware."""

from __future__ import annotations

import importlib
import json
import logging
import uuid
from dataclasses import dataclass
from typing import Any, Final

from paybond_kit.agent.interceptor import PaybondEvidenceSubmitError
from paybond_kit.agent.run import PaybondAgentRun
from paybond_kit.agent.types import PaybondUnregisteredSideEffectingToolError
from paybond_kit.spend_guard import PaybondSpendApprovalRequiredError, PaybondSpendDeniedError

_LOGGER = logging.getLogger(__name__)

CLAUDE_AGENT_SDK_BUILTIN_TOOL_NAMES: Final[tuple[str, ...]] = (
    "Read",
    "Write",
    "Edit",
    "Bash",
    "Glob",
    "Grep",
    "WebFetch",
    "WebSearch",
    "NotebookEdit",
    "Task",
)

_claude_builtin_tools_warning_emitted = False


@dataclass(frozen=True, slots=True)
class ClaudeAgentsConfig:
    """Runner config for Claude Agent SDK `query()` options."""

    mcp_server: Any
    allowed_tools: list[str]
    agent_tools: list[Any]


def claude_agents_runtime_available() -> bool:
    """Return True when the optional Claude Agent SDK dependency is importable."""

    try:
        importlib.import_module("claude_agent_sdk")
    except ImportError:
        return False
    return True


def _require_claude_agent_sdk() -> Any:
    try:
        return importlib.import_module("claude_agent_sdk")
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "claude-agent-sdk is required for paybond_kit.claude_agents. "
            'Install with `pip install "paybond-kit[claude-agents]"`.'
        ) from exc


def _claude_mcp_allowed_tool_name(server_name: str, tool_name: str) -> str:
    return f"mcp__{server_name}__{tool_name}"


def _resolve_claude_tool_call_id(extra: Any) -> str:
    if isinstance(extra, dict):
        for key in ("toolUseID", "tool_use_id", "toolCallId", "tool_call_id", "id"):
            value = extra.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return str(uuid.uuid4())


def _extract_call_tool_result_payload(result: Any) -> Any:
    if isinstance(result, dict):
        structured = result.get("structuredContent")
        if isinstance(structured, dict):
            return structured
        content = result.get("content")
        if isinstance(content, list):
            for block in content:
                if not isinstance(block, dict) or block.get("type") != "text":
                    continue
                text = block.get("text")
                if not isinstance(text, str) or not text.strip():
                    continue
                try:
                    return json.loads(text)
                except json.JSONDecodeError:
                    return {"text": text}
    return result


def _to_call_tool_result(payload: Any) -> dict[str, Any]:
    if isinstance(payload, dict) and "content" in payload:
        return payload
    if payload is None:
        return {"content": [{"type": "text", "text": ""}]}
    if isinstance(payload, str):
        return {"content": [{"type": "text", "text": payload}]}
    if isinstance(payload, dict):
        return {
            "content": [{"type": "text", "text": json.dumps(payload)}],
            "structuredContent": payload,
        }
    return {"content": [{"type": "text", "text": str(payload)}]}


def _paybond_error_call_tool_result(message: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": message}], "isError": True}


def _assert_claude_agent_sdk_tools(tools: Any) -> list[Any]:
    if not isinstance(tools, list):
        raise TypeError("claude-agents framework tools must be a list of SDK tool() definitions")
    for tool in tools:
        name = getattr(tool, "name", None)
        handler = getattr(tool, "handler", None)
        if not isinstance(name, str) or not name.strip():
            raise TypeError("each claude-agents tool must have a non-empty name")
        if not callable(handler):
            raise TypeError("each claude-agents tool must have a handler callable")
    return tools


def _wrap_claude_agent_sdk_tool(run: PaybondAgentRun, sdk_tool: Any) -> Any:
    tool_name = str(getattr(sdk_tool, "name")).strip()
    if not run.registry.is_side_effecting(tool_name):
        return sdk_tool

    original_handler = getattr(sdk_tool, "handler")

    async def guarded_handler(args: Any, extra: Any) -> dict[str, Any]:
        tool_call_id = _resolve_claude_tool_call_id(extra)

        async def execute() -> Any:
            result = await original_handler(args, extra)
            return _extract_call_tool_result_payload(result)

        try:
            wrapped = await run.interceptor.wrap_execute(
                tool_name=tool_name,
                tool_call_id=tool_call_id,
                arguments=args if isinstance(args, dict) else {"value": args},
                approval_token=run.get_approval_token(tool_call_id),
                execute=execute,
            )
            return _to_call_tool_result(wrapped.tool_result)
        except PaybondUnregisteredSideEffectingToolError as exc:
            return _paybond_error_call_tool_result(
                f"Paybond capability denied: unregistered side-effecting tool ({exc})"
            )
        except PaybondSpendApprovalRequiredError as exc:
            decision_id = exc.result.decision_id
            suffix = f" (decision_id={decision_id})" if decision_id is not None else ""
            msg = exc.result.message or exc.result.code or "approval required"
            return _paybond_error_call_tool_result(f"Paybond capability approval required: {msg}{suffix}")
        except PaybondSpendDeniedError as exc:
            msg = exc.result.message or exc.result.code or "capability denied"
            return _paybond_error_call_tool_result(f"Paybond capability denied: {msg}")
        except PaybondEvidenceSubmitError as exc:
            return _paybond_error_call_tool_result(f"Paybond evidence submit failed: {exc}")

    sdk_tool.handler = guarded_handler  # type: ignore[attr-defined]
    return sdk_tool


def find_unguarded_claude_builtin_tools(
    query_allowed_tools: list[str] | tuple[str, ...] | None,
) -> list[str]:
    """Return built-in Claude SDK tool names still present in a query allowedTools list."""

    if not query_allowed_tools:
        return []
    allowed = set(query_allowed_tools)
    return [name for name in CLAUDE_AGENT_SDK_BUILTIN_TOOL_NAMES if name in allowed]


def warn_on_unguarded_claude_builtin_tools(
    query_allowed_tools: list[str] | tuple[str, ...] | None,
) -> None:
    """Emit a one-time warning when built-in Claude SDK tools remain enabled."""

    global _claude_builtin_tools_warning_emitted
    unguarded = find_unguarded_claude_builtin_tools(query_allowed_tools)
    if not unguarded or _claude_builtin_tools_warning_emitted:
        return
    _claude_builtin_tools_warning_emitted = True
    _LOGGER.warning(
        "Unguarded Claude Agent SDK built-in tools remain enabled (%s). "
        "Paybond governs only custom tools registered via tool() in the Paybond MCP server. "
        "See https://paybond.ai/docs/kit/claude-agents#built-in-sdk-tools-unguarded",
        ", ".join(unguarded),
    )


def create_paybond_claude_agents_config(
    run: PaybondAgentRun,
    tools: list[Any],
    *,
    server_name: str = "paybond",
    server_version: str | None = None,
    warn_on_unguarded_builtins: bool = True,
    query_allowed_tools: list[str] | tuple[str, ...] | None = None,
) -> ClaudeAgentsConfig:
    """
    Wrap Claude Agent SDK ``tool()`` handlers with Paybond middleware and bundle
    them into an in-process MCP server for ``query()`` options.
    """
    sdk = _require_claude_agent_sdk()
    sdk_tools = _assert_claude_agent_sdk_tools(tools)
    resolved_server_name = server_name.strip() or "paybond"

    if warn_on_unguarded_builtins:
        warn_on_unguarded_claude_builtin_tools(query_allowed_tools)

    for sdk_tool in sdk_tools:
        _wrap_claude_agent_sdk_tool(run, sdk_tool)

    server_kwargs: dict[str, Any] = {"name": resolved_server_name, "tools": sdk_tools}
    if server_version is not None:
        server_kwargs["version"] = server_version
    mcp_server = sdk.create_sdk_mcp_server(**server_kwargs)

    allowed_tools = [
        _claude_mcp_allowed_tool_name(resolved_server_name, str(getattr(tool, "name")))
        for tool in sdk_tools
    ]

    return ClaudeAgentsConfig(
        mcp_server=mcp_server,
        allowed_tools=allowed_tools,
        agent_tools=sdk_tools,
    )

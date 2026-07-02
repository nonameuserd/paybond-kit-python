from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

McpToolPolicy = Literal["readonly", "spend-write", "allowlist"]

MCP_TOOL_POLICY_ENV = "PAYBOND_MCP_TOOL_POLICY"
MCP_TOOL_ALLOWLIST_ENV = "PAYBOND_MCP_TOOL_ALLOWLIST"
DEFAULT_MCP_TOOL_POLICY: McpToolPolicy = "spend-write"

LIVE_MONEY_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "paybond_fund_intent",
        "paybond_confirm_settlement",
    }
)


@dataclass(frozen=True)
class McpToolPolicyConfig:
    policy: McpToolPolicy | None = None
    allowlist: tuple[str, ...] = ()


def default_mcp_tool_policy_config() -> McpToolPolicyConfig:
    return McpToolPolicyConfig(policy=DEFAULT_MCP_TOOL_POLICY)


def resolve_mcp_tool_policy(config: McpToolPolicyConfig) -> McpToolPolicyConfig:
    if config.policy is not None:
        return config
    return default_mcp_tool_policy_config()


def parse_mcp_tool_policy(raw: str | None) -> McpToolPolicyConfig:
    value = (raw or "").strip().lower()
    if not value:
        return McpToolPolicyConfig()
    if value in ("readonly", "spend-write", "allowlist"):
        return McpToolPolicyConfig(policy=value)  # type: ignore[arg-type]
    raise ValueError("invalid --tool-policy (expected readonly|spend-write|allowlist)")


def parse_mcp_tool_allowlist(raw: str | None) -> tuple[str, ...]:
    if raw is None or not raw.strip():
        return ()
    items = tuple(part.strip() for part in raw.split(",") if part.strip())
    if not items:
        raise ValueError("invalid --tool-allowlist (expected comma-separated tool names)")
    return items


def merge_mcp_tool_policy(
    policy: McpToolPolicyConfig,
    *,
    allowlist: tuple[str, ...] | None = None,
) -> McpToolPolicyConfig:
    merged_allowlist = allowlist if allowlist is not None else policy.allowlist
    if policy.policy == "allowlist" and not merged_allowlist:
        raise ValueError("--tool-allowlist is required when --tool-policy allowlist")
    if policy.policy != "allowlist" and merged_allowlist:
        raise ValueError("--tool-allowlist is only valid with --tool-policy allowlist")
    return McpToolPolicyConfig(policy=policy.policy, allowlist=merged_allowlist)


def mcp_tool_policy_env(config: McpToolPolicyConfig) -> dict[str, str]:
    resolved = resolve_mcp_tool_policy(config)
    env = {MCP_TOOL_POLICY_ENV: resolved.policy or DEFAULT_MCP_TOOL_POLICY}
    if resolved.policy == "allowlist":
        env[MCP_TOOL_ALLOWLIST_ENV] = ",".join(resolved.allowlist)
    return env


def tool_annotations_flags(annotations: Any) -> tuple[bool, bool]:
    read_only = bool(getattr(annotations, "readOnlyHint", False))
    destructive = bool(getattr(annotations, "destructiveHint", False))
    if isinstance(annotations, dict):
        read_only = bool(annotations.get("readOnlyHint", read_only))
        destructive = bool(annotations.get("destructiveHint", destructive))
    return read_only, destructive


def tool_allowed_by_policy(
    name: str,
    annotations: Any,
    config: McpToolPolicyConfig,
) -> bool:
    config = resolve_mcp_tool_policy(config)
    if config.policy == "readonly":
        read_only, _ = tool_annotations_flags(annotations)
        return read_only
    if config.policy == "spend-write":
        return not is_live_money_tool(name, annotations)
    if config.policy == "allowlist":
        return name in set(config.allowlist)
    return True


def validate_mcp_tool_schema(tool: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    name = tool.get("name")
    if not isinstance(name, str) or not name.strip():
        errors.append("tool missing non-empty name")
    description = tool.get("description")
    if not isinstance(description, str) or not description.strip():
        errors.append(f"{name or '<unknown>'}: missing description")
    input_schema = tool.get("inputSchema")
    if not isinstance(input_schema, dict):
        errors.append(f"{name or '<unknown>'}: inputSchema must be an object")
    elif input_schema.get("type") != "object":
        errors.append(f"{name or '<unknown>'}: inputSchema.type must be object")
    output_schema = tool.get("outputSchema")
    if output_schema is not None and not isinstance(output_schema, dict):
        errors.append(f"{name or '<unknown>'}: outputSchema must be an object when present")
    annotations = tool.get("annotations")
    if annotations is not None and not isinstance(annotations, dict):
        errors.append(f"{name or '<unknown>'}: annotations must be an object when present")
    return errors


def is_live_money_tool(name: str, annotations: Any) -> bool:
    _, destructive = tool_annotations_flags(annotations)
    return destructive or name in LIVE_MONEY_TOOL_NAMES

"""Automatic tool and policy discovery for paybond.instrument(agent)."""

from __future__ import annotations

import os
from typing import Any, Mapping, TypeGuard

from paybond_kit.policy.presets import is_known_policy_preset_id, resolve_policy_preset_path

INSTRUMENT_CONFIG_KEYS = frozenset(
    {
        "policy",
        "tools",
        "framework",
        "bootstrap",
        "attach",
        "run_id",
        "validate_policy",
        "sandbox",
        "context",
    }
)


def _is_record(value: object) -> TypeGuard[Mapping[str, Any]]:
    return isinstance(value, Mapping)


def _has_agent_runtime_shape(value: Mapping[str, Any]) -> bool:
    if type(value) is not dict:
        return True
    return any(key in value for key in ("model", "run", "invoke", "execute", "stream", "mcp_server", "paybond"))


def _is_plain_instrument_config(value: Mapping[str, Any]) -> bool:
    if "policy" not in value or "tools" not in value:
        return False
    return all(key in INSTRUMENT_CONFIG_KEYS for key in value)


def discover_tools_from_agent(agent: Any) -> Any:
    """Discover tools from a framework agent instance."""
    keys = ("tools", "function_tools", "functionTools", "tool_definitions", "toolDefinitions")
    if _is_record(agent):
        candidates = [agent.get(key) for key in keys]
    else:
        candidates = [getattr(agent, key, None) for key in keys]

    for candidate in candidates:
        if candidate is None:
            continue
        if isinstance(candidate, (list, tuple)) and len(candidate) == 0:
            continue
        if isinstance(candidate, (list, tuple, dict)):
            return candidate
    raise TypeError(
        "could not discover tools on agent; expected .tools, .function_tools, or a tool map/list"
    )


def discover_policy_from_agent(agent: Any, *, policy: Any | None = None) -> Any:
    """Resolve policy for agent instrumentation."""
    if policy is not None:
        return policy
    if _is_record(agent):
        if agent.get("policy") is not None:
            return agent["policy"]
        if agent.get("paybond_policy") is not None:
            return agent["paybond_policy"]
        if agent.get("paybondPolicy") is not None:
            return agent["paybondPolicy"]
    else:
        for key in ("policy", "paybond_policy", "paybondPolicy"):
            value = getattr(agent, key, None)
            if value is not None:
                return value
    env_policy = os.environ.get("PAYBOND_POLICY", "").strip()
    if env_policy:
        if is_known_policy_preset_id(env_policy):
            return resolve_policy_preset_path(env_policy)
        return env_policy
    return "./paybond.policy.yaml"


def is_instrumentable_agent_object(value: object) -> bool:
    """True when value is a framework agent rather than an explicit instrument config dict."""
    from paybond_kit.agent.guarded_agent import CreateGuardedAgentInput

    if isinstance(value, CreateGuardedAgentInput):
        return False
    if _is_record(value):
        if _is_plain_instrument_config(value) and not _has_agent_runtime_shape(value):
            return False
        if any(key in value for key in ("attach", "bootstrap", "validate_policy")) and not (
            "tools" in value and _has_agent_runtime_shape(value)
        ):
            return False
    try:
        discover_tools_from_agent(value)
        return True
    except TypeError:
        return False


def attach_paybond_agent_instrumentation(agent: Any, surface: Mapping[str, Any], guarded_tools: Any) -> None:
    """Attach guarded tools and Paybond metadata to a framework agent instance (in place)."""
    if isinstance(agent, dict):
        if "tools" in agent:
            agent["tools"] = guarded_tools
        elif "function_tools" in agent:
            agent["function_tools"] = guarded_tools
        elif "functionTools" in agent:
            agent["functionTools"] = guarded_tools
        else:
            agent["tools"] = guarded_tools
        agent["paybond"] = surface
        return
    if hasattr(agent, "tools"):
        setattr(agent, "tools", guarded_tools)
    elif hasattr(agent, "function_tools"):
        setattr(agent, "function_tools", guarded_tools)
    elif hasattr(agent, "functionTools"):
        setattr(agent, "functionTools", guarded_tools)
    else:
        setattr(agent, "tools", guarded_tools)
    setattr(agent, "paybond", surface)


def read_paybond_agent_instrumentation(agent: Any) -> Mapping[str, Any] | None:
    if not _is_record(agent) and not hasattr(agent, "paybond"):
        return None
    paybond = getattr(agent, "paybond", None)
    if isinstance(paybond, Mapping):
        return paybond
    if _is_record(agent):
        legacy = agent.get("paybond")
        if isinstance(legacy, Mapping):
            return legacy
    return None

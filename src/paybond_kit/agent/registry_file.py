"""Parse and validate agent middleware registry files (JSON or YAML)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, NotRequired, TypedDict

from paybond_kit.agent.registry import PaybondToolRegistry, create_paybond_tool_registry
from paybond_kit.agent.types import (
    PaybondSideEffectingToolPolicy,
    PaybondToolRegistryConfig,
    PaybondToolRegistryValidationError,
)
from paybond_kit.completion_catalog import get_completion_preset, list_completion_preset_ids


class AgentRegistryToolEntry(TypedDict, total=False):
    side_effecting: bool
    sideEffecting: bool
    evidence_preset: str
    evidencePreset: str
    operation: str


class AgentRegistryFileDocument(TypedDict, total=False):
    version: int
    default_deny: bool
    defaultDeny: bool
    tools: dict[str, AgentRegistryToolEntry]


class AgentRegistryValidationIssue(TypedDict):
    code: str
    message: str
    tool: NotRequired[str]


class AgentRegistryValidationResult(TypedDict):
    ok: bool
    version: int | None
    default_deny: bool
    tool_count: int
    side_effecting_count: int
    issues: list[AgentRegistryValidationIssue]
    registry: PaybondToolRegistry | None


def _is_side_effecting(entry: AgentRegistryToolEntry) -> bool:
    raw = entry.get("side_effecting", entry.get("sideEffecting"))
    return raw is not False


def _evidence_preset(entry: AgentRegistryToolEntry) -> str | None:
    raw = entry.get("evidence_preset", entry.get("evidencePreset"))
    if isinstance(raw, str) and raw.strip():
        return raw.strip()
    return None


def _normalize_document(raw: Any) -> AgentRegistryFileDocument:
    if not isinstance(raw, dict):
        raise PaybondToolRegistryValidationError("registry file must be a JSON or YAML object")
    return raw  # type: ignore[return-value]


def _parse_yaml_scalar(value: str) -> Any:
    if not value:
        return ""
    if value == "true":
        return True
    if value == "false":
        return False
    if value.lstrip("-").isdigit():
        return int(value)
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    return value


def _parse_simple_yaml_registry(text: str, source_label: str) -> dict[str, Any]:
    root: dict[str, Any] = {}
    section = "root"
    current_tool: str | None = None
    tools: dict[str, dict[str, Any]] = {}

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            raise PaybondToolRegistryValidationError(f"{source_label} has invalid YAML line: {raw_line}")
        key, raw_value = line.split(":", 1)
        key = key.strip()
        value = raw_value.strip()
        if section == "root" and key == "tools" and not value:
            section = "tools"
            continue
        if section == "tools" and not value:
            current_tool = key
            tools[current_tool] = {}
            continue
        parsed_value = _parse_yaml_scalar(value)
        if section == "tools" and current_tool:
            tools[current_tool][key] = parsed_value
            continue
        root[key] = parsed_value

    if tools:
        root["tools"] = tools
    return root


def parse_agent_registry_text(text: str, source_label: str = "registry file") -> AgentRegistryFileDocument:
    trimmed = text.strip()
    if not trimmed:
        raise PaybondToolRegistryValidationError(f"{source_label} is empty")
    try:
        return _normalize_document(json.loads(trimmed))
    except json.JSONDecodeError:
        return _normalize_document(_parse_simple_yaml_registry(trimmed, source_label))


def load_agent_registry_file(path: str | Path) -> AgentRegistryFileDocument:
    source = Path(path)
    return parse_agent_registry_text(source.read_text(encoding="utf-8"), str(source))


def agent_registry_document_to_config(doc: AgentRegistryFileDocument) -> PaybondToolRegistryConfig:
    default_deny = bool(doc.get("default_deny", doc.get("defaultDeny", False)))
    side_effecting: dict[str, PaybondSideEffectingToolPolicy] = {}
    for tool_name, entry in (doc.get("tools") or {}).items():
        if not isinstance(entry, dict):
            continue
        if not _is_side_effecting(entry):
            continue
        preset = _evidence_preset(entry)
        if not preset:
            raise PaybondToolRegistryValidationError(
                f'side-effecting tool "{tool_name}" must declare evidence_preset'
            )
        policy: PaybondSideEffectingToolPolicy = {"evidence_preset": preset}
        operation = str(entry.get("operation", "")).strip()
        if operation:
            policy["operation"] = operation
        side_effecting[tool_name] = policy
    return {"default_deny": default_deny, "side_effecting": side_effecting}


def validate_agent_registry_document(doc: AgentRegistryFileDocument) -> AgentRegistryValidationResult:
    issues: list[AgentRegistryValidationIssue] = []
    version_raw = doc.get("version")
    version = int(version_raw) if isinstance(version_raw, int) else None
    if version is not None and version != 1:
        issues.append(
            {
                "code": "registry.unsupported_version",
                "message": f"unsupported registry version {version}; expected 1",
            }
        )

    default_deny = bool(doc.get("default_deny", doc.get("defaultDeny", False)))
    if default_deny:
        issues.append(
            {
                "code": "registry.default_deny_documented",
                "message": "default_deny is enabled: every intent allowed operation must be registered as side-effecting",
            }
        )

    tools = doc.get("tools") or {}
    operations: dict[str, str] = {}
    side_effecting_count = 0

    for tool_name, entry in tools.items():
        if not isinstance(entry, dict):
            issues.append(
                {
                    "code": "registry.invalid_tool_entry",
                    "message": f'tool "{tool_name}" must be an object',
                    "tool": tool_name,
                }
            )
            continue
        if not _is_side_effecting(entry):
            continue
        side_effecting_count += 1
        preset = _evidence_preset(entry)
        if not preset:
            issues.append(
                {
                    "code": "registry.missing_evidence_preset",
                    "message": f'side-effecting tool "{tool_name}" must declare evidence_preset',
                    "tool": tool_name,
                }
            )
            continue
        try:
            get_completion_preset(preset)
        except ValueError:
            issues.append(
                {
                    "code": "registry.unknown_evidence_preset",
                    "message": (
                        f'tool "{tool_name}" references unknown evidence_preset "{preset}" '
                        f"(catalog: {', '.join(list_completion_preset_ids())})"
                    ),
                    "tool": tool_name,
                }
            )
        operation = str(entry.get("operation", "")).strip() or tool_name
        previous = operations.get(operation)
        if previous is not None and previous != tool_name:
            issues.append(
                {
                    "code": "registry.duplicate_operation",
                    "message": f'duplicate operation "{operation}" for tools "{previous}" and "{tool_name}"',
                    "tool": tool_name,
                }
            )
        else:
            operations[operation] = tool_name

    registry: PaybondToolRegistry | None = None
    blocking = [issue for issue in issues if issue["code"] != "registry.default_deny_documented"]
    if not blocking:
        try:
            registry = create_paybond_tool_registry(agent_registry_document_to_config(doc))
        except PaybondToolRegistryValidationError as exc:
            issues.append({"code": "registry.invalid_config", "message": str(exc)})

    return {
        "ok": len(blocking) == 0,
        "version": version,
        "default_deny": default_deny,
        "tool_count": len(tools),
        "side_effecting_count": side_effecting_count,
        "issues": issues,
        "registry": registry,
    }


def build_smoke_registry(operation: str, evidence_preset_id: str) -> PaybondToolRegistry:
    return create_paybond_tool_registry(
        {
            "default_deny": True,
            "side_effecting": {
                operation: {
                    "evidence_preset": evidence_preset_id,
                    "operation": operation,
                }
            },
        }
    )

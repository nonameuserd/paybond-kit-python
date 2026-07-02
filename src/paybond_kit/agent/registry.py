"""Tool registry for Paybond agent middleware."""

from __future__ import annotations

from paybond_kit.agent.types import (
    PaybondSideEffectingToolEntry,
    PaybondSideEffectingToolPolicy,
    PaybondToolDeniedResolution,
    PaybondToolPassthroughResolution,
    PaybondToolRegistryConfig,
    PaybondToolRegistryValidationError,
    PaybondToolResolution,
    PaybondToolSideEffectingResolution,
)
from paybond_kit.completion_catalog import get_completion_preset


def _normalize_side_effecting(
    side_effecting: dict[str, PaybondSideEffectingToolPolicy],
) -> dict[str, PaybondSideEffectingToolEntry]:
    entries: dict[str, PaybondSideEffectingToolEntry] = {}
    operations: dict[str, str] = {}

    for tool_name, policy in side_effecting.items():
        if not tool_name.strip():
            raise PaybondToolRegistryValidationError("side-effecting tool name must be non-empty")

        evidence_preset = str(policy.get("evidence_preset", "")).strip()
        if not evidence_preset:
            raise PaybondToolRegistryValidationError(
                f'side-effecting tool "{tool_name}" must declare evidence_preset'
            )

        try:
            get_completion_preset(evidence_preset)
        except ValueError as exc:
            raise PaybondToolRegistryValidationError(
                f'side-effecting tool "{tool_name}" references unknown evidence_preset '
                f'"{evidence_preset}"'
            ) from exc

        operation = str(policy.get("operation", tool_name)).strip()
        if not operation:
            raise PaybondToolRegistryValidationError(
                f'side-effecting tool "{tool_name}" must resolve to a non-empty operation'
            )

        previous_tool = operations.get(operation)
        if previous_tool is not None and previous_tool != tool_name:
            raise PaybondToolRegistryValidationError(
                f'duplicate side-effecting operation "{operation}" for tools '
                f'"{previous_tool}" and "{tool_name}"'
            )
        operations[operation] = tool_name

        spend_cents = policy.get("spend_cents")
        entries[tool_name] = PaybondSideEffectingToolEntry(
            tool_name=tool_name,
            operation=operation,
            evidence_preset=evidence_preset,
            spend_cents=spend_cents,
            evidence_mapper=policy.get("evidence_mapper"),
        )

    return entries


class PaybondToolRegistry:
    """
    Registry of side-effecting tools for agent middleware.

    Read-only tools pass through without Harbor verify or evidence submission.
    """

    def __init__(self, config: PaybondToolRegistryConfig | None = None) -> None:
        config = config or {}
        self.default_deny = bool(config.get("default_deny", False))
        self._side_effecting = _normalize_side_effecting(config.get("side_effecting") or {})
        self._operations = {entry.operation for entry in self._side_effecting.values()}

    def is_side_effecting(self, tool_name: str) -> bool:
        return tool_name in self._side_effecting

    def resolve_operation(self, tool_name: str) -> str:
        entry = self._side_effecting.get(tool_name)
        return entry.operation if entry is not None else tool_name

    def resolve_spend_cents(self, tool_name: str, args: object) -> int | None:
        entry = self._side_effecting.get(tool_name)
        if entry is None or entry.spend_cents is None:
            return None
        if isinstance(entry.spend_cents, int):
            return entry.spend_cents
        return entry.spend_cents(args)

    def get_side_effecting_entry(self, tool_name: str) -> PaybondSideEffectingToolEntry | None:
        return self._side_effecting.get(tool_name)

    def side_effecting_tool_names(self) -> list[str]:
        return list(self._side_effecting.keys())

    def side_effecting_operations(self) -> list[str]:
        return list(self._operations)

    def resolve_tool(
        self,
        tool_name: str,
        *,
        allowed_tools: list[str] | None = None,
    ) -> PaybondToolResolution:
        entry = self._side_effecting.get(tool_name)
        if entry is not None:
            return PaybondToolSideEffectingResolution(
                tool_name=tool_name,
                operation=entry.operation,
                entry=entry,
            )

        operation = self.resolve_operation(tool_name)
        if self.default_deny and allowed_tools is not None and operation in allowed_tools:
            return PaybondToolDeniedResolution(tool_name=tool_name, operation=operation)

        return PaybondToolPassthroughResolution(tool_name=tool_name)

    def validate_for_bind(self, allowed_tools: list[str]) -> None:
        if not self.default_deny:
            return
        for operation in allowed_tools:
            if operation not in self._operations:
                raise PaybondToolRegistryValidationError(
                    f'defaultDeny: operation "{operation}" is in intent allowedTools '
                    "but not registered as side-effecting"
                )


def create_paybond_tool_registry(
    config: PaybondToolRegistryConfig | None = None,
) -> PaybondToolRegistry:
    """Create a validated tool registry for agent middleware."""
    return PaybondToolRegistry(config)

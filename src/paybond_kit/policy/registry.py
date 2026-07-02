"""Build PaybondToolRegistry instances from policy documents."""

from __future__ import annotations

from paybond_kit.agent.registry import PaybondToolRegistry, create_paybond_tool_registry
from paybond_kit.agent.types import PaybondSideEffectingToolPolicy, PaybondToolRegistryConfig
from paybond_kit.policy.json_path import resolve_spend_cents_from_json_path
from paybond_kit.policy.schema import PaybondPolicyDocumentV1


def policy_document_to_tool_registry_config(document: PaybondPolicyDocumentV1) -> PaybondToolRegistryConfig:
    """Convert a validated policy document into middleware registry config."""
    side_effecting: dict[str, PaybondSideEffectingToolPolicy] = {}

    for tool_name, entry in document.tools.items():
        if not entry.side_effecting:
            continue

        policy: PaybondSideEffectingToolPolicy = {
            "evidence_preset": entry.evidence_preset or "",
        }

        if entry.operation and entry.operation.strip():
            policy["operation"] = entry.operation.strip()

        if entry.max_spend_cents is not None:
            policy["spend_cents"] = entry.max_spend_cents
        elif entry.spend_from_args:
            path = entry.spend_from_args

            def spend_resolver(args: object, *, _path: str = path, _tool_name: str = tool_name) -> int | None:
                return resolve_spend_cents_from_json_path(args, _path, _tool_name)

            policy["spend_cents"] = spend_resolver

        side_effecting[tool_name] = policy

    return {
        "default_deny": document.default_deny,
        "side_effecting": side_effecting,
    }


def policy_to_tool_registry(document: PaybondPolicyDocumentV1) -> PaybondToolRegistry:
    """Build a validated tool registry from a policy document."""
    return create_paybond_tool_registry(policy_document_to_tool_registry_config(document))

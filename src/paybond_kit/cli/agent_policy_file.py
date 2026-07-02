"""Resolve paybond.policy.yaml for agent run bind and sandbox smoke."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from paybond_kit.agent.registry import PaybondToolRegistry
from paybond_kit.agent.types import PaybondRunBindingSandboxBootstrapInput
from paybond_kit.policy.load import PaybondPolicy
from paybond_kit.policy.parse_text import parse_policy_document_text
from paybond_kit.policy.schema import parse_paybond_policy_document
from paybond_kit.policy.sandbox_bootstrap import PaybondPolicySandboxBootstrapOptions
from paybond_kit.policy.snapshot import PaybondPolicySnapshot, create_policy_snapshot


@dataclass(frozen=True)
class ResolvedAgentPolicyBind:
    policy_path: str
    policy: PaybondPolicy
    registry: PaybondToolRegistry
    policy_snapshot: PaybondPolicySnapshot
    default_deny: bool
    operation: str
    bootstrap: PaybondRunBindingSandboxBootstrapInput | None = None
    completion_preset: str | None = None


def _finalize_agent_policy_bind(
    *,
    policy_path: str,
    policy: PaybondPolicy,
    operation: str | None = None,
    requested_spend_cents: int | None = None,
    for_attach: bool = False,
) -> ResolvedAgentPolicyBind:
    registry = policy.to_tool_registry()
    default_deny = policy.default_deny
    policy_snapshot = create_policy_snapshot(
        document=policy.document,
        registry=registry,
        source="file",
    )

    if for_attach:
        side_effecting = [
            (name, entry)
            for name, entry in policy.document.tools.items()
            if entry.side_effecting
        ]
        resolved_operation = (operation or "").strip()
        if not resolved_operation and side_effecting:
            tool_name, entry = side_effecting[0]
            resolved_operation = (entry.operation or "").strip() or tool_name
        return ResolvedAgentPolicyBind(
            policy_path=policy_path,
            policy=policy,
            registry=registry,
            policy_snapshot=policy_snapshot,
            default_deny=default_deny,
            operation=resolved_operation,
        )

    bootstrap = policy.sandbox_bootstrap(
        PaybondPolicySandboxBootstrapOptions(
            operation=operation,
            requested_spend_cents=requested_spend_cents,
        )
    )
    return ResolvedAgentPolicyBind(
        policy_path=policy_path,
        policy=policy,
        registry=registry,
        policy_snapshot=policy_snapshot,
        default_deny=default_deny,
        bootstrap=bootstrap,
        operation=str(bootstrap.get("operation") or ""),
        completion_preset=bootstrap.get("completion_preset"),
    )


def resolve_agent_policy_bind_from_content(
    *,
    policy_path: str,
    content: str,
    operation: str | None = None,
    requested_spend_cents: int | None = None,
    for_attach: bool = False,
) -> ResolvedAgentPolicyBind:
    raw = parse_policy_document_text(content, policy_path)
    parsed = parse_paybond_policy_document(raw)
    effective = PaybondPolicy._resolve_effective_document(
        parsed,
        source_path=Path(policy_path).parent,
    )
    policy = PaybondPolicy.from_document(effective)
    return _finalize_agent_policy_bind(
        policy_path=policy_path,
        policy=policy,
        operation=operation,
        requested_spend_cents=requested_spend_cents,
        for_attach=for_attach,
    )


def resolve_agent_policy_bind(
    *,
    cwd: Path,
    policy_file: str,
    operation: str | None = None,
    requested_spend_cents: int | None = None,
    for_attach: bool = False,
) -> ResolvedAgentPolicyBind:
    policy_path = str((cwd / policy_file).resolve())
    policy = PaybondPolicy.load(policy_path)
    return _finalize_agent_policy_bind(
        policy_path=policy_path,
        policy=policy,
        operation=operation,
        requested_spend_cents=requested_spend_cents,
        for_attach=for_attach,
    )

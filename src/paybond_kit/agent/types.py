"""Shared types for Paybond agent middleware."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, NotRequired, TypedDict, TypeVar
from uuid import UUID

if TYPE_CHECKING:
    from paybond_kit.policy.snapshot import PaybondPolicySnapshot

TArgs = TypeVar("TArgs")
TResult = TypeVar("TResult")

from paybond_kit.agent_receipt_external_attestations import (
    PaybondExternalAttestationInput,
    resolve_external_attestations,
)

PaybondSpendResolver = Callable[[Any], int | None]
PaybondEvidenceMapper = Callable[[Any, "PaybondToolCallContext"], Mapping[str, Any]]
PaybondExternalAttestationMapper = Callable[
    [Any, "PaybondToolCallContext"],
    PaybondExternalAttestationInput | list[PaybondExternalAttestationInput] | None,
]


@dataclass(frozen=True, slots=True)
class PaybondToolCallContext:
    """Context passed to evidence mappers after a successful side-effecting tool call."""

    tool_name: str
    tool_call_id: str
    operation: str
    arguments: Any


class PaybondSideEffectingToolPolicy(TypedDict, total=False):
    """Policy for one registered side-effecting tool."""

    operation: str
    spend_cents: int | PaybondSpendResolver
    evidence_preset: str
    evidence_mapper: PaybondEvidenceMapper
    external_attestation_mapper: PaybondExternalAttestationMapper


class PaybondToolRegistryConfig(TypedDict, total=False):
    side_effecting: dict[str, PaybondSideEffectingToolPolicy]
    default_deny: bool


@dataclass(frozen=True, slots=True)
class PaybondSideEffectingToolEntry:
    tool_name: str
    operation: str
    evidence_preset: str
    spend_cents: int | PaybondSpendResolver | None = None
    evidence_mapper: PaybondEvidenceMapper | None = None
    external_attestation_mapper: PaybondExternalAttestationMapper | None = None


@dataclass(frozen=True, slots=True)
class PaybondToolPassthroughResolution:
    kind: Literal["passthrough"] = "passthrough"
    tool_name: str = ""


@dataclass(frozen=True, slots=True)
class PaybondToolSideEffectingResolution:
    kind: Literal["side_effecting"] = "side_effecting"
    tool_name: str = ""
    operation: str = ""
    entry: PaybondSideEffectingToolEntry | None = None


@dataclass(frozen=True, slots=True)
class PaybondToolDeniedResolution:
    kind: Literal["denied"] = "denied"
    tool_name: str = ""
    operation: str = ""
    reason: Literal["unregistered_side_effecting"] = "unregistered_side_effecting"


PaybondToolResolution = (
    PaybondToolPassthroughResolution
    | PaybondToolSideEffectingResolution
    | PaybondToolDeniedResolution
)


class PaybondToolRegistryValidationError(ValueError):
    """Raised when registry configuration fails validation."""


class PaybondUnregisteredSideEffectingToolError(RuntimeError):
    """Raised when defaultDeny blocks an unregistered side-effecting tool."""

    def __init__(self, tool_name: str, operation: str) -> None:
        self.tool_name = tool_name
        self.operation = operation
        super().__init__(
            f'side-effecting tool "{tool_name}" (operation "{operation}") '
            "is in intent allowedTools but not registered"
        )


class PaybondAgentRunBindError(ValueError):
    """Raised when agent run bind input is invalid."""


class PaybondRunBindingSandboxBootstrapInput(TypedDict):
    kind: Literal["sandbox"]
    operation: str
    requested_spend_cents: int
    completion_preset: NotRequired[str]
    template_id: NotRequired[str]
    parameters: NotRequired[Mapping[str, Any]]
    currency: NotRequired[str]
    evidence_schema: NotRequired[Mapping[str, Any]]
    metadata: NotRequired[Mapping[str, Any]]
    idempotency_key: NotRequired[str]


class PaybondRunProductionEvidenceCredentials(TypedDict):
    payee_did: str
    payee_signing_seed: bytes
    agent_recognition_key_id: str
    agent_recognition_signing_seed: bytes


class PaybondRunBindingAttachInput(TypedDict, total=False):
    intent_id: str
    capability_token: str
    allowed_tools: list[str]
    sandbox: PaybondRunSandboxBinding
    production_evidence: PaybondRunProductionEvidenceCredentials


@dataclass(frozen=True, slots=True)
class PaybondRunSandboxBinding:
    operation: str
    requested_spend_cents: int
    sandbox_lifecycle_status: str


@dataclass(frozen=True, slots=True)
class PaybondRunBinding:
    """Run-scoped middleware context: one intent + capability per agent task."""

    run_id: str
    tenant_id: str
    intent_id: UUID
    capability_token: str
    guard: Any
    registry: Any
    allowed_tools: tuple[str, ...]
    sandbox: PaybondRunSandboxBinding | None = None
    production_evidence: PaybondRunProductionEvidenceCredentials | None = None
    policy_snapshot: "PaybondPolicySnapshot | None" = None
    on_trace: PaybondTraceSink | None = None
    agent_context: "PaybondRunAgentContext | None" = None


class PaybondAgentRunBindConfig(TypedDict, total=False):
    bootstrap: PaybondRunBindingSandboxBootstrapInput
    attach: PaybondRunBindingAttachInput
    registry: Any
    policy_snapshot: "PaybondPolicySnapshot"
    run_id: str
    policy_file: str
    reload: Any
    trace_sink: PaybondTraceSink
    on_trace: PaybondTraceSink
    agent_context: "PaybondRunAgentContextInput"


class _PaybondAuthorizeToolCallInputRequired(TypedDict):
    tool_name: str
    tool_call_id: str


class PaybondAuthorizeToolCallInput(_PaybondAuthorizeToolCallInputRequired, total=False):
    arguments: Any
    operation: str
    requested_spend_cents: int
    vendor_id: str
    task_id: str
    workflow_id: str
    currency: str
    agent_subject: str
    approval_token: str
    idempotency_key: str


class PaybondRunConfigHashMaterials(TypedDict):
    """Materials to auto-compute ``config_hash_hex`` per the Agent Receipt Standard spec:
    ``sha256(JCS({ system_prompt, tools_manifest, policy_snapshot_id }))``. ``policy_snapshot_id``
    defaults to the bound policy snapshot digest (without the ``sha256:`` prefix) when omitted."""

    system_prompt: str
    tools_manifest: Any
    policy_snapshot_id: NotRequired[str]


class PaybondRunAgentContextInput(TypedDict):
    """Optional agent identity/config context for :meth:`PaybondAgentRun.bind`.

    Threaded onto every spend verify call and used to compose the unsigned Agent Receipt
    Standard draft returned from :meth:`PaybondToolInterceptor.wrap_execute`. Raw prompts are
    hashed locally and never retained or transmitted; only ``prompt_hash_hex`` is kept on the
    resolved binding.
    """

    model_family: str
    model_instance_id: NotRequired[str]
    config_hash_hex: NotRequired[str]
    config_hash_materials: NotRequired[PaybondRunConfigHashMaterials]
    prompt_hash_hex: NotRequired[str]
    normalized_user_prompt: NotRequired[str]
    principal_did: NotRequired[str]
    operator_did: NotRequired[str]
    policy_template_id: NotRequired[str]


@dataclass(frozen=True, slots=True)
class PaybondRunAgentContext:
    """Resolved agent context stored on the run binding after bind-time hash computation."""

    model_family: str
    model_instance_id: str | None = None
    config_hash_hex: str | None = None
    prompt_hash_hex: str | None = None
    principal_did: str | None = None
    operator_did: str | None = None
    policy_template_id: str | None = None


class PaybondToolInputGuardAllowDecision(TypedDict, total=False):
    kind: Literal["allow"]
    passthrough: bool
    operation: str
    audit_id: str
    decision_id: str
    policy_digest: str


class PaybondToolInputGuardDenyDecision(TypedDict, total=False):
    kind: Literal["deny"]
    message: str
    operation: str
    audit_id: str
    code: str


class PaybondToolInputGuardApprovalRequiredDecision(TypedDict, total=False):
    kind: Literal["approval_required"]
    message: str
    operation: str
    audit_id: str
    code: str


PaybondToolInputGuardDecision = (
    PaybondToolInputGuardAllowDecision
    | PaybondToolInputGuardDenyDecision
    | PaybondToolInputGuardApprovalRequiredDecision
)

PaybondTraceSink = Callable[[dict[str, Any]], None]

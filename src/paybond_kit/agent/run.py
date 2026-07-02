"""Run binding for Paybond agent middleware."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, Callable, Literal, Protocol
from uuid import UUID, uuid4

from paybond_kit.guardrails import (
    SandboxGuardrailBootstrapResult,
    SandboxGuardrailEvidenceResult,
)
from paybond_kit.harbor import VerifyCapabilityResult

from paybond_kit.dev.trace_buffer import resolve_dev_trace_sink
from paybond_kit.agent.registry import PaybondToolRegistry
from paybond_kit.agent.types import (
    PaybondAgentRunBindConfig,
    PaybondAgentRunBindError,
    PaybondRunBinding,
    PaybondRunBindingAttachInput,
    PaybondRunBindingSandboxBootstrapInput,
    PaybondRunProductionEvidenceCredentials,
    PaybondRunSandboxBinding,
)
from paybond_kit.policy.reload import (
    PaybondPolicyReloadBindConfig,
    PaybondPolicyReloadOptions,
    PaybondPolicyReloadResult,
    reload_policy_on_run,
)
from paybond_kit.policy.watcher import PaybondPolicyReloadController

if TYPE_CHECKING:
    from paybond_kit.paybond import Paybond
    from paybond_kit.policy.snapshot import PaybondPolicySnapshot


class _AgentRunHarborHost(Protocol):
    @property
    def tenant_id(self) -> str: ...

    async def get_intent(self, intent_id: UUID) -> dict[str, Any]: ...

    async def verify_capability(
        self,
        *,
        intent_id: UUID,
        token: str,
        operation: str,
        requested_spend_cents: int = 0,
        vendor_id: str | None = None,
        task_id: str | None = None,
        workflow_id: str | None = None,
        tool_call_id: str | None = None,
        tool_name: str | None = None,
        currency: str | None = None,
        agent_subject: str | None = None,
        approval_token: str | None = None,
        idempotency_key: str | None = None,
    ) -> VerifyCapabilityResult: ...

    async def complete_spend_decision(
        self,
        *,
        decision_id: str,
        outcome: Literal["consumed", "released"],
    ) -> None: ...

    async def submit_evidence(
        self,
        intent_id: UUID,
        evidence_body: dict[str, Any],
        *,
        recognition_proof: Mapping[str, Any],
        idempotency_key: str | None = None,
    ) -> dict[str, Any]: ...


class _AgentRunGuardrailsHost(Protocol):
    async def bootstrap_sandbox(
        self,
        *,
        operation: str,
        requested_spend_cents: int,
        currency: str | None = None,
        evidence_schema: Mapping[str, Any] | None = None,
        metadata: Mapping[str, Any] | None = None,
        completion_preset: str | None = None,
        template_id: str | None = None,
        parameters: Mapping[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> SandboxGuardrailBootstrapResult: ...

    async def submit_sandbox_evidence(
        self,
        intent_id: UUID,
        payload: Mapping[str, Any] | None = None,
        *,
        vendor_payload: Mapping[str, Any] | None = None,
        artifacts: list[str] | None = None,
        operation: str | None = None,
        requested_spend_cents: int | None = None,
        metadata: Mapping[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> SandboxGuardrailEvidenceResult: ...


class PaybondAgentRunHost(Protocol):
    @property
    def harbor(self) -> _AgentRunHarborHost: ...

    @property
    def guardrails(self) -> _AgentRunGuardrailsHost: ...

    def spend_guard(self, intent_id: UUID, capability_token: str) -> Any: ...


def _new_run_id(explicit: str | None = None) -> str:
    trimmed = (explicit or "").strip()
    return trimmed or str(uuid4())


def _read_allowed_tools(intent: dict[str, Any]) -> list[str]:
    raw = intent.get("allowed_tools")
    if not isinstance(raw, list):
        return []
    return [str(entry).strip() for entry in raw if str(entry).strip()]


def _normalize_production_evidence(
    raw: PaybondRunProductionEvidenceCredentials | None,
    sandbox: PaybondRunSandboxBinding | None,
) -> PaybondRunProductionEvidenceCredentials | None:
    if sandbox is not None:
        return None
    if raw is None:
        raise PaybondAgentRunBindError(
            "attach.production_evidence is required for production auto-evidence submission"
        )

    payee_did = str(raw.get("payee_did", "")).strip()
    key_id = str(raw.get("agent_recognition_key_id", "")).strip()
    payee_seed = raw.get("payee_signing_seed", b"")
    agent_seed = raw.get("agent_recognition_signing_seed", b"")
    if not payee_did:
        raise PaybondAgentRunBindError(
            "attach.production_evidence requires a payee identity"
        )
    if not key_id:
        raise PaybondAgentRunBindError(
            "attach.production_evidence.agent_recognition_key_id must be non-empty"
        )
    if not isinstance(payee_seed, (bytes, bytearray)) or len(payee_seed) != 32:
        raise PaybondAgentRunBindError(
            "attach.production_evidence.payee_signing_seed must be exactly 32 bytes"
        )
    if not isinstance(agent_seed, (bytes, bytearray)) or len(agent_seed) != 32:
        raise PaybondAgentRunBindError(
            "attach.production_evidence.agent_recognition_signing_seed must be exactly 32 bytes"
        )

    return {
        "payee_did": payee_did,
        "payee_signing_seed": bytes(payee_seed),
        "agent_recognition_key_id": key_id,
        "agent_recognition_signing_seed": bytes(agent_seed),
    }


def _assert_exclusive_bind_mode(config: PaybondAgentRunBindConfig) -> None:
    has_bootstrap = config.get("bootstrap") is not None
    has_attach = config.get("attach") is not None
    if has_bootstrap == has_attach:
        raise PaybondAgentRunBindError("agent run bind requires exactly one of bootstrap or attach")


async def _resolve_attach_binding(
    paybond: PaybondAgentRunHost,
    attach: PaybondRunBindingAttachInput,
) -> tuple[UUID, str, tuple[str, ...]]:
    intent_id_raw = str(attach.get("intent_id", "")).strip()
    capability_token = str(attach.get("capability_token", "")).strip()
    if not intent_id_raw:
        raise PaybondAgentRunBindError("attach.intent_id must be non-empty")
    if not capability_token:
        raise PaybondAgentRunBindError("attach.capability_token must be non-empty")

    try:
        intent_id = UUID(intent_id_raw)
    except ValueError as exc:
        raise PaybondAgentRunBindError("attach.intent_id must be a UUID") from exc

    allowed_tools_raw = attach.get("allowed_tools")
    if allowed_tools_raw is None:
        intent = await paybond.harbor.get_intent(intent_id)
        allowed_tools = _read_allowed_tools(intent)
    else:
        allowed_tools = [str(entry).strip() for entry in allowed_tools_raw if str(entry).strip()]

    if not allowed_tools:
        raise PaybondAgentRunBindError(
            f"attach: intent {intent_id} has no allowed_tools; pass attach.allowed_tools explicitly"
        )

    return intent_id, capability_token, tuple(allowed_tools)


async def _resolve_sandbox_bootstrap(
    paybond: PaybondAgentRunHost,
    bootstrap: PaybondRunBindingSandboxBootstrapInput,
) -> tuple[UUID, str, tuple[str, ...], PaybondRunSandboxBinding]:
    kind = str(bootstrap.get("kind", "sandbox")).strip()
    if kind != "sandbox":
        raise PaybondAgentRunBindError('bootstrap.kind must be "sandbox"')

    operation = str(bootstrap.get("operation", "")).strip()
    if not operation:
        raise PaybondAgentRunBindError("bootstrap.operation must be non-empty")

    requested_spend_cents = int(bootstrap.get("requested_spend_cents", -1))
    if requested_spend_cents < 0:
        raise PaybondAgentRunBindError("bootstrap.requested_spend_cents must be a non-negative integer")

    bootstrap_result = await paybond.guardrails.bootstrap_sandbox(
        operation=operation,
        requested_spend_cents=requested_spend_cents,
        currency=bootstrap.get("currency"),
        evidence_schema=bootstrap.get("evidence_schema"),
        metadata=bootstrap.get("metadata"),
        completion_preset=bootstrap.get("completion_preset"),
        template_id=bootstrap.get("template_id"),
        parameters=bootstrap.get("parameters"),
        idempotency_key=bootstrap.get("idempotency_key"),
    )

    sandbox = PaybondRunSandboxBinding(
        operation=bootstrap_result.operation,
        requested_spend_cents=bootstrap_result.requested_spend_cents,
        sandbox_lifecycle_status=bootstrap_result.sandbox_lifecycle_status,
    )
    return (
        bootstrap_result.intent_id,
        bootstrap_result.capability_token,
        (bootstrap_result.operation,),
        sandbox,
    )


class PaybondAgentRun:
    """Run-scoped agent middleware context for one agent task."""

    __slots__ = (
        "binding",
        "_host",
        "interceptor",
        "_current_snapshot",
        "policy_file_path",
        "_reload_controller",
        "_reload_listeners",
    )

    def __init__(
        self,
        binding: PaybondRunBinding,
        host: PaybondAgentRunHost,
        *,
        current_snapshot: PaybondPolicySnapshot | None = None,
        policy_file_path: str | None = None,
    ) -> None:
        from paybond_kit.agent.interceptor import PaybondToolInterceptor

        self.binding = binding
        self._host = host
        self._current_snapshot = current_snapshot
        self.policy_file_path = policy_file_path
        self._reload_controller: PaybondPolicyReloadController | None = None
        self._reload_listeners: dict[str, list[Callable[..., None]]] = {
            "policy_reloaded": [],
            "policy_reload_failed": [],
        }
        self.interceptor = PaybondToolInterceptor(binding, host)

    @property
    def current_snapshot(self) -> PaybondPolicySnapshot | None:
        return self._current_snapshot

    @property
    def policy_digest(self) -> str | None:
        snapshot = self._current_snapshot
        return None if snapshot is None else snapshot.digest

    @property
    def policy_version(self) -> str | None:
        snapshot = self._current_snapshot
        return None if snapshot is None else snapshot.version

    @property
    def policy_loaded_at(self) -> str | None:
        snapshot = self._current_snapshot
        return None if snapshot is None else snapshot.loaded_at

    @property
    def run_id(self) -> str:
        return self.binding.run_id

    @property
    def tenant_id(self) -> str:
        return self.binding.tenant_id

    @property
    def intent_id(self) -> UUID:
        return self.binding.intent_id

    @property
    def capability_token(self) -> str:
        return self.binding.capability_token

    @property
    def guard(self) -> Any:
        return self.binding.guard

    @property
    def registry(self) -> PaybondToolRegistry:
        return self.binding.registry

    @property
    def allowed_tools(self) -> tuple[str, ...]:
        return self.binding.allowed_tools

    @property
    def in_flight_count(self) -> int:
        return self.interceptor.in_flight_count

    def on(self, event: str, listener: Callable[..., None]) -> None:
        if event in self._reload_listeners:
            self._reload_listeners[event].append(listener)

    def off(self, event: str, listener: Callable[..., None]) -> None:
        if event in self._reload_listeners:
            self._reload_listeners[event] = [
                item for item in self._reload_listeners[event] if item is not listener
            ]

    def _emit(self, event: str, payload: Any) -> None:
        for listener in self._reload_listeners.get(event, []):
            listener(payload)

    def apply_policy_snapshot(self, snapshot: PaybondPolicySnapshot) -> None:
        # Mutate binding in place so the interceptor keeps the same reference (Tier 7).
        object.__setattr__(self.binding, "registry", snapshot.registry)
        object.__setattr__(self.binding, "policy_snapshot", snapshot)
        self._current_snapshot = snapshot

    def start_policy_reload(self, config: PaybondPolicyReloadBindConfig) -> None:
        if not self.policy_file_path:
            raise RuntimeError("start_policy_reload requires policy_file_path from bind")
        self.stop_policy_reload()
        self._reload_controller = PaybondPolicyReloadController.start(
            self,
            config,
            self.policy_file_path,
        )

    async def reload_policy(
        self,
        options: PaybondPolicyReloadOptions | None = None,
    ) -> PaybondPolicyReloadResult:
        try:
            result = await reload_policy_on_run(self, options)
            if result.applied and result.previous_digest and result.new_digest:
                self._emit(
                    "policy_reloaded",
                    {"previous_digest": result.previous_digest, "new_digest": result.new_digest},
                )
            return result
        except Exception as exc:
            self._emit("policy_reload_failed", {"error": exc})
            raise

    def stop_policy_reload(self) -> None:
        if self._reload_controller is not None:
            self._reload_controller.stop()
            self._reload_controller = None

    @classmethod
    async def bind(cls, paybond: PaybondAgentRunHost, config: PaybondAgentRunBindConfig) -> PaybondAgentRun:
        _assert_exclusive_bind_mode(config)

        registry = config.get("registry")
        if registry is None:
            raise PaybondAgentRunBindError("registry is required")

        run_id = _new_run_id(config.get("run_id"))
        tenant_id = paybond.harbor.tenant_id
        sandbox: PaybondRunSandboxBinding | None = None
        attach: PaybondRunBindingAttachInput | None = None
        production_evidence: PaybondRunProductionEvidenceCredentials | None = None

        bootstrap = config.get("bootstrap")
        if bootstrap is not None:
            intent_id, capability_token, allowed_tools, sandbox = await _resolve_sandbox_bootstrap(
                paybond,
                bootstrap,
            )
        else:
            attach = config.get("attach")
            if attach is None:
                raise PaybondAgentRunBindError("agent run bind requires exactly one of bootstrap or attach")
            intent_id, capability_token, allowed_tools = await _resolve_attach_binding(paybond, attach)
            sandbox_raw = attach.get("sandbox")
            if isinstance(sandbox_raw, PaybondRunSandboxBinding):
                sandbox = sandbox_raw
            elif isinstance(sandbox_raw, dict):
                sandbox = PaybondRunSandboxBinding(
                    operation=str(sandbox_raw.get("operation", "")),
                    requested_spend_cents=int(sandbox_raw.get("requested_spend_cents", 0)),
                    sandbox_lifecycle_status=str(sandbox_raw.get("sandbox_lifecycle_status", "")),
                )
            production_evidence = _normalize_production_evidence(
                attach.get("production_evidence"),
                sandbox,
            )

        snapshot = config.get("policy_snapshot")
        registry = snapshot.registry if snapshot is not None else registry
        registry.validate_for_bind(list(allowed_tools))
        guard = paybond.spend_guard(intent_id, capability_token)
        binding = PaybondRunBinding(
            run_id=run_id,
            tenant_id=tenant_id,
            intent_id=intent_id,
            capability_token=capability_token,
            guard=guard,
            registry=registry,
            allowed_tools=allowed_tools,
            sandbox=sandbox,
            production_evidence=production_evidence,
            policy_snapshot=snapshot,
            on_trace=config.get("trace_sink") or config.get("on_trace") or resolve_dev_trace_sink(),
        )
        policy_file_path = (config.get("policy_file") or "").strip() or None
        run = cls(binding, paybond, current_snapshot=snapshot, policy_file_path=policy_file_path)
        reload_cfg = config.get("reload")
        if reload_cfg and policy_file_path:
            run.start_policy_reload(reload_cfg)
        return run


class PaybondAgentRunFacade:
    """Facade exposed as ``paybond.agent_run``."""

    __slots__ = ("_paybond",)

    def __init__(self, paybond: Paybond) -> None:
        self._paybond = paybond

    async def bind(self, config: PaybondAgentRunBindConfig) -> PaybondAgentRun:
        return await PaybondAgentRun.bind(self._paybond, config)

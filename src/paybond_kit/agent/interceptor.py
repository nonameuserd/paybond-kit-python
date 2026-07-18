"""Pre/post intercept: authorize, execute, complete spend, and auto-evidence."""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Literal
from uuid import UUID

from paybond_kit.agent.authorization_cache import (
    evict_expired_authorization_cache,
    take_valid_cached_authorization,
)
from paybond_kit.agent.types import (
    PaybondRunBinding,
    PaybondSideEffectingToolEntry,
    PaybondToolCallContext,
    PaybondToolInputGuardApprovalRequiredDecision,
    PaybondToolInputGuardDecision,
    PaybondToolInputGuardDenyDecision,
    PaybondUnregisteredSideEffectingToolError,
)
from paybond_kit.agent_receipt import (
    AGENT_RECEIPT_KIND_V1,
    AGENT_RECEIPT_SCHEMA_VERSION,
    AGENT_RECEIPT_SCOPE_ACTION,
    AGENT_RECEIPT_SIGNING_ALGORITHM_ED25519,
    AGENT_RECEIPT_VERSION_V1,
    action_receipt_id,
    agent_receipt_message_digest_sha256_hex,
    value_digest_sha256_hex,
)
from paybond_kit.agent_receipt_external_attestations import resolve_external_attestations
from paybond_kit.agent.evidence import build_auto_evidence_payload
from paybond_kit.agent_recognition import sign_harbor_evidence_submit_recognition_proof
from paybond_kit.signing import sign_payee_evidence_binding
from paybond_kit.spend_guard import PaybondSpendApprovalRequiredError, PaybondSpendDeniedError

if TYPE_CHECKING:
    from paybond_kit.agent.run import PaybondAgentRunHost


class PaybondEvidenceSubmitError(RuntimeError):
    """Raised when auto-evidence submission fails after a successful tool execution."""

    def __init__(self, message: str, tool_result: Any, *, cause: BaseException | None = None) -> None:
        super().__init__(message)
        self.tool_result = tool_result
        self.__cause__ = cause


PaybondAutoEvidenceSubmitError = PaybondEvidenceSubmitError


@dataclass(frozen=True, slots=True)
class AgentReceiptComposeResult:
    compose_status: Literal["composed", "failed"]
    receipt_id: str | None = None
    scope: str | None = None
    warning_code: str | None = None
    warning_message: str | None = None


@dataclass(frozen=True, slots=True)
class PaybondInterceptEvidenceResult:
    submitted: Literal[True]
    intent_id: str
    predicate_passed: bool | None = None
    sandbox_lifecycle_status: str | None = None
    intent_state: str | None = None
    payload_digest_sha256_hex: str | None = None
    artifacts_digest_sha256_hex: str | None = None
    agent_receipt: AgentReceiptComposeResult | None = None


def _parse_agent_receipt_compose_result(value: Any) -> AgentReceiptComposeResult | None:
    if not isinstance(value, dict):
        return None
    compose_status = value.get("compose_status")
    if compose_status not in ("composed", "failed"):
        return None
    receipt_id = value.get("receipt_id")
    scope = value.get("scope")
    warning_code = value.get("warning_code")
    warning_message = value.get("warning_message")
    return AgentReceiptComposeResult(
        compose_status=compose_status,
        receipt_id=str(receipt_id) if isinstance(receipt_id, str) else None,
        scope=str(scope) if isinstance(scope, str) else None,
        warning_code=str(warning_code) if isinstance(warning_code, str) else None,
        warning_message=str(warning_message) if isinstance(warning_message, str) else None,
    )


@dataclass(frozen=True, slots=True)
class PaybondInterceptWrapExecuteResult:
    tool_result: Any
    authorization: dict[str, Any] | None = None
    evidence: PaybondInterceptEvidenceResult | None = None
    receipt_draft: dict[str, Any] | None = None


def _now_rfc3339_seconds() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _epoch_ms_to_rfc3339(epoch_ms: int) -> str:
    return datetime.fromtimestamp(epoch_ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _trace_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _evidence_idempotency_key(intent_id: str | UUID, tool_call_id: str) -> str:
    return f"evidence:{intent_id}:{tool_call_id}"


def _assert_operation_allowed(operation: str, allowed_tools: tuple[str, ...]) -> None:
    if operation not in allowed_tools:
        allowed = ", ".join(allowed_tools)
        raise RuntimeError(
            f'operation "{operation}" is not in bound intent allowedTools ({allowed})'
        )


def _build_auto_evidence_payload(
    entry: PaybondSideEffectingToolEntry,
    result: Any,
    ctx: PaybondToolCallContext,
) -> dict[str, Any]:
    return build_auto_evidence_payload(entry, result, ctx)


def _authorization_cache_key(tool_call_id: str, operation: str) -> str:
    return f"{tool_call_id}:{operation}"


def _map_spend_error_to_decision(
    exc: PaybondSpendApprovalRequiredError | PaybondSpendDeniedError,
    operation: str,
    *,
    kind: Literal["deny", "approval_required"],
) -> PaybondToolInputGuardDecision:
    result = exc.result
    message = result.message or result.code or str(exc)
    if kind == "approval_required":
        decision: PaybondToolInputGuardApprovalRequiredDecision = {
            "kind": "approval_required",
            "message": message,
            "operation": operation,
        }
        if result.audit_id is not None:
            decision["audit_id"] = str(result.audit_id)
        if result.code is not None:
            decision["code"] = result.code
        return decision
    deny_decision: PaybondToolInputGuardDenyDecision = {
        "kind": "deny",
        "message": message,
        "operation": operation,
    }
    if result.audit_id is not None:
        deny_decision["audit_id"] = str(result.audit_id)
    if result.code is not None:
        deny_decision["code"] = result.code
    return deny_decision


class PaybondToolInterceptor:
    """Authorize side-effecting tools, execute handlers, and submit auto-evidence."""

    __slots__ = ("_binding", "_host", "_authorized_calls", "_in_flight_count")

    def __init__(self, binding: PaybondRunBinding, host: "PaybondAgentRunHost") -> None:
        self._binding = binding
        self._host = host
        self._authorized_calls: dict[str, Any] = {}
        self._in_flight_count = 0

    @property
    def in_flight_count(self) -> int:
        return self._in_flight_count

    def _begin_in_flight(self) -> str | None:
        self._in_flight_count += 1
        snapshot = self._binding.policy_snapshot
        return None if snapshot is None else snapshot.digest

    def _end_in_flight(self) -> None:
        self._in_flight_count = max(0, self._in_flight_count - 1)

    def _emit_trace(self, event: dict[str, Any]) -> None:
        sink = self._binding.on_trace
        if sink is None:
            return
        if "recorded_at" not in event:
            event = {**event, "recorded_at": _trace_timestamp()}
        sink(event)

    async def authorize_tool_call(
        self,
        *,
        tool_name: str,
        tool_call_id: str,
        arguments: Any,
        operation: str | None = None,
        requested_spend_cents: int | None = None,
        vendor_id: str | None = None,
        task_id: str | None = None,
        workflow_id: str | None = None,
        currency: str | None = None,
        agent_subject: str | None = None,
        approval_token: str | None = None,
        idempotency_key: str | None = None,
    ) -> PaybondToolInputGuardDecision:
        tool_name = tool_name.strip()
        tool_call_id = tool_call_id.strip()
        if not tool_name:
            raise ValueError("tool_name must be non-empty")
        if not tool_call_id:
            raise ValueError("tool_call_id must be non-empty")

        pinned_digest = self._begin_in_flight()
        try:
            resolution = self._binding.registry.resolve_tool(
                tool_name,
                allowed_tools=list(self._binding.allowed_tools),
            )

            if resolution.kind == "passthrough":
                return {"kind": "allow", "passthrough": True, "operation": tool_name}

            if resolution.kind == "denied":
                return {
                    "kind": "deny",
                    "operation": resolution.operation,
                    "message": (
                        f'side-effecting tool "{resolution.tool_name}" '
                        f'(operation "{resolution.operation}") is in intent allowedTools but not registered'
                    ),
                }

            try:
                resolved = self._resolve_side_effecting_call(
                    tool_name=tool_name,
                    tool_call_id=tool_call_id,
                    arguments=arguments,
                    entry=resolution.entry,
                    default_operation=resolution.operation,
                    operation=operation,
                    requested_spend_cents=requested_spend_cents,
                    vendor_id=vendor_id,
                    task_id=task_id,
                    workflow_id=workflow_id,
                    currency=currency,
                    agent_subject=agent_subject,
                    approval_token=approval_token,
                    idempotency_key=idempotency_key,
                )
            except RuntimeError as exc:
                return {"kind": "deny", "message": str(exc), "operation": resolution.operation}

            self._emit_trace(
                {
                    "type": "tool_selected",
                    "run_id": self._binding.run_id,
                    "tool_name": tool_name,
                    "tool_call_id": tool_call_id,
                    "operation": resolved["operation"],
                }
            )

            guard = self._binding.guard
            try:
                auth = await guard.assert_spend_authorized(**resolved["auth_kwargs"])
            except PaybondSpendApprovalRequiredError as exc:
                decision = _map_spend_error_to_decision(
                    exc,
                    resolved["operation"],
                    kind="approval_required",
                )
                if decision.get("kind") == "approval_required":
                    self._emit_trace(
                        {
                            "type": "approval_required",
                            "run_id": self._binding.run_id,
                            "tool_call_id": tool_call_id,
                            "operation": resolved["operation"],
                            "message": str(decision.get("message") or "approval_required"),
                            "audit_id": decision.get("audit_id"),
                            "code": decision.get("code"),
                        }
                    )
                return decision
            except PaybondSpendDeniedError as exc:
                decision = _map_spend_error_to_decision(exc, resolved["operation"], kind="deny")
                if decision.get("kind") == "deny":
                    self._emit_trace(
                        {
                            "type": "spend_denied",
                            "run_id": self._binding.run_id,
                            "tool_call_id": tool_call_id,
                            "operation": resolved["operation"],
                            "message": str(decision.get("message") or "denied"),
                            "audit_id": decision.get("audit_id"),
                            "code": decision.get("code"),
                        }
                    )
                return decision

            evict_expired_authorization_cache(self._authorized_calls)
            self._authorized_calls[_authorization_cache_key(tool_call_id, resolved["operation"])] = {
                "auth": auth,
                "policy_digest": pinned_digest,
                "operation": resolved["operation"],
                "requested_spend_cents": resolved["requested_spend_cents"],
                "tool_name": tool_name,
                "cached_at": time.monotonic(),
                "authorized_at_ms": int(time.time() * 1000),
            }
            self._emit_trace(
                {
                    "type": "spend_authorized",
                    "run_id": self._binding.run_id,
                    "tool_call_id": tool_call_id,
                    "operation": resolved["operation"],
                    "audit_id": str(auth.audit_id),
                    "decision_id": str(auth.decision_id) if auth.decision_id is not None else None,
                    "amount_cents": resolved["requested_spend_cents"],
                }
            )
            decision: PaybondToolInputGuardDecision = {
                "kind": "allow",
                "operation": resolved["operation"],
                "audit_id": str(auth.audit_id),
            }
            if auth.decision_id is not None:
                decision["decision_id"] = str(auth.decision_id)
            if pinned_digest is not None:
                decision["policy_digest"] = pinned_digest
            return decision
        finally:
            self._end_in_flight()

    async def wrap_execute(
        self,
        *,
        tool_name: str,
        tool_call_id: str,
        arguments: Any,
        execute: Callable[[], Any | Awaitable[Any]],
        operation: str | None = None,
        requested_spend_cents: int | None = None,
        vendor_id: str | None = None,
        task_id: str | None = None,
        workflow_id: str | None = None,
        currency: str | None = None,
        agent_subject: str | None = None,
        approval_token: str | None = None,
        idempotency_key: str | None = None,
    ) -> PaybondInterceptWrapExecuteResult:
        tool_name = tool_name.strip()
        tool_call_id = tool_call_id.strip()
        if not tool_name:
            raise ValueError("tool_name must be non-empty")
        if not tool_call_id:
            raise ValueError("tool_call_id must be non-empty")

        pinned_digest = self._begin_in_flight()
        try:
            resolution = self._binding.registry.resolve_tool(
                tool_name,
                allowed_tools=list(self._binding.allowed_tools),
            )

            if resolution.kind == "passthrough":
                out = execute()
                if hasattr(out, "__await__"):
                    out = await out
                return PaybondInterceptWrapExecuteResult(tool_result=out)

            if resolution.kind == "denied":
                raise PaybondUnregisteredSideEffectingToolError(
                    resolution.tool_name,
                    resolution.operation,
                )

            resolved = self._resolve_side_effecting_call(
                tool_name=tool_name,
                tool_call_id=tool_call_id,
                arguments=arguments,
                entry=resolution.entry,
                default_operation=resolution.operation,
                operation=operation,
                requested_spend_cents=requested_spend_cents,
                vendor_id=vendor_id,
                task_id=task_id,
                workflow_id=workflow_id,
                currency=currency,
                agent_subject=agent_subject,
                approval_token=approval_token,
                idempotency_key=idempotency_key,
            )
            self._emit_trace(
                {
                    "type": "tool_selected",
                    "run_id": self._binding.run_id,
                    "tool_name": tool_name,
                    "tool_call_id": tool_call_id,
                    "operation": resolved["operation"],
                }
            )

            cache_key = _authorization_cache_key(tool_call_id, resolved["operation"])
            cached = take_valid_cached_authorization(
                self._authorized_calls,
                cache_key,
                {
                    "operation": resolved["operation"],
                    "requested_spend_cents": resolved["requested_spend_cents"],
                    "tool_name": tool_name,
                },
            )
            evidence_policy_digest = (
                cached.get("policy_digest") if cached is not None else None
            ) or pinned_digest
            guard = self._binding.guard
            if cached is not None:
                auth = cached["auth"]
                authorized_at_ms = cached["authorized_at_ms"]
            else:
                auth = await guard.assert_spend_authorized(**resolved["auth_kwargs"])
                authorized_at_ms = int(time.time() * 1000)
                self._emit_trace(
                    {
                        "type": "spend_authorized",
                        "run_id": self._binding.run_id,
                        "tool_call_id": tool_call_id,
                        "operation": resolved["operation"],
                        "audit_id": str(auth.audit_id),
                        "decision_id": str(auth.decision_id) if auth.decision_id is not None else None,
                        "amount_cents": resolved["requested_spend_cents"],
                    }
                )

            execute_started_at = time.perf_counter()
            execute_started_at_ms = int(time.time() * 1000)
            try:
                tool_result = execute()
                if hasattr(tool_result, "__await__"):
                    tool_result = await tool_result
                duration_ms = int((time.perf_counter() - execute_started_at) * 1000)
                self._emit_trace(
                    {
                        "type": "tool_executed",
                        "run_id": self._binding.run_id,
                        "tool_call_id": tool_call_id,
                        "operation": resolved["operation"],
                        "duration_ms": duration_ms,
                    }
                )

                if auth.decision_id is not None:
                    await guard.complete_spend_authorization(str(auth.decision_id), "consumed")
                    self._emit_trace(
                        {
                            "type": "spend_finalized",
                            "run_id": self._binding.run_id,
                            "tool_call_id": tool_call_id,
                            "operation": resolved["operation"],
                            "status": "consumed",
                        }
                    )
            except Exception:
                if auth.decision_id is not None:
                    try:
                        await guard.complete_spend_authorization(str(auth.decision_id), "released")
                        self._emit_trace(
                            {
                                "type": "spend_finalized",
                                "run_id": self._binding.run_id,
                                "tool_call_id": tool_call_id,
                                "operation": resolved["operation"],
                                "status": "released",
                            }
                        )
                    except Exception:
                        pass
                raise

            evidence_id = _evidence_idempotency_key(str(self._binding.intent_id), tool_call_id)
            external_attestations = self._resolve_tool_external_attestations(
                resolved["entry"],
                tool_result,
                PaybondToolCallContext(
                    tool_name=tool_name,
                    tool_call_id=tool_call_id,
                    operation=resolved["operation"],
                    arguments=arguments,
                ),
            )
            evidence = await self._submit_auto_evidence(
                entry=resolved["entry"],
                tool_name=tool_name,
                tool_call_id=tool_call_id,
                operation=resolved["operation"],
                arguments=arguments,
                requested_spend_cents=resolved["requested_spend_cents"],
                tool_result=tool_result,
                auth=auth,
                evidence_id=evidence_id,
            )
            reported_cost_cents = (
                tool_result.get("cost_cents")
                if isinstance(tool_result, dict)
                and isinstance(tool_result.get("cost_cents"), int)
                and not isinstance(tool_result.get("cost_cents"), bool)
                else None
            )
            self._emit_trace(
                {
                    "type": "evidence_submitted",
                    "run_id": self._binding.run_id,
                    "tool_call_id": tool_call_id,
                    "operation": resolved["operation"],
                    "evidence_id": evidence_id,
                    "preset_id": resolved["entry"].evidence_preset,
                    "evidence_preset": resolved["entry"].evidence_preset,
                    "reported_cost_cents": reported_cost_cents,
                    "sandbox_lifecycle_status": evidence.sandbox_lifecycle_status,
                    "predicate_passed": evidence.predicate_passed,
                    "external_attestations": external_attestations,
                }
            )

            authorization: dict[str, Any] = {
                "allow": True,
                "audit_id": str(auth.audit_id),
                "decision_id": str(auth.decision_id) if auth.decision_id is not None else None,
            }
            if evidence_policy_digest is not None:
                authorization["policy_digest"] = evidence_policy_digest

            receipt_draft = self._build_receipt_draft(
                tool_name=tool_name,
                tool_call_id=tool_call_id,
                operation=resolved["operation"],
                arguments=arguments,
                agent_subject=resolved["auth_kwargs"].get("agent_subject"),
                requested_spend_cents=resolved["requested_spend_cents"],
                currency=resolved["auth_kwargs"].get("currency"),
                vendor_id=resolved["auth_kwargs"].get("vendor_id"),
                entry=resolved["entry"],
                auth=auth,
                authorized_at_ms=authorized_at_ms,
                policy_digest=evidence_policy_digest,
                execute_started_at_ms=execute_started_at_ms,
                tool_result=tool_result,
                evidence=evidence,
                external_attestations=external_attestations,
            )

            return PaybondInterceptWrapExecuteResult(
                tool_result=tool_result,
                authorization=authorization,
                evidence=evidence,
                receipt_draft=receipt_draft,
            )
        finally:
            self._end_in_flight()

    def _resolve_side_effecting_call(
        self,
        *,
        tool_name: str,
        tool_call_id: str,
        arguments: Any,
        entry: PaybondSideEffectingToolEntry,
        default_operation: str,
        operation: str | None,
        requested_spend_cents: int | None,
        vendor_id: str | None,
        task_id: str | None,
        workflow_id: str | None,
        currency: str | None,
        agent_subject: str | None,
        approval_token: str | None,
        idempotency_key: str | None,
    ) -> dict[str, Any]:
        resolved_operation = (operation or default_operation).strip()
        _assert_operation_allowed(resolved_operation, self._binding.allowed_tools)

        spend_cents = requested_spend_cents
        if spend_cents is None:
            spend_cents = self._binding.registry.resolve_spend_cents(tool_name, arguments)
        if self._binding.sandbox is not None:
            sandbox_spend = self._binding.sandbox.requested_spend_cents
            if spend_cents is None:
                spend_cents = sandbox_spend
            else:
                spend_cents = min(spend_cents, sandbox_spend)

        agent_context = self._binding.agent_context
        return {
            "operation": resolved_operation,
            "requested_spend_cents": spend_cents,
            "entry": entry,
            "auth_kwargs": {
                "operation": resolved_operation,
                "requested_spend_cents": spend_cents or 0,
                "vendor_id": vendor_id,
                "task_id": task_id,
                "workflow_id": workflow_id,
                "tool_call_id": tool_call_id,
                "tool_name": tool_name,
                "currency": currency,
                "agent_subject": agent_subject or (agent_context.operator_did if agent_context else None),
                "approval_token": approval_token,
                "idempotency_key": idempotency_key,
                "model_family": agent_context.model_family if agent_context else None,
                "config_hash_hex": agent_context.config_hash_hex if agent_context else None,
                "prompt_hash_hex": agent_context.prompt_hash_hex if agent_context else None,
            },
        }

    async def _submit_auto_evidence(
        self,
        *,
        entry: PaybondSideEffectingToolEntry,
        tool_name: str,
        tool_call_id: str,
        operation: str,
        arguments: Any,
        requested_spend_cents: int | None,
        tool_result: Any,
        auth: Any,
        evidence_id: str,
    ) -> PaybondInterceptEvidenceResult:
        ctx = PaybondToolCallContext(
            tool_name=tool_name,
            tool_call_id=tool_call_id,
            operation=operation,
            arguments=arguments,
        )

        try:
            payload = _build_auto_evidence_payload(entry, tool_result, ctx)
        except Exception as exc:
            raise PaybondEvidenceSubmitError(str(exc), tool_result, cause=exc) from exc

        intent_id = self._binding.intent_id
        idempotency_key = evidence_id

        try:
            if self._binding.sandbox is not None:
                result = await self._host.guardrails.submit_sandbox_evidence(
                    intent_id=intent_id,
                    payload=payload,
                    operation=operation,
                    requested_spend_cents=requested_spend_cents,
                    metadata={
                        "tool_name": tool_name,
                        "tool_call_id": tool_call_id,
                        "evidence_preset": entry.evidence_preset,
                        "decision_id": auth.decision_id,
                    },
                    idempotency_key=idempotency_key,
                )
                payload_digest = getattr(result, "payload_digest", None)
                artifacts_digest = getattr(result, "artifacts_digest", None)
                agent_receipt_raw = (
                    result.get("agent_receipt")
                    if isinstance(result, dict)
                    else getattr(result, "agent_receipt", None)
                )
                return PaybondInterceptEvidenceResult(
                    submitted=True,
                    intent_id=str(result.intent_id),
                    predicate_passed=result.predicate_passed,
                    sandbox_lifecycle_status=result.sandbox_lifecycle_status,
                    payload_digest_sha256_hex=(payload_digest or "").strip().lower() or None,
                    artifacts_digest_sha256_hex=(artifacts_digest or "").strip().lower() or None,
                    agent_receipt=_parse_agent_receipt_compose_result(agent_receipt_raw),
                )

            production_evidence = self._binding.production_evidence
            if production_evidence is None:
                raise RuntimeError(
                    "production agent run bind requires attach.production_evidence for auto-evidence submission"
                )

            wire = sign_payee_evidence_binding(
                tenant_id=self._binding.tenant_id,
                intent_id=intent_id,
                payee_did=production_evidence["payee_did"],
                payload=payload,
                artifacts_blake3_hex=[],
                submitted_at_rfc3339=_now_rfc3339_seconds(),
                payee_signing_seed=production_evidence["payee_signing_seed"],
            )
            recognition_proof = sign_harbor_evidence_submit_recognition_proof(
                tenant_id=self._binding.tenant_id,
                intent_id=str(intent_id),
                evidence_body=wire,
                key_id=production_evidence["agent_recognition_key_id"],
                signing_seed=production_evidence["agent_recognition_signing_seed"],
            )

            result = await self._host.harbor.submit_evidence(
                intent_id,
                wire,
                recognition_proof=recognition_proof,
                idempotency_key=idempotency_key,
            )

            intent_state = None
            predicate_passed = None
            payload_digest = None
            artifacts_digest = None
            agent_receipt_raw = None
            if isinstance(result, dict):
                intent_state = result.get("intent_state") or result.get("state")
                if isinstance(result.get("predicate_passed"), bool):
                    predicate_passed = result["predicate_passed"]
                if isinstance(result.get("payload_digest"), str):
                    payload_digest = result["payload_digest"].strip().lower() or None
                if isinstance(result.get("artifacts_digest"), str):
                    artifacts_digest = result["artifacts_digest"].strip().lower() or None
                agent_receipt_raw = result.get("agent_receipt")

            return PaybondInterceptEvidenceResult(
                submitted=True,
                intent_id=str(intent_id),
                intent_state=str(intent_state) if intent_state is not None else None,
                predicate_passed=predicate_passed,
                payload_digest_sha256_hex=payload_digest,
                artifacts_digest_sha256_hex=artifacts_digest,
                agent_receipt=_parse_agent_receipt_compose_result(agent_receipt_raw),
            )
        except PaybondEvidenceSubmitError:
            raise
        except Exception as exc:
            message = str(exc) if str(exc) else "auto-evidence submission failed"
            raise PaybondEvidenceSubmitError(message, tool_result, cause=exc) from exc

    def _build_receipt_draft(
        self,
        *,
        tool_name: str,
        tool_call_id: str,
        operation: str,
        arguments: Any,
        agent_subject: str | None,
        requested_spend_cents: int,
        currency: str | None,
        vendor_id: str | None,
        entry: PaybondSideEffectingToolEntry,
        auth: Any,
        authorized_at_ms: int,
        policy_digest: str | None,
        execute_started_at_ms: int,
        tool_result: Any,
        evidence: PaybondInterceptEvidenceResult,
        external_attestations: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any] | None:
        """Composes an unsigned Agent Receipt Standard draft (Phase 1) after a successful
        authorize -> execute -> evidence cycle. Never signed or persisted here; Phase 2 covers
        compose/sign/persist. Best-effort: returns ``None`` instead of raising whenever required
        receipt fields (agent context, principal/operator DID, policy template, pinned policy
        digest, or a Harbor decision id) are unavailable on this binding or call.
        """
        try:
            agent_context = self._binding.agent_context
            if agent_context is None or not (
                agent_context.operator_did and agent_context.principal_did and agent_context.policy_template_id
            ):
                return None
            if not (agent_context.config_hash_hex and agent_context.prompt_hash_hex):
                return None
            if auth.decision_id is None or not policy_digest:
                return None

            actor_subject = agent_subject or agent_context.operator_did
            bare_digest = policy_digest[len("sha256:") :] if policy_digest.startswith("sha256:") else policy_digest

            completed_at_ms = int(time.time() * 1000)
            arguments_digest = value_digest_sha256_hex(arguments)
            try:
                result_digest: str | None = value_digest_sha256_hex(tool_result)
            except Exception:
                result_digest = None

            harbor_state = evidence.intent_state or evidence.sandbox_lifecycle_status or "evidence_submitted"

            merchant: dict[str, Any] | None = None
            evidence_block: dict[str, Any] | None = None
            payee_did = (
                self._binding.production_evidence.get("payee_did")
                if self._binding.production_evidence is not None
                else None
            )
            if payee_did and evidence.payload_digest_sha256_hex:
                merchant = {"payee_did": payee_did}
                if vendor_id:
                    merchant["vendor_id"] = vendor_id
                evidence_block = {
                    "completion_preset_id": entry.evidence_preset,
                    "payload_digest_sha256_hex": evidence.payload_digest_sha256_hex,
                    "predicate_passed": bool(evidence.predicate_passed),
                    "payee_did": payee_did,
                }
                if evidence.artifacts_digest_sha256_hex:
                    evidence_block["artifacts_digest_sha256_hex"] = evidence.artifacts_digest_sha256_hex

            draft: dict[str, Any] = {
                "schema_version": AGENT_RECEIPT_SCHEMA_VERSION,
                "kind": AGENT_RECEIPT_KIND_V1,
                "receipt_version": AGENT_RECEIPT_VERSION_V1,
                "scope": AGENT_RECEIPT_SCOPE_ACTION,
                "receipt_id": action_receipt_id(str(self._binding.intent_id), tool_call_id),
                "issued_at": _epoch_ms_to_rfc3339(completed_at_ms),
                "tenant_id": self._binding.tenant_id,
                "authorization": {
                    "principal_did": agent_context.principal_did,
                    "actor_subject": actor_subject,
                    "agent": {
                        "operator_did": agent_context.operator_did,
                        "model_family": agent_context.model_family,
                        **(
                            {"model_instance_id": agent_context.model_instance_id}
                            if agent_context.model_instance_id
                            else {}
                        ),
                        "config_hash_sha256_hex": agent_context.config_hash_hex,
                        "prompt_hash_sha256_hex": agent_context.prompt_hash_hex,
                    },
                    "decision_id": str(auth.decision_id),
                    "audit_id": str(auth.audit_id),
                    "policy": {
                        "template_id": agent_context.policy_template_id,
                        "content_digest_sha256_hex": bare_digest,
                    },
                    "authorized_at": _epoch_ms_to_rfc3339(authorized_at_ms),
                    "requested_spend_cents": requested_spend_cents,
                    "currency": (currency or "usd").lower(),
                },
                "execution": {
                    "run_id": self._binding.run_id,
                    "tool_call_id": tool_call_id,
                    "tool_name": tool_name,
                    "operation": operation,
                    "arguments_digest_sha256_hex": arguments_digest,
                    **(
                        {"result_digest_sha256_hex": result_digest}
                        if result_digest is not None
                        else {}
                    ),
                    "outcome": "executed",
                    "started_at": _epoch_ms_to_rfc3339(execute_started_at_ms),
                    "completed_at": _epoch_ms_to_rfc3339(completed_at_ms),
                    "duration_ms": max(0, completed_at_ms - execute_started_at_ms),
                },
                "outcome": {
                    "harbor_state": harbor_state,
                    "spend_reservation_outcome": "consumed",
                    **(
                        {"predicate_passed": evidence.predicate_passed}
                        if evidence.predicate_passed is not None
                        else {}
                    ),
                },
                "references": {
                    "intent_id": str(self._binding.intent_id),
                    "settlement_receipt_id": None,
                },
                "external_attestations": external_attestations or [],
                "signing_algorithm": AGENT_RECEIPT_SIGNING_ALGORITHM_ED25519,
                "message_digest_sha256_hex": "",
                "signing_public_key_ed25519_hex": "",
                "ed25519_signature_hex": "",
            }
            if merchant is not None:
                draft["merchant"] = merchant
            if evidence_block is not None:
                draft["evidence"] = evidence_block

            draft["message_digest_sha256_hex"] = agent_receipt_message_digest_sha256_hex(draft)
            return draft
        except Exception:
            # Draft composition is always best-effort; never fails tool execution (Phase 1).
            return None

    def _resolve_tool_external_attestations(
        self,
        entry: PaybondSideEffectingToolEntry,
        tool_result: Any,
        ctx: PaybondToolCallContext,
    ) -> list[dict[str, Any]]:
        mapper = entry.external_attestation_mapper
        if mapper is None:
            return []
        try:
            mapped = mapper(tool_result, ctx)
            if mapped is None:
                return []
            inputs = mapped if isinstance(mapped, list) else [mapped]
            return [dict(item) for item in resolve_external_attestations(inputs)]
        except Exception:
            return []


__all__ = [
    "PaybondAutoEvidenceSubmitError",
    "PaybondEvidenceSubmitError",
    "AgentReceiptComposeResult",
    "PaybondInterceptEvidenceResult",
    "PaybondInterceptWrapExecuteResult",
    "PaybondToolInterceptor",
]

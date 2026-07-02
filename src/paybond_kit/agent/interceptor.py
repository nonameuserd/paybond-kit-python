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
from paybond_kit.agent_recognition import sign_harbor_evidence_submit_recognition_proof
from paybond_kit.signing import sign_payee_evidence_binding
from paybond_kit.spend_guard import PaybondSpendApprovalRequiredError, PaybondSpendDeniedError
from paybond_kit.completion_resolve import (
    is_vendor_pack,
    map_vendor_evidence_to_canonical,
    resolve_completion_preset,
)

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
class PaybondInterceptEvidenceResult:
    submitted: Literal[True]
    intent_id: str
    predicate_passed: bool | None = None
    sandbox_lifecycle_status: str | None = None
    intent_state: str | None = None


@dataclass(frozen=True, slots=True)
class PaybondInterceptWrapExecuteResult:
    tool_result: Any
    authorization: dict[str, Any] | None = None
    evidence: PaybondInterceptEvidenceResult | None = None


def _now_rfc3339_seconds() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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
    if entry.evidence_mapper is not None:
        mapped = entry.evidence_mapper(result, ctx)
        return dict(mapped)

    resolved = resolve_completion_preset(entry.evidence_preset)
    preset = resolved["preset"]
    if is_vendor_pack(preset):
        if isinstance(result, dict):
            return map_vendor_evidence_to_canonical(preset, result)
        raise ValueError(
            f'side-effecting tool "{ctx.tool_name}" uses vendor pack preset '
            f'"{entry.evidence_preset}"; provide evidence_mapper when tool result is not a dict'
        )

    if isinstance(result, dict):
        return dict(result)

    return dict(resolved["archetype"]["sample_evidence"])


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
            else:
                auth = await guard.assert_spend_authorized(**resolved["auth_kwargs"])
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
            self._emit_trace(
                {
                    "type": "evidence_submitted",
                    "run_id": self._binding.run_id,
                    "tool_call_id": tool_call_id,
                    "operation": resolved["operation"],
                    "evidence_id": evidence_id,
                    "preset_id": resolved["entry"].evidence_preset,
                    "evidence_preset": resolved["entry"].evidence_preset,
                    "sandbox_lifecycle_status": evidence.sandbox_lifecycle_status,
                    "predicate_passed": evidence.predicate_passed,
                }
            )

            authorization: dict[str, Any] = {
                "allow": True,
                "audit_id": str(auth.audit_id),
                "decision_id": str(auth.decision_id) if auth.decision_id is not None else None,
            }
            if evidence_policy_digest is not None:
                authorization["policy_digest"] = evidence_policy_digest

            return PaybondInterceptWrapExecuteResult(
                tool_result=tool_result,
                authorization=authorization,
                evidence=evidence,
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
                "agent_subject": agent_subject,
                "approval_token": approval_token,
                "idempotency_key": idempotency_key,
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
                return PaybondInterceptEvidenceResult(
                    submitted=True,
                    intent_id=str(result.intent_id),
                    predicate_passed=result.predicate_passed,
                    sandbox_lifecycle_status=result.sandbox_lifecycle_status,
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
            if isinstance(result, dict):
                intent_state = result.get("intent_state") or result.get("state")
                if isinstance(result.get("predicate_passed"), bool):
                    predicate_passed = result["predicate_passed"]

            return PaybondInterceptEvidenceResult(
                submitted=True,
                intent_id=str(intent_id),
                intent_state=str(intent_state) if intent_state is not None else None,
                predicate_passed=predicate_passed,
            )
        except PaybondEvidenceSubmitError:
            raise
        except Exception as exc:
            message = str(exc) if str(exc) else "auto-evidence submission failed"
            raise PaybondEvidenceSubmitError(message, tool_result, cause=exc) from exc


__all__ = [
    "PaybondAutoEvidenceSubmitError",
    "PaybondEvidenceSubmitError",
    "PaybondInterceptEvidenceResult",
    "PaybondInterceptWrapExecuteResult",
    "PaybondToolInterceptor",
]

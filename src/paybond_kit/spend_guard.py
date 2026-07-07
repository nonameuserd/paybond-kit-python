"""Spend-oriented guard helpers over Paybond capability verification."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Literal, ParamSpec, Protocol, TypeVar
from uuid import UUID

from paybond_kit.harbor import VerifyCapabilityResult

P = ParamSpec("P")
R = TypeVar("R")


async def _maybe_await(value: R | Awaitable[R]) -> R:
    if inspect.isawaitable(value):
        return await value
    return value


class _CapabilityVerifier(Protocol):
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
        model_family: str | None = None,
        config_hash_hex: str | None = None,
        prompt_hash_hex: str | None = None,
    ) -> VerifyCapabilityResult: ...


class _SpendGuardSource(Protocol):
    harbor: _CapabilityVerifier
    intent_id: UUID
    capability_token: str


class PaybondSpendDeniedError(RuntimeError):
    """Raised when Paybond denies a guarded spend or tool invocation."""

    def __init__(self, result: VerifyCapabilityResult) -> None:
        reason = result.message or result.code or "denied"
        super().__init__(f"Paybond spend authorization denied: {reason}")
        self.result = result


class PaybondSpendApprovalRequiredError(RuntimeError):
    """Raised when Paybond requires operator approval before spend may proceed."""

    def __init__(self, result: VerifyCapabilityResult) -> None:
        reason = result.message or result.code or "approval_required"
        super().__init__(f"Paybond spend authorization requires approval: {reason}")
        self.result = result


@dataclass(frozen=True, init=False)
class PaybondSpendGuard:
    """Authorize delegated agent spend before side-effecting tool work runs."""

    harbor: _CapabilityVerifier
    intent_id: UUID
    capability_token: str

    def __init__(
        self,
        source: _SpendGuardSource | None = None,
        *,
        harbor: _CapabilityVerifier | None = None,
        intent_id: UUID | None = None,
        capability_token: str | None = None,
    ) -> None:
        if source is not None:
            if harbor is not None or intent_id is not None or capability_token is not None:
                raise ValueError("pass either source or harbor/intent_id/capability_token")
            harbor = source.harbor
            intent_id = source.intent_id
            capability_token = source.capability_token
        if harbor is None or intent_id is None or capability_token is None:
            raise ValueError("harbor, intent_id, and capability_token are required")
        object.__setattr__(self, "harbor", harbor)
        object.__setattr__(self, "intent_id", intent_id)
        object.__setattr__(self, "capability_token", capability_token)

    async def verify_spend_capability(
        self,
        *,
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
        model_family: str | None = None,
        config_hash_hex: str | None = None,
        prompt_hash_hex: str | None = None,
    ) -> VerifyCapabilityResult:
        return await self.harbor.verify_capability(
            intent_id=self.intent_id,
            token=self.capability_token,
            operation=operation,
            requested_spend_cents=requested_spend_cents,
            vendor_id=vendor_id,
            task_id=task_id,
            workflow_id=workflow_id,
            tool_call_id=tool_call_id,
            tool_name=tool_name,
            currency=currency,
            agent_subject=agent_subject,
            approval_token=approval_token,
            idempotency_key=idempotency_key,
            model_family=model_family,
            config_hash_hex=config_hash_hex,
            prompt_hash_hex=prompt_hash_hex,
        )

    async def authorize_spend(
        self,
        *,
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
        model_family: str | None = None,
        config_hash_hex: str | None = None,
        prompt_hash_hex: str | None = None,
    ) -> VerifyCapabilityResult:
        return await self.verify_spend_capability(
            operation=operation,
            requested_spend_cents=requested_spend_cents,
            vendor_id=vendor_id,
            task_id=task_id,
            workflow_id=workflow_id,
            tool_call_id=tool_call_id,
            tool_name=tool_name,
            currency=currency,
            agent_subject=agent_subject,
            approval_token=approval_token,
            idempotency_key=idempotency_key,
            model_family=model_family,
            config_hash_hex=config_hash_hex,
            prompt_hash_hex=prompt_hash_hex,
        )

    async def assert_spend_authorized(
        self,
        *,
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
        model_family: str | None = None,
        config_hash_hex: str | None = None,
        prompt_hash_hex: str | None = None,
    ) -> VerifyCapabilityResult:
        result = await self.authorize_spend(
            operation=operation,
            requested_spend_cents=requested_spend_cents,
            vendor_id=vendor_id,
            task_id=task_id,
            workflow_id=workflow_id,
            tool_call_id=tool_call_id,
            tool_name=tool_name,
            currency=currency,
            agent_subject=agent_subject,
            approval_token=approval_token,
            idempotency_key=idempotency_key,
            model_family=model_family,
            config_hash_hex=config_hash_hex,
            prompt_hash_hex=prompt_hash_hex,
        )
        if not result.allow:
            if result.approval_required:
                raise PaybondSpendApprovalRequiredError(result)
            raise PaybondSpendDeniedError(result)
        return result

    async def complete_spend_authorization(
        self,
        decision_id: str,
        outcome: Literal["consumed", "released"],
    ) -> None:
        """Finalize scope reservations after tool execution completes or is aborted."""
        complete = getattr(self.harbor, "complete_spend_decision", None)
        if complete is None:
            return
        await complete(decision_id=decision_id, outcome=outcome)

    def guard_tool(
        self,
        *,
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
        handler: Callable[P, R | Awaitable[R]],
    ) -> Callable[P, Awaitable[R]]:
        """Authorize spend for ``operation``, then invoke ``handler``.

        The ``operation`` label and ``requested_spend_cents`` are sent to Harbor
        for policy evaluation only. This wrapper does not inspect or constrain
        what ``handler`` actually does — callers must keep the authorization
        label, spend amount, and handler side effects aligned with the bound
        intent's ``allowed_tools`` and policy predicates.

        For registry-backed operation-to-handler coupling, prefer
        ``paybond.instrument()`` or ``wrap_tools()`` over per-tool
        ``guard_tool``.
        """
        async def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
            auth = await self.assert_spend_authorized(
                operation=operation,
                requested_spend_cents=requested_spend_cents,
                vendor_id=vendor_id,
                task_id=task_id,
                workflow_id=workflow_id,
                tool_call_id=tool_call_id,
                tool_name=tool_name,
                currency=currency,
                agent_subject=agent_subject,
                approval_token=approval_token,
                idempotency_key=idempotency_key,
            )
            try:
                out = await _maybe_await(handler(*args, **kwargs))
                if auth.decision_id is not None:
                    await self.complete_spend_authorization(str(auth.decision_id), "consumed")
                return out
            except Exception:
                if auth.decision_id is not None:
                    try:
                        await self.complete_spend_authorization(str(auth.decision_id), "released")
                    except Exception:
                        pass
                raise

        return wrapped


async def authorize_spend(
    source: _SpendGuardSource,
    *,
    operation: str,
    requested_spend_cents: int = 0,
) -> VerifyCapabilityResult:
    return await PaybondSpendGuard(source).authorize_spend(
        operation=operation,
        requested_spend_cents=requested_spend_cents,
    )


def guard_tool(
    source: _SpendGuardSource,
    *,
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
    handler: Callable[P, R | Awaitable[R]],
) -> Callable[P, Awaitable[R]]:
    """Standalone alias for :meth:`PaybondSpendGuard.guard_tool`."""
    return PaybondSpendGuard(source).guard_tool(
        operation=operation,
        requested_spend_cents=requested_spend_cents,
        vendor_id=vendor_id,
        task_id=task_id,
        workflow_id=workflow_id,
        tool_call_id=tool_call_id,
        tool_name=tool_name,
        currency=currency,
        agent_subject=agent_subject,
        approval_token=approval_token,
        idempotency_key=idempotency_key,
        handler=handler,
    )


paybond_agent_tool_spend_guard = guard_tool
paybond_runtime_neutral_tool_spend_guard = guard_tool
paybond_langgraph_tool_spend_guard = guard_tool
paybond_mcp_tool_spend_guard = guard_tool


__all__ = [
    "PaybondSpendApprovalRequiredError",
    "PaybondSpendDeniedError",
    "PaybondSpendGuard",
    "authorize_spend",
    "guard_tool",
    "paybond_agent_tool_spend_guard",
    "paybond_langgraph_tool_spend_guard",
    "paybond_mcp_tool_spend_guard",
    "paybond_runtime_neutral_tool_spend_guard",
]

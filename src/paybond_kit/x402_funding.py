"""High-level x402 intent funding orchestration for PaybondIntents."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any, TypeAlias
from uuid import UUID

from paybond_kit.harbor import FundIntentResult

PaymentRequired: TypeAlias = str

TERMINAL_X402_FUNDING_STATUSES = frozenset(
    {
        "authorization_failed",
        "capture_failed",
        "void_failed",
    }
)
_FUND_REQUEST_BODY: dict[str, Any] = {}
_DEFAULT_MAX_ATTEMPTS = 30
_DEFAULT_INTERVAL_MS = 2_000


@dataclass(frozen=True)
class FundRequestEnvelope:
    """Request metadata bound by each fresh recognition proof for ``/fund``."""

    intent_id: UUID
    method: str
    path: str
    body: Mapping[str, Any]


@dataclass(frozen=True)
class X402FundPollOptions:
    max_attempts: int = _DEFAULT_MAX_ATTEMPTS
    interval_ms: int = _DEFAULT_INTERVAL_MS


class PaybondX402FundingFailedError(RuntimeError):
    """Raised when x402 funding cannot complete."""

    def __init__(
        self,
        message: str,
        *,
        intent_id: UUID,
        last_result: FundIntentResult | None = None,
    ) -> None:
        super().__init__(message)
        self.intent_id = intent_id
        self.last_result = last_result


class PaybondX402FundingPendingError(RuntimeError):
    """Raised when polling exhausts ``max_attempts`` before funding completes."""

    def __init__(
        self,
        message: str,
        *,
        intent_id: UUID,
        last_result: FundIntentResult,
        attempts: int,
    ) -> None:
        super().__init__(message)
        self.intent_id = intent_id
        self.last_result = last_result
        self.attempts = attempts


def build_x402_fund_request_envelope(intent_id: UUID) -> FundRequestEnvelope:
    """Canonical ``/fund`` request envelope for Gateway ``POST /harbor/intents/{id}/fund``."""
    return FundRequestEnvelope(
        intent_id=intent_id,
        method="POST",
        path=f"/harbor/intents/{intent_id}/fund",
        body=_FUND_REQUEST_BODY,
    )


def _is_funding_complete(result: FundIntentResult) -> bool:
    if result.capability_token and result.capability_token.strip():
        return True
    return result.status_code == 200 and result.funded


def _is_terminal_funding_failure(result: FundIntentResult) -> bool:
    status = (result.funding.status if result.funding else None) or ""
    return status.strip() in TERMINAL_X402_FUNDING_STATUSES


def _failure_message(result: FundIntentResult) -> str:
    status = (result.funding.status if result.funding else None) or result.state
    return f"x402 funding failed for intent {result.intent_id} (status={status})"


FundCallable = Callable[..., Awaitable[FundIntentResult]]
IssueRecognitionProofCallable = Callable[
    [FundRequestEnvelope], Awaitable[Mapping[str, Any]]
]
SignPaymentCallable = Callable[[PaymentRequired], Awaitable[str]]


async def execute_fund_with_x402(
    *,
    intent_id: UUID,
    recognition_proof: Mapping[str, Any],
    sign_payment: SignPaymentCallable,
    issue_recognition_proof: IssueRecognitionProofCallable,
    fund: FundCallable,
    poll_options: X402FundPollOptions | None = None,
) -> FundIntentResult:
    """
    Orchestrate x402 ``/fund``: handle 402 signing, retry with ``payment-signature``, poll 202 until funded.
    """
    opts = poll_options or X402FundPollOptions()
    max_attempts = max(1, opts.max_attempts)
    interval_ms = max(0, opts.interval_ms)
    envelope = build_x402_fund_request_envelope(intent_id)

    payment_signature: str | None = None
    result = await fund(recognition_proof=recognition_proof)

    if result.status_code == 402:
        if not (result.payment_required and result.payment_required.strip()):
            raise PaybondX402FundingFailedError(
                "x402 fund challenge missing payment-required header",
                intent_id=intent_id,
                last_result=result,
            )
        payment_signature = (await sign_payment(result.payment_required)).strip()
        if not payment_signature:
            raise PaybondX402FundingFailedError(
                "x402 sign_payment returned an empty payment signature",
                intent_id=intent_id,
                last_result=result,
            )
        retry_proof = await issue_recognition_proof(envelope)
        result = await fund(
            recognition_proof=retry_proof,
            payment_signature=payment_signature,
        )

    if _is_terminal_funding_failure(result):
        raise PaybondX402FundingFailedError(
            _failure_message(result),
            intent_id=intent_id,
            last_result=result,
        )
    if _is_funding_complete(result):
        return result

    attempts = 0
    while result.status_code == 202 or (
        not _is_funding_complete(result) and result.status_code == 200
    ):
        attempts += 1
        if attempts > max_attempts:
            raise PaybondX402FundingPendingError(
                f"x402 funding still pending after {max_attempts} poll attempt(s) for intent {intent_id}",
                intent_id=intent_id,
                last_result=result,
                attempts=max_attempts,
            )
        if interval_ms > 0:
            await asyncio.sleep(interval_ms / 1000)
        poll_proof = await issue_recognition_proof(envelope)
        if payment_signature:
            result = await fund(
                recognition_proof=poll_proof,
                payment_signature=payment_signature,
            )
        else:
            result = await fund(recognition_proof=poll_proof)
        if _is_terminal_funding_failure(result):
            raise PaybondX402FundingFailedError(
                _failure_message(result),
                intent_id=intent_id,
                last_result=result,
            )
        if _is_funding_complete(result):
            return result

    if _is_funding_complete(result):
        return result

    raise PaybondX402FundingFailedError(
        f"unexpected x402 fund response HTTP {result.status_code} for intent {intent_id}",
        intent_id=intent_id,
        last_result=result,
    )

"""High-level MPP intent funding orchestration for PaybondIntents."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any, TypeAlias
from uuid import UUID

from paybond_kit.harbor import FundIntentResult
from paybond_kit.x402_funding import (
    FundRequestEnvelope,
    X402FundPollOptions,
    build_x402_fund_request_envelope,
)

PaymentAuthChallenge: TypeAlias = str

_MPP_PARAM_RE = re.compile(r'([a-zA-Z_][\w-]*)=(?:"([^"]*)"|([^,\s]+))')
_PAYMENT_SCHEME_RE = re.compile(r"^payment\b", re.IGNORECASE)

TERMINAL_MPP_FUNDING_STATUSES = frozenset(
    {
        "authorization_failed",
        "capture_failed",
        "void_failed",
        "credential_rejected",
        "payment_failed",
        "charge_failed",
        "session_open_failed",
    }
)
_MPP_CHARGE_EXPECTED = ("charge", "stripe")
_MPP_SESSION_EXPECTED = ("session", "tempo")
_DEFAULT_MAX_ATTEMPTS = 30
_DEFAULT_INTERVAL_MS = 2_000

MppFundPollOptions = X402FundPollOptions


@dataclass(frozen=True)
class ParsedPaymentAuthChallenge:
    """Parsed Payment Auth challenge parameters."""

    raw: str
    id: str | None = None
    realm: str | None = None
    method: str | None = None
    intent: str | None = None
    request: str | None = None


class PaybondMppFundingFailedError(RuntimeError):
    """Raised when MPP funding cannot complete."""

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


class PaybondMppFundingPendingError(RuntimeError):
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


def parse_payment_auth_challenge(raw: str) -> ParsedPaymentAuthChallenge:
    """
    Parse a ``WWW-Authenticate: Payment …`` challenge into structured parameters.

    Raises:
        ValueError: When the value is empty or does not start with the Payment scheme.
    """
    trimmed = raw.strip()
    if not trimmed:
        raise ValueError("Payment Auth challenge must be non-empty")
    if not _PAYMENT_SCHEME_RE.match(trimmed):
        raise ValueError("expected Payment Auth challenge")

    params: dict[str, str] = {}
    after_scheme = _PAYMENT_SCHEME_RE.sub("", trimmed, count=1).strip()
    for match in _MPP_PARAM_RE.finditer(after_scheme):
        key = match.group(1).lower()
        params[key] = match.group(2) if match.group(2) is not None else (match.group(3) or "")

    return ParsedPaymentAuthChallenge(
        raw=trimmed,
        id=params.get("id"),
        realm=params.get("realm"),
        method=params.get("method"),
        intent=params.get("intent"),
        request=params.get("request"),
    )


def _select_mpp_payment_challenge(
    www_authenticate: list[str] | None,
    *,
    expected_intent: str,
    expected_method: str,
) -> PaymentAuthChallenge:
    if not www_authenticate:
        raise ValueError("MPP fund challenge missing WWW-Authenticate Payment header")

    for header in www_authenticate:
        parsed = parse_payment_auth_challenge(header)
        if parsed.intent == expected_intent and parsed.method == expected_method:
            return parsed.raw

    if len(www_authenticate) == 1:
        parsed = parse_payment_auth_challenge(www_authenticate[0])
        if parsed.intent != expected_intent or parsed.method != expected_method:
            raise ValueError(
                "MPP fund challenge intent/method mismatch: "
                f"expected intent={expected_intent} method={expected_method}, "
                f"got intent={parsed.intent or 'unknown'} method={parsed.method or 'unknown'}"
            )
        return parsed.raw

    raise ValueError(
        "MPP fund challenge missing Payment Auth header for "
        f"intent={expected_intent} method={expected_method}"
    )


def select_mpp_charge_challenge(www_authenticate: list[str] | None) -> PaymentAuthChallenge:
    """Select the Stripe MPP charge challenge from ``WWW-Authenticate`` values."""
    expected_intent, expected_method = _MPP_CHARGE_EXPECTED
    return _select_mpp_payment_challenge(
        www_authenticate,
        expected_intent=expected_intent,
        expected_method=expected_method,
    )


def select_mpp_session_challenge(www_authenticate: list[str] | None) -> PaymentAuthChallenge:
    """Select the Tempo MPP session challenge from ``WWW-Authenticate`` values."""
    expected_intent, expected_method = _MPP_SESSION_EXPECTED
    return _select_mpp_payment_challenge(
        www_authenticate,
        expected_intent=expected_intent,
        expected_method=expected_method,
    )


def build_mpp_fund_request_envelope(intent_id: UUID) -> FundRequestEnvelope:
    """Canonical ``/fund`` request envelope for Gateway ``POST /harbor/intents/{id}/fund``."""
    return build_x402_fund_request_envelope(intent_id)


def _is_funding_complete(result: FundIntentResult) -> bool:
    if result.capability_token and result.capability_token.strip():
        return True
    return result.status_code == 200 and result.funded


def _is_terminal_funding_failure(result: FundIntentResult) -> bool:
    status = (result.funding.status if result.funding else None) or ""
    return status.strip() in TERMINAL_MPP_FUNDING_STATUSES


def _failure_message(result: FundIntentResult) -> str:
    status = (result.funding.status if result.funding else None) or result.state
    return f"MPP funding failed for intent {result.intent_id} (status={status})"


FundCallable = Callable[..., Awaitable[FundIntentResult]]
IssueRecognitionProofCallable = Callable[
    [FundRequestEnvelope], Awaitable[Mapping[str, Any]]
]
CreatePaymentCredentialCallable = Callable[[PaymentAuthChallenge], Awaitable[str]]
SelectChallengeCallable = Callable[[list[str] | None], PaymentAuthChallenge]


async def execute_fund_with_mpp(
    *,
    intent_id: UUID,
    recognition_proof: Mapping[str, Any],
    create_payment_credential: CreatePaymentCredentialCallable,
    issue_recognition_proof: IssueRecognitionProofCallable,
    select_challenge: SelectChallengeCallable,
    fund: FundCallable,
    poll_options: MppFundPollOptions | None = None,
) -> FundIntentResult:
    """
    Orchestrate MPP ``/fund``: handle 402 Payment Auth challenges, retry with credentials, poll until funded.

    Wallet and SPT secrets stay app-owned — pass injectable ``create_payment_credential`` and
    ``issue_recognition_proof`` callbacks; Paybond never stores MPP signing material.
    """
    opts = poll_options or MppFundPollOptions()
    max_attempts = max(1, opts.max_attempts)
    interval_ms = max(0, opts.interval_ms)
    envelope = build_mpp_fund_request_envelope(intent_id)

    payment_authorization: str | None = None
    result = await fund(recognition_proof=recognition_proof)

    if result.status_code == 402:
        challenge = select_challenge(result.www_authenticate)
        payment_authorization = (await create_payment_credential(challenge)).strip()
        if not payment_authorization:
            raise PaybondMppFundingFailedError(
                "MPP create_payment_credential returned an empty credential",
                intent_id=intent_id,
                last_result=result,
            )
        retry_proof = await issue_recognition_proof(envelope)
        result = await fund(
            recognition_proof=retry_proof,
            payment_authorization=payment_authorization,
        )

    if _is_terminal_funding_failure(result):
        raise PaybondMppFundingFailedError(
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
            raise PaybondMppFundingPendingError(
                f"MPP funding still pending after {max_attempts} poll attempt(s) for intent {intent_id}",
                intent_id=intent_id,
                last_result=result,
                attempts=max_attempts,
            )
        if interval_ms > 0:
            await asyncio.sleep(interval_ms / 1000)
        poll_proof = await issue_recognition_proof(envelope)
        if payment_authorization:
            result = await fund(
                recognition_proof=poll_proof,
                payment_authorization=payment_authorization,
            )
        else:
            result = await fund(recognition_proof=poll_proof)
        if _is_terminal_funding_failure(result):
            raise PaybondMppFundingFailedError(
                _failure_message(result),
                intent_id=intent_id,
                last_result=result,
            )
        if _is_funding_complete(result):
            return result

    if _is_funding_complete(result):
        return result

    raise PaybondMppFundingFailedError(
        f"unexpected MPP fund response HTTP {result.status_code} for intent {intent_id}",
        intent_id=intent_id,
        last_result=result,
    )


async def execute_fund_with_mpp_charge(
    *,
    intent_id: UUID,
    recognition_proof: Mapping[str, Any],
    create_payment_credential: CreatePaymentCredentialCallable,
    issue_recognition_proof: IssueRecognitionProofCallable,
    fund: FundCallable,
    poll_options: MppFundPollOptions | None = None,
) -> FundIntentResult:
    """One-shot Stripe MPP charge funding through Payment Auth semantics."""
    return await execute_fund_with_mpp(
        intent_id=intent_id,
        recognition_proof=recognition_proof,
        create_payment_credential=create_payment_credential,
        issue_recognition_proof=issue_recognition_proof,
        select_challenge=select_mpp_charge_challenge,
        fund=fund,
        poll_options=poll_options,
    )


async def execute_fund_with_mpp_session(
    *,
    intent_id: UUID,
    recognition_proof: Mapping[str, Any],
    create_payment_credential: CreatePaymentCredentialCallable,
    issue_recognition_proof: IssueRecognitionProofCallable,
    fund: FundCallable,
    poll_options: MppFundPollOptions | None = None,
) -> FundIntentResult:
    """Tempo MPP session funding through Payment Auth semantics."""
    return await execute_fund_with_mpp(
        intent_id=intent_id,
        recognition_proof=recognition_proof,
        create_payment_credential=create_payment_credential,
        issue_recognition_proof=issue_recognition_proof,
        select_challenge=select_mpp_session_challenge,
        fund=fund,
        poll_options=poll_options,
    )

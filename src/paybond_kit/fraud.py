"""Tenant-bound gateway fraud review and metrics client."""

from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass
from typing import Any, Literal, NotRequired, TypedDict
from urllib.parse import quote, urlencode

import httpx

from paybond_kit.credentials import (
    DEFAULT_PAYBOND_GATEWAY_BASE_URL,
    GatewayAuthError,
    PaybondEnvironment,
    _assert_expected_environment,
    _normalize_expected_environment,
)

_DEFAULT_PRINCIPAL_PATH = "/v1/auth/principal"
_FRAUD_REVIEW_EVENT_TYPES = {
    "review_open_requested",
    "appeal_requested",
    "replay_requested",
    "review_outcome_recorded",
    "confirmed_risk",
    "false_positive",
    "needs_more_evidence",
}
_FRAUD_REVIEW_OUTCOMES = {"confirmed_risk", "false_positive", "needs_more_evidence"}

SignalFraudSeverity = Literal["elevated", "high", "critical"]
SignalFraudMetricsWindow = Literal["24h", "7d", "30d"]
SignalFraudReleaseGateMode = Literal["review_only", "critical_hold"]
SignalFraudReviewEventType = Literal[
    "review_open_requested",
    "appeal_requested",
    "replay_requested",
    "review_outcome_recorded",
    "confirmed_risk",
    "false_positive",
    "needs_more_evidence",
]


class FraudHttpError(RuntimeError):
    """Raised for non-success HTTP status codes from gateway fraud routes."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int,
        url: str,
        body_text: str,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.url = url
        self.body_text = body_text


class SignalFraudSignal(TypedDict):
    code: str
    severity: str
    category: str
    window: str
    evidence_count: int
    summary: str
    affects_score: bool
    signal_source: NotRequired[str]
    first_seen_at: NotRequired[str]
    last_seen_at: NotRequired[str]
    evidence_binding_strength: NotRequired[str]
    provider_event_refs: NotRequired[list[str]]
    intent_refs: NotRequired[list[str]]


class SignalFraudAssessment(TypedDict):
    fraud_signal_version: str
    level: str
    highest_severity: str
    review_priority: str
    signal_count: int
    severe_signal_count: int
    summary: str


class SignalFraudReleaseGateConfig(TypedDict):
    mode: str


class SignalFraudSignalFamilyReliability(TypedDict):
    signal_family: str
    reliable: bool
    stale: bool
    sparse: bool
    reviewed_count: int
    labeled_outcome_count: int
    review_precision_bps: int
    min_signal_family_labeled_outcome_count: int
    last_labeled_at: NotRequired[str]
    reasons: list[str]
    summary: str


class SignalFraudReleaseGateMetricsReliability(TypedDict):
    reliable: bool
    stale: NotRequired[bool]
    sparse: NotRequired[bool]
    reviewed_count: int
    labeled_outcome_count: int
    review_precision_bps: int
    min_reviewed_count: int
    min_labeled_outcome_count: int
    min_signal_family_labeled_outcome_count: NotRequired[int]
    min_review_precision_bps: int
    last_labeled_at: NotRequired[str]
    signal_families: NotRequired[list[SignalFraudSignalFamilyReliability]]
    reasons: list[str]
    summary: str


class SignalFraudReleaseGateDecision(TypedDict):
    mode: str
    enforcement_enabled: bool
    metrics_reliable: bool
    release_allowed: bool
    hold_required: bool
    critical_signal_count: int
    critical_signal_codes: list[str]
    blocking_signal_codes: NotRequired[list[str]]
    blocking_evidence_refs: NotRequired[list[str]]
    reliability_reasons: NotRequired[list[str]]
    reasons: list[str]
    summary: str


class SignalFraudAssessmentResponse(TypedDict, total=False):
    schema_version: int
    tenant_id: str
    operator_did: str
    score_model_version: str
    review_state: str
    review_outcome: str
    review_reasons: list[str]
    fraud_signals: list[SignalFraudSignal]
    fraud_assessment: SignalFraudAssessment
    release_gate: SignalFraudReleaseGateDecision


class SignalFraudReviewQueueItem(TypedDict, total=False):
    operator_did: str
    review_state: str
    review_outcome: str
    review_reasons: list[str]
    anomaly_flagged: bool
    opened_at: str
    reviewed_at: str
    updated_at: str
    last_receipt_message_digest_hex: str
    fraud_signals: list[SignalFraudSignal]
    fraud_assessment: SignalFraudAssessment
    release_gate: SignalFraudReleaseGateDecision


class SignalFraudReviewQueueResponse(TypedDict):
    schema_version: int
    tenant_id: str
    score_model_version: str
    items: list[SignalFraudReviewQueueItem]


class SignalFraudMetricsResponse(TypedDict):
    schema_version: int
    tenant_id: str
    score_model_version: str
    fraud_signal_version: str
    window: str
    window_started_at: str
    window_ended_at: str
    generated_at: str
    flagged_operator_count: int
    critical_signal_count: int
    high_signal_count: int
    elevated_signal_count: int
    review_open_count: int
    review_load_count: int
    reviewed_count: int
    labeled_outcome_count: int
    confirmed_risk_count: int
    false_positive_count: int
    needs_more_evidence_count: int
    review_precision_bps: int
    false_positive_rate_bps: int
    confirmed_risk_rate_bps: int
    labeled_coverage_bps: int
    median_time_to_review_seconds: int
    refund_burst_count: int
    dispute_cluster_count: int
    replay_appeal_abuse_count: int
    critical_signal_hold_candidate_count: int
    provider_signal_count: int
    stale_label_gap_seconds: int
    stale_signal_family_label_gap_count: int
    backtest_summary: str
    release_gate_config: SignalFraudReleaseGateConfig
    release_gate_metrics_reliability: SignalFraudReleaseGateMetricsReliability


class SignalFraudReleaseGateConfigResponse(TypedDict):
    schema_version: int
    tenant_id: str
    score_model_version: str
    fraud_signal_version: str
    generated_at: str
    config: SignalFraudReleaseGateConfig
    metrics_reliability: SignalFraudReleaseGateMetricsReliability


class SignalFraudReviewEventInput(TypedDict, total=False):
    eventType: str
    event_type: str
    reviewOutcome: str
    review_outcome: str
    signalCode: str
    signal_code: str
    intentId: str
    intent_id: str
    providerEventId: str
    provider_event_id: str
    summary: str


class SignalFraudReviewEventResponse(TypedDict, total=False):
    schema_version: int
    tenant_id: str
    operator_did: str
    score_model_version: str
    requested_event_type: str
    recorded_event_type: str
    review_outcome: str
    signal_code: str
    intent_id: str
    provider_event_id: str
    accepted: bool
    next_eligible_at: str


class GatewayFraudClient:
    """Async fraud review and metrics client bound to one tenant realm."""

    def __init__(
        self,
        gateway_base_url: str,
        tenant_id: str,
        *,
        static_gateway_bearer_token: str,
        max_retries: int = 3,
        request_timeout_sec: float = 30.0,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base = gateway_base_url.strip().rstrip("/") + "/"
        self._tenant = tenant_id.strip()
        self._bearer = static_gateway_bearer_token.strip()
        self._max_retries = max(1, int(max_retries))
        self._owns_client = http_client is None
        self._client = http_client or httpx.AsyncClient(timeout=request_timeout_sec)

    @property
    def tenant_id(self) -> str:
        return self._tenant

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def _get_json_with_retries(self, path: str) -> httpx.Response:
        url = f"{self._base}{path.lstrip('/')}"
        last_exc: BaseException | None = None
        response: httpx.Response | None = None
        for attempt in range(self._max_retries):
            try:
                response = await self._client.get(
                    url,
                    headers={
                        "accept": "application/json",
                        "authorization": f"Bearer {self._bearer}",
                    },
                )
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_exc = exc
                if attempt + 1 >= self._max_retries:
                    raise
                await asyncio.sleep(_backoff_seconds(attempt))
                continue
            if response.status_code in (429, 500, 502, 503, 504):
                if attempt + 1 >= self._max_retries:
                    break
                delay = _parse_retry_after(response.headers.get("retry-after"))
                if delay is None:
                    delay = _backoff_seconds(attempt)
                await asyncio.sleep(delay)
                continue
            return response
        if response is not None:
            return response
        if last_exc is not None:
            raise last_exc
        raise RuntimeError("fraud request failed without a response")

    async def _post_json_once(self, path: str, payload: dict[str, Any]) -> httpx.Response:
        url = f"{self._base}{path.lstrip('/')}"
        return await self._client.post(
            url,
            headers={
                "accept": "application/json",
                "authorization": f"Bearer {self._bearer}",
                "content-type": "application/json",
            },
            json=payload,
        )

    async def _put_json_once(self, path: str, payload: dict[str, Any]) -> httpx.Response:
        url = f"{self._base}{path.lstrip('/')}"
        return await self._client.put(
            url,
            headers={
                "accept": "application/json",
                "authorization": f"Bearer {self._bearer}",
                "content-type": "application/json",
            },
            json=payload,
        )

    def _assert_tenant(self, body: dict[str, Any], *, url: str) -> None:
        tenant = str(body.get("tenant_id", ""))
        if tenant != self._tenant:
            raise RuntimeError(
                f"fraud tenant mismatch: client={self._tenant!r} gateway={tenant!r} url={url}"
            )

    @staticmethod
    def _assert_operator(body: dict[str, Any], operator_did: str, *, label: str) -> None:
        echoed_operator = str(body.get("operator_did", ""))
        if echoed_operator != operator_did:
            raise RuntimeError(
                f"fraud {label} operator mismatch: requested={operator_did!r} gateway={echoed_operator!r}"
            )

    async def get_fraud_assessment(
        self, operator_did: str, *, score_version: str | None = None
    ) -> SignalFraudAssessmentResponse | None:
        query = _query({"score_version": score_version})
        path = f"signal/v1/operators/{quote(operator_did, safe='')}/review-status{query}"
        url = f"{self._base}{path}"
        response = await self._get_json_with_retries(path)
        if response.status_code == 404:
            return None
        if response.status_code >= 400:
            raise FraudHttpError(
                f"Fraud assessment HTTP {response.status_code}: {response.text}",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        body = response.json()
        if not isinstance(body, dict):
            raise RuntimeError("fraud assessment response was not a JSON object")
        self._assert_tenant(body, url=url)
        self._assert_operator(body, operator_did, label="assessment")
        return body  # type: ignore[return-value]

    async def list_fraud_review_queue(
        self,
        *,
        state: str | None = None,
        severity: str | None = None,
        limit: int | None = None,
        score_version: str | None = None,
    ) -> SignalFraudReviewQueueResponse:
        normalized_limit: int | None = None
        if limit is not None:
            normalized_limit = max(1, min(int(limit), 500))
        query = _query(
            {
                "state": state,
                "fraud_severity": _normalize_severity(severity),
                "limit": normalized_limit,
                "score_version": score_version,
            }
        )
        path = f"signal/v1/review-queue{query}"
        url = f"{self._base}{path}"
        response = await self._get_json_with_retries(path)
        if response.status_code >= 400:
            raise FraudHttpError(
                f"Fraud review queue HTTP {response.status_code}: {response.text}",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        body = response.json()
        if not isinstance(body, dict):
            raise RuntimeError("fraud review queue response was not a JSON object")
        self._assert_tenant(body, url=url)
        return body  # type: ignore[return-value]

    async def get_fraud_metrics(
        self,
        *,
        window: str | None = None,
        score_version: str | None = None,
    ) -> SignalFraudMetricsResponse:
        query = _query(
            {
                "window": _normalize_window(window),
                "score_version": score_version,
            }
        )
        path = f"signal/v1/fraud/metrics{query}"
        url = f"{self._base}{path}"
        response = await self._get_json_with_retries(path)
        if response.status_code >= 400:
            raise FraudHttpError(
                f"Fraud metrics HTTP {response.status_code}: {response.text}",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        body = response.json()
        if not isinstance(body, dict):
            raise RuntimeError("fraud metrics response was not a JSON object")
        self._assert_tenant(body, url=url)
        return body  # type: ignore[return-value]

    async def get_fraud_release_gate_config(
        self, *, score_version: str | None = None
    ) -> SignalFraudReleaseGateConfigResponse:
        query = _query({"score_version": score_version})
        path = f"signal/v1/fraud/release-gate{query}"
        url = f"{self._base}{path}"
        response = await self._get_json_with_retries(path)
        if response.status_code >= 400:
            raise FraudHttpError(
                f"Fraud release gate HTTP {response.status_code}: {response.text}",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        body = response.json()
        if not isinstance(body, dict):
            raise RuntimeError("fraud release gate response was not a JSON object")
        self._assert_tenant(body, url=url)
        return body  # type: ignore[return-value]

    async def set_fraud_release_gate_mode(
        self, mode: str
    ) -> SignalFraudReleaseGateConfigResponse:
        normalized_mode = _normalize_release_gate_mode(mode)
        path = "signal/v1/fraud/release-gate"
        url = f"{self._base}{path}"
        response = await self._put_json_once(path, {"mode": normalized_mode})
        if response.status_code >= 400:
            raise FraudHttpError(
                f"Fraud release gate update HTTP {response.status_code}: {response.text}",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        body = response.json()
        if not isinstance(body, dict):
            raise RuntimeError("fraud release gate response was not a JSON object")
        self._assert_tenant(body, url=url)
        return body  # type: ignore[return-value]

    async def record_fraud_review_event(
        self,
        operator_did: str,
        event: SignalFraudReviewEventInput,
        *,
        score_version: str | None = None,
    ) -> SignalFraudReviewEventResponse:
        event_type = _normalize_review_event_type(
            str(event.get("eventType", event.get("event_type", "")))
        )
        review_outcome = event.get("reviewOutcome", event.get("review_outcome"))
        if event_type in _FRAUD_REVIEW_OUTCOMES:
            review_outcome = event_type
            event_type = "review_outcome_recorded"
        normalized_outcome = (
            _normalize_review_outcome(str(review_outcome))
            if review_outcome is not None
            else None
        )
        if event_type == "review_outcome_recorded" and normalized_outcome is None:
            raise ValueError(
                "fraud review outcome must be one of confirmed_risk, false_positive, or needs_more_evidence"
            )
        query = _query({"score_version": score_version})
        path = f"signal/v1/operators/{quote(operator_did, safe='')}/review-events{query}"
        body = {
            "event_type": event_type,
            "summary": str(event.get("summary", "")),
        }
        if normalized_outcome is not None:
            body["review_outcome"] = normalized_outcome
        signal_code = _optional_context_value(event.get("signalCode", event.get("signal_code")))
        intent_id = _optional_context_value(event.get("intentId", event.get("intent_id")))
        provider_event_id = _optional_context_value(
            event.get("providerEventId", event.get("provider_event_id"))
        )
        if signal_code is not None:
            body["signal_code"] = signal_code
        if intent_id is not None:
            body["intent_id"] = intent_id
        if provider_event_id is not None:
            body["provider_event_id"] = provider_event_id
        url = f"{self._base}{path}"
        response = await self._post_json_once(
            path,
            body,
        )
        if response.status_code >= 400 and response.status_code != 429:
            raise FraudHttpError(
                f"Fraud review event HTTP {response.status_code}: {response.text}",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        body = response.json()
        if not isinstance(body, dict):
            raise RuntimeError("fraud review event response was not a JSON object")
        self._assert_tenant(body, url=url)
        self._assert_operator(body, operator_did, label="review event")
        return body  # type: ignore[return-value]


@dataclass
class ServiceAccountFraudSession:
    """Gateway fraud session for one service-account API key."""

    fraud: GatewayFraudClient

    @classmethod
    async def open(
        cls,
        *,
        api_key: str,
        gateway_base_url: str = DEFAULT_PAYBOND_GATEWAY_BASE_URL,
        principal_path: str = _DEFAULT_PRINCIPAL_PATH,
        expected_environment: PaybondEnvironment | None = None,
        max_retries: int = 3,
    ) -> ServiceAccountFraudSession:
        tenant_id = await _resolve_gateway_tenant_id(
            gateway_base_url=gateway_base_url,
            api_key=api_key,
            principal_path=principal_path,
            expected_environment=expected_environment,
            max_retries=max_retries,
        )
        client = GatewayFraudClient(
            gateway_base_url,
            tenant_id,
            static_gateway_bearer_token=api_key,
            max_retries=max_retries,
        )
        return cls(fraud=client)

    async def aclose(self) -> None:
        await self.fraud.aclose()


async def _resolve_gateway_tenant_id(
    *,
    gateway_base_url: str,
    api_key: str,
    principal_path: str,
    expected_environment: PaybondEnvironment | None,
    max_retries: int,
) -> str:
    retries = max(1, int(max_retries))
    expected_environment = _normalize_expected_environment(expected_environment)
    client = httpx.AsyncClient(timeout=30.0)
    try:
        path = principal_path if principal_path.startswith("/") else f"/{principal_path}"
        url = gateway_base_url.strip().rstrip("/") + path
        last_exc: BaseException | None = None
        for attempt in range(retries):
            try:
                response = await client.get(
                    url,
                    headers={
                        "accept": "application/json",
                        "authorization": f"Bearer {api_key.strip()}",
                    },
                )
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_exc = exc
                if attempt + 1 >= retries:
                    raise
                await asyncio.sleep(_backoff_seconds(attempt))
                continue
            if response.status_code >= 400:
                if (
                    response.status_code in (429, 500, 502, 503, 504)
                    and attempt + 1 < retries
                ):
                    delay = _parse_retry_after(response.headers.get("retry-after"))
                    if delay is None:
                        delay = _backoff_seconds(attempt)
                    await asyncio.sleep(delay)
                    continue
                raise GatewayAuthError(
                    f"gateway principal HTTP {response.status_code}",
                    status_code=response.status_code,
                    body_text=response.text,
                )
            body = response.json()
            if not isinstance(body, dict):
                raise GatewayAuthError(
                    "gateway principal response was not a JSON object",
                    body_text=response.text,
                )
            tenant = str(body.get("tenant_id", "")).strip()
            if not tenant:
                raise GatewayAuthError(
                    "gateway principal JSON missing tenant_id",
                    body_text=response.text,
                )
            _assert_expected_environment(
                source="gateway principal",
                body=body,
                expected_environment=expected_environment,
                body_text=response.text,
            )
            return tenant
        raise RuntimeError(str(last_exc))
    finally:
        await client.aclose()


def _query(values: dict[str, str | int | None]) -> str:
    params: dict[str, str] = {}
    for key, value in values.items():
        if value is None:
            continue
        if isinstance(value, int):
            params[key] = str(value)
            continue
        trimmed = value.strip()
        if trimmed:
            params[key] = trimmed
    if not params:
        return ""
    return "?" + urlencode(params)


def _normalize_severity(severity: str | None) -> str | None:
    if severity is None or not severity.strip():
        return None
    normalized = severity.strip()
    if normalized not in {"elevated", "high", "critical"}:
        raise ValueError("fraud severity must be one of elevated, high, or critical")
    return normalized


def _normalize_window(window: str | None) -> str | None:
    if window is None or not window.strip():
        return None
    normalized = window.strip()
    if normalized not in {"24h", "7d", "30d"}:
        raise ValueError("fraud metrics window must be one of 24h, 7d, or 30d")
    return normalized


def _normalize_release_gate_mode(mode: str) -> str:
    normalized = mode.strip()
    if normalized not in {"review_only", "critical_hold"}:
        raise ValueError("fraud release gate mode must be one of review_only or critical_hold")
    return normalized


def _normalize_review_event_type(event_type: str) -> str:
    normalized = event_type.strip()
    if normalized not in _FRAUD_REVIEW_EVENT_TYPES:
        raise ValueError(
            "fraud review eventType must be one of review_open_requested, appeal_requested, replay_requested, review_outcome_recorded, confirmed_risk, false_positive, or needs_more_evidence"
        )
    return normalized


def _normalize_review_outcome(outcome: str) -> str:
    normalized = outcome.strip()
    if normalized not in _FRAUD_REVIEW_OUTCOMES:
        raise ValueError(
            "fraud review outcome must be one of confirmed_risk, false_positive, or needs_more_evidence"
        )
    return normalized


def _optional_context_value(value: object) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def _parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        parsed = float(value.strip())
    except ValueError:
        return None
    if parsed < 0:
        return None
    return min(parsed, 30.0)


def _backoff_seconds(attempt: int) -> float:
    base = 0.2 * (2**attempt)
    jitter = random.random() * 0.1
    return min(base + jitter, 5.0)

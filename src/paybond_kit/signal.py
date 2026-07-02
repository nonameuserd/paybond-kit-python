"""Tenant-bound gateway Signal read client and service-account session helpers."""

from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass
from typing import Any, TypedDict
from urllib.parse import quote

import httpx

from paybond_kit.credentials import (
    DEFAULT_PAYBOND_GATEWAY_BASE_URL,
    GatewayAuthError,
    PaybondEnvironment,
    _assert_expected_environment,
    _normalize_expected_environment,
    normalize_gateway_base_url,
)

_DEFAULT_PRINCIPAL_PATH = "/v1/auth/principal"


class SignalHttpError(RuntimeError):
    """Raised for non-success HTTP status codes from gateway Signal routes."""

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


class SignalMetrics(TypedDict):
    terminal_intents: int
    released: int
    refunded: int
    disputed: int
    success_rate_bps: int
    dispute_rate_bps: int
    refund_rate_bps: int
    mean_latency_nanos: int
    latency_sample_count: int
    receipted_volume_cents: int


class SignalConfidence(TypedDict):
    band: str
    support_score: int
    summary: str


class SignalSupportDepth(TypedDict):
    band: str
    terminal_intents: int
    receipted_volume_cents: int
    history_depth: int
    latency_sample_count: int


class SignalExplanationMetricDelta(TypedDict):
    metric: str
    previous: int
    current: int
    delta: int


class SignalExplanationDelta(TypedDict):
    basis: str
    previous_score: int
    score_delta: int
    previous_ledger_watermark_seq: int
    changed_metrics: list[SignalExplanationMetricDelta]
    reason_codes_added: list[str]
    reason_codes_removed: list[str]
    summary: str


class SignalSignedReceipt(TypedDict, total=False):
    schema_version: int
    receipt_version: str
    tenant_id: str
    operator_did: str
    score_version: str
    scoring_model: str
    scoring_narrative: str
    explanation_summary: str
    ledger_watermark_seq: int
    reason_codes: list[str]
    confidence: SignalConfidence
    support_depth: SignalSupportDepth
    review_state: str
    explanation_delta: SignalExplanationDelta
    metrics: SignalMetrics
    score: int
    signing_algorithm: str
    message_digest_hex: str
    signing_public_key_hex: str
    signature_hex: str


class SignalReceiptEnvelope(TypedDict):
    schema_version: int
    updated_at: str
    receipt: SignalSignedReceipt


class SignalPortfolioOperator(TypedDict, total=False):
    operator_did: str
    receipt_version: str
    score: int
    ledger_watermark_seq: int
    receipt_message_digest_hex: str
    confidence: SignalConfidence
    support_depth: SignalSupportDepth
    review_state: str
    explanation_delta: SignalExplanationDelta


class SignalSignedPortfolioArtifact(TypedDict):
    schema_version: int
    artifact_version: str
    kind: str
    tenant_id: str
    score_model_version: str
    scoring_model: str
    checkpoint_last_ledger_seq: int
    operators: list[SignalPortfolioOperator]
    signing_algorithm: str
    message_digest_hex: str
    signing_public_key_hex: str
    signature_hex: str


class SignalPortfolioSummary(TypedDict):
    schema_version: int
    tenant_id: str
    score_model_version: str
    scoring_model: str
    checkpoint_last_ledger_seq: int
    operator_count: int
    average_score: int
    total_terminal_intents: int
    total_receipted_volume_cents: int
    operators_under_review: int


class GatewaySignalClient:
    """Async read-only Signal client bound to one tenant realm."""

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
        self._base = normalize_gateway_base_url(gateway_base_url) + "/"
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
        if last_exc is not None:
            raise last_exc
        if response is None:
            raise RuntimeError(f"GET {path} exhausted retries without a response")
        return response

    def _assert_tenant(self, body: dict[str, Any], *, url: str) -> None:
        tenant = str(body.get("tenant_id", ""))
        if tenant != self._tenant:
            raise RuntimeError(
                f"signal tenant mismatch: client={self._tenant!r} gateway={tenant!r} url={url}"
            )

    async def get_reputation_receipt(
        self, operator_did: str, *, score_version: str | None = None
    ) -> SignalReceiptEnvelope | None:
        query = f"?score_version={score_version}" if score_version else ""
        path = f"reputation/{quote(operator_did, safe='')}{query}"
        url = f"{self._base}{path}"
        response = await self._get_json_with_retries(path)
        if response.status_code == 404:
            return None
        if response.status_code >= 400:
            raise SignalHttpError(
                f"Signal receipt HTTP {response.status_code}: {response.text}",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        body = response.json()
        if not isinstance(body, dict):
            raise RuntimeError("signal receipt response was not a JSON object")
        receipt = body.get("receipt")
        if not isinstance(receipt, dict):
            raise RuntimeError("signal receipt response missing receipt object")
        tenant = str(receipt.get("tenant_id", ""))
        echoed_operator = str(receipt.get("operator_did", ""))
        if tenant != self._tenant:
            raise RuntimeError(
                f"signal receipt tenant mismatch: client={self._tenant!r} gateway={tenant!r}"
            )
        if echoed_operator != operator_did:
            raise RuntimeError(
                f"signal receipt operator mismatch: requested={operator_did!r} gateway={echoed_operator!r}"
            )
        return body  # type: ignore[return-value]

    async def get_portfolio_summary(
        self, *, score_version: str | None = None
    ) -> SignalPortfolioSummary:
        query = f"?score_version={score_version}" if score_version else ""
        path = f"signal/v1/portfolio/summary{query}"
        url = f"{self._base}{path}"
        response = await self._get_json_with_retries(path)
        if response.status_code >= 400:
            raise SignalHttpError(
                f"Signal portfolio summary HTTP {response.status_code}: {response.text}",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        body = response.json()
        if not isinstance(body, dict):
            raise RuntimeError("signal portfolio summary response was not a JSON object")
        self._assert_tenant(body, url=url)
        return body  # type: ignore[return-value]

    async def get_signed_portfolio_artifact(
        self, *, score_version: str | None = None
    ) -> SignalSignedPortfolioArtifact:
        query = f"?score_version={score_version}" if score_version else ""
        path = f"signal/v1/portfolio/signed-export{query}"
        url = f"{self._base}{path}"
        response = await self._get_json_with_retries(path)
        if response.status_code >= 400:
            raise SignalHttpError(
                f"Signal signed portfolio artifact HTTP {response.status_code}: {response.text}",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        body = response.json()
        if not isinstance(body, dict):
            raise RuntimeError("signal signed portfolio artifact response was not a JSON object")
        self._assert_tenant(body, url=url)
        return body  # type: ignore[return-value]

    async def get_operator_explanation(
        self, operator_did: str, *, score_version: str | None = None
    ) -> dict[str, Any] | None:
        query = f"?score_version={score_version}" if score_version else ""
        path = f"signal/v1/operators/{quote(operator_did, safe='')}/explanation{query}"
        url = f"{self._base}{path}"
        response = await self._get_json_with_retries(path)
        if response.status_code == 404:
            return None
        if response.status_code >= 400:
            raise SignalHttpError(
                f"Signal explanation HTTP {response.status_code}: {response.text}",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        body = response.json()
        if not isinstance(body, dict):
            raise RuntimeError("signal explanation response was not a JSON object")
        self._assert_tenant(body, url=url)
        if str(body.get("operator_did", "")) != operator_did:
            raise RuntimeError(
                f"signal explanation operator mismatch: requested={operator_did!r} gateway={str(body.get('operator_did', ''))!r}"
            )
        return body

    async def get_operator_review_status(
        self, operator_did: str, *, score_version: str | None = None
    ) -> dict[str, Any] | None:
        query = f"?score_version={score_version}" if score_version else ""
        path = f"signal/v1/operators/{quote(operator_did, safe='')}/review-status{query}"
        url = f"{self._base}{path}"
        response = await self._get_json_with_retries(path)
        if response.status_code == 404:
            return None
        if response.status_code >= 400:
            raise SignalHttpError(
                f"Signal review status HTTP {response.status_code}: {response.text}",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        body = response.json()
        if not isinstance(body, dict):
            raise RuntimeError("signal review status response was not a JSON object")
        self._assert_tenant(body, url=url)
        if str(body.get("operator_did", "")) != operator_did:
            raise RuntimeError(
                f"signal review status operator mismatch: requested={operator_did!r} gateway={str(body.get('operator_did', ''))!r}"
            )
        return body


@dataclass
class ServiceAccountSignalSession:
    """Read-only gateway Signal session for one service-account API key."""

    signal: GatewaySignalClient

    @classmethod
    async def open(
        cls,
        *,
        api_key: str,
        gateway_base_url: str = DEFAULT_PAYBOND_GATEWAY_BASE_URL,
        principal_path: str = _DEFAULT_PRINCIPAL_PATH,
        expected_environment: PaybondEnvironment | None = None,
        max_retries: int = 3,
    ) -> ServiceAccountSignalSession:
        tenant_id = await _resolve_gateway_tenant_id(
            gateway_base_url=gateway_base_url,
            api_key=api_key,
            principal_path=principal_path,
            expected_environment=expected_environment,
            max_retries=max_retries,
        )
        client = GatewaySignalClient(
            gateway_base_url,
            tenant_id,
            static_gateway_bearer_token=api_key,
            max_retries=max_retries,
        )
        return cls(signal=client)

    async def aclose(self) -> None:
        await self.signal.aclose()


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
        url = normalize_gateway_base_url(gateway_base_url) + path
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

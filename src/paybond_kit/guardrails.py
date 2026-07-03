"""Gateway sandbox guardrail wrappers for first paid-tool integrations."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from uuid import UUID

import httpx

from paybond_kit.credentials import normalize_gateway_base_url
from paybond_kit.harbor import (
    HarborHttpError,
    TenantBindingError,
    _backoff_seconds,
    _parse_retry_after,
)


@dataclass(frozen=True)
class SandboxGuardrailBootstrapResult:
    tenant_id: str
    intent_id: UUID
    capability_token: str
    operation: str
    requested_spend_cents: int
    sandbox_lifecycle_status: str
    currency: str | None = None
    settlement_rail: str | None = None
    settlement_mode: str | None = None
    simulator_event: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class SandboxGuardrailSchemaValidation:
    vendor_schema_ok: bool
    canonical_schema_ok: bool
    quality_fields_missing: tuple[str, ...]
    pack_stale: bool
    drift_kinds: tuple[str, ...]


@dataclass(frozen=True)
class SandboxGuardrailEvidenceResult:
    tenant_id: str
    intent_id: UUID
    operation: str
    requested_spend_cents: int
    sandbox_lifecycle_status: str
    capability_token: str | None = None
    settlement_rail: str | None = None
    settlement_mode: str | None = None
    predicate_passed: bool | None = None
    payload_digest: str | None = None
    artifacts_digest: str | None = None
    schema_validation: SandboxGuardrailSchemaValidation | None = None
    simulator_event: Mapping[str, Any] | None = None


class GatewaySandboxGuardrailsClient:
    """
    Gateway-backed sandbox guardrail helpers.

    Sandbox guardrail routes derive tenant scope from the service-account bearer token and reject
    caller-supplied tenant IDs, including the normal Harbor proxy ``x-tenant-id`` header.
    """

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

    def _headers(self, *, idempotency_key: str | None = None) -> dict[str, str]:
        headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "authorization": f"Bearer {self._bearer}",
        }
        if idempotency_key is not None and idempotency_key.strip():
            headers["idempotency-key"] = idempotency_key.strip()
        return headers

    async def _post_json_with_retries(
        self,
        path: str,
        payload: dict[str, Any],
        *,
        idempotency_key: str | None = None,
    ) -> httpx.Response:
        url = f"{self._base}{path.lstrip('/')}"
        headers = self._headers(idempotency_key=idempotency_key)
        last_exc: BaseException | None = None
        for attempt in range(self._max_retries):
            try:
                response = await self._client.post(url, headers=headers, json=payload)
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_exc = exc
                if attempt + 1 >= self._max_retries:
                    raise
                await asyncio.sleep(_backoff_seconds(attempt))
                continue
            if response.status_code in (429, 500, 502, 503, 504):
                if attempt + 1 >= self._max_retries:
                    return response
                delay = _parse_retry_after(response.headers.get("retry-after"))
                if delay is None:
                    delay = _backoff_seconds(attempt)
                await asyncio.sleep(delay)
                continue
            return response
        if last_exc is not None:
            raise last_exc
        raise RuntimeError("sandbox guardrail POST exhausted retries without a response")

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
    ) -> SandboxGuardrailBootstrapResult:
        payload: dict[str, Any] = {
            "operation": operation,
            "requested_spend_cents": int(requested_spend_cents),
        }
        if currency is not None:
            payload["currency"] = currency
        if evidence_schema is not None and completion_preset is None:
            payload["evidence_schema"] = dict(evidence_schema)
        if metadata is not None:
            payload["metadata"] = dict(metadata)
        if completion_preset is not None:
            payload["completion_preset"] = completion_preset
        if template_id is not None:
            payload["template_id"] = template_id
        if parameters is not None:
            payload["parameters"] = dict(parameters)
        path = "v1/sandbox/guardrails/bootstrap"
        url = f"{self._base}{path}"
        response = await self._post_json_with_retries(
            path,
            payload,
            idempotency_key=idempotency_key,
        )
        if response.status_code >= 400:
            raise HarborHttpError(
                f"Gateway sandbox guardrail bootstrap HTTP {response.status_code}: {response.text}",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        body = response.json()
        if not isinstance(body, dict):
            raise HarborHttpError(
                "Gateway sandbox guardrail bootstrap response was not a JSON object",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        return _parse_sandbox_bootstrap_result(
            body,
            tenant_id=self._tenant,
            status_code=response.status_code,
            url=url,
            body_text=response.text,
        )

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
    ) -> SandboxGuardrailEvidenceResult:
        body: dict[str, Any] = {}
        if payload is not None:
            body["payload"] = dict(payload)
        if vendor_payload is not None:
            body["vendor_payload"] = dict(vendor_payload)
        if artifacts is not None:
            body["artifacts"] = list(artifacts)
        if operation is not None:
            body["operation"] = operation
        if requested_spend_cents is not None:
            body["requested_spend_cents"] = int(requested_spend_cents)
        if metadata is not None:
            body["metadata"] = dict(metadata)
        path = f"v1/sandbox/guardrails/{intent_id}/evidence"
        url = f"{self._base}{path}"
        response = await self._post_json_with_retries(
            path,
            body,
            idempotency_key=idempotency_key,
        )
        if response.status_code >= 400:
            raise HarborHttpError(
                f"Gateway sandbox guardrail evidence HTTP {response.status_code}: {response.text}",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        parsed = response.json()
        if not isinstance(parsed, dict):
            raise HarborHttpError(
                "Gateway sandbox guardrail evidence response was not a JSON object",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        return _parse_sandbox_evidence_result(
            parsed,
            tenant_id=self._tenant,
            intent_id=intent_id,
            status_code=response.status_code,
            url=url,
            body_text=response.text,
        )


def _parse_sandbox_bootstrap_result(
    body: dict[str, Any],
    *,
    tenant_id: str,
    status_code: int,
    url: str,
    body_text: str,
) -> SandboxGuardrailBootstrapResult:
    tenant = _required_string(body, "tenant_id", status_code=status_code, url=url, body_text=body_text)
    if tenant != tenant_id:
        raise TenantBindingError(
            f"sandbox guardrail tenant mismatch: client={tenant_id!r} gateway={tenant!r}"
        )
    simulator_event = body.get("simulator_event")
    return SandboxGuardrailBootstrapResult(
        tenant_id=tenant,
        intent_id=UUID(_required_string(body, "intent_id", status_code=status_code, url=url, body_text=body_text)),
        capability_token=_required_string(body, "capability_token", status_code=status_code, url=url, body_text=body_text),
        operation=_required_string(body, "operation", status_code=status_code, url=url, body_text=body_text),
        requested_spend_cents=_required_int(
            body,
            "requested_spend_cents",
            status_code=status_code,
            url=url,
            body_text=body_text,
        ),
        sandbox_lifecycle_status=_required_string(
            body,
            "sandbox_lifecycle_status",
            status_code=status_code,
            url=url,
            body_text=body_text,
        ),
        currency=_optional_string(body.get("currency")),
        settlement_rail=_optional_string(body.get("settlement_rail")),
        settlement_mode=_optional_string(body.get("settlement_mode")),
        simulator_event=simulator_event if isinstance(simulator_event, Mapping) else None,
    )


def _parse_sandbox_evidence_result(
    body: dict[str, Any],
    *,
    tenant_id: str,
    intent_id: UUID,
    status_code: int,
    url: str,
    body_text: str,
) -> SandboxGuardrailEvidenceResult:
    tenant = _required_string(body, "tenant_id", status_code=status_code, url=url, body_text=body_text)
    if tenant != tenant_id:
        raise TenantBindingError(
            f"sandbox guardrail tenant mismatch: client={tenant_id!r} gateway={tenant!r}"
        )
    echoed_intent_id = UUID(
        _required_string(body, "intent_id", status_code=status_code, url=url, body_text=body_text)
    )
    if echoed_intent_id != intent_id:
        raise TenantBindingError(
            f"sandbox guardrail intent mismatch: requested={intent_id} gateway={echoed_intent_id}"
        )
    predicate_passed = body.get("predicate_passed")
    simulator_event = body.get("simulator_event")
    return SandboxGuardrailEvidenceResult(
        tenant_id=tenant,
        intent_id=echoed_intent_id,
        capability_token=_optional_string(body.get("capability_token")),
        operation=_required_string(body, "operation", status_code=status_code, url=url, body_text=body_text),
        requested_spend_cents=_required_int(
            body,
            "requested_spend_cents",
            status_code=status_code,
            url=url,
            body_text=body_text,
        ),
        sandbox_lifecycle_status=_required_string(
            body,
            "sandbox_lifecycle_status",
            status_code=status_code,
            url=url,
            body_text=body_text,
        ),
        settlement_rail=_optional_string(body.get("settlement_rail")),
        settlement_mode=_optional_string(body.get("settlement_mode")),
        predicate_passed=predicate_passed if isinstance(predicate_passed, bool) else None,
        payload_digest=_optional_string(body.get("payload_digest")),
        artifacts_digest=_optional_string(body.get("artifacts_digest")),
        schema_validation=_parse_schema_validation(body.get("schema_validation")),
        simulator_event=simulator_event if isinstance(simulator_event, Mapping) else None,
    )


def _parse_schema_validation(value: Any) -> SandboxGuardrailSchemaValidation | None:
    if not isinstance(value, dict):
        return None
    vendor_ok = value.get("vendor_schema_ok")
    canonical_ok = value.get("canonical_schema_ok")
    if not isinstance(vendor_ok, bool) or not isinstance(canonical_ok, bool):
        return None
    quality_fields = value.get("quality_fields_missing")
    drift_kinds = value.get("drift_kinds")
    return SandboxGuardrailSchemaValidation(
        vendor_schema_ok=vendor_ok,
        canonical_schema_ok=canonical_ok,
        quality_fields_missing=tuple(
            field for field in quality_fields if isinstance(field, str)
        )
        if isinstance(quality_fields, list)
        else (),
        pack_stale=bool(value.get("pack_stale")),
        drift_kinds=tuple(kind for kind in drift_kinds if isinstance(kind, str))
        if isinstance(drift_kinds, list)
        else (),
    )


def _required_string(
    body: dict[str, Any],
    field: str,
    *,
    status_code: int,
    url: str,
    body_text: str,
) -> str:
    value = body.get(field)
    if isinstance(value, str) and value.strip():
        return value
    raise HarborHttpError(
        f"Gateway sandbox guardrail response missing {field}",
        status_code=status_code,
        url=url,
        body_text=body_text,
    )


def _optional_string(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value
    return None


def _required_int(
    body: dict[str, Any],
    field: str,
    *,
    status_code: int,
    url: str,
    body_text: str,
) -> int:
    value = body.get(field)
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    raise HarborHttpError(
        f"Gateway sandbox guardrail response missing {field}",
        status_code=status_code,
        url=url,
        body_text=body_text,
    )

"""Typed async Harbor client with tenant binding checks, retries, and optional upstream JWT."""

from __future__ import annotations

import base64
import json
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, TypeAlias, cast

if TYPE_CHECKING:
    from paybond_kit.agent.gateway_trace_reporter import GatewayAgentRunTraceReporter
    from paybond_kit.policy.load_effective import PolicyEffectiveResolveResult
    from paybond_kit.policy.validate_remote import (
        PolicyRemoteValidateOptions,
        PolicyRemoteValidateResult,
    )
from urllib.parse import urlencode
from uuid import UUID

import httpx

from paybond_kit.credentials import normalize_gateway_base_url
from paybond_kit.gateway_retry import httpx_with_gateway_retries

SettlementRail: TypeAlias = Literal["stripe_connect", "stripe_ach_debit", "x402_usdc_base"]
_SETTLEMENT_RAIL_VALUES = frozenset({"stripe_connect", "stripe_ach_debit", "x402_usdc_base"})


def validate_settlement_rail(value: str, *, field: str = "settlement_rail") -> SettlementRail:
    value = value.strip()
    if value not in _SETTLEMENT_RAIL_VALUES:
        raise ValueError(
            f"{field} must be one of {', '.join(sorted(_SETTLEMENT_RAIL_VALUES))}"
        )
    return cast(SettlementRail, value)


@dataclass(frozen=True)
class VerifyCapabilityResult:
    """Structured ``POST /verify`` outcome (HTTP 200 for allow/deny)."""

    allow: bool
    audit_id: UUID
    tenant: str
    intent_id: UUID
    code: str | None
    message: str | None
    decision_id: UUID | None = None
    approval_request_id: UUID | None = None
    policy_version: int | None = None
    reason_codes: tuple[str, ...] = ()
    spend_scope: dict[str, str] | None = None
    remaining_cents: int | None = None
    retry_after: int | None = None

    @property
    def approval_required(self) -> bool:
        if self.code == "approval_required":
            return True
        return any(
            code in self.reason_codes
            for code in (
                "approval_threshold_exceeded",
                "approval_required_pending",
                "approval_quorum_incomplete",
                "anomaly_new_vendor",
                "anomaly_amount_spike",
                "anomaly_rapid_auth",
                "anomaly_cap_proximity",
            )
        )


def _parse_verify_capability_result(
    body: dict[str, Any],
    *,
    expected_tenant: str,
    expected_intent_id: UUID,
) -> VerifyCapabilityResult:
    tenant = str(body["tenant"])
    rid = UUID(str(body["intent_id"]))
    if tenant != expected_tenant:
        raise TenantBindingError(
            f"verify tenant mismatch: client={expected_tenant!r} remote={tenant!r}"
        )
    if rid != expected_intent_id:
        raise TenantBindingError(
            f"verify intent mismatch: requested={expected_intent_id} remote={rid}"
        )
    reason_codes = tuple(str(code) for code in body.get("reason_codes") or ())
    spend_scope_raw = body.get("spend_scope")
    spend_scope = (
        {
            "scope_type": str(spend_scope_raw.get("scope_type", "")),
            "scope_key": str(spend_scope_raw.get("scope_key", "")),
        }
        if isinstance(spend_scope_raw, dict)
        else None
    )
    decision_id = UUID(str(body["decision_id"])) if body.get("decision_id") else None
    approval_request_id = (
        UUID(str(body["approval_request_id"])) if body.get("approval_request_id") else None
    )
    policy_version = int(body["policy_version"]) if body.get("policy_version") is not None else None
    remaining_cents = (
        int(body["remaining_cents"]) if body.get("remaining_cents") is not None else None
    )
    retry_after = int(body["retry_after"]) if body.get("retry_after") is not None else None
    return VerifyCapabilityResult(
        allow=bool(body["allow"]),
        audit_id=UUID(str(body["audit_id"])),
        tenant=tenant,
        intent_id=rid,
        code=body.get("code"),
        message=body.get("message"),
        decision_id=decision_id,
        approval_request_id=approval_request_id,
        policy_version=policy_version,
        reason_codes=reason_codes,
        spend_scope=spend_scope,
        remaining_cents=remaining_cents,
        retry_after=retry_after,
    )


def _verify_capability_payload(
    *,
    intent_id: UUID,
    token: str,
    operation: str,
    requested_spend_cents: int,
    vendor_id: str | None = None,
    task_id: str | None = None,
    workflow_id: str | None = None,
    tool_call_id: str | None = None,
    tool_name: str | None = None,
    currency: str | None = None,
    agent_subject: str | None = None,
    approval_token: str | None = None,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "intent_id": str(intent_id),
        "token": token,
        "operation": operation,
        "requested_spend_cents": int(requested_spend_cents),
    }
    if vendor_id and vendor_id.strip():
        payload["vendor_id"] = vendor_id.strip()
    if task_id and task_id.strip():
        payload["task_id"] = task_id.strip()
    if workflow_id and workflow_id.strip():
        payload["workflow_id"] = workflow_id.strip()
    if tool_call_id and tool_call_id.strip():
        payload["tool_call_id"] = tool_call_id.strip()
    if tool_name and tool_name.strip():
        payload["tool_name"] = tool_name.strip()
    if currency and currency.strip():
        payload["currency"] = currency.strip()
    if agent_subject and agent_subject.strip():
        payload["agent_subject"] = agent_subject.strip()
    if approval_token and approval_token.strip():
        payload["approval_token"] = approval_token.strip()
    if idempotency_key and idempotency_key.strip():
        payload["idempotency_key"] = idempotency_key.strip()
    return payload


@dataclass(frozen=True)
class IntentFundingResult:
    """Structured Harbor funding payload for x402 / USDC-on-Base intent funding."""

    settlement_rail: SettlementRail
    harbor_fund_endpoint: str | None
    status: str | None
    payment_session_id: str | None
    payment_url: str | None
    stripe_payment_intent_id: str | None
    client_secret: str | None
    stripe_connect_destination: str | None
    stripe_customer_id: str | None
    latest_charge_id: str | None
    payment_method_id: str | None
    mandate_id: str | None
    financial_connections_account_id: str | None
    bank_last4: str | None
    bank_fingerprint: str | None
    bank_name: str | None
    asset: str | None
    network: str | None
    authorization_id: str | None
    capture_id: str | None
    void_id: str | None
    transfer_id: str | None
    refund_id: str | None
    expected_debit_date: str | None
    payment_reference: str | None
    refund_reference: str | None
    refund_reference_status: str | None
    source_address: str | None
    target_address: str | None
    authorization_expires_at: str | None
    capture_expires_at: str | None
    refund_expires_at: str | None
    onchain_transaction_hashes: dict[str, list[str]] | None


@dataclass(frozen=True)
class FundIntentResult:
    """Structured result for ``POST /intents/{intent_id}/fund``."""

    status_code: int
    payment_required: str | None
    payment_response: str | None
    intent_id: UUID
    tenant: str
    state: str
    settlement_rail: SettlementRail
    currency: str
    amount_cents: int
    funded: bool
    capability_token: str | None
    funding: IntentFundingResult | None


class TenantBindingError(RuntimeError):
    """Raised when Harbor echoes a tenant or intent id that does not match the bound Kit client."""


class HarborHttpError(RuntimeError):
    """Raised for non-success HTTP status codes from Harbor."""

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


HarborBearerSupplier = Callable[[], Awaitable[str | None]]


class HarborClient:
    """
    Async Harbor client bound to a single tenant.

    Every request sends ``x-tenant-id`` using the configured tenant. Verify responses must echo the
    same tenant and the requested ``intent_id`` or :class:`TenantBindingError` is raised (confused
    deputy hardening).

    When ``harbor_bearer_supplier`` is set, each request awaits it and sends a non-empty value as
    ``Authorization: Bearer …`` (gateway-minted Harbor JWTs for authenticated upstream Harbor).

    Ledger read helpers (``GET /ledger/v1/*``) require JSON ``tenant_id`` to match the bound tenant,
    same confused-deputy hardening as verify.
    """

    def __init__(
        self,
        harbor_base: str,
        tenant_id: str,
        *,
        harbor_bearer_supplier: HarborBearerSupplier | None = None,
        static_harbor_bearer_token: str | None = None,
        max_retries: int = 3,
        request_timeout_sec: float = 30.0,
    ) -> None:
        if harbor_bearer_supplier is not None and static_harbor_bearer_token is not None:
            raise ValueError(
                "pass at most one of harbor_bearer_supplier or static_harbor_bearer_token"
            )
        base = harbor_base.strip().rstrip("/")
        self._base = f"{base}/"
        self._tenant = tenant_id.strip()
        self._bearer_supplier = harbor_bearer_supplier
        self._static_bearer = (
            static_harbor_bearer_token.strip()
            if static_harbor_bearer_token
            else None
        )
        self._max_retries = max(1, int(max_retries))
        self._client = httpx.AsyncClient(timeout=request_timeout_sec)

    @property
    def tenant_id(self) -> str:
        return self._tenant

    async def _authorization_header(self) -> dict[str, str]:
        if self._static_bearer:
            return {"authorization": f"Bearer {self._static_bearer}"}
        if self._bearer_supplier is not None:
            tok = await self._bearer_supplier()
            if tok and tok.strip():
                return {"authorization": f"Bearer {tok.strip()}"}
        return {}

    async def _post_json_with_retries(
        self,
        path: str,
        headers: dict[str, str],
        payload: dict[str, Any],
    ) -> httpx.Response:
        url = f"{self._base}{path.lstrip('/')}"
        auth_hdr = await self._authorization_header()
        merged = {
            "content-type": "application/json",
            "x-tenant-id": self._tenant,
            **auth_hdr,
            **headers,
        }
        return await httpx_with_gateway_retries(
            lambda: self._client.post(url, headers=merged, json=payload),
            max_retries=self._max_retries,
        )

    async def _get_json_with_retries(self, path: str) -> httpx.Response:
        """GET with the same retry policy as :meth:`_post_json_with_retries`."""
        url = f"{self._base}{path.lstrip('/')}"
        auth_hdr = await self._authorization_header()
        merged = {
            "accept": "application/json",
            "x-tenant-id": self._tenant,
            **auth_hdr,
        }
        return await httpx_with_gateway_retries(
            lambda: self._client.get(url, headers=merged),
            max_retries=self._max_retries,
        )

    def _assert_ledger_tenant(self, body: dict[str, Any], *, url: str) -> None:
        """Harbor ledger JSON always echoes ``tenant_id``; reject confused-deputy mismatches."""
        tenant = str(body.get("tenant_id", ""))
        if tenant != self._tenant:
            raise TenantBindingError(
                f"ledger tenant mismatch: client={self._tenant!r} harbor={tenant!r} url={url}"
            )

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
    ) -> VerifyCapabilityResult:
        """
        Call ``POST /verify`` with a Biscuit capability token (PAYBOND-006).

        Args:
            intent_id: Funded intent the token is scoped to.
            token: Standard base64-encoded Biscuit v3 token bytes.
            operation: Delegated operation name (must appear in the intent allow-list when enforced).
            requested_spend_cents: Spend the tool intends to consume against the token budget.
        """
        url = f"{self._base}verify"
        payload = _verify_capability_payload(
            intent_id=intent_id,
            token=token,
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
        extra_headers = {}
        if idempotency_key and idempotency_key.strip():
            extra_headers["idempotency-key"] = idempotency_key.strip()
        response = await self._post_json_with_retries("verify", extra_headers, payload)
        if response.status_code >= 400:
            raise HarborHttpError(
                f"Harbor verify HTTP {response.status_code}: {response.text}",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        body = response.json()
        return _parse_verify_capability_result(
            body,
            expected_tenant=self._tenant,
            expected_intent_id=intent_id,
        )

    async def verify_spend_capability(
        self,
        *,
        intent_id: UUID,
        token: str,
        operation: str,
        requested_spend_cents: int = 0,
    ) -> VerifyCapabilityResult:
        return await self.verify_capability(
            intent_id=intent_id,
            token=token,
            operation=operation,
            requested_spend_cents=requested_spend_cents,
        )

    async def authorize_spend(
        self,
        *,
        intent_id: UUID,
        token: str,
        operation: str,
        requested_spend_cents: int = 0,
    ) -> VerifyCapabilityResult:
        return await self.verify_capability(
            intent_id=intent_id,
            token=token,
            operation=operation,
            requested_spend_cents=requested_spend_cents,
        )

    async def create_intent(
        self,
        body: dict[str, Any],
        *,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """
        Call ``POST /intents`` with a principal-signed ``CreateIntentRequest`` JSON body.

        For raw ``predicate_dsl`` flows, prefer :meth:`paybond_kit.paybond.PaybondIntents.create`.
        """
        path = "intents"
        url = f"{self._base}{path}"
        extra: dict[str, str] = {}
        if idempotency_key is not None and idempotency_key.strip() != "":
            extra["idempotency-key"] = idempotency_key.strip()
        auth_hdr = await self._authorization_header()
        merged = {
            "content-type": "application/json",
            "x-tenant-id": self._tenant,
            **auth_hdr,
            **extra,
        }
        response = await httpx_with_gateway_retries(
            lambda: self._client.post(url, headers=merged, json=body),
            max_retries=self._max_retries,
        )
        if response.status_code >= 400:
            raise HarborHttpError(
                f"Harbor create intent HTTP {response.status_code}: {response.text}",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        return response.json()

    async def fund_intent(
        self,
        intent_id: UUID,
        *,
        payment_signature: str | None = None,
        idempotency_key: str | None = None,
    ) -> FundIntentResult:
        """
        Call ``POST /intents/{intent_id}/fund`` for x402 / USDC-on-Base funding.

        Harbor returns:
        - ``402`` with ``payment_required`` when a wallet or facilitator must sign
        - ``202`` while authorization is pending
        - ``200`` once the intent is funded
        """
        path = f"intents/{intent_id}/fund"
        url = f"{self._base}{path}"
        extra: dict[str, str] = {}
        if idempotency_key is not None and idempotency_key.strip() != "":
            extra["idempotency-key"] = idempotency_key.strip()
        if payment_signature is not None and payment_signature.strip() != "":
            extra["payment-signature"] = payment_signature.strip()
        response = await self._post_json_with_retries(path, extra, {})
        if response.status_code not in (200, 202, 402):
            raise HarborHttpError(
                f"Harbor fund intent HTTP {response.status_code}: {response.text}",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        body = response.json()
        if not isinstance(body, dict):
            raise HarborHttpError(
                "Harbor fund intent response was not a JSON object",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )

        tenant = str(body.get("tenant", ""))
        echoed_intent_id = UUID(str(body.get("intent_id", "")))
        if tenant != self._tenant:
            raise TenantBindingError(
                f"fund tenant mismatch: client={self._tenant!r} harbor={tenant!r}"
            )
        if echoed_intent_id != intent_id:
            raise TenantBindingError(
                f"fund intent mismatch: requested={intent_id} harbor={echoed_intent_id}"
            )

        state = body.get("state")
        settlement_rail = body.get("settlement_rail")
        currency = body.get("currency")
        amount_cents = body.get("amount_cents")
        if not isinstance(state, str) or not state.strip():
            raise HarborHttpError(
                "Harbor fund intent response missing state",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        if not isinstance(settlement_rail, str) or not settlement_rail.strip():
            raise HarborHttpError(
                "Harbor fund intent response missing settlement_rail",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        try:
            settlement_rail = validate_settlement_rail(
                settlement_rail,
                field="Harbor fund intent response settlement_rail",
            )
        except ValueError as exc:
            raise HarborHttpError(
                str(exc),
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            ) from exc
        if not isinstance(currency, str) or not currency.strip():
            raise HarborHttpError(
                "Harbor fund intent response missing currency",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        if not isinstance(amount_cents, int):
            raise HarborHttpError(
                "Harbor fund intent response missing amount_cents",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )

        funding_raw = body.get("funding")
        try:
            funding = (
                _parse_intent_funding_result(funding_raw)
                if isinstance(funding_raw, dict)
                else None
            )
        except ValueError as exc:
            raise HarborHttpError(
                f"Harbor fund intent response invalid: {exc}",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            ) from exc
        capability_token = body.get("capability_token")
        return FundIntentResult(
            status_code=response.status_code,
            payment_required=response.headers.get("payment-required"),
            payment_response=response.headers.get("payment-response"),
            intent_id=echoed_intent_id,
            tenant=tenant,
            state=state,
            settlement_rail=settlement_rail,
            currency=currency,
            amount_cents=amount_cents,
            funded=bool(body.get("funded")),
            capability_token=capability_token if isinstance(capability_token, str) else None,
            funding=funding,
        )

    async def submit_evidence(
        self,
        intent_id: UUID,
        evidence_body: dict[str, Any],
        *,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """
        Call ``POST /intents/{intent_id}/evidence`` with a signed evidence payload.

        ``evidence_body`` is typically produced by :func:`paybond_kit.signing.sign_payee_evidence_binding`.

        Args:
            idempotency_key: Optional Harbor ``idempotency-key`` header (1–256 chars) for
                duplicate-safe retries; scoped per tenant. See ``docs/api/harbor-idempotency-openapi.yaml``.
        """
        path = f"intents/{intent_id}/evidence"
        url = f"{self._base}{path}"
        extra: dict[str, str] = {}
        if idempotency_key is not None and idempotency_key.strip() != "":
            extra["idempotency-key"] = idempotency_key.strip()
        auth_hdr = await self._authorization_header()
        merged = {
            "content-type": "application/json",
            "x-tenant-id": self._tenant,
            **auth_hdr,
            **extra,
        }
        response = await httpx_with_gateway_retries(
            lambda: self._client.post(url, headers=merged, json=evidence_body),
            max_retries=self._max_retries,
        )
        if response.status_code >= 400:
            raise HarborHttpError(
                f"Harbor evidence HTTP {response.status_code}: {response.text}",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        return response.json()

    async def get_ledger_tip(self) -> dict[str, Any]:
        """
        Call ``GET /ledger/v1/tip`` for the bound tenant (PAYBOND-007 provenance read contract).

        Returns:
            Harbor JSON body; ``tenant_id`` must match the client tenant or :class:`TenantBindingError`.
        """
        path = "ledger/v1/tip"
        url = f"{self._base}{path}"
        response = await self._get_json_with_retries(path)
        if response.status_code >= 400:
            raise HarborHttpError(
                f"Harbor ledger tip HTTP {response.status_code}: {response.text}",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        body = response.json()
        if not isinstance(body, dict):
            raise HarborHttpError(
                "Harbor ledger tip response was not a JSON object",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        self._assert_ledger_tenant(body, url=url)
        return body

    async def get_ledger_authority(self) -> dict[str, Any]:
        """
        Call ``GET /ledger/v1/authority`` — Ed25519 verifying key hex for this Harbor deployment.
        """
        path = "ledger/v1/authority"
        url = f"{self._base}{path}"
        response = await self._get_json_with_retries(path)
        if response.status_code >= 400:
            raise HarborHttpError(
                f"Harbor ledger authority HTTP {response.status_code}: {response.text}",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        body = response.json()
        if not isinstance(body, dict):
            raise HarborHttpError(
                "Harbor ledger authority response was not a JSON object",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        self._assert_ledger_tenant(body, url=url)
        return body

    async def get_ledger_events(
        self,
        *,
        after_seq: int = 0,
        limit: int = 64,
    ) -> dict[str, Any]:
        """
        Call protected Harbor ``GET /ledger/v1/events`` with an exclusive ``after_seq`` cursor
        (Harbor default ``0``).

        ``limit`` is clamped to ``1..256`` to match Harbor enforcement.
        """
        if after_seq < 0:
            raise ValueError("after_seq must be >= 0")
        lim = max(1, min(int(limit), 256))
        qs = urlencode({"after_seq": str(int(after_seq)), "limit": str(lim)})
        path = f"ledger/v1/events?{qs}"
        url = f"{self._base}{path}"
        response = await self._get_json_with_retries(path)
        if response.status_code >= 400:
            raise HarborHttpError(
                f"Harbor ledger events HTTP {response.status_code}: {response.text}",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        body = response.json()
        if not isinstance(body, dict):
            raise HarborHttpError(
                "Harbor ledger events response was not a JSON object",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        self._assert_ledger_tenant(body, url=url)
        return body

    async def get_ledger_merkle_latest(self) -> dict[str, Any]:
        """Call ``GET /ledger/v1/merkle/latest`` for the latest Merkle checkpoint envelope."""
        path = "ledger/v1/merkle/latest"
        url = f"{self._base}{path}"
        response = await self._get_json_with_retries(path)
        if response.status_code >= 400:
            raise HarborHttpError(
                f"Harbor ledger merkle HTTP {response.status_code}: {response.text}",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        body = response.json()
        if not isinstance(body, dict):
            raise HarborHttpError(
                "Harbor ledger merkle response was not a JSON object",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        self._assert_ledger_tenant(body, url=url)
        return body

    async def aclose(self) -> None:
        await self._client.aclose()


class GatewayHarborClient:
    """
    Gateway-backed Harbor surface for hosted Paybond integrations.

    The client sends the service-account API key to Gateway. Gateway derives tenant scope, mints
    upstream Harbor credentials internally, and applies recognition/guardrail checks before
    forwarding state-changing Harbor requests.
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

    def _headers(self, *, content_type: str | None = None) -> dict[str, str]:
        headers = {
            "accept": "application/json",
            "x-tenant-id": self._tenant,
            "authorization": f"Bearer {self._bearer}",
        }
        if content_type is not None:
            headers["content-type"] = content_type
        return headers

    async def _post_json_with_retries(
        self,
        path: str,
        payload: dict[str, Any],
        *,
        extra_headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        url = f"{self._base}{path.lstrip('/')}"
        headers = self._headers(content_type="application/json")
        if extra_headers:
            headers.update(extra_headers)
        return await httpx_with_gateway_retries(
            lambda: self._client.post(url, headers=headers, json=payload),
            max_retries=self._max_retries,
        )

    async def _put_json_with_retries(
        self,
        path: str,
        payload: dict[str, Any],
        *,
        extra_headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        url = f"{self._base}{path.lstrip('/')}"
        headers = self._headers(content_type="application/json")
        if extra_headers:
            headers.update(extra_headers)
        return await httpx_with_gateway_retries(
            lambda: self._client.put(url, headers=headers, json=payload),
            max_retries=self._max_retries,
        )

    def create_agent_run_trace_reporter(self, run_id: str) -> GatewayAgentRunTraceReporter:
        """Gateway-backed middleware trace reporter for tenant console agent-runs view."""
        from paybond_kit.agent.gateway_trace_reporter import GatewayAgentRunTraceReporter

        trimmed = run_id.strip()
        if not trimmed:
            raise ValueError("create_agent_run_trace_reporter requires a non-empty run_id")

        async def write_json(method: str, path: str, body: dict[str, Any]) -> Any:
            if method == "PUT":
                response = await self._put_json_with_retries(path, body)
            else:
                response = await self._post_json_with_retries(path, body)
            url = f"{self._base}{path.lstrip('/')}"
            if response.status_code >= 400:
                raise HarborHttpError(
                    f"Gateway agent run trace HTTP {response.status_code}: {response.text}",
                    status_code=response.status_code,
                    url=url,
                    body_text=response.text,
                )
            if not response.text.strip():
                return {}
            parsed = response.json()
            return parsed if isinstance(parsed, dict) else {}

        return GatewayAgentRunTraceReporter(write_json, trimmed)

    async def _get_json_with_retries(self, path: str) -> httpx.Response:
        url = f"{self._base}{path.lstrip('/')}"
        headers = self._headers()
        return await httpx_with_gateway_retries(
            lambda: self._client.get(url, headers=headers),
            max_retries=self._max_retries,
        )

    async def get_intent(self, intent_id: UUID) -> dict[str, Any]:
        """Tenant-scoped Harbor operator intent detail (for attach run binding)."""
        path = f"harbor/operator/v1/intents/{intent_id}"
        url = f"{self._base}{path}"
        response = await self._get_json_with_retries(path)
        if response.status_code >= 400:
            raise HarborHttpError(
                f"Gateway Harbor get intent HTTP {response.status_code}: {response.text}",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        body = response.json()
        if not isinstance(body, dict):
            raise HarborHttpError(
                "Gateway Harbor get intent response was not a JSON object",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        tenant = str(body.get("tenant_id", "")).strip()
        if tenant != self._tenant:
            raise TenantBindingError(
                f"intent tenant mismatch: client={self._tenant!r} remote={tenant!r}"
            )
        return body

    def _mutation_headers(
        self,
        operation: str,
        recognition_proof: Mapping[str, Any] | None,
        *,
        idempotency_key: str | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, str]:
        if recognition_proof is None:
            raise ValueError(f"{operation} requires recognition_proof")
        headers = dict(extra_headers or {})
        headers["x-paybond-agent-recognition-proof"] = _encode_recognition_proof_header(
            dict(recognition_proof)
        )
        if idempotency_key is not None and idempotency_key.strip():
            headers["idempotency-key"] = idempotency_key.strip()
        return headers

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
    ) -> VerifyCapabilityResult:
        path = "verify"
        url = f"{self._base}{path}"
        payload = _verify_capability_payload(
            intent_id=intent_id,
            token=token,
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
        extra_headers = {}
        if idempotency_key and idempotency_key.strip():
            extra_headers["idempotency-key"] = idempotency_key.strip()
        response = await self._post_json_with_retries(path, payload, extra_headers=extra_headers)
        if response.status_code >= 400:
            raise HarborHttpError(
                f"Gateway verify HTTP {response.status_code}: {response.text}",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        body = response.json()
        if not isinstance(body, dict):
            raise HarborHttpError(
                "Gateway verify response was not a JSON object",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        return _parse_verify_capability_result(
            body,
            expected_tenant=self._tenant,
            expected_intent_id=intent_id,
        )

    async def verify_spend_capability(
        self,
        *,
        intent_id: UUID,
        token: str,
        operation: str,
        requested_spend_cents: int = 0,
    ) -> VerifyCapabilityResult:
        return await self.verify_capability(
            intent_id=intent_id,
            token=token,
            operation=operation,
            requested_spend_cents=requested_spend_cents,
        )

    async def authorize_spend(
        self,
        *,
        intent_id: UUID,
        token: str,
        operation: str,
        requested_spend_cents: int = 0,
    ) -> VerifyCapabilityResult:
        return await self.verify_capability(
            intent_id=intent_id,
            token=token,
            operation=operation,
            requested_spend_cents=requested_spend_cents,
        )

    async def complete_spend_decision(
        self,
        *,
        decision_id: str,
        outcome: Literal["consumed", "released"],
    ) -> None:
        """Finalize active spend reservations after tool execution completes or is aborted."""
        path = f"v1/spend/decisions/{decision_id}/complete"
        url = f"{self._base}{path}"
        response = await self._post_json_with_retries(path, {"outcome": outcome})
        if response.status_code >= 400:
            raise HarborHttpError(
                f"Gateway spend complete HTTP {response.status_code}: {response.text}",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )

    async def validate_policy(
        self,
        document: dict[str, Any],
        *,
        options: "PolicyRemoteValidateOptions | None" = None,
    ) -> "PolicyRemoteValidateResult":
        """Validate a paybond.policy.yaml document against the tenant Harbor registry."""
        from paybond_kit.policy.validate_remote import (
            PolicyRemoteValidateOptions,
            PolicyRemoteValidateResult,
            parse_policy_remote_validate_response,
            policy_validate_query_string,
        )

        options = options or PolicyRemoteValidateOptions()
        path = f"v1/policy/validate{policy_validate_query_string(options=options)}"
        url = f"{self._base}{path}"
        response = await self._post_json_with_retries(path, document)
        if response.status_code >= 400:
            raise HarborHttpError(
                f"Gateway policy validate HTTP {response.status_code}: {response.text}",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        return parse_policy_remote_validate_response(response.json())

    async def resolve_policy_effective(
        self,
        org_policy_id: str,
        overlay: dict[str, Any],
        *,
        current_digest: str | None = None,
    ) -> "PolicyEffectiveResolveResult":
        """Resolve merged effective policy for a tenant overlay."""
        from paybond_kit.policy.load_effective import (
            PolicyEffectiveResolveResult,
            parse_policy_effective_resolve_response,
        )

        path = f"v1/org-policies/{org_policy_id}/effective"
        if current_digest and current_digest.strip():
            from urllib.parse import quote

            path = f"{path}?digest={quote(current_digest.strip(), safe='')}"
        url = f"{self._base}{path}"
        response = await self._post_json_with_retries(path, overlay)
        if response.status_code >= 400:
            raise HarborHttpError(
                f"Gateway policy effective HTTP {response.status_code}: {response.text}",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        return parse_policy_effective_resolve_response(response.json())

    async def create_intent(
        self,
        body: dict[str, Any],
        *,
        recognition_proof: Mapping[str, Any],
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        path = "harbor/intents"
        url = f"{self._base}{path}"
        response = await self._post_json_with_retries(
            path,
            body,
            extra_headers=self._mutation_headers(
                "create_intent",
                recognition_proof,
                idempotency_key=idempotency_key,
            ),
        )
        if response.status_code >= 400:
            raise HarborHttpError(
                f"Gateway Harbor create intent HTTP {response.status_code}: {response.text}",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        payload = response.json()
        if not isinstance(payload, dict):
            raise HarborHttpError(
                "Gateway Harbor create intent response was not a JSON object",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        return payload

    async def fund_intent(
        self,
        intent_id: UUID,
        *,
        recognition_proof: Mapping[str, Any],
        payment_signature: str | None = None,
        idempotency_key: str | None = None,
    ) -> FundIntentResult:
        path = f"harbor/intents/{intent_id}/fund"
        url = f"{self._base}{path}"
        extra_headers: dict[str, str] = {}
        if payment_signature is not None and payment_signature.strip():
            extra_headers["payment-signature"] = payment_signature.strip()
        response = await self._post_json_with_retries(
            path,
            {},
            extra_headers=self._mutation_headers(
                "fund_intent",
                recognition_proof,
                idempotency_key=idempotency_key,
                extra_headers=extra_headers,
            ),
        )
        if response.status_code not in (200, 202, 402):
            raise HarborHttpError(
                f"Gateway Harbor fund intent HTTP {response.status_code}: {response.text}",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        body = response.json()
        if not isinstance(body, dict):
            raise HarborHttpError(
                "Gateway Harbor fund intent response was not a JSON object",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        return _parse_fund_intent_response(
            body,
            status_code=response.status_code,
            payment_required=response.headers.get("payment-required"),
            payment_response=response.headers.get("payment-response"),
            tenant_id=self._tenant,
            intent_id=intent_id,
            source="gateway",
            url=url,
            body_text=response.text,
        )

    async def submit_evidence(
        self,
        intent_id: UUID,
        evidence_body: dict[str, Any],
        *,
        recognition_proof: Mapping[str, Any],
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        path = f"harbor/intents/{intent_id}/evidence"
        url = f"{self._base}{path}"
        response = await self._post_json_with_retries(
            path,
            evidence_body,
            extra_headers=self._mutation_headers(
                "submit_evidence",
                recognition_proof,
                idempotency_key=idempotency_key,
            ),
        )
        if response.status_code >= 400:
            raise HarborHttpError(
                f"Gateway Harbor evidence HTTP {response.status_code}: {response.text}",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        payload = response.json()
        if not isinstance(payload, dict):
            raise HarborHttpError(
                "Gateway Harbor evidence response was not a JSON object",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        return payload


def _optional_nonempty_string(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value
    return None


def _string_list(value: Any, *, field: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"invalid {field}")
    return [str(item) for item in value]


def _parse_fund_intent_response(
    body: dict[str, Any],
    *,
    status_code: int,
    payment_required: str | None,
    payment_response: str | None,
    tenant_id: str,
    intent_id: UUID,
    source: str,
    url: str,
    body_text: str,
) -> FundIntentResult:
    tenant = str(body.get("tenant", ""))
    echoed_intent_id = UUID(str(body.get("intent_id", "")))
    if tenant != tenant_id:
        raise TenantBindingError(
            f"fund tenant mismatch: client={tenant_id!r} {source}={tenant!r}"
        )
    if echoed_intent_id != intent_id:
        raise TenantBindingError(
            f"fund intent mismatch: requested={intent_id} {source}={echoed_intent_id}"
        )

    state = body.get("state")
    settlement_rail = body.get("settlement_rail")
    currency = body.get("currency")
    amount_cents = body.get("amount_cents")
    if not isinstance(state, str) or not state.strip():
        raise HarborHttpError(
            "fund response missing state",
            status_code=status_code,
            url=url,
            body_text=body_text,
        )
    if not isinstance(settlement_rail, str) or not settlement_rail.strip():
        raise HarborHttpError(
            "fund response missing settlement_rail",
            status_code=status_code,
            url=url,
            body_text=body_text,
        )
    try:
        settlement_rail = validate_settlement_rail(
            settlement_rail,
            field="fund response settlement_rail",
        )
    except ValueError as exc:
        raise HarborHttpError(
            str(exc),
            status_code=status_code,
            url=url,
            body_text=body_text,
        ) from exc
    if not isinstance(currency, str) or not currency.strip():
        raise HarborHttpError(
            "fund response missing currency",
            status_code=status_code,
            url=url,
            body_text=body_text,
        )
    if not isinstance(amount_cents, int):
        raise HarborHttpError(
            "fund response missing amount_cents",
            status_code=status_code,
            url=url,
            body_text=body_text,
        )

    funding_raw = body.get("funding")
    try:
        funding = (
            _parse_intent_funding_result(funding_raw)
            if isinstance(funding_raw, dict)
            else None
        )
    except ValueError as exc:
        raise HarborHttpError(
            f"fund response invalid: {exc}",
            status_code=status_code,
            url=url,
            body_text=body_text,
        ) from exc
    capability_token = body.get("capability_token")
    return FundIntentResult(
        status_code=status_code,
        payment_required=payment_required,
        payment_response=payment_response,
        intent_id=echoed_intent_id,
        tenant=tenant,
        state=state,
        settlement_rail=settlement_rail,
        currency=currency,
        amount_cents=amount_cents,
        funded=bool(body.get("funded")),
        capability_token=capability_token if isinstance(capability_token, str) else None,
        funding=funding,
    )


def _parse_intent_funding_result(value: dict[str, Any]) -> IntentFundingResult:
    onchain_raw = value.get("onchain_transaction_hashes")
    onchain: dict[str, list[str]] | None = None
    if onchain_raw is not None:
        if not isinstance(onchain_raw, dict):
            raise ValueError("invalid funding.onchain_transaction_hashes")
        parsed: dict[str, list[str]] = {}
        if "authorizations" in onchain_raw:
            parsed["authorizations"] = _string_list(
                onchain_raw["authorizations"],
                field="funding.onchain_transaction_hashes.authorizations",
            )
        if "captures" in onchain_raw:
            parsed["captures"] = _string_list(
                onchain_raw["captures"],
                field="funding.onchain_transaction_hashes.captures",
            )
        if "voids" in onchain_raw:
            parsed["voids"] = _string_list(
                onchain_raw["voids"],
                field="funding.onchain_transaction_hashes.voids",
            )
        if "refunds" in onchain_raw:
            parsed["refunds"] = _string_list(
                onchain_raw["refunds"],
                field="funding.onchain_transaction_hashes.refunds",
            )
        onchain = parsed

    settlement_rail = value.get("settlement_rail")
    if not isinstance(settlement_rail, str) or not settlement_rail.strip():
        raise ValueError("invalid funding.settlement_rail")
    settlement_rail = validate_settlement_rail(
        settlement_rail,
        field="funding.settlement_rail",
    )

    return IntentFundingResult(
        settlement_rail=settlement_rail,
        harbor_fund_endpoint=_optional_nonempty_string(value.get("harbor_fund_endpoint")),
        status=_optional_nonempty_string(value.get("status")),
        payment_session_id=_optional_nonempty_string(value.get("payment_session_id")),
        payment_url=_optional_nonempty_string(value.get("payment_url")),
        stripe_payment_intent_id=_optional_nonempty_string(
            value.get("stripe_payment_intent_id")
        ),
        client_secret=_optional_nonempty_string(value.get("client_secret")),
        stripe_connect_destination=_optional_nonempty_string(
            value.get("stripe_connect_destination")
        ),
        stripe_customer_id=_optional_nonempty_string(value.get("stripe_customer_id")),
        latest_charge_id=_optional_nonempty_string(value.get("latest_charge_id")),
        payment_method_id=_optional_nonempty_string(value.get("payment_method_id")),
        mandate_id=_optional_nonempty_string(value.get("mandate_id")),
        financial_connections_account_id=_optional_nonempty_string(
            value.get("financial_connections_account_id")
        ),
        bank_last4=_optional_nonempty_string(value.get("bank_last4")),
        bank_fingerprint=_optional_nonempty_string(value.get("bank_fingerprint")),
        bank_name=_optional_nonempty_string(value.get("bank_name")),
        asset=_optional_nonempty_string(value.get("asset")),
        network=_optional_nonempty_string(value.get("network")),
        authorization_id=_optional_nonempty_string(value.get("authorization_id")),
        capture_id=_optional_nonempty_string(value.get("capture_id")),
        void_id=_optional_nonempty_string(value.get("void_id")),
        transfer_id=_optional_nonempty_string(value.get("transfer_id")),
        refund_id=_optional_nonempty_string(value.get("refund_id")),
        expected_debit_date=_optional_nonempty_string(value.get("expected_debit_date")),
        payment_reference=_optional_nonempty_string(value.get("payment_reference")),
        refund_reference=_optional_nonempty_string(value.get("refund_reference")),
        refund_reference_status=_optional_nonempty_string(
            value.get("refund_reference_status")
        ),
        source_address=_optional_nonempty_string(value.get("source_address")),
        target_address=_optional_nonempty_string(value.get("target_address")),
        authorization_expires_at=_optional_nonempty_string(
            value.get("authorization_expires_at")
        ),
        capture_expires_at=_optional_nonempty_string(value.get("capture_expires_at")),
        refund_expires_at=_optional_nonempty_string(value.get("refund_expires_at")),
        onchain_transaction_hashes=onchain,
    )


def _encode_recognition_proof_header(proof: dict[str, Any]) -> str:
    encoded = base64.urlsafe_b64encode(json.dumps(proof).encode("utf-8")).rstrip(b"=")
    return encoded.decode("ascii")

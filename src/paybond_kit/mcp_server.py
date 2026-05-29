"""Paybond MCP server for tenant-bound internal runtimes and orchestrators."""

from __future__ import annotations

import argparse
import asyncio
import json
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass, is_dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import quote, urlencode, urljoin
from uuid import UUID

import httpx

from paybond_kit.credentials import DEFAULT_PAYBOND_GATEWAY_BASE_URL
from paybond_kit.fraud import GatewayFraudClient
from paybond_kit.harbor import TenantBindingError
from paybond_kit.signal import GatewaySignalClient

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Mapping


DEFAULT_PRINCIPAL_PATH = "/v1/auth/principal"
DEFAULT_RECOGNITION_VERIFIER_ID = "paybond-gateway"


class GatewayHTTPError(RuntimeError):
    """Raised for non-success HTTP responses from the Paybond gateway."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int,
        url: str,
        body_text: str,
        error_code: str | None = None,
        error_message: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.url = url
        self.body_text = body_text
        parsed_code, parsed_message = _parse_gateway_error_envelope(body_text)
        self.error_code = error_code or parsed_code
        self.error_message = error_message or parsed_message


def _parse_gateway_error_envelope(body_text: str) -> tuple[str | None, str | None]:
    if not body_text.lstrip().startswith("{"):
        return None, None
    try:
        body = json.loads(body_text)
    except ValueError:
        return None, None
    if not isinstance(body, dict):
        return None, None
    error_code = body.get("error")
    error_message = body.get("message")
    return (
        error_code.strip() if isinstance(error_code, str) and error_code.strip() else None,
        error_message.strip() if isinstance(error_message, str) and error_message.strip() else None,
    )


def _gateway_http_error_message(
    method: str,
    path: str,
    status_code: int,
    body_text: str,
) -> str:
    error_code, error_message = _parse_gateway_error_envelope(body_text)
    if error_code is not None:
        return f"Gateway {method} {path} HTTP {status_code} ({error_code}): {error_message or body_text}"
    return f"Gateway {method} {path} HTTP {status_code}: {body_text}"


@dataclass(frozen=True)
class PaybondMCPSettings:
    """Environment-backed configuration for the MCP server."""

    api_key: str
    gateway_base_url: str = DEFAULT_PAYBOND_GATEWAY_BASE_URL
    principal_path: str = DEFAULT_PRINCIPAL_PATH
    max_retries: int = 3

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> PaybondMCPSettings:
        import os

        values = env or os.environ
        api_key = values.get("PAYBOND_API_KEY", "").strip()
        principal_path = values.get("PAYBOND_PRINCIPAL_PATH", "").strip() or DEFAULT_PRINCIPAL_PATH
        max_retries_raw = values.get("PAYBOND_MCP_MAX_RETRIES", "").strip()

        if not api_key:
            raise SystemExit("PAYBOND_API_KEY is required")

        max_retries = 3
        if max_retries_raw:
            try:
                max_retries = max(1, int(max_retries_raw))
            except ValueError as exc:
                raise SystemExit("PAYBOND_MCP_MAX_RETRIES must be an integer") from exc

        return cls(
            gateway_base_url=DEFAULT_PAYBOND_GATEWAY_BASE_URL,
            api_key=api_key,
            principal_path=principal_path,
            max_retries=max_retries,
        )


class GatewayAPIClient:
    """Thin authenticated JSON client for gateway-owned routes."""

    def __init__(
        self,
        *,
        gateway_base_url: str,
        api_key: str,
        max_retries: int = 3,
        request_timeout_sec: float = 30.0,
    ) -> None:
        self._base = gateway_base_url.strip().rstrip("/") + "/"
        self._api_key = api_key.strip()
        self._max_retries = max(1, int(max_retries))
        self._client = httpx.AsyncClient(timeout=request_timeout_sec)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def get_json(
        self,
        path: str,
        *,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        return await self._request_json(
            "GET", path, payload=None, extra_headers=extra_headers
        )

    async def post_json(
        self,
        path: str,
        payload: dict[str, Any],
        *,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        return await self._request_json(
            "POST", path, payload=payload, extra_headers=extra_headers
        )

    async def _request_json(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        url = urljoin(self._base, path.lstrip("/"))
        headers = {
            "accept": "application/json",
            "authorization": f"Bearer {self._api_key}",
        }
        if extra_headers is not None:
            headers.update(extra_headers)
        if payload is not None:
            headers["content-type"] = "application/json"

        last_exc: BaseException | None = None
        response: httpx.Response | None = None
        for attempt in range(self._max_retries):
            try:
                response = await self._client.request(
                    method,
                    url,
                    headers=headers,
                    json=payload,
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
            break

        if response is None:
            if last_exc is not None:
                raise last_exc
            raise RuntimeError("gateway request failed without a response")
        if response.status_code >= 400:
            error_code, error_message = _parse_gateway_error_envelope(response.text)
            raise GatewayHTTPError(
                _gateway_http_error_message(method, path, response.status_code, response.text),
                status_code=response.status_code,
                url=url,
                body_text=response.text,
                error_code=error_code,
                error_message=error_message,
            )

        body = response.json()
        if not isinstance(body, dict):
            raise RuntimeError(f"Gateway {method} {path} response was not a JSON object")
        return body


class PaybondMCPRuntime:
    """Lazy runtime state shared by MCP tools."""

    def __init__(self, settings: PaybondMCPSettings) -> None:
        self._settings = settings
        self._gateway = GatewayAPIClient(
            gateway_base_url=settings.gateway_base_url,
            api_key=settings.api_key,
            max_retries=settings.max_retries,
        )
        self._principal: dict[str, Any] | None = None
        self._principal_lock = asyncio.Lock()
        self._signal: GatewaySignalClient | None = None
        self._signal_lock = asyncio.Lock()
        self._fraud: GatewayFraudClient | None = None
        self._fraud_lock = asyncio.Lock()

    async def aclose(self) -> None:
        if self._signal is not None:
            await self._signal.aclose()
        if self._fraud is not None:
            await self._fraud.aclose()
        await self._gateway.aclose()

    async def principal(self) -> dict[str, Any]:
        async with self._principal_lock:
            if self._principal is None:
                self._principal = await self._gateway.get_json(self._settings.principal_path)
            return dict(self._principal)

    async def tenant_id(self) -> str:
        body = await self.principal()
        tenant_id = str(body.get("tenant_id", "")).strip()
        if not tenant_id:
            raise RuntimeError("gateway principal response missing tenant_id")
        return tenant_id

    async def signal(self) -> GatewaySignalClient:
        async with self._signal_lock:
            if self._signal is None:
                self._signal = GatewaySignalClient(
                    self._settings.gateway_base_url,
                    await self.tenant_id(),
                    static_gateway_bearer_token=self._settings.api_key,
                    max_retries=self._settings.max_retries,
                )
            return self._signal

    async def fraud(self) -> GatewayFraudClient:
        async with self._fraud_lock:
            if self._fraud is None:
                self._fraud = GatewayFraudClient(
                    self._settings.gateway_base_url,
                    await self.tenant_id(),
                    static_gateway_bearer_token=self._settings.api_key,
                    max_retries=self._settings.max_retries,
                )
            return self._fraud

    async def list_intents(
        self,
        *,
        status: str | None = None,
        operator_did: str | None = None,
        limit: int = 20,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, str] = {
            "limit": str(max(1, min(int(limit), 200))),
        }
        if status and status.strip():
            params["status"] = status.strip()
        if operator_did and operator_did.strip():
            params["operator_did"] = operator_did.strip()
        if cursor and cursor.strip():
            params["cursor"] = cursor.strip()
        query = urlencode(params)
        return await self._gateway.get_json(
            f"/harbor/operator/v1/intents?{query}",
            extra_headers={"x-tenant-id": await self.tenant_id()},
        )

    async def get_intent(self, intent_id: UUID) -> dict[str, Any]:
        return await self._gateway.get_json(
            f"/harbor/operator/v1/intents/{intent_id}",
            extra_headers={"x-tenant-id": await self.tenant_id()},
        )

    async def get_a2a_agent_card(self) -> dict[str, Any]:
        return await self._gateway.get_json("/.well-known/agent-card.json")

    async def get_a2a_task_contracts(self) -> dict[str, Any]:
        return await self._gateway.get_json("/protocol/v2/a2a/task-contracts")

    async def get_a2a_task_contract(self, contract_id: str) -> dict[str, Any]:
        return await self._gateway.get_json(
            f"/protocol/v2/a2a/task-contracts/{quote(contract_id, safe='')}"
        )

    async def verify_capability(
        self,
        *,
        intent_id: UUID,
        token: str,
        operation: str,
        requested_spend_cents: int = 0,
    ) -> dict[str, Any]:
        body = await self._gateway.post_json(
            "/verify",
            {
                "intent_id": str(intent_id),
                "token": token,
                "operation": operation,
                "requested_spend_cents": requested_spend_cents,
            },
            extra_headers={"x-tenant-id": await self.tenant_id()},
        )
        await self._assert_tenant_echo(body, field="tenant")
        echoed_intent = str(body.get("intent_id", "")).strip()
        if echoed_intent != str(intent_id):
            raise TenantBindingError(
                f"verify intent mismatch: requested={intent_id} gateway={echoed_intent!r}"
            )
        return body

    async def verify_agent_mandate_v1(self, signed_mandate: dict[str, Any]) -> dict[str, Any]:
        return await self._gateway.post_json(
            "/protocol/v2/mandates/verify",
            signed_mandate,
            extra_headers={"x-tenant-id": await self.tenant_id()},
        )

    async def verify_agent_recognition_proof_v1(
        self,
        *,
        proof: dict[str, Any],
        expected_purpose: str,
        expected_request: dict[str, Any],
        expected_verifier: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        verifier = dict(expected_verifier or {})
        verifier.setdefault("tenant_id", await self.tenant_id())
        verifier.setdefault("verifier_id", DEFAULT_RECOGNITION_VERIFIER_ID)
        return await self._gateway.post_json(
            "/protocol/v2/recognition/verify",
            {
                "proof": proof,
                "expected_purpose": expected_purpose,
                "expected_verifier": verifier,
                "expected_request": expected_request,
            },
            extra_headers={"x-tenant-id": await self.tenant_id()},
        )

    async def import_agent_mandate_v1(
        self,
        *,
        signed_mandate: dict[str, Any],
        intent_id: str,
        recognition_proof: dict[str, Any],
        transport_binding: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        body = await self._gateway.post_json(
            "/protocol/v2/mandates",
            {
                "signed_mandate": signed_mandate,
                "intent_id": intent_id,
                "transport_binding": dict(transport_binding or {}),
                "recognition_proof": recognition_proof,
            },
            extra_headers={"x-tenant-id": await self.tenant_id()},
        )
        echoed_intent = str(body.get("intent_id", "")).strip()
        if echoed_intent != intent_id:
            raise TenantBindingError(
                f"intent mismatch: requested={intent_id!r} gateway={echoed_intent!r}"
            )
        mandate = body.get("mandate", {})
        if not isinstance(mandate, dict):
            raise RuntimeError("protocol mandate import response missing mandate object")
        authorization = mandate.get("authorization", {})
        if not isinstance(authorization, dict):
            raise RuntimeError("protocol mandate import response missing authorization object")
        echoed_tenant = str(authorization.get("tenant_id", "")).strip()
        expected = await self.tenant_id()
        if echoed_tenant != expected:
            raise TenantBindingError(
                f"tenant mismatch: expected={expected!r} gateway={echoed_tenant!r}"
            )
        return body

    async def get_settlement_receipt_v1(self, receipt_id: str) -> dict[str, Any]:
        body = await self._gateway.get_json(
            f"/protocol/v2/receipts/{quote(receipt_id, safe='')}",
            extra_headers={"x-tenant-id": await self.tenant_id()},
        )
        echoed_receipt = str(body.get("receipt_id", "")).strip()
        if echoed_receipt != receipt_id:
            raise TenantBindingError(
                f"receipt mismatch: requested={receipt_id!r} gateway={echoed_receipt!r}"
            )
        await self._assert_tenant_echo(body, field="tenant_id")
        return body

    async def verify_protocol_receipt_v1(
        self,
        receipt: dict[str, Any],
    ) -> dict[str, Any]:
        return await self._gateway.post_json(
            "/protocol/v2/receipts/verify",
            receipt,
            extra_headers={"x-tenant-id": await self.tenant_id()},
        )

    async def create_harbor_intent(
        self,
        *,
        body: dict[str, Any],
        recognition_proof: dict[str, Any],
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        return await self._gateway_harbor_mutation(
            "/harbor/intents",
            body,
            recognition_proof,
            idempotency_key=idempotency_key,
        )

    async def fund_harbor_intent(
        self,
        intent_id: UUID,
        *,
        recognition_proof: dict[str, Any],
        payment_signature: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        extra_headers: dict[str, str] = {}
        if payment_signature is not None and payment_signature.strip():
            extra_headers["payment-signature"] = payment_signature.strip()
        return await self._gateway_harbor_mutation(
            f"/harbor/intents/{intent_id}/fund",
            {},
            recognition_proof,
            idempotency_key=idempotency_key,
            extra_headers=extra_headers,
        )

    async def submit_harbor_evidence(
        self,
        intent_id: UUID,
        *,
        body: dict[str, Any],
        recognition_proof: dict[str, Any],
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        return await self._gateway_harbor_mutation(
            f"/harbor/intents/{intent_id}/evidence",
            body,
            recognition_proof,
            idempotency_key=idempotency_key,
        )

    async def confirm_harbor_settlement(
        self,
        intent_id: UUID,
        *,
        body: dict[str, Any],
        recognition_proof: dict[str, Any],
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        return await self._gateway_harbor_mutation(
            f"/harbor/intents/{intent_id}/settlement/confirm",
            body,
            recognition_proof,
            idempotency_key=idempotency_key,
        )

    async def _gateway_harbor_mutation(
        self,
        path: str,
        body: dict[str, Any],
        recognition_proof: dict[str, Any],
        *,
        idempotency_key: str | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        headers = dict(extra_headers or {})
        headers["x-tenant-id"] = await self.tenant_id()
        headers["x-paybond-agent-recognition-proof"] = _encode_recognition_proof_header(
            recognition_proof
        )
        if idempotency_key is not None and idempotency_key.strip():
            headers["idempotency-key"] = idempotency_key.strip()
        return await self._gateway.post_json(path, body, extra_headers=headers)

    async def _assert_tenant_echo(self, body: dict[str, Any], *, field: str) -> None:
        echoed = str(body.get(field, "")).strip()
        expected = await self.tenant_id()
        if echoed != expected:
            raise TenantBindingError(
                f"tenant mismatch: expected={expected!r} gateway={echoed!r}"
            )


def build_mcp_server(settings: PaybondMCPSettings | None = None) -> Any:
    """Build the stdio MCP server instance."""

    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:  # pragma: no cover - exercised only without the optional dep
        raise RuntimeError(
            "The Paybond MCP server requires the optional 'mcp' dependency. "
            "Install it with `pip install \"paybond-kit[mcp]\"`."
        ) from exc

    resolved = settings or PaybondMCPSettings.from_env()
    runtime = PaybondMCPRuntime(resolved)

    @asynccontextmanager
    async def lifespan(_: Any) -> AsyncIterator[None]:
        try:
            yield
        finally:
            await runtime.aclose()

    server = FastMCP(
        name="Paybond MCP",
        instructions=(
            "This server is bound to one Paybond tenant derived from the configured "
            "service-account API key. Use paybond_create_spend_intent or "
            "paybond_fund_intent to obtain the intent_id and capability_token, then "
            "call paybond_authorize_agent_spend before side-effecting tools. The server "
            "works with any MCP-compatible host and does not assume a specific model "
            "provider. Do not invent tenant identifiers. Gateway-first Harbor mutation "
            "tools expect already-signed request bodies plus replay-safe recognition "
            "proofs; do not pass signing seeds or long-lived private keys through MCP "
            "tool arguments."
        ),
        website_url="https://paybond.ai",
        lifespan=lifespan,
    )

    @server.tool(
        name="paybond_get_principal",
        description=(
            "Resolve the tenant-bound Paybond principal behind the configured "
            "service-account API key."
        ),
        structured_output=True,
    )
    async def paybond_get_principal() -> dict[str, Any]:
        return await runtime.principal()

    @server.tool(
        name="paybond_verify_capability",
        description=(
            "Verify a capability token returned by a created or funded Paybond intent "
            "for one tenant-bound Harbor intent."
        ),
        structured_output=True,
    )
    async def paybond_verify_capability(
        intent_id: str,
        token: str,
        operation: str,
        requested_spend_cents: int = 0,
    ) -> dict[str, Any]:
        return await runtime.verify_capability(
            intent_id=UUID(intent_id),
            token=token,
            operation=operation,
            requested_spend_cents=requested_spend_cents,
        )

    @server.tool(
        name="paybond_authorize_agent_spend",
        description=(
            "Provider-agnostic spend gate: verify the funded intent's capability token "
            "before a side-effecting tool, paid API, vendor action, or settlement "
            "workflow executes."
        ),
        structured_output=True,
    )
    async def paybond_authorize_agent_spend(
        intent_id: str,
        token: str,
        operation: str,
        requested_spend_cents: int = 0,
    ) -> dict[str, Any]:
        return await runtime.verify_capability(
            intent_id=UUID(intent_id),
            token=token,
            operation=operation,
            requested_spend_cents=requested_spend_cents,
        )

    @server.tool(
        name="paybond_list_intents",
        description=(
            "List tenant-scoped Harbor intents through the gateway operator view. "
            "Supports optional status, operator DID, limit, and cursor filters."
        ),
        structured_output=True,
    )
    async def paybond_list_intents(
        status: str | None = None,
        operator_did: str | None = None,
        limit: int = 20,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        return await runtime.list_intents(
            status=status,
            operator_did=operator_did,
            limit=limit,
            cursor=cursor,
        )

    @server.tool(
        name="paybond_get_intent",
        description="Fetch one tenant-scoped Harbor intent detail through the gateway operator view.",
        structured_output=True,
    )
    async def paybond_get_intent(intent_id: str) -> dict[str, Any]:
        return await runtime.get_intent(UUID(intent_id))

    @server.tool(
        name="paybond_get_reputation_receipt",
        description="Fetch the signed Signal receipt for one operator DID.",
        structured_output=True,
    )
    async def paybond_get_reputation_receipt(
        operator_did: str,
        score_version: str | None = None,
    ) -> dict[str, Any] | None:
        signal = await runtime.signal()
        return await signal.get_reputation_receipt(
            operator_did,
            score_version=score_version,
        )

    @server.tool(
        name="paybond_get_portfolio_summary",
        description="Fetch the tenant-scoped Signal portfolio summary.",
        structured_output=True,
    )
    async def paybond_get_portfolio_summary(
        score_version: str | None = None,
    ) -> dict[str, Any]:
        signal = await runtime.signal()
        return await signal.get_portfolio_summary(score_version=score_version)

    @server.tool(
        name="paybond_get_signed_portfolio_artifact",
        description=(
            "Fetch the tenant-scoped signed Signal portfolio artifact for portable verifier "
            "and partner sharing."
        ),
        structured_output=True,
    )
    async def paybond_get_signed_portfolio_artifact(
        score_version: str | None = None,
    ) -> dict[str, Any]:
        signal = await runtime.signal()
        return await signal.get_signed_portfolio_artifact(score_version=score_version)

    @server.tool(
        name="paybond_get_fraud_assessment",
        description="Fetch the read-only fraud assessment for one tenant-scoped operator DID.",
        structured_output=True,
    )
    async def paybond_get_fraud_assessment(
        operator_did: str,
        score_version: str | None = None,
    ) -> dict[str, Any] | None:
        fraud = await runtime.fraud()
        return await fraud.get_fraud_assessment(
            operator_did,
            score_version=score_version,
        )

    @server.tool(
        name="paybond_get_fraud_metrics",
        description="Fetch tenant-scoped read-only fraud backtesting and monitoring metrics for a supported active window.",
        structured_output=True,
    )
    async def paybond_get_fraud_metrics(
        window: str | None = None,
        score_version: str | None = None,
    ) -> dict[str, Any]:
        fraud = await runtime.fraud()
        return await fraud.get_fraud_metrics(window=window, score_version=score_version)

    @server.tool(
        name="paybond_get_a2a_agent_card",
        description="Fetch the published Paybond A2A discovery card for protocol-trust delegation.",
        structured_output=True,
    )
    async def paybond_get_a2a_agent_card() -> dict[str, Any]:
        return await runtime.get_a2a_agent_card()

    @server.tool(
        name="paybond_list_a2a_task_contracts",
        description="Fetch the published catalog of Paybond A2A task contracts for delegated Harbor workflows.",
        structured_output=True,
    )
    async def paybond_list_a2a_task_contracts() -> dict[str, Any]:
        return await runtime.get_a2a_task_contracts()

    @server.tool(
        name="paybond_get_a2a_task_contract",
        description="Fetch one published Paybond A2A task contract by identifier.",
        structured_output=True,
    )
    async def paybond_get_a2a_task_contract(contract_id: str) -> dict[str, Any]:
        return await runtime.get_a2a_task_contract(contract_id)

    @server.tool(
        name="paybond_verify_agent_mandate_v1",
        description=(
            "Verify a signed AgentMandateV1 envelope through the gateway v2 protocol surface."
        ),
        structured_output=True,
    )
    async def paybond_verify_agent_mandate_v1(
        signed_mandate: dict[str, Any],
    ) -> dict[str, Any]:
        return await runtime.verify_agent_mandate_v1(signed_mandate)

    @server.tool(
        name="paybond_verify_agent_recognition_proof_v1",
        description=(
            "Verify a replay-safe AgentRecognitionProofV1 against an expected purpose, "
            "verifier context, and request envelope."
        ),
        structured_output=True,
    )
    async def paybond_verify_agent_recognition_proof_v1(
        proof: dict[str, Any],
        expected_purpose: str,
        expected_request: dict[str, Any],
        expected_verifier: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return await runtime.verify_agent_recognition_proof_v1(
            proof=proof,
            expected_purpose=expected_purpose,
            expected_request=expected_request,
            expected_verifier=expected_verifier,
        )

    @server.tool(
        name="paybond_import_agent_mandate_v1",
        description=(
            "Import a signed AgentMandateV1 through the gateway v2 protocol surface and bind it "
            "to one Harbor intent using a replay-safe recognition proof."
        ),
        structured_output=True,
    )
    async def paybond_import_agent_mandate_v1(
        signed_mandate: dict[str, Any],
        intent_id: str,
        recognition_proof: dict[str, Any],
        transport_binding: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return await runtime.import_agent_mandate_v1(
            signed_mandate=signed_mandate,
            intent_id=intent_id,
            recognition_proof=recognition_proof,
            transport_binding=transport_binding,
        )

    @server.tool(
        name="paybond_get_settlement_receipt_v1",
        description="Fetch the signed protocol-v2 settlement receipt for one Harbor intent.",
        structured_output=True,
    )
    async def paybond_get_settlement_receipt_v1(receipt_id: str) -> dict[str, Any]:
        return await runtime.get_settlement_receipt_v1(receipt_id)

    @server.tool(
        name="paybond_verify_protocol_receipt_v1",
        description="Verify a protocol-v2 authorization or settlement receipt through the gateway.",
        structured_output=True,
    )
    async def paybond_verify_protocol_receipt_v1(receipt: dict[str, Any]) -> dict[str, Any]:
        return await runtime.verify_protocol_receipt_v1(receipt)

    @server.tool(
        name="paybond_create_intent",
        description=(
            "Create a Harbor intent through the gateway /harbor path. The request body must "
            "already be signed upstream and every call requires a recognition proof."
        ),
        structured_output=True,
    )
    async def paybond_create_intent(
        body: dict[str, Any],
        recognition_proof: dict[str, Any],
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        return await runtime.create_harbor_intent(
            body=body,
            recognition_proof=recognition_proof,
            idempotency_key=idempotency_key,
        )

    @server.tool(
        name="paybond_create_spend_intent",
        description=(
            "Create a signed Paybond spend intent through the gateway /harbor route. "
            "Use this when an agent workflow needs bounded budget, allowed operations, "
            "evidence, and settlement review. If the selected rail funds immediately, "
            "use the returned intent_id and capability_token with "
            "paybond_authorize_agent_spend."
        ),
        structured_output=True,
    )
    async def paybond_create_spend_intent(
        body: dict[str, Any],
        recognition_proof: dict[str, Any],
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        return await runtime.create_harbor_intent(
            body=body,
            recognition_proof=recognition_proof,
            idempotency_key=idempotency_key,
        )

    @server.tool(
        name="paybond_fund_intent",
        description=(
            "Advance Harbor funding through the gateway /harbor path with a replay-safe "
            "recognition proof. When funding succeeds, use the returned capability_token "
            "with intent_id in paybond_authorize_agent_spend."
        ),
        structured_output=True,
    )
    async def paybond_fund_intent(
        intent_id: str,
        recognition_proof: dict[str, Any],
        payment_signature: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        return await runtime.fund_harbor_intent(
            UUID(intent_id),
            recognition_proof=recognition_proof,
            payment_signature=payment_signature,
            idempotency_key=idempotency_key,
        )

    @server.tool(
        name="paybond_submit_evidence",
        description=(
            "Submit evidence through the gateway /harbor path with a replay-safe recognition proof."
        ),
        structured_output=True,
    )
    async def paybond_submit_evidence(
        intent_id: str,
        body: dict[str, Any],
        recognition_proof: dict[str, Any],
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        return await runtime.submit_harbor_evidence(
            UUID(intent_id),
            body=body,
            recognition_proof=recognition_proof,
            idempotency_key=idempotency_key,
        )

    @server.tool(
        name="paybond_submit_spend_evidence",
        description=(
            "Submit signed evidence for a Paybond spend intent so release, refund, "
            "review, and receipt generation use the same audit-ready record."
        ),
        structured_output=True,
    )
    async def paybond_submit_spend_evidence(
        intent_id: str,
        body: dict[str, Any],
        recognition_proof: dict[str, Any],
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        return await runtime.submit_harbor_evidence(
            UUID(intent_id),
            body=body,
            recognition_proof=recognition_proof,
            idempotency_key=idempotency_key,
        )

    @server.tool(
        name="paybond_confirm_settlement",
        description=(
            "Confirm Harbor settlement through the gateway /harbor path with a replay-safe "
            "recognition proof."
        ),
        structured_output=True,
    )
    async def paybond_confirm_settlement(
        intent_id: str,
        body: dict[str, Any],
        recognition_proof: dict[str, Any],
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        return await runtime.confirm_harbor_settlement(
            UUID(intent_id),
            body=body,
            recognition_proof=recognition_proof,
            idempotency_key=idempotency_key,
        )

    setattr(server, "_paybond_runtime", runtime)
    return server


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for `paybond-mcp-server`."""

    parser = argparse.ArgumentParser(
        description="Run the tenant-bound Paybond MCP server over stdio."
    )
    parser.parse_args(argv)

    try:
        server = build_mcp_server(PaybondMCPSettings.from_env())
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc
    server.run(transport="stdio")
    return 0


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
    return min(base + 0.1, 5.0)


def _jsonable(value: Any) -> Any:
    if is_dataclass(value):
        return _jsonable(asdict(value))
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    if isinstance(value, tuple):
        return [_jsonable(item) for item in value]
    return value


def _encode_recognition_proof_header(proof: dict[str, Any]) -> str:
    import base64
    import json

    return (
        base64.urlsafe_b64encode(json.dumps(proof).encode("utf-8"))
        .rstrip(b"=")
        .decode("ascii")
    )


__all__ = [
    "DEFAULT_RECOGNITION_VERIFIER_ID",
    "PaybondMCPSettings",
    "build_mcp_server",
    "main",
]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

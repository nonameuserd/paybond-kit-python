"""Typed async client for Paybond Gateway protocol-v2 mandate import and receipt routes."""

from __future__ import annotations

import json
from typing import Any, TypedDict
from urllib.parse import quote

import httpx

from paybond_kit.credentials import normalize_gateway_base_url
from paybond_kit.gateway_retry import httpx_with_gateway_retries


class AgentMandateAuthorization(TypedDict, total=False):
    kind: str
    tenant_id: str
    principal_subject: str
    principal_type: str


class AgentMandateAgentIdentity(TypedDict, total=False):
    subject: str
    issuer: str
    key_id: str
    display_name: str


class AgentMandateSpendCeiling(TypedDict):
    amount_minor: int
    currency: str


class AgentMandateSettlementRailPolicy(TypedDict):
    default_rail: str
    allowed_rails: list[str]


class AgentMandateConstraintReference(TypedDict, total=False):
    kind: str
    id: str
    version: str
    digest_sha256_hex: str
    uri: str


class AgentMandateV1(TypedDict):
    schema_version: int
    kind: str
    authorization: AgentMandateAuthorization
    agent: AgentMandateAgentIdentity
    allowed_actions: list[str]
    allowed_tools: list[str]
    spend_ceiling: AgentMandateSpendCeiling
    settlement: AgentMandateSettlementRailPolicy
    constraint: AgentMandateConstraintReference
    expires_at: str
    nonce: str
    human_presence_mode: str


class SignedAgentMandateV1(AgentMandateV1):
    signing_algorithm: str
    message_digest_sha256_hex: str
    signing_public_key_ed25519_hex: str
    ed25519_signature_hex: str


class AgentRecognitionVerifierContext(TypedDict):
    tenant_id: str
    verifier_id: str


class AgentRecognitionRequestEnvelope(TypedDict):
    method: str
    path: str
    body_digest_sha256_hex: str


class AgentRecognitionProofV1(TypedDict, total=False):
    schema_version: int
    kind: str
    key_id: str
    signature_algorithm: str
    issued_at: str
    expires_at: str
    nonce: str
    purpose: str
    verifier_context: AgentRecognitionVerifierContext
    request_envelope: AgentRecognitionRequestEnvelope
    message_digest_sha256_hex: str
    signing_public_key_ed25519_hex: str
    ed25519_signature_hex: str


class ProtocolTransportBindingV1(TypedDict, total=False):
    source_protocol: str
    partner_platform: str
    external_authorization_id: str
    request_id: str


class ProtocolAuthorizationReceiptV1(TypedDict):
    schema_version: int
    kind: str
    receipt_version: str
    receipt_id: str
    issued_at: str
    status: str
    intent_id: str
    tenant_id: str
    verifier_id: str
    transport_binding: ProtocolTransportBindingV1
    mandate_digest_sha256_hex: str
    imported_mandate_signing_public_key_ed25519_hex: str
    authorization: AgentMandateAuthorization
    agent: AgentMandateAgentIdentity
    allowed_actions: list[str]
    allowed_tools: list[str]
    spend_ceiling: AgentMandateSpendCeiling
    settlement: AgentMandateSettlementRailPolicy
    constraint: AgentMandateConstraintReference
    expires_at: str
    nonce: str
    human_presence_mode: str
    signing_algorithm: str
    message_digest_sha256_hex: str
    signing_public_key_ed25519_hex: str
    ed25519_signature_hex: str


class ProtocolSettlementReceiptV1(TypedDict):
    schema_version: int
    kind: str
    receipt_version: str
    receipt_id: str
    issued_at: str
    intent_id: str
    tenant_id: str
    verifier_id: str
    transport_binding: ProtocolTransportBindingV1
    authorization_receipt_id: str
    mandate_digest_sha256_hex: str
    harbor_state: str
    predicate_passed: bool
    settlement_rail: str
    settlement_mode: str
    principal_did: str
    payee_did: str
    currency: str
    amount_cents: int
    terminal_observed_at: str
    signing_algorithm: str
    message_digest_sha256_hex: str
    signing_public_key_ed25519_hex: str
    ed25519_signature_hex: str


class ImportAgentMandateV1Result(TypedDict):
    valid: bool
    intent_id: str
    mandate_digest_sha256_hex: str
    mandate: AgentMandateV1
    authorization_receipt: ProtocolAuthorizationReceiptV1


class VerifyProtocolReceiptV1Result(TypedDict):
    valid: bool
    kind: str
    receipt_id: str
    tenant_id: str
    receipt: dict[str, Any]


class ProtocolHttpError(RuntimeError):
    """Raised for non-success HTTP status codes from the protocol-v2 routes."""

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


def _protocol_http_error_message(prefix: str, status_code: int, body_text: str) -> str:
    error_code, error_message = _parse_gateway_error_envelope(body_text)
    if error_code is not None:
        return f"{prefix} HTTP {status_code} ({error_code}): {error_message or body_text}"
    return f"{prefix} HTTP {status_code}: {body_text}"


class GatewayProtocolClient:
    """Tenant-bound async client for protocol-v2 mandate import and receipt export/verify."""

    def __init__(
        self,
        gateway_base_url: str,
        tenant_id: str,
        *,
        static_gateway_bearer_token: str | None = None,
        max_retries: int = 3,
        request_timeout_sec: float = 30.0,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base = normalize_gateway_base_url(gateway_base_url) + "/"
        self._tenant = tenant_id.strip()
        self._bearer = (
            static_gateway_bearer_token.strip()
            if static_gateway_bearer_token and static_gateway_bearer_token.strip()
            else None
        )
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
        }
        if content_type is not None:
            headers["content-type"] = content_type
        if self._bearer is not None:
            headers["authorization"] = f"Bearer {self._bearer}"
        return headers

    async def _request_with_retries(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        url = f"{self._base}{path.lstrip('/')}"
        headers = self._headers(content_type="application/json" if json_body is not None else None)
        if extra_headers is not None:
            headers.update(extra_headers)
        return await httpx_with_gateway_retries(
            lambda: self._client.request(
                method,
                url,
                headers=headers,
                json=json_body,
            ),
            max_retries=self._max_retries,
        )

    async def import_agent_mandate_v1(
        self,
        *,
        signed_mandate: SignedAgentMandateV1,
        intent_id: str,
        recognition_proof: AgentRecognitionProofV1 | dict[str, Any],
        transport_binding: ProtocolTransportBindingV1 | None = None,
    ) -> ImportAgentMandateV1Result:
        path = "protocol/v2/mandates"
        url = f"{self._base}{path}"
        response = await self._request_with_retries(
            "POST",
            path,
            json_body={
                "signed_mandate": signed_mandate,
                "intent_id": intent_id,
                "transport_binding": dict(transport_binding or {}),
                "recognition_proof": dict(recognition_proof),
            },
        )
        if response.status_code >= 400:
            error_code, error_message = _parse_gateway_error_envelope(response.text)
            raise ProtocolHttpError(
                _protocol_http_error_message("protocol mandate import", response.status_code, response.text),
                status_code=response.status_code,
                url=url,
                body_text=response.text,
                error_code=error_code,
                error_message=error_message,
            )
        body = response.json()
        if not isinstance(body, dict):
            raise RuntimeError("protocol mandate import response was not a JSON object")
        echoed_intent = str(body.get("intent_id", "")).strip()
        if echoed_intent != intent_id:
            raise RuntimeError(
                f"protocol intent mismatch: requested={intent_id!r} gateway={echoed_intent!r}"
            )
        mandate = body.get("mandate", {})
        if not isinstance(mandate, dict):
            raise RuntimeError("protocol mandate import response missing mandate object")
        authorization = mandate.get("authorization", {})
        tenant_id = str(authorization.get("tenant_id", "")).strip()
        if tenant_id != self._tenant:
            raise RuntimeError(
                f"protocol mandate tenant mismatch: client={self._tenant!r} gateway={tenant_id!r}"
            )
        return body  # type: ignore[return-value]

    async def get_settlement_receipt_v1(
        self,
        receipt_id: str,
    ) -> ProtocolSettlementReceiptV1:
        path = f"protocol/v2/receipts/{quote(receipt_id, safe='')}"
        url = f"{self._base}{path}"
        response = await self._request_with_retries("GET", path)
        if response.status_code >= 400:
            error_code, error_message = _parse_gateway_error_envelope(response.text)
            raise ProtocolHttpError(
                _protocol_http_error_message("protocol settlement receipt", response.status_code, response.text),
                status_code=response.status_code,
                url=url,
                body_text=response.text,
                error_code=error_code,
                error_message=error_message,
            )
        body = response.json()
        if not isinstance(body, dict):
            raise RuntimeError("protocol settlement receipt response was not a JSON object")
        echoed_receipt_id = str(body.get("receipt_id", "")).strip()
        if echoed_receipt_id != receipt_id:
            raise RuntimeError(
                f"protocol receipt mismatch: requested={receipt_id!r} gateway={echoed_receipt_id!r}"
            )
        tenant_id = str(body.get("tenant_id", "")).strip()
        if tenant_id != self._tenant:
            raise RuntimeError(
                f"protocol receipt tenant mismatch: client={self._tenant!r} gateway={tenant_id!r}"
            )
        return body  # type: ignore[return-value]

    async def verify_protocol_receipt_v1(
        self,
        receipt: ProtocolAuthorizationReceiptV1 | ProtocolSettlementReceiptV1 | dict[str, Any],
    ) -> VerifyProtocolReceiptV1Result:
        path = "protocol/v2/receipts/verify"
        url = f"{self._base}{path}"
        response = await self._request_with_retries(
            "POST",
            path,
            json_body=dict(receipt),
        )
        if response.status_code >= 400:
            error_code, error_message = _parse_gateway_error_envelope(response.text)
            raise ProtocolHttpError(
                _protocol_http_error_message("protocol receipt verify", response.status_code, response.text),
                status_code=response.status_code,
                url=url,
                body_text=response.text,
                error_code=error_code,
                error_message=error_message,
            )
        body = response.json()
        if not isinstance(body, dict):
            raise RuntimeError("protocol receipt verify response was not a JSON object")
        return body  # type: ignore[return-value]

    async def create_harbor_intent(
        self,
        *,
        body: dict[str, Any],
        recognition_proof: AgentRecognitionProofV1 | dict[str, Any],
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        return await self._gateway_mutation(
            "harbor/intents",
            body,
            recognition_proof,
            idempotency_key=idempotency_key,
        )

    async def fund_harbor_intent(
        self,
        intent_id: str,
        *,
        recognition_proof: AgentRecognitionProofV1 | dict[str, Any],
        payment_signature: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        extra_headers: dict[str, str] = {}
        if payment_signature is not None and payment_signature.strip():
            extra_headers["payment-signature"] = payment_signature.strip()
        return await self._gateway_mutation(
            f"harbor/intents/{quote(intent_id, safe='')}/fund",
            {},
            recognition_proof,
            idempotency_key=idempotency_key,
            extra_headers=extra_headers,
        )

    async def submit_harbor_evidence(
        self,
        intent_id: str,
        *,
        body: dict[str, Any],
        recognition_proof: AgentRecognitionProofV1 | dict[str, Any],
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        return await self._gateway_mutation(
            f"harbor/intents/{quote(intent_id, safe='')}/evidence",
            body,
            recognition_proof,
            idempotency_key=idempotency_key,
        )

    async def confirm_harbor_settlement(
        self,
        intent_id: str,
        *,
        body: dict[str, Any],
        recognition_proof: AgentRecognitionProofV1 | dict[str, Any],
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        return await self._gateway_mutation(
            f"harbor/intents/{quote(intent_id, safe='')}/settlement/confirm",
            body,
            recognition_proof,
            idempotency_key=idempotency_key,
        )

    async def _gateway_mutation(
        self,
        path: str,
        body: dict[str, Any],
        recognition_proof: AgentRecognitionProofV1 | dict[str, Any],
        *,
        idempotency_key: str | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        url = f"{self._base}{path}"
        headers = dict(extra_headers or {})
        headers["x-paybond-agent-recognition-proof"] = _encode_recognition_proof_header(
            dict(recognition_proof)
        )
        if idempotency_key is not None and idempotency_key.strip():
            headers["idempotency-key"] = idempotency_key.strip()
        response = await self._request_with_retries(
            "POST",
            path,
            json_body=body,
            extra_headers=headers,
        )
        if response.status_code >= 400:
            error_code, error_message = _parse_gateway_error_envelope(response.text)
            raise ProtocolHttpError(
                _protocol_http_error_message("gateway mutation", response.status_code, response.text),
                status_code=response.status_code,
                url=url,
                body_text=response.text,
                error_code=error_code,
                error_message=error_message,
            )
        payload = response.json()
        if not isinstance(payload, dict):
            raise RuntimeError("gateway mutation response was not a JSON object")
        return payload


def _encode_recognition_proof_header(proof: dict[str, Any]) -> str:
    import base64
    import json

    return (
        base64.urlsafe_b64encode(json.dumps(proof).encode("utf-8"))
        .rstrip(b"=")
        .decode("ascii")
    )

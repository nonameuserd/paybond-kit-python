"""Typed async Harbor client with tenant binding checks, retries, and optional upstream JWT."""

from __future__ import annotations

import asyncio
import random
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode
from uuid import UUID

import httpx


@dataclass(frozen=True)
class VerifyCapabilityResult:
    """Structured ``POST /verify`` outcome (HTTP 200 for allow/deny)."""

    allow: bool
    audit_id: UUID
    tenant: str
    intent_id: UUID
    code: str | None
    message: str | None


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
        last_exc: BaseException | None = None
        for attempt in range(self._max_retries):
            try:
                response = await self._client.post(url, headers=merged, json=payload)
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_exc = exc
                if attempt + 1 >= self._max_retries:
                    raise
                await asyncio.sleep(_backoff_seconds(attempt))
                continue
            if response.status_code in (429, 500, 502, 503, 504):
                if attempt + 1 >= self._max_retries:
                    break
                ra = response.headers.get("retry-after")
                delay = _parse_retry_after(ra)
                if delay is None:
                    delay = _backoff_seconds(attempt)
                await asyncio.sleep(delay)
                continue
            return response
        if last_exc is not None:
            raise last_exc
        return response

    async def _get_json_with_retries(self, path: str) -> httpx.Response:
        """GET with the same retry policy as :meth:`_post_json_with_retries`."""
        url = f"{self._base}{path.lstrip('/')}"
        auth_hdr = await self._authorization_header()
        merged = {
            "accept": "application/json",
            "x-tenant-id": self._tenant,
            **auth_hdr,
        }
        last_exc: BaseException | None = None
        for attempt in range(self._max_retries):
            try:
                response = await self._client.get(url, headers=merged)
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_exc = exc
                if attempt + 1 >= self._max_retries:
                    raise
                await asyncio.sleep(_backoff_seconds(attempt))
                continue
            if response.status_code in (429, 500, 502, 503, 504):
                if attempt + 1 >= self._max_retries:
                    break
                ra = response.headers.get("retry-after")
                delay = _parse_retry_after(ra)
                if delay is None:
                    delay = _backoff_seconds(attempt)
                await asyncio.sleep(delay)
                continue
            return response
        if last_exc is not None:
            raise last_exc
        return response

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
        payload: dict[str, Any] = {
            "intent_id": str(intent_id),
            "token": token,
            "operation": operation,
            "requested_spend_cents": requested_spend_cents,
        }
        response = await self._post_json_with_retries("verify", {}, payload)
        if response.status_code >= 400:
            raise HarborHttpError(
                f"Harbor verify HTTP {response.status_code}: {response.text}",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        body = response.json()
        tenant = str(body["tenant"])
        rid = UUID(str(body["intent_id"]))
        if tenant != self._tenant:
            raise TenantBindingError(
                f"verify tenant mismatch: client={self._tenant!r} harbor={tenant!r}"
            )
        if rid != intent_id:
            raise TenantBindingError(
                f"verify intent mismatch: requested={intent_id} harbor={rid}"
            )
        return VerifyCapabilityResult(
            allow=bool(body["allow"]),
            audit_id=UUID(str(body["audit_id"])),
            tenant=tenant,
            intent_id=rid,
            code=body.get("code"),
            message=body.get("message"),
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
        last_exc: BaseException | None = None
        for attempt in range(self._max_retries):
            try:
                response = await self._client.post(url, headers=merged, json=body)
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_exc = exc
                if attempt + 1 >= self._max_retries:
                    raise
                await asyncio.sleep(_backoff_seconds(attempt))
                continue
            if response.status_code in (429, 500, 502, 503, 504):
                if attempt + 1 >= self._max_retries:
                    break
                ra = response.headers.get("retry-after")
                delay = _parse_retry_after(ra)
                if delay is None:
                    delay = _backoff_seconds(attempt)
                await asyncio.sleep(delay)
                continue
            if response.status_code >= 400:
                raise HarborHttpError(
                    f"Harbor create intent HTTP {response.status_code}: {response.text}",
                    status_code=response.status_code,
                    url=url,
                    body_text=response.text,
                )
            return response.json()
        if last_exc is not None:
            raise last_exc
        raise HarborHttpError(
            f"Harbor create intent HTTP {response.status_code}: {response.text}",
            status_code=response.status_code,
            url=url,
            body_text=response.text,
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
        last_exc: BaseException | None = None
        for attempt in range(self._max_retries):
            try:
                response = await self._client.post(
                    url, headers=merged, json=evidence_body
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
                ra = response.headers.get("retry-after")
                delay = _parse_retry_after(ra)
                if delay is None:
                    delay = _backoff_seconds(attempt)
                await asyncio.sleep(delay)
                continue
            if response.status_code >= 400:
                raise HarborHttpError(
                    f"Harbor evidence HTTP {response.status_code}: {response.text}",
                    status_code=response.status_code,
                    url=url,
                    body_text=response.text,
                )
            return response.json()
        if last_exc is not None:
            raise last_exc
        raise HarborHttpError(
            f"Harbor evidence HTTP {response.status_code}: {response.text}",
            status_code=response.status_code,
            url=url,
            body_text=response.text,
        )

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
        Call ``GET /ledger/v1/events`` with an exclusive ``after_seq`` cursor (Harbor default ``0``).

        ``limit`` is clamped to ``1…256`` to match Harbor enforcement.
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


def _backoff_seconds(attempt: int) -> float:
    base = 0.2 * (2**attempt)
    jitter = random.uniform(0.0, 0.1)
    return min(base + jitter, 5.0)


def _parse_retry_after(header_val: str | None) -> float | None:
    if header_val is None:
        return None
    s = header_val.strip()
    if not s:
        return None
    try:
        return min(float(s), 30.0)
    except ValueError:
        return None

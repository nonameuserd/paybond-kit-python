"""SDK surface for compliance audit export jobs and local bundle verification."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol, runtime_checkable
from urllib.parse import urlencode

import httpx

from paybond_kit.audit.verify import audit_verify_result, verify_audit_manifest
from paybond_kit.audit.wire import (
    AuditExportJobGetResponse,
    AuditExportListPage,
    parse_audit_export_job_get,
    parse_audit_export_list,
)
from paybond_kit.credentials import DEFAULT_PAYBOND_GATEWAY_BASE_URL, normalize_gateway_base_url


@runtime_checkable
class AuditExportsGateway(Protocol):
    async def get_json(self, path: str) -> dict[str, Any]: ...

    async def delete_json(self, path: str) -> dict[str, Any]: ...


@dataclass(frozen=True)
class GatewayAuditExportsClientOptions:
    static_gateway_bearer_token: str
    max_retries: int = 3


class GatewayAuditExportsClient:
    """Gateway-backed compliance audit export client."""

    def __init__(
        self,
        gateway_base_url: str,
        tenant_id: str,
        *,
        options: GatewayAuditExportsClientOptions,
    ) -> None:
        self._base = normalize_gateway_base_url(gateway_base_url).rstrip("/")
        self._tenant_id = tenant_id.strip()
        self._bearer_token = options.static_gateway_bearer_token.strip()
        self._max_retries = max(1, options.max_retries)
        self._client = httpx.AsyncClient(timeout=30.0)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def get_json(self, path: str) -> dict[str, Any]:
        return await self._request("GET", path)

    async def delete_json(self, path: str) -> dict[str, Any]:
        return await self._request("DELETE", path)

    async def _request(self, method: str, path: str) -> dict[str, Any]:
        url = f"{self._base}{path if path.startswith('/') else f'/{path}'}"
        last_err: Exception | None = None
        for attempt in range(self._max_retries):
            try:
                response = await self._client.request(
                    method,
                    url,
                    headers={
                        "accept": "application/json",
                        "authorization": f"Bearer {self._bearer_token}",
                    },
                )
            except httpx.HTTPError as exc:
                last_err = exc
                if attempt + 1 >= self._max_retries:
                    raise
                continue
            if response.status_code in (429, 500, 502, 503, 504) and attempt + 1 < self._max_retries:
                continue
            if not response.is_success:
                raise RuntimeError(
                    f"Gateway {method} {path} HTTP {response.status_code}: {response.text}"
                )
            if not response.text.strip():
                return {}
            parsed = response.json()
            if not isinstance(parsed, dict):
                raise RuntimeError(f"Gateway {method} {path} returned non-object JSON")
            return parsed
        if last_err is not None:
            raise last_err
        raise RuntimeError(f"Gateway {method} {path} failed")


@dataclass
class PaybondAuditExports:
    """Compliance audit export list/get/verify helpers."""

    _gateway: AuditExportsGateway

    @classmethod
    def from_gateway(cls, gateway: AuditExportsGateway) -> PaybondAuditExports:
        return cls(_gateway=gateway)

    @classmethod
    def open(
        cls,
        gateway_base_url: str,
        tenant_id: str,
        *,
        options: GatewayAuditExportsClientOptions,
    ) -> PaybondAuditExports:
        return cls(_gateway=GatewayAuditExportsClient(gateway_base_url, tenant_id, options=options))

    async def list(
        self,
        *,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> AuditExportListPage:
        params: dict[str, str] = {
            "limit": str(max(1, min(limit or 50, 200))),
        }
        if cursor and cursor.strip():
            params["cursor"] = cursor.strip()
        body = await self._gateway.get_json(f"/v1/compliance/audit-exports?{urlencode(params)}")
        return parse_audit_export_list(body)

    async def get(
        self,
        job_id: str,
        *,
        issue_download: bool = False,
    ) -> AuditExportJobGetResponse:
        query = "?issue_download=1" if issue_download else ""
        body = await self._gateway.get_json(
            f"/v1/compliance/audit-exports/{job_id}{query}"
        )
        return parse_audit_export_job_get(body)

    async def delete(self, job_id: str) -> dict[str, Any]:
        await self._gateway.delete_json(f"/v1/compliance/audit-exports/{job_id}")
        return {"job_id": job_id, "deleted": True}

    async def verify(
        self,
        manifest_or_path: Mapping[str, Any] | str,
        *,
        cwd: str | Path = ".",
    ) -> dict[str, Any]:
        if isinstance(manifest_or_path, str):
            from paybond_kit.audit.verify import verify_audit_bundle_local

            return verify_audit_bundle_local(manifest_or_path, cwd)
        return audit_verify_result(dict(manifest_or_path))

    def verify_manifest(self, manifest: Mapping[str, Any]) -> bool:
        return verify_audit_manifest(dict(manifest))


@dataclass(frozen=True)
class PaybondAudit:
    exports: PaybondAuditExports


__all__ = [
    "AuditExportsGateway",
    "AuditExportJobGetResponse",
    "AuditExportListPage",
    "GatewayAuditExportsClient",
    "GatewayAuditExportsClientOptions",
    "PaybondAudit",
    "PaybondAuditExports",
    "DEFAULT_PAYBOND_GATEWAY_BASE_URL",
]

"""SDK surface for compliance audit export jobs and local bundle verification."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol, runtime_checkable
from urllib.parse import urlencode

import httpx

from paybond_kit.audit.verify import audit_verify_result, verify_audit_manifest
from paybond_kit.audit.wire import (
    AuditExportCreateFilter,
    AuditExportJobGetResponse,
    AuditExportListPage,
    parse_audit_export_job_get,
    parse_audit_export_list,
)
from paybond_kit.credentials import DEFAULT_PAYBOND_GATEWAY_BASE_URL, normalize_gateway_base_url


@runtime_checkable
class AuditExportsGateway(Protocol):
    async def get_json(self, path: str) -> dict[str, Any]: ...

    async def post_json(self, path: str, body: Mapping[str, Any]) -> dict[str, Any]: ...

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

    async def post_json(self, path: str, body: Mapping[str, Any]) -> dict[str, Any]:
        return await self._request("POST", path, body=dict(body))

    async def delete_json(self, path: str) -> dict[str, Any]:
        return await self._request("DELETE", path)

    async def _request(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
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
                        **(
                            {"content-type": "application/json"}
                            if method == "POST"
                            else {}
                        ),
                    },
                    json=body if method == "POST" else None,
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


def _build_audit_export_create_body(
    *,
    filter: AuditExportCreateFilter | Mapping[str, Any],
    disclosure_tier: str = "standard",
    retention_hours: int | None = None,
) -> dict[str, Any]:
    if isinstance(filter, AuditExportCreateFilter):
        filter_obj = filter
    else:
        includes = filter.get("includes")
        filter_obj = AuditExportCreateFilter(
            time_start=str(filter["time_start"]).strip() if filter.get("time_start") else None,
            time_end=str(filter["time_end"]).strip() if filter.get("time_end") else None,
            intent_id=str(filter["intent_id"]).strip() if filter.get("intent_id") else None,
            case_id=str(filter["case_id"]).strip() if filter.get("case_id") else None,
            operator_did=str(filter["operator_did"]).strip() if filter.get("operator_did") else None,
            includes=tuple(str(item) for item in includes) if isinstance(includes, list) else None,
        )
    payload_filter: dict[str, Any] = {}
    if filter_obj.time_start:
        payload_filter["time_start"] = filter_obj.time_start
    if filter_obj.time_end:
        payload_filter["time_end"] = filter_obj.time_end
    if filter_obj.intent_id:
        payload_filter["intent_id"] = filter_obj.intent_id
    if filter_obj.case_id:
        payload_filter["case_id"] = filter_obj.case_id
    if filter_obj.operator_did:
        payload_filter["operator_did"] = filter_obj.operator_did
    if filter_obj.includes:
        payload_filter["includes"] = list(filter_obj.includes)
    body: dict[str, Any] = {
        "filter": payload_filter,
        "disclosure_tier": disclosure_tier or "standard",
    }
    if retention_hours is not None and retention_hours > 0:
        body["retention_hours"] = retention_hours
    return body


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

    async def create(
        self,
        *,
        filter: AuditExportCreateFilter | Mapping[str, Any],
        disclosure_tier: str = "standard",
        retention_hours: int | None = None,
    ) -> AuditExportJobGetResponse:
        """Create a compliance audit export job (``POST /v1/compliance/audit-exports``)."""
        body = await self._gateway.post_json(
            "/v1/compliance/audit-exports",
            _build_audit_export_create_body(
                filter=filter,
                disclosure_tier=disclosure_tier,
                retention_hours=retention_hours,
            ),
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
    "AuditExportCreateFilter",
    "AuditExportsGateway",
    "AuditExportJobGetResponse",
    "AuditExportListPage",
    "GatewayAuditExportsClient",
    "GatewayAuditExportsClientOptions",
    "PaybondAudit",
    "PaybondAuditExports",
    "DEFAULT_PAYBOND_GATEWAY_BASE_URL",
]

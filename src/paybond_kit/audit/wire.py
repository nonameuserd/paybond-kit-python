"""Wire types for Gateway compliance audit export responses."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AuditExportJobSummary:
    id: str
    status: str
    disclosure_tier: str
    created_at: str
    expires_at: str
    manifest_sha256: str
    bundle_sha256: str
    bundle_size_bytes: int


@dataclass(frozen=True)
class AuditExportListPage:
    tenant_realm_id: str
    jobs: tuple[AuditExportJobSummary, ...]
    next_cursor: str | None = None


@dataclass(frozen=True)
class AuditExportCreateFilter:
    time_start: str | None = None
    time_end: str | None = None
    intent_id: str | None = None
    case_id: str | None = None
    operator_did: str | None = None
    includes: tuple[str, ...] | None = None


@dataclass(frozen=True)
class AuditExportJobDetail:
    id: str
    status: str
    tenant_realm_id: str
    disclosure_tier: str
    created_at: str
    expires_at: str
    error: str
    manifest_sha256: str
    bundle_sha256: str
    download_token: str | None = None
    bundle_size_bytes: int | None = None
    download_token_expires: str | None = None
    download_path: str | None = None


@dataclass(frozen=True)
class AuditExportJobGetResponse:
    job: AuditExportJobDetail


def _assert_json_object(value: Any, label: str = "value") -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object for {label}")
    return value


def _read_string(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"Invalid {field}")
    return value


def _read_number(value: Any, field: str) -> int:
    if not isinstance(value, (int, float)) or not float(value).is_integer():
        raise ValueError(f"Invalid {field}")
    return int(value)


def _extract_next_cursor(body: dict[str, Any]) -> str | None:
    cursor = body.get("next_cursor") or body.get("nextCursor")
    if isinstance(cursor, str) and cursor.strip():
        return cursor.strip()
    return None


def parse_audit_export_list(json: Any) -> AuditExportListPage:
    body = _assert_json_object(json)
    tenant_realm_id = _read_string(body.get("tenant_realm_id"), "tenant_realm_id")
    jobs_raw = body.get("jobs") or body.get("items") or body.get("exports")
    if not isinstance(jobs_raw, list):
        raise ValueError("Invalid export list: jobs")
    jobs: list[AuditExportJobSummary] = []
    for row in jobs_raw:
        item = _assert_json_object(row, "jobs[]")
        jobs.append(
            AuditExportJobSummary(
                id=_read_string(item.get("id") or item.get("job_id"), "jobs[].id"),
                status=_read_string(item.get("status"), "jobs[].status"),
                disclosure_tier=_read_string(item.get("disclosure_tier"), "jobs[].disclosure_tier"),
                created_at=_read_string(item.get("created_at"), "jobs[].created_at"),
                expires_at=_read_string(item.get("expires_at"), "jobs[].expires_at"),
                manifest_sha256=str(item.get("manifest_sha256") or ""),
                bundle_sha256=str(item.get("bundle_sha256") or ""),
                bundle_size_bytes=_read_number(item.get("bundle_size_bytes", 0), "jobs[].bundle_size_bytes"),
            )
        )
    return AuditExportListPage(
        tenant_realm_id=tenant_realm_id,
        jobs=tuple(jobs),
        next_cursor=_extract_next_cursor(body),
    )


def parse_audit_export_job_get(json: Any) -> AuditExportJobGetResponse:
    body = _assert_json_object(json)
    job_raw = body.get("job", body)
    job_obj = _assert_json_object(job_raw, "job")
    download_token = job_obj.get("download_token")
    bundle_size = job_obj.get("bundle_size_bytes")
    download_token_expires = job_obj.get("download_token_expires") or job_obj.get(
        "download_token_expires_at"
    )
    download_path = job_obj.get("download_path")
    created_at = job_obj.get("created_at")
    return AuditExportJobGetResponse(
        job=AuditExportJobDetail(
            id=_read_string(job_obj.get("id") or job_obj.get("job_id"), "job.id"),
            status=_read_string(job_obj.get("status"), "job.status"),
            tenant_realm_id=_read_string(job_obj.get("tenant_realm_id"), "job.tenant_realm_id"),
            disclosure_tier=_read_string(job_obj.get("disclosure_tier"), "job.disclosure_tier"),
            created_at=str(created_at) if isinstance(created_at, str) else "",
            expires_at=_read_string(job_obj.get("expires_at"), "job.expires_at"),
            error=str(job_obj.get("error") or ""),
            manifest_sha256=str(job_obj.get("manifest_sha256") or ""),
            bundle_sha256=str(job_obj.get("bundle_sha256") or ""),
            download_token=str(download_token).strip() if download_token else None,
            bundle_size_bytes=int(bundle_size)
            if isinstance(bundle_size, (int, float)) and float(bundle_size).is_integer()
            else None,
            download_token_expires=str(download_token_expires).strip()
            if isinstance(download_token_expires, str) and download_token_expires.strip()
            else None,
            download_path=str(download_path).strip()
            if isinstance(download_path, str) and download_path.strip()
            else None,
        )
    )

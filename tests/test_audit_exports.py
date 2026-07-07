from __future__ import annotations

from typing import Any

import pytest

from paybond_kit.audit.exports import PaybondAuditExports
from paybond_kit.audit.verify import verify_audit_manifest
from paybond_kit.audit.wire import parse_audit_export_job_get, parse_audit_export_list
from paybond_kit.mcp_policy import parse_mcp_tool_policy, tool_allowed_by_policy


class _FakeGateway:
    def __init__(self) -> None:
        self.paths: list[str] = []
        self.post_bodies: list[dict[str, Any]] = []

    async def get_json(self, path: str) -> dict[str, Any]:
        self.paths.append(path)
        if path.startswith("/v1/compliance/audit-exports?"):
            return {
                "tenant_realm_id": "realm-1",
                "jobs": [
                    {
                        "id": "job-1",
                        "status": "ready",
                        "disclosure_tier": "standard",
                        "created_at": "2026-01-01T00:00:00Z",
                        "expires_at": "2026-02-01T00:00:00Z",
                        "manifest_sha256": "",
                        "bundle_sha256": "",
                        "bundle_size_bytes": 1,
                    }
                ],
                "next_cursor": "cursor-2",
            }
        if path.endswith("?issue_download=1"):
            return {
                "job": {
                    "id": "job-1",
                    "status": "ready",
                    "tenant_realm_id": "realm-1",
                    "disclosure_tier": "standard",
                    "created_at": "2026-01-01T00:00:00Z",
                    "expires_at": "2026-02-01T00:00:00Z",
                    "error": "",
                    "manifest_sha256": "",
                    "bundle_sha256": "",
                    "download_token": "tok",
                }
            }
        raise AssertionError(path)

    async def post_json(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        self.paths.append(path)
        self.post_bodies.append(body)
        return {
            "job": {
                "id": "job-new",
                "status": "ready",
                "tenant_realm_id": "realm-1",
                "disclosure_tier": body.get("disclosure_tier", "standard"),
                "expires_at": "2026-02-01T00:00:00Z",
                "manifest_sha256": "abc",
                "bundle_sha256": "def",
                "bundle_size_bytes": 1024,
                "download_token": "tok",
                "download_path": "/v1/compliance/audit-exports/job-new/bundle",
            }
        }

    async def delete_json(self, path: str) -> dict[str, Any]:
        self.paths.append(path)
        return {}


@pytest.mark.asyncio
async def test_paybond_audit_exports_create() -> None:
    gateway = _FakeGateway()
    exports = PaybondAuditExports.from_gateway(gateway)
    body = await exports.create(
        filter={
            "time_start": "2026-01-01T00:00:00Z",
            "time_end": "2026-01-31T23:59:59Z",
            "includes": ["signal", "disputes"],
        },
        disclosure_tier="standard",
        retention_hours=168,
    )
    assert body.job.id == "job-new"
    assert body.job.bundle_size_bytes == 1024
    assert gateway.post_bodies[0] == {
        "filter": {
            "time_start": "2026-01-01T00:00:00Z",
            "time_end": "2026-01-31T23:59:59Z",
            "includes": ["signal", "disputes"],
        },
        "disclosure_tier": "standard",
        "retention_hours": 168,
    }


@pytest.mark.asyncio
async def test_paybond_audit_exports_list_and_get() -> None:
    gateway = _FakeGateway()
    exports = PaybondAuditExports.from_gateway(gateway)
    page = await exports.list(limit=10)
    assert page.tenant_realm_id == "realm-1"
    assert page.jobs[0].id == "job-1"
    assert page.next_cursor == "cursor-2"
    body = await exports.get("job-1", issue_download=True)
    assert body.job.download_token == "tok"
    deleted = await exports.delete("job-1")
    assert deleted["deleted"] is True


@pytest.mark.asyncio
async def test_paybond_audit_exports_verify_manifest_object() -> None:
    exports = PaybondAuditExports.from_gateway(_FakeGateway())
    result = await exports.verify(
        {
            "schema_version": 1,
            "kind": "paybond.audit_export_manifest_v1",
            "tenant_realm_id": "realm-1",
            "job_id": "job-1",
            "signed_payload_sha256_hex": "00",
        }
    )
    assert result["verified"] is False
    assert result["job_id"] == "job-1"


def test_audit_export_wire_parsers() -> None:
    page = parse_audit_export_list(
        {
            "tenant_realm_id": "realm-1",
            "exports": [
                {
                    "job_id": "job-2",
                    "status": "pending",
                    "disclosure_tier": "extended",
                    "created_at": "2026-01-02T00:00:00Z",
                    "expires_at": "2026-02-02T00:00:00Z",
                    "bundle_size_bytes": 0,
                }
            ],
        }
    )
    assert page.jobs[0].id == "job-2"
    body = parse_audit_export_job_get(
        {
            "job": {
                "id": "job-3",
                "status": "ready",
                "tenant_realm_id": "realm-1",
                "disclosure_tier": "standard",
                "created_at": "2026-01-03T00:00:00Z",
                "expires_at": "2026-02-03T00:00:00Z",
            }
        }
    )
    assert body.job.id == "job-3"
    assert verify_audit_manifest({"signed_payload_sha256_hex": "00"}) is False


def test_readonly_mcp_policy_allows_audit_export_tools() -> None:
    config = parse_mcp_tool_policy("readonly")
    assert tool_allowed_by_policy(
        "paybond_list_audit_exports",
        {"readOnlyHint": True},
        config,
    )
    assert tool_allowed_by_policy(
        "paybond_get_audit_export",
        {"readOnlyHint": True},
        config,
    )

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import httpx
import pytest
import respx

from paybond_kit.audit.exports import PaybondAudit, PaybondAuditExports
from paybond_kit.paybond import Paybond
from paybond_kit.signal import GatewaySignalClient
from paybond_kit.sync import PaybondSync, _run_async


class _FakeAuditGateway:
    def __init__(self) -> None:
        self.paths: list[str] = []

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

    async def post_json(self, path: str, body: Mapping[str, Any]) -> dict[str, Any]:
        raise AssertionError(f"unexpected post: {path}")

    async def delete_json(self, path: str) -> dict[str, Any]:
        raise AssertionError(f"unexpected delete: {path}")


@dataclass
class _NoopAsyncClient:
    async def aclose(self) -> None:
        return None


def _paybond_with_audit_exports(exports: PaybondAuditExports) -> Paybond:
    return Paybond(
        harbor=_NoopAsyncClient(),  # type: ignore[arg-type]
        guardrails=_NoopAsyncClient(),  # type: ignore[arg-type]
        signal=_NoopAsyncClient(),  # type: ignore[arg-type]
        fraud=_NoopAsyncClient(),  # type: ignore[arg-type]
        a2a=_NoopAsyncClient(),  # type: ignore[arg-type]
        protocol=_NoopAsyncClient(),  # type: ignore[arg-type]
        intents=_NoopAsyncClient(),  # type: ignore[arg-type]
        audit=PaybondAudit(exports=exports),
    )


def test_paybond_sync_audit_exports_list_and_get() -> None:
    gateway = _FakeAuditGateway()
    exports = PaybondAuditExports.from_gateway(gateway)
    sync = PaybondSync(_paybond_with_audit_exports(exports))

    page = sync.audit_exports_list(limit=10)
    assert page.tenant_realm_id == "realm-1"
    assert page.jobs[0].id == "job-1"
    assert page.next_cursor == "cursor-2"

    body = sync.audit_exports_get("job-1", issue_download=True)
    assert body.job.download_token == "tok"


def test_paybond_sync_audit_verify_manifest_is_local() -> None:
    gateway = _FakeAuditGateway()
    exports = PaybondAuditExports.from_gateway(gateway)
    sync = PaybondSync(_paybond_with_audit_exports(exports))

    assert sync.audit_verify_manifest(
        {
            "schema_version": 1,
            "kind": "paybond.audit_export_manifest_v1",
            "tenant_realm_id": "realm-1",
            "job_id": "job-1",
            "signed_payload_sha256_hex": "00",
        }
    ) is False


@respx.mock
def test_paybond_sync_get_reputation_receipt() -> None:
    respx.get("https://gateway.test/reputation/did%3Aexample%3Aoperator").mock(
        return_value=httpx.Response(
            200,
            json={
                "receipt": {
                    "tenant_id": "tenant-a",
                    "operator_did": "did:example:operator",
                    "score": 0.9,
                }
            },
        )
    )
    signal = GatewaySignalClient(
        "https://gateway.test",
        "tenant-a",
        static_gateway_bearer_token="paybond_sk_" + "a" * 32 + "_" + "b" * 64,
    )
    paybond = _paybond_with_audit_exports(
        PaybondAuditExports.from_gateway(_FakeAuditGateway())
    )
    paybond.signal = signal  # type: ignore[assignment]
    sync = PaybondSync(paybond)

    receipt = sync.get_reputation_receipt("did:example:operator")
    assert receipt is not None
    assert receipt["receipt"].get("operator_did") == "did:example:operator"


@pytest.mark.asyncio
async def test_run_async_works_when_loop_is_already_running() -> None:
    async def _returns_value() -> str:
        return "ok"

    assert _run_async(_returns_value()) == "ok"


def test_run_async_without_running_loop() -> None:
    async def _returns_value() -> int:
        return 42

    assert _run_async(_returns_value()) == 42

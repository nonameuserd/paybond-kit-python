"""In-process offline Gateway mock for `paybond dev --offline`."""

from __future__ import annotations

import json
import os
import re
from typing import Any

from paybond_kit.dev.x402_fund_mock import X402FundStateMachine

_HARBOR_FUND_PATH = re.compile(r"^/harbor/intents/([^/]+)/fund$")

OFFLINE_DEV_INTENT_ID = "00000000-0000-4000-8000-000000000001"
OFFLINE_DEV_TENANT_ID = "tenant-dev-offline"

OFFLINE_SANDBOX_API_KEY = (
    "paybond_sk_sandbox_0123456789abcdef0123456789abcdef_"
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

LIVE_API_KEY_PREFIX = "paybond_sk_live_"


def is_production_api_key(api_key: str) -> bool:
    """Return True when ``api_key`` is a production (``paybond_sk_live_…``) service-account key."""
    return api_key.startswith(LIVE_API_KEY_PREFIX)

DEV_WIREMOCK_DEFAULT_PORT = 18089
DEV_WIREMOCK_CONTAINER_NAME = "paybond-dev-wiremock"


class _FakeResponse:
    def __init__(self, payload: dict[str, Any], status_code: int = 200) -> None:
        self._payload = payload
        self.status_code = status_code
        self.text = json.dumps(payload)

    def json(self) -> dict[str, Any]:
        return self._payload


def _parse_harbor_fund_intent_id(url: str) -> str | None:
    try:
        from urllib.parse import urlparse

        match = _HARBOR_FUND_PATH.match(urlparse(url).path)
        return match.group(1) if match else None
    except Exception:  # noqa: BLE001
        return None


def create_offline_dev_gateway_transport(
    *,
    allow_verify: bool = True,
    deny_message: str = "spend denied",
) -> Any:
    """Return an httpx transport that stubs Gateway routes for local dev smoke."""

    import httpx

    x402_fund_state = X402FundStateMachine()

    class OfflineDevTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:  # noqa: N802
            url = str(request.url)
            body: dict[str, Any] = {}
            if request.content:
                body = json.loads(request.content.decode("utf-8"))

            if request.method.upper() == "POST":
                harbor_fund_intent_id = _parse_harbor_fund_intent_id(url)
                if harbor_fund_intent_id is not None:
                    payment_signature = request.headers.get("payment-signature")
                    mock = x402_fund_state.next(
                        harbor_fund_intent_id,
                        OFFLINE_DEV_TENANT_ID,
                        payment_signature,
                    )
                    if mock is not None:
                        return httpx.Response(mock.status, json=mock.body, headers=mock.headers)
                    return httpx.Response(404, json={})

            if url.endswith("/v1/auth/principal"):
                payload = {
                    "tenant_id": OFFLINE_DEV_TENANT_ID,
                    "tenant_uuid": "550e8400-e29b-41d4-a716-446655440000",
                    "environment": "sandbox",
                    "service_account_role": "operator",
                }
            elif url.endswith("/v1/sandbox/guardrails/bootstrap"):
                payload = {
                    "tenant_id": OFFLINE_DEV_TENANT_ID,
                    "intent_id": OFFLINE_DEV_INTENT_ID,
                    "capability_token": "cap-dev-offline-1",
                    "operation": body.get("operation"),
                    "requested_spend_cents": body.get("requested_spend_cents"),
                    "sandbox_lifecycle_status": "funded",
                }
            elif url.endswith("/verify"):
                if not allow_verify:
                    payload = {
                        "allow": False,
                        "tenant": OFFLINE_DEV_TENANT_ID,
                        "intent_id": OFFLINE_DEV_INTENT_ID,
                        "audit_id": "audit-deny",
                        "decision_id": "decision-deny",
                        "message": deny_message,
                    }
                else:
                    payload = {
                        "allow": True,
                        "tenant": OFFLINE_DEV_TENANT_ID,
                        "intent_id": OFFLINE_DEV_INTENT_ID,
                        "audit_id": "00000000-0000-4000-8000-000000000002",
                        "decision_id": "00000000-0000-4000-8000-000000000003",
                    }
            elif url.endswith("/v1/spend/preflight"):
                payload = {
                    "classification": "allow",
                    "outcome": "allow",
                    "reason_codes": [],
                    "remaining_cents": 100000,
                    "spend_scope": {"scope_type": "tenant", "scope_key": ""},
                    "policy_version": 1,
                    "explanation": "Spend is allowed under the current policy.",
                }
            elif url.endswith(f"/v1/sandbox/guardrails/{OFFLINE_DEV_INTENT_ID}/evidence"):
                payload = {
                    "tenant_id": OFFLINE_DEV_TENANT_ID,
                    "intent_id": OFFLINE_DEV_INTENT_ID,
                    "operation": body.get("operation", "paid-tool"),
                    "requested_spend_cents": body.get("requested_spend_cents", 100),
                    "sandbox_lifecycle_status": "released",
                    "predicate_passed": True,
                    "settlement_mode": "simulated",
                }
            elif "/v1/spend/decisions/" in url and url.endswith("/complete"):
                payload = {"settlement_mode": "simulated"}
            else:
                payload = {}

            status_code = 200 if payload else 404
            fake = _FakeResponse(payload, status_code=status_code)
            return httpx.Response(status_code=fake.status_code, json=fake.json())

    return OfflineDevTransport()


def activate_offline_dev_mode() -> Any:
    """Apply offline dev credentials; returns a context manager-like restore handle."""

    previous_api_key = os.environ.get("PAYBOND_API_KEY")
    trimmed_previous = (previous_api_key or "").strip()
    if trimmed_previous and is_production_api_key(trimmed_previous):
        raise RuntimeError(
            "offline dev mode cannot be used with production API keys (paybond_sk_live_...); "
            "unset PAYBOND_API_KEY or use a sandbox key"
        )

    class _Restore:
        def restore(self) -> None:
            if previous_api_key is None:
                os.environ.pop("PAYBOND_API_KEY", None)
            else:
                os.environ["PAYBOND_API_KEY"] = previous_api_key

    os.environ["PAYBOND_API_KEY"] = OFFLINE_SANDBOX_API_KEY
    return _Restore()


def offline_dev_http_context() -> Any:
    """Patch httpx and credentials for one offline dev smoke/loop run."""

    from contextlib import contextmanager
    from unittest.mock import patch

    import httpx

    x402_fund_state = X402FundStateMachine()

    @contextmanager
    def _context() -> Any:
        async def fake_request(self: Any, method: str, url: str, **kwargs: Any) -> _FakeResponse:  # noqa: ARG001
            body: dict[str, Any] = kwargs.get("json") or {}
            headers: dict[str, str] = kwargs.get("headers") or {}
            if method.upper() == "POST":
                harbor_fund_intent_id = _parse_harbor_fund_intent_id(url)
                if harbor_fund_intent_id is not None:
                    payment_signature = headers.get("payment-signature")
                    mock = x402_fund_state.next(
                        harbor_fund_intent_id,
                        OFFLINE_DEV_TENANT_ID,
                        payment_signature,
                    )
                    if mock is not None:
                        return _FakeResponse(mock.body, status_code=mock.status)
                    return _FakeResponse({}, status_code=404)
            if url.endswith("/v1/auth/principal"):
                payload = {
                    "tenant_id": OFFLINE_DEV_TENANT_ID,
                    "tenant_uuid": "550e8400-e29b-41d4-a716-446655440000",
                    "environment": "sandbox",
                    "service_account_role": "operator",
                }
            elif url.endswith("/v1/sandbox/guardrails/bootstrap"):
                payload = {
                    "tenant_id": OFFLINE_DEV_TENANT_ID,
                    "intent_id": OFFLINE_DEV_INTENT_ID,
                    "capability_token": "cap-dev-offline-1",
                    "operation": body.get("operation"),
                    "requested_spend_cents": body.get("requested_spend_cents"),
                    "sandbox_lifecycle_status": "funded",
                }
            elif url.endswith("/verify"):
                payload = {
                    "allow": True,
                    "tenant": OFFLINE_DEV_TENANT_ID,
                    "intent_id": OFFLINE_DEV_INTENT_ID,
                    "audit_id": "00000000-0000-4000-8000-000000000002",
                    "decision_id": "00000000-0000-4000-8000-000000000003",
                }
            elif url.endswith("/v1/spend/preflight"):
                payload = {
                    "classification": "allow",
                    "outcome": "allow",
                    "reason_codes": [],
                    "remaining_cents": 100000,
                    "spend_scope": {"scope_type": "tenant", "scope_key": ""},
                    "policy_version": 1,
                    "explanation": "Spend is allowed under the current policy.",
                }
            elif url.endswith(f"/v1/sandbox/guardrails/{OFFLINE_DEV_INTENT_ID}/evidence"):
                payload = {
                    "tenant_id": OFFLINE_DEV_TENANT_ID,
                    "intent_id": OFFLINE_DEV_INTENT_ID,
                    "operation": body.get("operation", "paid-tool"),
                    "requested_spend_cents": body.get("requested_spend_cents", 100),
                    "sandbox_lifecycle_status": "released",
                    "predicate_passed": True,
                    "settlement_mode": "simulated",
                }
            elif "/v1/spend/decisions/" in url and url.endswith("/complete"):
                payload = {"settlement_mode": "simulated"}
            else:
                return _FakeResponse({}, status_code=404)
            return _FakeResponse(payload)

        restore = activate_offline_dev_mode()
        with patch.object(httpx.AsyncClient, "request", fake_request):
            try:
                yield
            finally:
                restore.restore()

    return _context()

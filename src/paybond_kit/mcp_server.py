"""Paybond MCP server for tenant-bound internal runtimes and orchestrators."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass, is_dataclass
from functools import wraps
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any
from urllib.parse import quote, urlencode, urljoin
from uuid import UUID

import httpx

from paybond_kit.credentials import DEFAULT_PAYBOND_GATEWAY_BASE_URL, normalize_gateway_base_url
from paybond_kit.gateway_retry import httpx_with_gateway_retries
from paybond_kit.mcp_capability_token_cache import (
    McpCapabilityTokenCache,
    McpCapabilityTokenCacheConfig,
    mcp_tool_stores_capability_token,
    parse_mcp_capability_token_cache_config,
)
from paybond_kit.mcp_evidence_policy import (
    MCP_EVIDENCE_POLICY_ENV,
    McpEvidencePolicy,
    McpEvidenceValidationGate,
    completion_evidence_validation_ok,
    extract_harbor_evidence_validation_input,
    extract_sandbox_guardrail_validation_input,
    parse_mcp_evidence_policy,
)
from paybond_kit.mcp_policy import (
    MCP_TOOL_ALLOWLIST_ENV,
    MCP_TOOL_POLICY_ENV,
    McpToolPolicyConfig,
    merge_mcp_tool_policy,
    parse_mcp_tool_allowlist,
    parse_mcp_tool_policy,
    resolve_mcp_tool_policy,
    tool_allowed_by_policy,
)
from paybond_kit.mcp_policy_reload import (
    McpPolicyReloadConfig,
    McpPolicyReloadGate,
    McpPolicySpendGateInput,
    create_mcp_policy_gateway_adapter,
    parse_mcp_policy_reload_config,
)
from paybond_kit.fraud import GatewayFraudClient
from paybond_kit.mcp_receipt_resource import (
    MCP_AGENT_RECEIPT_RESOURCE_MIME_TYPE,
    agent_receipt_resource_uri,
    parse_agent_receipt_resource_uri,
)
from paybond_kit.harbor import TenantBindingError
from paybond_kit.signal import GatewaySignalClient

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Mapping


DEFAULT_PRINCIPAL_PATH = "/v1/auth/principal"
DEFAULT_RECOGNITION_VERIFIER_ID = "paybond-gateway"
DEFAULT_ENV_FILE = ".env.local"

logger = logging.getLogger(__name__)


def _read_env_file_value(env_file: str, key: str) -> str:
    try:
        body = Path(env_file).read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""
    prefix = f"{key}="
    export_prefix = f"export {key}="
    for raw_line in body.splitlines():
        line = raw_line.strip()
        if line.startswith(export_prefix):
            value = line[len(export_prefix):].strip()
        elif line.startswith(prefix):
            value = line[len(prefix):].strip()
        else:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        return value.strip()
    return ""


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


def _read_intent_allowed_tools(intent: dict[str, Any]) -> list[str]:
    raw = intent.get("allowed_tools")
    if not isinstance(raw, list):
        return []
    return [entry.strip() for entry in raw if isinstance(entry, str) and entry.strip()]


@dataclass(frozen=True)
class PaybondMCPSettings:
    """Environment-backed configuration for the MCP server."""

    api_key: str
    gateway_base_url: str = DEFAULT_PAYBOND_GATEWAY_BASE_URL
    principal_path: str = DEFAULT_PRINCIPAL_PATH
    max_retries: int = 3
    tool_policy: McpToolPolicyConfig = McpToolPolicyConfig()
    evidence_policy: McpEvidencePolicy = "strict"
    policy_reload: McpPolicyReloadConfig | None = None
    capability_token_cache: McpCapabilityTokenCacheConfig = McpCapabilityTokenCacheConfig()

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> PaybondMCPSettings:
        import os

        values = env or os.environ
        env_file = values.get("PAYBOND_ENV_FILE", "").strip() or DEFAULT_ENV_FILE
        api_key = values.get("PAYBOND_API_KEY", "").strip() or _read_env_file_value(env_file, "PAYBOND_API_KEY")
        gateway_base_url = normalize_gateway_base_url(
            values.get("PAYBOND_GATEWAY_URL", "").strip()
            or values.get("PAYBOND_GATEWAY_BASE_URL", "").strip()
            or _read_env_file_value(env_file, "PAYBOND_GATEWAY_URL")
            or _read_env_file_value(env_file, "PAYBOND_GATEWAY_BASE_URL")
            or DEFAULT_PAYBOND_GATEWAY_BASE_URL
        )
        principal_path = values.get("PAYBOND_PRINCIPAL_PATH", "").strip() or DEFAULT_PRINCIPAL_PATH
        max_retries_raw = values.get("PAYBOND_MCP_MAX_RETRIES", "").strip()
        tool_policy = resolve_mcp_tool_policy(
            merge_mcp_tool_policy(
                parse_mcp_tool_policy(values.get(MCP_TOOL_POLICY_ENV, "").strip() or None),
                allowlist=parse_mcp_tool_allowlist(values.get(MCP_TOOL_ALLOWLIST_ENV, "").strip() or None) or None,
            )
        )
        evidence_policy = parse_mcp_evidence_policy(values.get(MCP_EVIDENCE_POLICY_ENV, "").strip() or None)
        policy_reload = parse_mcp_policy_reload_config(dict(values))
        capability_token_cache = parse_mcp_capability_token_cache_config(values)

        if not api_key:
            raise SystemExit("PAYBOND_API_KEY is required; run paybond-kit-login or configure your MCP host environment")

        max_retries = 3
        if max_retries_raw:
            try:
                max_retries = max(1, int(max_retries_raw))
            except ValueError as exc:
                raise SystemExit("PAYBOND_MCP_MAX_RETRIES must be an integer") from exc

        return cls(
            gateway_base_url=gateway_base_url,
            api_key=api_key,
            principal_path=principal_path,
            max_retries=max_retries,
            tool_policy=tool_policy,
            evidence_policy=evidence_policy,
            policy_reload=policy_reload,
            capability_token_cache=capability_token_cache,
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
        self._base = normalize_gateway_base_url(gateway_base_url) + "/"
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

        response = await httpx_with_gateway_retries(
            lambda: self._client.request(
                method,
                url,
                headers=headers,
                json=payload,
            ),
            max_retries=self._max_retries,
        )
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
        self._capability_token_cache = McpCapabilityTokenCache(settings.capability_token_cache)
        self._evidence_gate = McpEvidenceValidationGate(policy=settings.evidence_policy)
        self._policy_reload_config = settings.policy_reload
        self._opened_policy_gate: McpPolicyReloadGate | None = None
        self._policy_gate_lock = asyncio.Lock()

    async def _policy_gate(self) -> McpPolicyReloadGate | None:
        if self._policy_reload_config is None:
            return None
        async with self._policy_gate_lock:
            if self._opened_policy_gate is None:
                self._opened_policy_gate = await McpPolicyReloadGate.open(
                    self._policy_reload_config,
                    gateway=create_mcp_policy_gateway_adapter(self._gateway),
                )
            return self._opened_policy_gate

    async def begin_policy_tool_call(self) -> None:
        gate = await self._policy_gate()
        if gate is not None:
            gate.begin_tool_call()

    async def end_policy_tool_call(self) -> None:
        gate = await self._policy_gate()
        if gate is not None:
            gate.end_tool_call()

    def stop_policy_reload(self) -> None:
        if self._opened_policy_gate is not None:
            self._opened_policy_gate.stop()
            self._opened_policy_gate = None

    async def authorize_agent_spend(
        self,
        *,
        intent_id: UUID,
        token: str,
        operation: str,
        requested_spend_cents: int | None = None,
        tool_name: str | None = None,
    ) -> dict[str, Any]:
        gate = await self._policy_gate()
        policy_digest: str | None = None
        resolved_operation = operation
        resolved_spend = 0 if requested_spend_cents is None else int(requested_spend_cents)

        if gate is not None:
            intent = await self.get_intent(intent_id)
            allowed_tools = _read_intent_allowed_tools(intent)
            gated = gate.assert_spend_gate(
                input=McpPolicySpendGateInput(
                    tool_name=tool_name,
                    operation=operation,
                    allowed_tools=allowed_tools,
                    requested_spend_cents=requested_spend_cents,
                ),
            )
            resolved_operation = gated.operation
            resolved_spend = gated.requested_spend_cents
            policy_digest = gated.policy_digest

        body = await self.verify_capability(
            intent_id=intent_id,
            token=token,
            operation=resolved_operation,
            requested_spend_cents=resolved_spend,
        )
        if policy_digest:
            body["policy_digest"] = policy_digest
        return body

    def validate_completion_evidence(
        self,
        *,
        preset_id: str,
        vendor_payload: dict[str, Any] | None = None,
        canonical_payload: dict[str, Any] | None = None,
        frozen_vendor_api_version: str | None = None,
        frozen_vendor_schema_digest_hex: str | None = None,
        frozen_canonical_schema_digest_hex: str | None = None,
    ) -> dict[str, Any]:
        report = self._evidence_gate.validate_and_record(
            preset_id=preset_id,
            vendor_payload=vendor_payload,
            canonical_payload=canonical_payload,
            frozen_vendor_api_version=frozen_vendor_api_version,
            frozen_vendor_schema_digest_hex=frozen_vendor_schema_digest_hex,
            frozen_canonical_schema_digest_hex=frozen_canonical_schema_digest_hex,
        )
        return {
            **report,
            "ok": completion_evidence_validation_ok(report),
        }

    def _require_evidence_validation(
        self,
        *,
        preset_id: str,
        vendor_payload: dict[str, Any] | None = None,
        canonical_payload: dict[str, Any] | None = None,
    ) -> None:
        self._evidence_gate.require_pass(
            preset_id=preset_id,
            vendor_payload=vendor_payload,
            canonical_payload=canonical_payload,
        )

    def _store_capability_token(self, intent_id: str, token: str) -> None:
        self._capability_token_cache.store(intent_id, token)

    async def resolve_capability_token(self, intent_id: str, token: str | None = None) -> str:
        explicit = (token or "").strip()
        if explicit:
            return explicit
        stored = self._capability_token_cache.resolve(str(intent_id))
        if stored:
            return stored
        raise ValueError(
            f"capability token unavailable or expired for intent {intent_id}; "
            "create or bootstrap a funded intent first"
        )

    def prepare_tool_response(self, body: dict[str, Any], *, tool_name: str) -> dict[str, Any]:
        from paybond_kit.cli.redact import redact_sensitive_fields

        intent_id = str(body.get("intent_id", "")).strip()
        token = body.get("capability_token")
        if (
            mcp_tool_stores_capability_token(tool_name)
            and intent_id
            and isinstance(token, str)
            and token.strip()
        ):
            self._store_capability_token(intent_id, token)
        redacted = redact_sensitive_fields(body)
        return redacted if isinstance(redacted, dict) else body

    async def aclose(self) -> None:
        self.stop_policy_reload()
        if self._signal is not None:
            await self._signal.aclose()
        if self._fraud is not None:
            await self._fraud.aclose()
        await self._gateway.aclose()

    async def preload_principal(self) -> None:
        """Resolve and cache the gateway principal during MCP server startup."""
        await self.principal()

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

    async def list_audit_exports(
        self,
        *,
        limit: int = 50,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, str] = {
            "limit": str(max(1, min(int(limit), 200))),
        }
        if cursor and cursor.strip():
            params["cursor"] = cursor.strip()
        query = urlencode(params)
        return await self._gateway.get_json(f"/v1/compliance/audit-exports?{query}")

    async def get_audit_export(
        self,
        job_id: str,
        *,
        issue_download: bool = False,
    ) -> dict[str, Any]:
        query = "?issue_download=1" if issue_download else ""
        return await self._gateway.get_json(
            f"/v1/compliance/audit-exports/{quote(job_id, safe='')}{query}"
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

    async def spend_preflight(
        self,
        *,
        intent_id: UUID,
        operation: str | None = None,
        requested_spend_cents: int | None = None,
        vendor_id: str | None = None,
        tool_name: str | None = None,
        task_id: str | None = None,
        workflow_id: str | None = None,
        tool_call_id: str | None = None,
        currency: str | None = None,
        agent_subject: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        """Side-effect-free spend policy dry-run via POST /v1/spend/preflight."""

        payload: dict[str, Any] = {
            "intent_id": str(intent_id),
            "operation": (operation or "").strip() or "*",
            "requested_spend_cents": 0 if requested_spend_cents is None else int(requested_spend_cents),
        }
        if vendor_id and vendor_id.strip():
            payload["vendor_id"] = vendor_id.strip()
        if tool_name and tool_name.strip():
            payload["tool_name"] = tool_name.strip()
        if task_id and task_id.strip():
            payload["task_id"] = task_id.strip()
        if workflow_id and workflow_id.strip():
            payload["workflow_id"] = workflow_id.strip()
        if tool_call_id and tool_call_id.strip():
            payload["tool_call_id"] = tool_call_id.strip()
        if currency and currency.strip():
            payload["currency"] = currency.strip()
        if agent_subject and agent_subject.strip():
            payload["agent_subject"] = agent_subject.strip()
        if approval_token and approval_token.strip():
            payload["approval_token"] = approval_token.strip()
        return await self._gateway.post_json(
            "/v1/spend/preflight",
            payload,
            extra_headers={"x-tenant-id": await self.tenant_id()},
        )

    async def get_budget_remaining(
        self,
        *,
        intent_id: UUID,
        operation: str | None = None,
        requested_spend_cents: int | None = None,
        vendor_id: str | None = None,
        tool_name: str | None = None,
        task_id: str | None = None,
        workflow_id: str | None = None,
        tool_call_id: str | None = None,
        currency: str | None = None,
        agent_subject: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        body = await self.spend_preflight(
            intent_id=intent_id,
            operation=operation,
            requested_spend_cents=requested_spend_cents,
            vendor_id=vendor_id,
            tool_name=tool_name,
            task_id=task_id,
            workflow_id=workflow_id,
            tool_call_id=tool_call_id,
            currency=currency,
            agent_subject=agent_subject,
            approval_token=approval_token,
        )
        return {
            "remaining_cents": body.get("remaining_cents"),
            "spend_scope": body.get("spend_scope"),
            "policy_version": body.get("policy_version"),
        }

    async def explain_policy(
        self,
        *,
        intent_id: UUID,
        operation: str | None = None,
        requested_spend_cents: int | None = None,
        vendor_id: str | None = None,
        tool_name: str | None = None,
        task_id: str | None = None,
        workflow_id: str | None = None,
        tool_call_id: str | None = None,
        currency: str | None = None,
        agent_subject: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        body = await self.spend_preflight(
            intent_id=intent_id,
            operation=operation,
            requested_spend_cents=requested_spend_cents,
            vendor_id=vendor_id,
            tool_name=tool_name,
            task_id=task_id,
            workflow_id=workflow_id,
            tool_call_id=tool_call_id,
            currency=currency,
            agent_subject=agent_subject,
            approval_token=approval_token,
        )
        raw_codes = body.get("reason_codes") or []
        reason_codes = [str(code) for code in raw_codes] if isinstance(raw_codes, list) else []
        outcome = _normalize_explain_policy_outcome(
            str(body.get("outcome", "")),
            str(body.get("classification", "")),
        )
        result: dict[str, Any] = {
            "outcome": outcome,
            "reason_codes": reason_codes,
            "explanation": str(body.get("explanation", "")),
            "remaining_cents": body.get("remaining_cents"),
        }
        if "approval_threshold_exceeded" in reason_codes or outcome == "approval_required":
            result["approval_threshold_exceeded"] = "approval_threshold_exceeded" in reason_codes
        return result

    async def bootstrap_sandbox_guardrail(
        self,
        *,
        operation: str,
        requested_spend_cents: int,
        currency: str | None = None,
        evidence_schema: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        expected_tenant = await self.tenant_id()
        payload: dict[str, Any] = {
            "operation": operation,
            "requested_spend_cents": int(requested_spend_cents),
        }
        if currency is not None and currency.strip():
            payload["currency"] = currency.strip()
        if evidence_schema is not None:
            payload["evidence_schema"] = dict(evidence_schema)
        if metadata is not None:
            payload["metadata"] = dict(metadata)
        body = await self._gateway.post_json(
            "/v1/sandbox/guardrails/bootstrap",
            payload,
            extra_headers=_idempotency_headers(idempotency_key),
        )
        _validate_sandbox_guardrail_response(
            body,
            expected_tenant=expected_tenant,
            require_capability_token=True,
        )
        return body

    async def submit_sandbox_guardrail_evidence(
        self,
        intent_id: UUID,
        *,
        payload: dict[str, Any] | None = None,
        artifacts: list[str] | None = None,
        operation: str | None = None,
        requested_spend_cents: int | None = None,
        metadata: dict[str, Any] | None = None,
        completion_preset_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        preset_id, vendor_payload, canonical_payload = extract_sandbox_guardrail_validation_input(
            payload=payload,
            completion_preset_id=completion_preset_id,
        )
        self._require_evidence_validation(
            preset_id=preset_id,
            vendor_payload=vendor_payload,
            canonical_payload=canonical_payload,
        )
        expected_tenant = await self.tenant_id()
        request_body: dict[str, Any] = {}
        if payload is not None:
            request_body["payload"] = dict(payload)
        if artifacts is not None:
            request_body["artifacts"] = list(artifacts)
        if operation is not None and operation.strip():
            request_body["operation"] = operation.strip()
        if requested_spend_cents is not None:
            request_body["requested_spend_cents"] = int(requested_spend_cents)
        if metadata is not None:
            request_body["metadata"] = dict(metadata)
        body = await self._gateway.post_json(
            f"/v1/sandbox/guardrails/{intent_id}/evidence",
            request_body,
            extra_headers=_idempotency_headers(idempotency_key),
        )
        _validate_sandbox_guardrail_response(body, expected_tenant=expected_tenant)
        echoed_intent = str(body.get("intent_id", "")).strip()
        if echoed_intent != str(intent_id):
            raise TenantBindingError(
                f"sandbox guardrail intent mismatch: requested={intent_id} gateway={echoed_intent!r}"
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
    ) -> dict[str, Any]:
        verifier = {
            "tenant_id": await self.tenant_id(),
            "verifier_id": DEFAULT_RECOGNITION_VERIFIER_ID,
        }
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

    async def get_agent_receipt_v1(self, receipt_id: str) -> dict[str, Any]:
        normalized = receipt_id.strip().lower()
        body = await self._gateway.get_json(
            f"/protocol/v2/agent-receipts/{quote(normalized, safe='')}",
            extra_headers={"x-tenant-id": await self.tenant_id()},
        )
        echoed_receipt = str(body.get("receipt_id", "")).strip().lower()
        if echoed_receipt != normalized:
            raise TenantBindingError(
                f"receipt mismatch: requested={normalized!r} gateway={echoed_receipt!r}"
            )
        await self._assert_tenant_echo(body, field="tenant_id")
        return body

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
        completion_preset_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        preset_id, vendor_payload, canonical_payload = extract_harbor_evidence_validation_input(
            body,
            completion_preset_id=completion_preset_id,
        )
        self._require_evidence_validation(
            preset_id=preset_id,
            vendor_payload=vendor_payload,
            canonical_payload=canonical_payload,
        )
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


def _mcp_output_object_schema(
    properties: dict[str, Any],
    required: list[str] | None = None,
) -> dict[str, Any]:
    schema: dict[str, Any] = {
        "type": "object",
        "properties": properties,
        "additionalProperties": True,
    }
    if required:
        schema["required"] = required
    return schema


_AUTHORIZE_SPEND_OUTPUT_PROPERTIES: dict[str, Any] = {
    "allow": {
        "type": "boolean",
        "description": "Whether the requested operation is allowed.",
    },
    "tenant": {
        "type": "string",
        "description": "Tenant echoed by the gateway.",
    },
    "intent_id": {
        "type": "string",
        "description": "Verified Harbor intent UUID.",
    },
    "audit_id": {
        "type": "string",
        "description": "Gateway audit identifier when available.",
    },
    "remaining_cents": {
        "type": "integer",
        "description": "Remaining spend budget in cents for the evaluated scope, when available.",
    },
    "reason_codes": {
        "type": "array",
        "items": {"type": "string"},
        "description": "Stable spend-policy reason codes from the authorization decision.",
    },
    "message": {
        "type": "string",
        "description": "Human-readable decision message when present.",
    },
    "decision_id": {
        "type": "string",
        "description": "Persisted spend decision identifier when authorization creates one.",
    },
    "approval_request_id": {
        "type": "string",
        "description": "Approval request identifier when human approval is required.",
    },
}


def _normalize_explain_policy_outcome(outcome: str, classification: str) -> str:
    normalized = outcome.strip().lower()
    if normalized in ("allow", "anomaly_observe"):
        return "allow"
    if normalized in ("approval_required", "anomaly_escalate"):
        return "approval_required"
    if normalized == "deny":
        return "deny"
    class_norm = classification.strip().lower()
    if class_norm == "allow":
        return "allow"
    if class_norm == "hold":
        return "approval_required"
    return "deny"


def _mcp_tool_selection_metadata(tool_annotations_cls: Any) -> dict[str, dict[str, Any]]:
    def read_only(title: str) -> Any:
        return tool_annotations_cls(
            title=title,
            readOnlyHint=True,
            openWorldHint=False,
        )

    def additive_mutation(title: str) -> Any:
        return tool_annotations_cls(
            title=title,
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=False,
            openWorldHint=True,
        )

    def live_mutation(title: str) -> Any:
        return tool_annotations_cls(
            title=title,
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=False,
            openWorldHint=True,
        )

    return {
        "paybond_get_principal": {
            "title": "Get Paybond Principal",
            "description": (
                "Use this when you need to confirm which tenant-bound service-account principal the "
                "configured PAYBOND_API_KEY authenticates as (tenant_id, subject, and roles). Call early "
                "as a prerequisite before Harbor escrow, Signal reads, or other tenant-scoped tools when "
                "tenant identity is unknown. Not required before every later call once tenant_id is "
                "already known from a prior principal response or host config. Do not use this when you "
                "need Harbor intent escrow detail; use paybond_get_intent instead when you have an "
                "intent_id. Do not use this for A2A discovery; use paybond_get_a2a_agent_card instead. "
                "Makes one read-only external GET to the gateway principal endpoint; idempotent identity "
                "lookup with no side effects (no mutations, spend reservations, escrow changes, or "
                "ledger writes); auth or gateway failures surface as tool errors."
            ),
            "annotations": read_only("Get Paybond Principal"),
            "output_schema": _mcp_output_object_schema(
                {
                    "tenant_id": {
                        "type": "string",
                        "description": "Tenant bound to the configured Paybond API key.",
                        "examples": ["tenant-a"],
                    },
                    "subject": {
                        "type": "string",
                        "description": (
                            "Service-account subject identifier echoed by the gateway for the "
                            "authenticated API key (example: service-account-1)."
                        ),
                        "examples": ["service-account-1"],
                    },
                    "roles": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "RBAC roles granted to this principal for the authenticated tenant "
                            '(example: ["operator"]).'
                        ),
                        "examples": [["operator"]],
                    },
                },
            ),
        },
        "paybond_verify_capability": {
            "title": "Verify Paybond Capability",
            "description": (
                "Use this when you need raw capability-token verification for one tenant-bound Harbor intent. "
                "Do not use this to create, fund, or modify intents; use paybond_authorize_agent_spend as "
                "the clearer gate before side-effecting agent tools."
            ),
            "annotations": additive_mutation("Verify Paybond Capability"),
            "output_schema": _mcp_output_object_schema(
                dict(_AUTHORIZE_SPEND_OUTPUT_PROPERTIES),
                ["tenant", "intent_id"],
            ),
        },
        "paybond_authorize_agent_spend": {
            "title": "Authorize Agent Spend",
            "description": (
                "Use this when an agent has an intent_id and capability_token and needs a tenant-bound spend "
                "gate before calling a side-effecting tool, paid API, vendor action, or settlement workflow. "
                "Do not use this for creating, funding, or changing intents; call paybond_create_spend_intent "
                "or paybond_fund_intent first when no funded capability token exists."
            ),
            "annotations": additive_mutation("Authorize Agent Spend"),
            "output_schema": _mcp_output_object_schema(
                dict(_AUTHORIZE_SPEND_OUTPUT_PROPERTIES),
                ["tenant", "intent_id"],
            ),
        },
        "paybond_get_budget_remaining": {
            "title": "Get Budget Remaining",
            "description": (
                "Use this when you need a read-only dry-run of remaining spend budget for a tenant-bound "
                "intent before authorizing a paid tool. Do not use this to authorize spend or create "
                "decisions; call paybond_authorize_agent_spend when you are ready to gate a side-effecting tool."
            ),
            "annotations": read_only("Get Budget Remaining"),
            "output_schema": _mcp_output_object_schema(
                {
                    "remaining_cents": {
                        "type": "integer",
                        "description": "Remaining spend budget in cents for the evaluated scope, when available.",
                    },
                    "spend_scope": {
                        "type": "object",
                        "description": "Spend scope used for the budget evaluation (scope_type and scope_key).",
                        "additionalProperties": True,
                    },
                    "policy_version": {
                        "type": "integer",
                        "description": "Active spend-control policy version when a policy is configured.",
                    },
                },
            ),
        },
        "paybond_explain_policy": {
            "title": "Explain Spend Policy",
            "description": (
                "Use this when you need a read-only explanation of whether a proposed spend would allow, "
                "require approval, or deny under the tenant spend-control policy. Do not use this to authorize "
                "spend or create approval requests; call paybond_authorize_agent_spend to persist a decision."
            ),
            "annotations": read_only("Explain Spend Policy"),
            "output_schema": _mcp_output_object_schema(
                {
                    "outcome": {
                        "type": "string",
                        "description": "Normalized policy outcome: allow, approval_required, or deny.",
                    },
                    "reason_codes": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Stable policy reason codes from the dry-run evaluation.",
                    },
                    "explanation": {
                        "type": "string",
                        "description": "Human-readable explanation derived from reason codes.",
                    },
                    "remaining_cents": {
                        "type": "integer",
                        "description": "Remaining spend budget in cents for the evaluated scope, when available.",
                    },
                    "approval_threshold_exceeded": {
                        "type": "boolean",
                        "description": (
                            "True when the dry-run indicates the request is at or above the approval threshold."
                        ),
                    },
                },
                ["outcome", "explanation"],
            ),
        },
        "paybond_bootstrap_sandbox_guardrail": {
            "title": "Bootstrap Sandbox Guardrail",
            "description": (
                "Use this when building or testing a first paid-tool integration and you need a sandbox-only "
                "guardrail intent with no live settlement rails. Do not use this for production live money "
                "movement or already-created Harbor intents."
            ),
            "annotations": additive_mutation("Bootstrap Sandbox Guardrail"),
            "output_schema": _mcp_output_object_schema(
                {
                    "tenant_id": {"type": "string"},
                    "intent_id": {"type": "string"},
                    "capability_token": {"type": "string"},
                    "operation": {"type": "string"},
                    "requested_spend_cents": {"type": "integer"},
                    "sandbox_lifecycle_status": {"type": "string"},
                    "settlement_rail": {"type": "string"},
                    "settlement_mode": {"type": "string"},
                },
                [
                    "tenant_id",
                    "intent_id",
                    "capability_token",
                    "operation",
                    "requested_spend_cents",
                    "sandbox_lifecycle_status",
                ],
            ),
        },
        "paybond_validate_completion_evidence": {
            "title": "Validate Completion Evidence",
            "description": (
                "Pre-validates vendor and canonical completion evidence against catalog JSON Schemas "
                "and preset forbidden_evidence_fields. Required before evidence submit tools when "
                "PAYBOND_MCP_EVIDENCE_POLICY=strict. Harbor remains authoritative at submit time."
            ),
            "annotations": read_only("Validate Completion Evidence"),
            "output_schema": _mcp_output_object_schema(
                {
                    "preset_id": {"type": "string"},
                    "ok": {"type": "boolean"},
                    "vendor_schema_ok": {"type": "boolean"},
                    "canonical_schema_ok": {"type": "boolean"},
                    "quality_fields_missing": {"type": "array", "items": {"type": "string"}},
                    "forbidden_fields_present": {"type": "array", "items": {"type": "string"}},
                    "pack_stale": {"type": "boolean"},
                    "drift_kinds": {"type": "array", "items": {"type": "string"}},
                },
                ["preset_id", "ok"],
            ),
        },
        "paybond_submit_sandbox_guardrail_evidence": {
            "title": "Submit Sandbox Guardrail Evidence",
            "description": (
                "Use this when a sandbox guardrail intent needs evidence to complete simulator settlement or "
                "predicate checks. Do not use this for live Harbor spend evidence; use "
                "paybond_submit_spend_evidence for production spend intents."
            ),
            "annotations": additive_mutation("Submit Sandbox Guardrail Evidence"),
            "output_schema": _mcp_output_object_schema(
                {
                    "tenant_id": {"type": "string"},
                    "intent_id": {"type": "string"},
                    "operation": {"type": "string"},
                    "requested_spend_cents": {"type": "integer"},
                    "sandbox_lifecycle_status": {"type": "string"},
                    "predicate_passed": {"type": "boolean"},
                    "payload_digest": {"type": "string"},
                },
                [
                    "tenant_id",
                    "intent_id",
                    "operation",
                    "requested_spend_cents",
                    "sandbox_lifecycle_status",
                ],
            ),
        },
        "paybond_list_intents": {
            "title": "List Harbor Intents",
            "annotations": read_only("List Harbor Intents"),
        },
        "paybond_get_intent": {
            "title": "Get Harbor Intent",
            "annotations": read_only("Get Harbor Intent"),
        },
        "paybond_list_audit_exports": {
            "title": "List Audit Exports",
            "annotations": read_only("List Audit Exports"),
        },
        "paybond_get_audit_export": {
            "title": "Get Audit Export",
            "annotations": read_only("Get Audit Export"),
        },
        "paybond_get_reputation_receipt": {
            "title": "Get Reputation Receipt",
            "description": (
                "Use this when you need the signed Signal reputation receipt for one known "
                "tenant-scoped operator DID (score, metrics, reason codes, and Ed25519 signing "
                "material under receipt). Requires PAYBOND_API_KEY with Signal analytics read "
                "access. Do not use this for tenant-wide aggregates—call "
                "paybond_get_portfolio_summary—or a portable signed operator list—call "
                "paybond_get_signed_portfolio_artifact—or one operator's fraud review posture—call "
                "paybond_get_fraud_assessment. Idempotent read with no side effects; returns null "
                "when no receipt exists for that operator and score_version."
            ),
            "annotations": read_only("Get Reputation Receipt"),
            "output_schema": _mcp_output_object_schema(
                {
                    "schema_version": {
                        "type": "integer",
                        "description": "Reputation receipt envelope schema version.",
                    },
                    "updated_at": {
                        "type": "string",
                        "description": (
                            "RFC3339 timestamp when the stored receipt row was last updated."
                        ),
                    },
                    "receipt": {
                        "type": "object",
                        "additionalProperties": True,
                        "description": (
                            "Signed Signal receipt for the operator (tenant_id, operator_did, "
                            "score_version, score, metrics, reason_codes, signing_algorithm, "
                            "message_digest_hex, signing_public_key_hex, signature_hex)."
                        ),
                        "examples": [
                            {
                                "tenant_id": "tenant-a",
                                "operator_did": "did:web:vendor.example#booker-agent",
                                "score_version": "1.0",
                                "score": 812,
                                "signature_hex": "ab" * 32,
                            },
                        ],
                    },
                },
            ),
        },
        "paybond_get_portfolio_summary": {
            "title": "Get Portfolio Summary",
            "description": (
                "Use this when you need a read-only, tenant-scoped Signal portfolio aggregate for the "
                "authenticated API key (operator_count, average_score, total_terminal_intents, "
                "total_receipted_volume_cents, operators_under_review, and checkpoint_last_ledger_seq). "
                "Requires PAYBOND_API_KEY with Signal analytics read access and the private-dashboards "
                "feature. Do not use this when you need a portable signed operator list for partner or "
                "verifier sharing—call paybond_get_signed_portfolio_artifact instead—or for one "
                "operator's signed receipt—call paybond_get_reputation_receipt. Idempotent read with "
                "no side effects; auth, RBAC, feature, or gateway failures surface as tool errors."
            ),
            "annotations": read_only("Get Portfolio Summary"),
            "output_schema": _mcp_output_object_schema(
                {
                    "schema_version": {
                        "type": "integer",
                        "description": "Portfolio summary schema version (currently 1).",
                    },
                    "tenant_id": {
                        "type": "string",
                        "description": (
                            "Tenant echoed by the gateway for the authenticated API key "
                            "(example: tenant-a)."
                        ),
                        "examples": ["tenant-a"],
                    },
                    "score_model_version": {
                        "type": "string",
                        "description": (
                            "Score model version used for the aggregate (echoes the requested "
                            "score_version or the gateway default 1.0)."
                        ),
                        "examples": ["1.0"],
                    },
                    "scoring_model": {
                        "type": "string",
                        "description": "Scoring model identifier used by Signal for this summary.",
                    },
                    "checkpoint_last_ledger_seq": {
                        "type": "integer",
                        "description": (
                            "Last ledger sequence included in the tenant Signal checkpoint."
                        ),
                    },
                    "operator_count": {
                        "type": "integer",
                        "description": (
                            "Number of operators with reputation data for this score model version."
                        ),
                    },
                    "average_score": {
                        "type": "number",
                        "description": (
                            "Average operator score across the tenant portfolio for this score "
                            "model version."
                        ),
                    },
                    "total_terminal_intents": {
                        "type": "integer",
                        "description": (
                            "Aggregate terminal Harbor intents across operators in the portfolio."
                        ),
                    },
                    "total_receipted_volume_cents": {
                        "type": "integer",
                        "description": (
                            "Aggregate receipted settlement volume in cents across the portfolio."
                        ),
                    },
                    "operators_under_review": {
                        "type": "integer",
                        "description": (
                            "Count of operators currently under Signal review for this score "
                            "model version."
                        ),
                    },
                },
            ),
        },
        "paybond_get_signed_portfolio_artifact": {
            "title": "Get Signed Portfolio Artifact",
            "description": (
                "Use this when you need a portable, tenant-scoped signed Signal portfolio snapshot "
                "(operator list plus Ed25519 signing material) for offline verifier checks or partner "
                "sharing—not a public leaderboard. Requires PAYBOND_API_KEY with Signal analytics read "
                "access. Omit score_version to use the gateway default current model (1.0). Do not use "
                "this for tenant-wide aggregates without signatures—call paybond_get_portfolio_summary—or "
                "for one operator's signed receipt—call paybond_get_reputation_receipt—or for one "
                "operator's fraud review posture—call paybond_get_fraud_assessment. Idempotent read with "
                "no side effects; auth, RBAC, feature, or gateway failures surface as tool errors."
            ),
            "annotations": read_only("Get Signed Portfolio Artifact"),
            "output_schema": _mcp_output_object_schema(
                {
                    "kind": {
                        "type": "string",
                        "description": (
                            "Artifact kind identifier (currently paybond.signal.portfolio_snapshot)."
                        ),
                        "examples": ["paybond.signal.portfolio_snapshot"],
                    },
                    "tenant_id": {
                        "type": "string",
                        "description": (
                            "Tenant echoed by the gateway for the authenticated API key "
                            "(example: tenant-a). Never invent tenant identifiers."
                        ),
                        "examples": ["tenant-a"],
                    },
                    "score_model_version": {
                        "type": "string",
                        "description": (
                            "Score model version used for the artifact (echoes the requested "
                            "score_version or the gateway default 1.0)."
                        ),
                        "examples": ["1.0"],
                    },
                    "checkpoint_last_ledger_seq": {
                        "type": "integer",
                        "description": (
                            "Last ledger sequence included in the tenant Signal checkpoint for "
                            "this artifact."
                        ),
                    },
                    "signature_hex": {
                        "type": "string",
                        "description": (
                            "Ed25519 signature hex over the canonical portfolio artifact payload."
                        ),
                    },
                },
            ),
        },
        "paybond_get_fraud_assessment": {
            "title": "Get Fraud Assessment",
            "description": (
                "Use this when you need the read-only fraud assessment and review posture for one "
                "known tenant-scoped operator DID (review state, fraud signals, and compact "
                "fraud_assessment). Example: look up operator_did=did:web:vendor.example#booker-agent "
                "(optionally score_version=1.0) before deciding whether to continue a spend workflow "
                "for that operator. Do not use this for tenant-wide fraud backtesting metrics—call "
                "paybond_get_fraud_metrics instead—or for Harbor intent escrow detail—call "
                "paybond_get_intent. Idempotent read; returns null when no assessment exists for "
                "that operator."
            ),
            "annotations": read_only("Get Fraud Assessment"),
            "output_schema": _mcp_output_object_schema(
                {
                    "tenant_id": {
                        "type": "string",
                        "description": (
                            "Tenant echoed by the gateway for the authenticated API key "
                            "(example: tenant-a)."
                        ),
                        "examples": ["tenant-a"],
                    },
                    "operator_did": {
                        "type": "string",
                        "description": (
                            "Operator DID echoed from the assessment response "
                            "(example: did:web:vendor.example#booker-agent)."
                        ),
                        "examples": ["did:web:vendor.example#booker-agent"],
                    },
                    "fraud_assessment": {
                        "type": "object",
                        "additionalProperties": True,
                        "description": (
                            "Compact fraud assessment for the operator (level, severity, "
                            "signal counts, summary). Example shape: "
                            '{"level":"high","highest_severity":"high","signal_count":1,'
                            '"summary":"level=high"}.'
                        ),
                        "examples": [
                            {
                                "level": "high",
                                "highest_severity": "high",
                                "signal_count": 1,
                                "summary": "level=high",
                            },
                        ],
                    },
                },
            ),
        },
        "paybond_get_fraud_metrics": {
            "title": "Get Fraud Metrics",
            "description": (
                "Use this when you need tenant-wide Signal fraud backtesting and monitoring metrics over a "
                "rolling window (flagged operators, severity counts, review outcomes, precision/"
                "false-positive rates, and backtest_summary). Requires PAYBOND_API_KEY with Signal "
                "analytics read access and the private-dashboards feature. Do not use this for one "
                "operator's fraud posture—call paybond_get_fraud_assessment instead—or for Harbor "
                "intent escrow detail—call paybond_get_intent. Idempotent read with no side effects; "
                "omit window to default to 24h; unsupported windows fail with HTTP 400 "
                '("window must be one of 24h, 7d, or 30d").'
            ),
            "annotations": read_only("Get Fraud Metrics"),
            "output_schema": _mcp_output_object_schema(
                {
                    "tenant_id": {
                        "type": "string",
                        "description": (
                            "Tenant echoed by the gateway for the authenticated API key "
                            "(example: tenant-a)."
                        ),
                        "examples": ["tenant-a"],
                    },
                    "score_model_version": {
                        "type": "string",
                        "description": (
                            "Score model version used for the metrics (echoes the requested "
                            "score_version or the gateway default 1.0)."
                        ),
                        "examples": ["1.0"],
                    },
                    "window": {
                        "type": "string",
                        "description": "Active metrics window label: 24h, 7d, or 30d.",
                        "examples": ["24h", "7d", "30d"],
                    },
                    "window_started_at": {
                        "type": "string",
                        "description": "RFC3339 start of the evaluated rolling window.",
                    },
                    "window_ended_at": {
                        "type": "string",
                        "description": "RFC3339 end of the evaluated rolling window.",
                    },
                    "flagged_operator_count": {
                        "type": "integer",
                        "description": "Operators with at least one fraud signal in the window.",
                    },
                    "critical_signal_count": {
                        "type": "integer",
                        "description": "Count of critical-severity fraud signals in the window.",
                    },
                    "high_signal_count": {
                        "type": "integer",
                        "description": "Count of high-severity fraud signals in the window.",
                    },
                    "elevated_signal_count": {
                        "type": "integer",
                        "description": "Count of elevated-severity fraud signals in the window.",
                    },
                    "review_open_count": {
                        "type": "integer",
                        "description": "Operators currently in an open review state.",
                    },
                    "labeled_outcome_count": {
                        "type": "integer",
                        "description": (
                            "Review outcomes labeled in the window (confirmed risk, false "
                            "positive, or needs more evidence)."
                        ),
                    },
                    "confirmed_risk_count": {
                        "type": "integer",
                        "description": "Labeled confirmed-risk outcomes in the window.",
                    },
                    "false_positive_count": {
                        "type": "integer",
                        "description": "Labeled false-positive outcomes in the window.",
                    },
                    "backtest_summary": {
                        "type": "string",
                        "description": (
                            "Human-readable backtest summary derived from the window metrics."
                        ),
                    },
                },
            ),
        },
        "paybond_get_a2a_agent_card": {
            "title": "Get A2A Agent Card",
            "annotations": read_only("Get A2A Agent Card"),
        },
        "paybond_list_a2a_task_contracts": {
            "title": "List A2A Task Contracts",
            "annotations": read_only("List A2A Task Contracts"),
        },
        "paybond_get_a2a_task_contract": {
            "title": "Get A2A Task Contract",
            "annotations": read_only("Get A2A Task Contract"),
        },
        "paybond_verify_agent_mandate_v1": {
            "title": "Verify Agent Mandate",
            "annotations": read_only("Verify Agent Mandate"),
        },
        "paybond_verify_agent_recognition_proof_v1": {
            "title": "Verify Agent Recognition Proof",
            "annotations": read_only("Verify Agent Recognition Proof"),
        },
        "paybond_import_agent_mandate_v1": {
            "title": "Import Agent Mandate",
            "annotations": additive_mutation("Import Agent Mandate"),
        },
        "paybond_get_settlement_receipt_v1": {
            "title": "Get Settlement Receipt",
            "annotations": read_only("Get Settlement Receipt"),
        },
        "paybond_verify_protocol_receipt_v1": {
            "title": "Verify Protocol Receipt",
            "description": (
                "Use this when you already have a signed protocol-v2 authorization or settlement "
                "receipt JSON object and need offline Ed25519 verification (structure, message "
                "digest, and signature) through the gateway. Do not use this to verify "
                "AgentMandateV1 envelopes—call paybond_verify_agent_mandate_v1—or to check a Harbor "
                "capability token before spend—call paybond_verify_capability or "
                "paybond_authorize_agent_spend. To load a settlement receipt by intent UUID first, "
                "call paybond_get_settlement_receipt_v1 then pass its body here. Read-only and "
                "side-effect free: success returns valid=true with kind, receipt_id, tenant_id, and "
                "the normalized receipt; unsupported kind, malformed JSON, digest mismatch, or bad "
                "signature fail with a gateway error (typically HTTP 400)."
            ),
            "annotations": read_only("Verify Protocol Receipt"),
            "output_schema": _mcp_output_object_schema(
                {
                    "valid": {
                        "type": "boolean",
                        "description": (
                            "True when the gateway accepted the receipt structure and Ed25519 "
                            "signature. Example: true."
                        ),
                        "examples": [True],
                    },
                    "kind": {
                        "type": "string",
                        "description": (
                            "Verified receipt kind echoed from the normalized receipt. One of "
                            "paybond.protocol_authorization_receipt_v1 or "
                            "paybond.protocol_settlement_receipt_v1."
                        ),
                        "examples": [
                            "paybond.protocol_authorization_receipt_v1",
                            "paybond.protocol_settlement_receipt_v1",
                        ],
                    },
                    "receipt_id": {
                        "type": "string",
                        "description": "Canonical receipt identifier from the verified receipt.",
                        "examples": ["550e8400-e29b-41d4-a716-446655440000"],
                    },
                    "tenant_id": {
                        "type": "string",
                        "description": (
                            "Tenant id embedded in the verified receipt (not invented by the caller)."
                        ),
                        "examples": ["acme-pilot"],
                    },
                    "receipt": {
                        "type": "object",
                        "additionalProperties": True,
                        "description": (
                            "Normalized verified receipt object matching the input kind "
                            "(authorization or settlement fields plus signing material)."
                        ),
                    },
                },
            ),
        },
        "paybond_create_intent": {
            "title": "Create Harbor Intent",
            "description": (
                "Use this when you already have a fully signed Harbor intent request body and replay-safe "
                "recognition proof for the gateway /harbor/intents route. Do not use this for the normal "
                "agent spend-control path unless you specifically need the low-level Harbor API; prefer "
                "paybond_create_spend_intent."
            ),
            "annotations": additive_mutation("Create Harbor Intent"),
            "output_schema": _mcp_output_object_schema(
                {
                    "intent_id": {"type": "string"},
                    "state": {"type": "string"},
                    "capability_token": {"type": "string"},
                },
            ),
        },
        "paybond_create_spend_intent": {
            "title": "Create Spend Intent",
            "description": (
                "Use this when an agent workflow needs a new Paybond spend intent with bounded budget, "
                "allowed operations, evidence requirements, and settlement review. Do not use this for "
                "checking an already funded capability token; use paybond_authorize_agent_spend before "
                "the paid action."
            ),
            "annotations": additive_mutation("Create Spend Intent"),
            "output_schema": _mcp_output_object_schema(
                {
                    "intent_id": {"type": "string"},
                    "state": {"type": "string"},
                    "capability_token": {"type": "string"},
                },
            ),
        },
        "paybond_fund_intent": {
            "title": "Fund Intent",
            "description": (
                "Use this when an existing Harbor intent needs to advance through funding via the gateway "
                "and you have a replay-safe recognition proof. Do not use this to create a new intent or "
                "to authorize a downstream tool call; use the returned intent_id and capability_token with "
                "paybond_authorize_agent_spend."
            ),
            "annotations": live_mutation("Fund Intent"),
            "output_schema": _mcp_output_object_schema(
                {
                    "intent_id": {"type": "string"},
                    "state": {"type": "string"},
                    "capability_token": {"type": "string"},
                },
            ),
        },
        "paybond_submit_evidence": {
            "title": "Submit Harbor Evidence",
            "description": (
                "Use this when you already have a Harbor evidence request body and recognition proof for "
                "the gateway /harbor/intents/{id}/evidence route. Do not use this for the high-level "
                "spend-control path unless you need the low-level Harbor API; prefer "
                "paybond_submit_spend_evidence."
            ),
            "annotations": additive_mutation("Submit Harbor Evidence"),
            "output_schema": _mcp_output_object_schema(
                {
                    "intent_id": {"type": "string"},
                    "state": {"type": "string"},
                    "evidence_id": {"type": "string"},
                },
            ),
        },
        "paybond_submit_spend_evidence": {
            "title": "Submit Spend Evidence",
            "description": (
                "Use this when a Paybond spend intent needs signed evidence so release, refund, review, "
                "and receipt generation use the same audit-ready record. Do not use this to create or "
                "fund intents, and do not use it for sandbox guardrail evidence."
            ),
            "annotations": additive_mutation("Submit Spend Evidence"),
            "output_schema": _mcp_output_object_schema(
                {
                    "intent_id": {"type": "string"},
                    "state": {"type": "string"},
                    "evidence_id": {"type": "string"},
                },
            ),
        },
        "paybond_confirm_settlement": {
            "title": "Confirm Settlement",
            "description": (
                "Use this when a Harbor intent is ready for final settlement confirmation and you have "
                "the signed body plus recognition proof. Do not use this for evidence submission or "
                "capability authorization."
            ),
            "annotations": live_mutation("Confirm Settlement"),
            "output_schema": _mcp_output_object_schema(
                {
                    "intent_id": {"type": "string"},
                    "state": {"type": "string"},
                    "receipt_id": {"type": "string"},
                },
            ),
        },
    }


def _apply_fastmcp_output_schemas(
    server: Any,
    tool_metadata: dict[str, dict[str, Any]],
) -> None:
    manager = getattr(server, "_tool_manager", None)
    tools = getattr(manager, "_tools", None)
    if not isinstance(tools, dict):
        return
    for name, metadata in tool_metadata.items():
        output_schema = metadata.get("output_schema")
        if output_schema is None:
            continue
        tool = tools.get(name)
        fn_metadata = getattr(tool, "fn_metadata", None)
        if fn_metadata is not None:
            # FastMCP has no decorator output_schema argument in the pinned SDK.
            fn_metadata.output_schema = output_schema


def build_mcp_server(settings: PaybondMCPSettings | None = None) -> Any:
    """Build the stdio MCP server instance."""

    try:
        from mcp.server.fastmcp import FastMCP
        from mcp.types import ToolAnnotations
        from pydantic import Field as PydanticField
    except ImportError as exc:  # pragma: no cover - exercised only without the optional dep
        raise RuntimeError(
            "The Paybond MCP server requires the optional 'mcp' dependency. "
            "Install it with `pip install \"paybond-kit[mcp]\"`."
        ) from exc

    # FastMCP evaluates postponed annotations against the module globals.
    global Field
    Field = PydanticField

    resolved = settings or PaybondMCPSettings.from_env()
    effective_policy = resolve_mcp_tool_policy(resolved.tool_policy)
    runtime = PaybondMCPRuntime(resolved)

    @asynccontextmanager
    async def lifespan(_: Any) -> AsyncIterator[None]:
        async def warm_principal() -> None:
            try:
                await runtime.preload_principal()
            except Exception as exc:  # noqa: BLE001 - preload is best-effort during startup
                logger.warning("Paybond MCP principal preload failed: %s", exc)

        preload_task = asyncio.create_task(warm_principal(), name="paybond-mcp-preload-principal")
        try:
            yield
        finally:
            preload_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await preload_task
            await runtime.aclose()

    server = FastMCP(
        name="Paybond MCP",
        instructions=(
            "This server is bound to one Paybond tenant derived from the configured "
            "service-account API key. Use paybond_create_spend_intent or "
            "paybond_bootstrap_sandbox_guardrail to obtain a funded intent_id, then "
            "call paybond_authorize_agent_spend before side-effecting tools. Capability "
            "tokens are stored inside this MCP server and are not returned to agent logs. "
            "works with any MCP-compatible host and does not assume a specific model "
            "provider. Do not invent tenant identifiers. Gateway-first Harbor mutation "
            "tools expect already-signed request bodies plus replay-safe recognition "
            "proofs; do not pass signing seeds or long-lived private keys through MCP "
            "tool arguments."
        ),
        website_url="https://paybond.ai",
        lifespan=lifespan,
    )
    tool_metadata = _mcp_tool_selection_metadata(ToolAnnotations)

    def paybond_tool(*, name: str, description: str) -> Any:
        metadata = tool_metadata[name]
        if not tool_allowed_by_policy(name, metadata["annotations"], effective_policy):
            def skip_tool(func: Any) -> Any:
                return func

            return skip_tool

        tool_decorator = server.tool(
            name=name,
            title=metadata["title"],
            description=metadata.get("description", description),
            annotations=metadata["annotations"],
            structured_output=True,
        )

        def register_tool(func: Any) -> Any:
            @wraps(func)
            async def wrapped(*args: Any, **kwargs: Any):
                await runtime.begin_policy_tool_call()
                try:
                    result = await func(*args, **kwargs)
                    if isinstance(result, dict):
                        return runtime.prepare_tool_response(result, tool_name=name)
                    return result
                finally:
                    await runtime.end_policy_tool_call()

            return tool_decorator(wrapped)

        return register_tool

    @paybond_tool(
        name="paybond_get_principal",
        description=(
            "Use this when you need to confirm which tenant-bound service-account principal the "
            "configured PAYBOND_API_KEY authenticates as (tenant_id, subject, and roles). Call early "
            "as a prerequisite before Harbor escrow, Signal reads, or other tenant-scoped tools when "
            "tenant identity is unknown. Not required before every later call once tenant_id is "
            "already known from a prior principal response or host config. Do not use this when you "
            "need Harbor intent escrow detail; use paybond_get_intent instead when you have an "
            "intent_id. Do not use this for A2A discovery; use paybond_get_a2a_agent_card instead. "
            "Makes one read-only external GET to the gateway principal endpoint; idempotent identity "
            "lookup with no side effects (no mutations, spend reservations, escrow changes, or "
            "ledger writes); auth or gateway failures surface as tool errors."
        ),
    )
    async def paybond_get_principal() -> dict[str, Any]:
        return await runtime.principal()

    @paybond_tool(
        name="paybond_verify_capability",
        description=(
            "Verify a capability token returned by a created or funded Paybond intent "
            "for one tenant-bound Harbor intent."
        ),
    )
    async def paybond_verify_capability(
        intent_id: str,
        operation: str,
        requested_spend_cents: int | None = None,
        token: str | None = None,
    ) -> dict[str, Any]:
        resolved_token = await runtime.resolve_capability_token(intent_id, token)
        return await runtime.authorize_agent_spend(
            intent_id=UUID(intent_id),
            token=resolved_token,
            operation=operation,
            requested_spend_cents=requested_spend_cents,
            tool_name=operation,
        )

    @paybond_tool(
        name="paybond_authorize_agent_spend",
        description=(
            "Provider-agnostic spend gate: verify the funded intent's capability token "
            "before a side-effecting tool, paid API, vendor action, or settlement "
            "workflow executes."
        ),
    )
    async def paybond_authorize_agent_spend(
        intent_id: str,
        operation: str,
        requested_spend_cents: int | None = None,
        token: str | None = None,
    ) -> dict[str, Any]:
        resolved_token = await runtime.resolve_capability_token(intent_id, token)
        return await runtime.authorize_agent_spend(
            intent_id=UUID(intent_id),
            token=resolved_token,
            operation=operation,
            requested_spend_cents=requested_spend_cents,
            tool_name=operation,
        )

    @paybond_tool(
        name="paybond_get_budget_remaining",
        description=(
            "Read-only dry-run of remaining spend budget for a tenant-bound intent "
            "via gateway spend preflight."
        ),
    )
    async def paybond_get_budget_remaining(
        intent_id: str,
        operation: str | None = None,
        requested_spend_cents: int | None = None,
        vendor_id: str | None = None,
        tool_name: str | None = None,
        task_id: str | None = None,
        workflow_id: str | None = None,
        tool_call_id: str | None = None,
        currency: str | None = None,
        agent_subject: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        return await runtime.get_budget_remaining(
            intent_id=UUID(intent_id),
            operation=operation,
            requested_spend_cents=requested_spend_cents,
            vendor_id=vendor_id,
            tool_name=tool_name,
            task_id=task_id,
            workflow_id=workflow_id,
            tool_call_id=tool_call_id,
            currency=currency,
            agent_subject=agent_subject,
            approval_token=approval_token,
        )

    @paybond_tool(
        name="paybond_explain_policy",
        description=(
            "Read-only dry-run explanation of whether proposed spend would allow, "
            "require approval, or deny under tenant spend policy."
        ),
    )
    async def paybond_explain_policy(
        intent_id: str,
        operation: str | None = None,
        requested_spend_cents: int | None = None,
        vendor_id: str | None = None,
        tool_name: str | None = None,
        task_id: str | None = None,
        workflow_id: str | None = None,
        tool_call_id: str | None = None,
        currency: str | None = None,
        agent_subject: str | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        return await runtime.explain_policy(
            intent_id=UUID(intent_id),
            operation=operation,
            requested_spend_cents=requested_spend_cents,
            vendor_id=vendor_id,
            tool_name=tool_name,
            task_id=task_id,
            workflow_id=workflow_id,
            tool_call_id=tool_call_id,
            currency=currency,
            agent_subject=agent_subject,
            approval_token=approval_token,
        )

    @paybond_tool(
        name="paybond_bootstrap_sandbox_guardrail",
        description=(
            "Bootstrap a sandbox-only Paybond guardrail intent for a first paid-tool "
            "integration. Tenant scope is derived from the configured service-account "
            "API key and the route never touches live settlement rails."
        ),
    )
    async def paybond_bootstrap_sandbox_guardrail(
        operation: str,
        requested_spend_cents: int,
        currency: str | None = None,
        evidence_schema: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        return await runtime.bootstrap_sandbox_guardrail(
            operation=operation,
            requested_spend_cents=requested_spend_cents,
            currency=currency,
            evidence_schema=evidence_schema,
            metadata=metadata,
            idempotency_key=idempotency_key,
        )

    @paybond_tool(
        name="paybond_validate_completion_evidence",
        description=(
            "Pre-validates completion evidence against the shared preset catalog. "
            "Call this before paybond_submit_*_evidence when PAYBOND_MCP_EVIDENCE_POLICY=strict."
        ),
    )
    async def paybond_validate_completion_evidence(
        preset_id: str,
        vendor_payload: dict[str, Any] | None = None,
        canonical_payload: dict[str, Any] | None = None,
        frozen_vendor_api_version: str | None = None,
        frozen_vendor_schema_digest_hex: str | None = None,
        frozen_canonical_schema_digest_hex: str | None = None,
    ) -> dict[str, Any]:
        return runtime.validate_completion_evidence(
            preset_id=preset_id,
            vendor_payload=vendor_payload,
            canonical_payload=canonical_payload,
            frozen_vendor_api_version=frozen_vendor_api_version,
            frozen_vendor_schema_digest_hex=frozen_vendor_schema_digest_hex,
            frozen_canonical_schema_digest_hex=frozen_canonical_schema_digest_hex,
        )

    @paybond_tool(
        name="paybond_submit_sandbox_guardrail_evidence",
        description=(
            "Submit evidence for a sandbox-only Paybond guardrail intent. Tenant scope "
            "is derived from the configured service-account API key and simulator "
            "settlement remains sandbox-only."
        ),
    )
    async def paybond_submit_sandbox_guardrail_evidence(
        intent_id: str,
        payload: dict[str, Any] | None = None,
        artifacts: list[str] | None = None,
        operation: str | None = None,
        requested_spend_cents: int | None = None,
        metadata: dict[str, Any] | None = None,
        completion_preset_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        return await runtime.submit_sandbox_guardrail_evidence(
            UUID(intent_id),
            payload=payload,
            artifacts=artifacts,
            operation=operation,
            requested_spend_cents=requested_spend_cents,
            metadata=metadata,
            completion_preset_id=completion_preset_id,
            idempotency_key=idempotency_key,
        )

    @paybond_tool(
        name="paybond_list_intents",
        description=(
            "List tenant-scoped Harbor intents through the gateway operator view. "
            "Supports optional status, operator DID, limit, and cursor filters."
        ),
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

    async def _handle_get_intent(intent_id: str) -> dict[str, Any]:
        return await runtime.get_intent(UUID(intent_id))

    paybond_tool(
        name="paybond_get_intent",
        description="Fetch one tenant-scoped Harbor intent detail through the gateway operator view.",
    )(_handle_get_intent)

    @paybond_tool(
        name="paybond_list_audit_exports",
        description=(
            "List tenant-scoped compliance audit export jobs through the gateway operator view."
        ),
    )
    async def paybond_list_audit_exports(
        limit: int = 50,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        return await runtime.list_audit_exports(limit=limit, cursor=cursor)

    @paybond_tool(
        name="paybond_get_audit_export",
        description=(
            "Fetch one tenant-scoped compliance audit export job detail through the gateway operator view."
        ),
    )
    async def paybond_get_audit_export(
        job_id: str,
        issue_download: bool = False,
    ) -> dict[str, Any]:
        return await runtime.get_audit_export(job_id, issue_download=issue_download)

    @paybond_tool(
        name="paybond_get_reputation_receipt",
        description="Fetch the signed Signal receipt for one operator DID.",
    )
    async def paybond_get_reputation_receipt(
        operator_did: Annotated[
            str,
            Field(
                description=(
                    "Tenant-scoped operator DID whose signed Signal reputation receipt to fetch. "
                    "Must belong to the authenticated tenant; do not invent tenant identifiers. "
                    "Examples: did:web:vendor.example#booker-agent, "
                    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK."
                ),
                examples=[
                    "did:web:vendor.example#booker-agent",
                    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
                ],
            ),
        ],
        score_version: Annotated[
            str | None,
            Field(
                description=(
                    "Optional Signal score model version to query. Omit to use the gateway "
                    "default current model (1.0). Example: 1.0."
                ),
                examples=["1.0"],
            ),
        ] = None,
    ) -> dict[str, Any] | None:
        signal = await runtime.signal()
        return _jsonable(
            await signal.get_reputation_receipt(
                operator_did,
                score_version=score_version,
            )
        )

    @paybond_tool(
        name="paybond_get_portfolio_summary",
        description="Fetch the tenant-scoped Signal portfolio summary.",
    )
    async def paybond_get_portfolio_summary(
        score_version: Annotated[
            str | None,
            Field(
                description=(
                    "Optional Signal score model version to query. Omit to use the gateway "
                    "default current model (1.0). Example: 1.0."
                ),
                examples=["1.0"],
            ),
        ] = None,
    ) -> dict[str, Any]:
        signal = await runtime.signal()
        return _jsonable(await signal.get_portfolio_summary(score_version=score_version))

    @paybond_tool(
        name="paybond_get_signed_portfolio_artifact",
        description=(
            "Fetch the tenant-scoped signed Signal portfolio artifact for portable verifier "
            "and partner sharing."
        ),
    )
    async def paybond_get_signed_portfolio_artifact(
        score_version: Annotated[
            str | None,
            Field(
                description=(
                    "Optional Signal score model version to query. Omit to use the gateway "
                    "default current model (1.0). Example: 1.0."
                ),
                examples=["1.0"],
            ),
        ] = None,
    ) -> dict[str, Any]:
        signal = await runtime.signal()
        return _jsonable(await signal.get_signed_portfolio_artifact(score_version=score_version))

    @paybond_tool(
        name="paybond_get_fraud_assessment",
        description="Fetch the read-only fraud assessment for one tenant-scoped operator DID.",
    )
    async def paybond_get_fraud_assessment(
        operator_did: Annotated[
            str,
            Field(
                description=(
                    "Tenant-scoped operator DID to assess. Must belong to the authenticated "
                    "tenant; do not invent tenant identifiers. Examples: "
                    "did:web:vendor.example#booker-agent, "
                    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK."
                ),
                examples=[
                    "did:web:vendor.example#booker-agent",
                    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
                ],
            ),
        ],
        score_version: Annotated[
            str | None,
            Field(
                description=(
                    "Optional Signal score model version to query. Omit to use the gateway "
                    "default current model. Example: 1.0."
                ),
                examples=["1.0"],
            ),
        ] = None,
    ) -> dict[str, Any] | None:
        fraud = await runtime.fraud()
        return _jsonable(
            await fraud.get_fraud_assessment(
                operator_did,
                score_version=score_version,
            )
        )

    @paybond_tool(
        name="paybond_get_fraud_metrics",
        description=(
            "Fetch tenant-scoped read-only fraud backtesting and monitoring metrics for a "
            "supported active window."
        ),
    )
    async def paybond_get_fraud_metrics(
        window: Annotated[
            str | None,
            Field(
                description=(
                    "Rolling metrics window. Allowed values: 24h, 7d, 30d. Omit to use the "
                    "gateway default 24h. Unsupported values fail with HTTP 400."
                ),
                examples=["24h", "7d", "30d"],
            ),
        ] = None,
        score_version: Annotated[
            str | None,
            Field(
                description=(
                    "Optional Signal score model version to query. Omit to use the gateway "
                    "default current model (1.0). Example: 1.0."
                ),
                examples=["1.0"],
            ),
        ] = None,
    ) -> dict[str, Any]:
        fraud = await runtime.fraud()
        return _jsonable(await fraud.get_fraud_metrics(window=window, score_version=score_version))

    @paybond_tool(
        name="paybond_get_a2a_agent_card",
        description="Fetch the published Paybond A2A discovery card for protocol-trust delegation.",
    )
    async def paybond_get_a2a_agent_card() -> dict[str, Any]:
        return await runtime.get_a2a_agent_card()

    @paybond_tool(
        name="paybond_list_a2a_task_contracts",
        description="Fetch the published catalog of Paybond A2A task contracts for delegated Harbor workflows.",
    )
    async def paybond_list_a2a_task_contracts() -> dict[str, Any]:
        return await runtime.get_a2a_task_contracts()

    @paybond_tool(
        name="paybond_get_a2a_task_contract",
        description="Fetch one published Paybond A2A task contract by identifier.",
    )
    async def paybond_get_a2a_task_contract(contract_id: str) -> dict[str, Any]:
        return await runtime.get_a2a_task_contract(contract_id)

    @paybond_tool(
        name="paybond_verify_agent_mandate_v1",
        description=(
            "Verify a signed AgentMandateV1 envelope through the gateway v2 protocol surface."
        ),
    )
    async def paybond_verify_agent_mandate_v1(
        signed_mandate: dict[str, Any],
    ) -> dict[str, Any]:
        return await runtime.verify_agent_mandate_v1(signed_mandate)

    @paybond_tool(
        name="paybond_verify_agent_recognition_proof_v1",
        description=(
            "Verify a replay-safe AgentRecognitionProofV1 against an expected purpose and "
            "request envelope. Verifier context (tenant_id, verifier_id) is derived from the "
            "authenticated MCP session only."
        ),
    )
    async def paybond_verify_agent_recognition_proof_v1(
        proof: dict[str, Any],
        expected_purpose: str,
        expected_request: dict[str, Any],
    ) -> dict[str, Any]:
        return await runtime.verify_agent_recognition_proof_v1(
            proof=proof,
            expected_purpose=expected_purpose,
            expected_request=expected_request,
        )

    @paybond_tool(
        name="paybond_import_agent_mandate_v1",
        description=(
            "Import a signed AgentMandateV1 through the gateway v2 protocol surface and bind it "
            "to one Harbor intent using a replay-safe recognition proof."
        ),
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

    @paybond_tool(
        name="paybond_get_settlement_receipt_v1",
        description="Fetch the signed protocol-v2 settlement receipt for one Harbor intent.",
    )
    async def paybond_get_settlement_receipt_v1(receipt_id: str) -> dict[str, Any]:
        return await runtime.get_settlement_receipt_v1(receipt_id)

    @paybond_tool(
        name="paybond_verify_protocol_receipt_v1",
        description=(
            "Verify a signed protocol-v2 authorization or settlement receipt through the gateway."
        ),
    )
    async def paybond_verify_protocol_receipt_v1(
        receipt: Annotated[
            dict[str, Any],
            Field(
                description=(
                    "Complete signed protocol receipt object posted as the verify request body "
                    "(not a receipt_id string). Discriminate on kind: "
                    "paybond.protocol_authorization_receipt_v1 requires schema_version=1, "
                    'receipt_version="1", receipt_id, issued_at, status (authorized), intent_id, '
                    "tenant_id, verifier_id, transport_binding, mandate_digest_sha256_hex, "
                    "imported_mandate_signing_public_key_ed25519_hex, authorization, agent, "
                    "allowed_actions, allowed_tools, spend_ceiling, settlement, constraint, "
                    "expires_at, nonce, human_presence_mode, plus "
                    "signing_algorithm=ed25519-sha256-json-v1, message_digest_sha256_hex, "
                    "signing_public_key_ed25519_hex, and ed25519_signature_hex. "
                    "paybond.protocol_settlement_receipt_v1 requires schema_version=1, "
                    'receipt_version="1", receipt_id, issued_at, intent_id, tenant_id, '
                    "verifier_id, transport_binding, authorization_receipt_id, "
                    "mandate_digest_sha256_hex, harbor_state, settlement_rail, settlement_mode, "
                    "principal_did, payee_did, currency, amount_cents, terminal_observed_at, "
                    "optional predicate_passed, and the same Ed25519 signing fields. Obtain "
                    "receipts from mandate import, paybond_get_settlement_receipt_v1, audit "
                    "export, or partner handoff—do not invent digests or signatures."
                ),
            ),
        ],
    ) -> dict[str, Any]:
        return await runtime.verify_protocol_receipt_v1(receipt)

    @paybond_tool(
        name="paybond_create_intent",
        description=(
            "Create a Harbor intent through the gateway /harbor path. The request body must "
            "already be signed upstream and every call requires a recognition proof."
        ),
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

    @paybond_tool(
        name="paybond_create_spend_intent",
        description=(
            "Create a signed Paybond spend intent through the gateway /harbor route. "
            "Use this when an agent workflow needs bounded budget, allowed operations, "
            "evidence, and settlement review. If the selected rail funds immediately, "
            "use the returned intent_id and capability_token with "
            "paybond_authorize_agent_spend."
        ),
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

    @paybond_tool(
        name="paybond_fund_intent",
        description=(
            "Advance Harbor funding through the gateway /harbor path with a replay-safe "
            "recognition proof. When funding succeeds, use the returned capability_token "
            "with intent_id in paybond_authorize_agent_spend."
        ),
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

    @paybond_tool(
        name="paybond_submit_evidence",
        description=(
            "Submit evidence through the gateway /harbor path with a replay-safe recognition proof."
        ),
    )
    async def paybond_submit_evidence(
        intent_id: str,
        body: dict[str, Any],
        recognition_proof: dict[str, Any],
        completion_preset_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        return await runtime.submit_harbor_evidence(
            UUID(intent_id),
            body=body,
            recognition_proof=recognition_proof,
            completion_preset_id=completion_preset_id,
            idempotency_key=idempotency_key,
        )

    async def _handle_submit_spend_evidence(
        intent_id: str,
        body: dict[str, Any],
        recognition_proof: dict[str, Any],
        completion_preset_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        return await runtime.submit_harbor_evidence(
            UUID(intent_id),
            body=body,
            recognition_proof=recognition_proof,
            completion_preset_id=completion_preset_id,
            idempotency_key=idempotency_key,
        )

    paybond_tool(
        name="paybond_submit_spend_evidence",
        description=(
            "Submit signed evidence for a Paybond spend intent so release, refund, "
            "review, and receipt generation use the same audit-ready record."
        ),
    )(_handle_submit_spend_evidence)

    @server.resource(
        "paybond://receipt/{receipt_id}",
        name="paybond_agent_receipt",
        title="Paybond Agent Receipt",
        description=(
            "Signed paybond.agent_receipt_v1 JSON fetched tenant-bound from "
            "Gateway GET /protocol/v2/agent-receipts/{receipt_id}."
        ),
        mime_type=MCP_AGENT_RECEIPT_RESOURCE_MIME_TYPE,
    )
    async def paybond_agent_receipt_resource(receipt_id: str) -> str:
        receipt = await runtime.get_agent_receipt_v1(receipt_id)
        return json.dumps(receipt, indent=2, sort_keys=True)

    @paybond_tool(
        name="paybond_confirm_settlement",
        description=(
            "Confirm Harbor settlement through the gateway /harbor path with a replay-safe "
            "recognition proof."
        ),
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

    _apply_fastmcp_output_schemas(server, tool_metadata)
    setattr(server, "_paybond_runtime", runtime)
    return server


def run_mcp_stdio(argv: list[str] | None = None) -> int:
    """Run the tenant-bound Paybond MCP server over stdio."""

    parser = argparse.ArgumentParser(
        description="Run the tenant-bound Paybond MCP server over stdio."
    )
    parser.parse_args(argv)

    try:
        server = build_mcp_server(PaybondMCPSettings.from_env())
    except (RuntimeError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
    server.run(transport="stdio")
    return 0


def main(argv: list[str] | None = None) -> int:
    import sys

    from paybond_kit.cli.automation import deprecated_alias_warning

    argv_list = list(argv if argv is not None else sys.argv[1:])
    alias_warning = deprecated_alias_warning(sys.argv[0])
    if alias_warning:
        sys.stderr.write(f"{alias_warning}\n")
    return run_mcp_stdio(argv_list)


def _jsonable(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
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


def _idempotency_headers(idempotency_key: str | None) -> dict[str, str]:
    if idempotency_key is not None and idempotency_key.strip():
        return {"idempotency-key": idempotency_key.strip()}
    return {}


def _validate_sandbox_guardrail_response(
    body: dict[str, Any],
    *,
    expected_tenant: str,
    require_capability_token: bool = False,
) -> None:
    echoed_tenant = _required_mcp_string(body, "tenant_id")
    if echoed_tenant != expected_tenant:
        raise TenantBindingError(
            f"sandbox guardrail tenant mismatch: expected={expected_tenant!r} gateway={echoed_tenant!r}"
        )
    _required_mcp_string(body, "intent_id")
    if require_capability_token:
        _required_mcp_string(body, "capability_token")
    _required_mcp_string(body, "operation")
    _required_mcp_int(body, "requested_spend_cents")
    _required_mcp_string(body, "sandbox_lifecycle_status")


def _required_mcp_string(body: dict[str, Any], field: str) -> str:
    value = body.get(field)
    if isinstance(value, str) and value.strip():
        return value
    raise RuntimeError(f"gateway sandbox guardrail response missing {field}")


def _required_mcp_int(body: dict[str, Any], field: str) -> int:
    value = body.get(field)
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    raise RuntimeError(f"gateway sandbox guardrail response missing {field}")


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

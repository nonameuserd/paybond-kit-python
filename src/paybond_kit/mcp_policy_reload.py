"""MCP policy hot-reload: env config, spend gate, and safe registry swap."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Protocol

from paybond_kit.agent.types import (
    PaybondToolDeniedResolution,
    PaybondToolPassthroughResolution,
    PaybondUnregisteredSideEffectingToolError,
)
from paybond_kit.policy.load_effective import parse_policy_effective_resolve_response
from paybond_kit.policy.reload import (
    PaybondPolicyReloadBindConfig,
    PaybondPolicyReloadOptions,
    PaybondPolicyReloadResult,
    load_policy_snapshot_from_file,
    reload_policy_on_handle,
)
from paybond_kit.policy.snapshot import PaybondPolicySnapshot
from paybond_kit.policy.validate_remote import (
    PolicyRemoteValidateOptions,
    parse_policy_remote_validate_response,
    policy_validate_query_string,
)
from paybond_kit.policy.watcher import PaybondPolicyReloadController

MCP_POLICY_FILE_ENV = "PAYBOND_POLICY_FILE"
MCP_POLICY_RELOAD_ENV = "PAYBOND_POLICY_RELOAD"
MCP_POLICY_RELOAD_ALLOW_LOOSEN_ENV = "PAYBOND_POLICY_RELOAD_ALLOW_LOOSEN"

McpPolicyReloadMode = Literal["off", "watch", "poll"]


@dataclass(frozen=True, slots=True)
class McpPolicyReloadConfig:
    policy_file: str
    reload_mode: McpPolicyReloadMode
    allow_loosen: bool = False
    watch_debounce_ms: int | None = None
    poll_interval_ms: int | None = None


@dataclass(frozen=True, slots=True)
class McpPolicySpendGateInput:
    operation: str
    allowed_tools: tuple[str, ...] | list[str]
    tool_name: str | None = None
    arguments: Any = None
    requested_spend_cents: int | None = None


@dataclass(frozen=True, slots=True)
class McpPolicySpendGateResult:
    operation: str
    requested_spend_cents: int
    policy_digest: str | None = None


@dataclass(frozen=True, slots=True)
class McpPolicyReloadStatus:
    enabled: bool
    reload_mode: McpPolicyReloadMode
    policy_file: str | None = None
    policy_digest: str | None = None
    policy_loaded_at: str | None = None
    last_reload_at: str | None = None
    last_reload_error: str | None = None


class McpPolicyReloadError(RuntimeError):
    """MCP policy gate failure."""


class McpPolicyGatewayClient(Protocol):
    async def post_json(
        self,
        path: str,
        payload: dict[str, Any],
        *,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]: ...


class _McpPolicyGatewayAdapter:
    """Gateway adapter for MCP poll reload with remote validation."""

    def __init__(self, client: McpPolicyGatewayClient) -> None:
        self._client = client

    async def validate_policy(
        self,
        document: Any,
        *,
        options: PolicyRemoteValidateOptions | None = None,
    ) -> Any:
        from paybond_kit.policy.digest import policy_document_to_dict

        payload = policy_document_to_dict(document)
        qs = policy_validate_query_string(options=options)
        body = await self._client.post_json(f"/v1/policy/validate{qs}", payload)
        return parse_policy_remote_validate_response(body)

    async def resolve_policy_effective(
        self,
        org_policy_id: str,
        overlay: dict[str, Any],
        *,
        current_digest: str | None = None,
    ) -> Any:
        path = f"/v1/org-policies/{org_policy_id}/effective"
        if current_digest and current_digest.strip():
            path += f"?digest={current_digest.strip()}"
        body = await self._client.post_json(path, overlay)
        return parse_policy_effective_resolve_response(body)


def create_mcp_policy_gateway_adapter(client: McpPolicyGatewayClient) -> _McpPolicyGatewayAdapter:
    return _McpPolicyGatewayAdapter(client)


def parse_mcp_policy_reload_mode(raw: str | None) -> McpPolicyReloadMode:
    value = (raw or "").strip().lower()
    if not value or value == "off":
        return "off"
    if value in ("watch", "poll"):
        return value
    raise ValueError("invalid PAYBOND_POLICY_RELOAD (expected watch|poll|off)")


def parse_mcp_policy_reload_config(env: dict[str, str | None]) -> McpPolicyReloadConfig | None:
    policy_file = (env.get(MCP_POLICY_FILE_ENV) or "").strip()
    if not policy_file:
        return None
    return McpPolicyReloadConfig(
        policy_file=str(Path(policy_file).resolve()),
        reload_mode=parse_mcp_policy_reload_mode(env.get(MCP_POLICY_RELOAD_ENV)),
        allow_loosen=env.get(MCP_POLICY_RELOAD_ALLOW_LOOSEN_ENV) == "1",
    )


class McpPolicyReloadGate:
    """Long-lived MCP policy gate: versioned snapshot, safe reload, spend-gate checks."""

    def __init__(
        self,
        config: McpPolicyReloadConfig,
        snapshot: PaybondPolicySnapshot,
    ) -> None:
        self.config = config
        self.policy_file_path = config.policy_file
        self._snapshot = snapshot
        self._in_flight_count = 0
        self._last_allowed_tools: list[str] = []
        self._controller: PaybondPolicyReloadController | None = None
        self._reload_defaults: PaybondPolicyReloadOptions = {}
        self.last_reload_at: str | None = None
        self.last_reload_error: str | None = None

    @classmethod
    async def open(
        cls,
        config: McpPolicyReloadConfig,
        *,
        gateway: _McpPolicyGatewayAdapter | None = None,
    ) -> McpPolicyReloadGate:
        snapshot = await load_policy_snapshot_from_file(config.policy_file)
        gate = cls(config, snapshot)
        gate._reload_defaults = {
            "file": config.policy_file,
            "allow_loosen": config.allow_loosen,
            "gateway": gateway,
        }

        if config.reload_mode == "watch":
            bind: PaybondPolicyReloadBindConfig = {
                "watch": {"debounce_ms": config.watch_debounce_ms}
                if config.watch_debounce_ms is not None
                else True,
            }
            gate._controller = PaybondPolicyReloadController.start(
                gate,
                bind,
                config.policy_file,
            )
        elif config.reload_mode == "poll":
            gate._reload_defaults["remote"] = True
            gate._reload_defaults["resolve_inheritance"] = True
            bind = {
                "poll": {
                    "interval_ms": config.poll_interval_ms,
                    "remote": True,
                    "resolve_inheritance": True,
                    "gateway": gateway,
                },
            }
            gate._controller = PaybondPolicyReloadController.start(
                gate,
                bind,
                config.policy_file,
            )
        return gate

    @property
    def current_snapshot(self) -> PaybondPolicySnapshot | None:
        return self._snapshot

    @property
    def policy_digest(self) -> str | None:
        return None if self._snapshot is None else self._snapshot.digest

    @property
    def in_flight_count(self) -> int:
        return self._in_flight_count

    @property
    def registry(self):
        if self._snapshot is None:
            raise McpPolicyReloadError("policy snapshot is not loaded")
        return self._snapshot.registry

    def apply_policy_snapshot(self, snapshot: PaybondPolicySnapshot) -> None:
        self._snapshot = snapshot

    async def reload_policy(
        self,
        options: PaybondPolicyReloadOptions | None = None,
    ) -> PaybondPolicyReloadResult:
        try:
            merged = {**self._reload_defaults, **(options or {})}
            result = await reload_policy_on_handle(
                self,
                merged,
                allowed_tools=self._last_allowed_tools or None,
            )
            if result.applied:
                from datetime import UTC, datetime

                self.last_reload_at = datetime.now(UTC).isoformat()
                self.last_reload_error = None
            return result
        except Exception as exc:
            self.last_reload_error = str(exc)
            raise

    def begin_tool_call(self) -> None:
        self._in_flight_count += 1

    def end_tool_call(self) -> None:
        self._in_flight_count = max(0, self._in_flight_count - 1)

    def assert_spend_gate(self, input: McpPolicySpendGateInput) -> McpPolicySpendGateResult:
        operation = input.operation.strip()
        tool_name = (input.tool_name or operation).strip()
        if not operation:
            raise McpPolicyReloadError("operation must be non-empty")

        self._last_allowed_tools = list(input.allowed_tools)
        policy_digest = self.policy_digest
        resolution = self.registry.resolve_tool(
            tool_name,
            allowed_tools=list(input.allowed_tools),
        )

        if isinstance(resolution, PaybondToolPassthroughResolution):
            return McpPolicySpendGateResult(operation=operation, requested_spend_cents=0, policy_digest=policy_digest)

        if isinstance(resolution, PaybondToolDeniedResolution):
            raise PaybondUnregisteredSideEffectingToolError(resolution.tool_name, resolution.operation)

        if operation not in input.allowed_tools:
            allowed = ", ".join(input.allowed_tools)
            raise McpPolicyReloadError(
                f'operation "{operation}" is not in intent allowed_tools ({allowed})',
            )

        requested_spend_cents = input.requested_spend_cents
        if requested_spend_cents is None:
            requested_spend_cents = self.registry.resolve_spend_cents(tool_name, input.arguments) or 0

        return McpPolicySpendGateResult(
            operation=resolution.operation,
            requested_spend_cents=int(requested_spend_cents),
            policy_digest=policy_digest,
        )

    def status(self) -> McpPolicyReloadStatus:
        controller_state = self._controller.state if self._controller is not None else None
        return McpPolicyReloadStatus(
            enabled=True,
            reload_mode=self.config.reload_mode,
            policy_file=self.policy_file_path,
            policy_digest=self.policy_digest,
            policy_loaded_at=None if self._snapshot is None else self._snapshot.loaded_at,
            last_reload_at=self.last_reload_at
            if self.last_reload_at is not None
            else (None if controller_state is None else controller_state.last_reload_at),
            last_reload_error=self.last_reload_error
            if self.last_reload_error is not None
            else (None if controller_state is None else controller_state.last_reload_error),
        )

    def stop(self) -> None:
        if self._controller is not None:
            self._controller.stop()
            self._controller = None

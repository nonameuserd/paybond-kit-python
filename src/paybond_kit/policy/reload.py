"""Policy hot-reload: load, validate, guard, and atomic registry swap."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, NotRequired, Protocol, TypedDict

from paybond_kit.policy.load import PaybondPolicy
from paybond_kit.policy.load_effective import PolicyEffectiveResolveClient
from paybond_kit.policy.schema import (
    PaybondPolicyDocumentV1,
    PaybondPolicyDocumentV2,
    is_paybond_policy_overlay,
    parse_paybond_policy_document,
    parse_paybond_policy_document_v1,
)
from paybond_kit.policy.snapshot import PaybondPolicySnapshot, create_policy_snapshot, create_policy_snapshot_from_effective
from paybond_kit.policy.validate import PolicyValidator, PolicyValidatorOptions
from paybond_kit.policy.validate_remote import PolicyRemoteValidateClient, PolicyRemoteValidateOptions, validate_policy_remote

if TYPE_CHECKING:
    from paybond_kit.agent.run import PaybondAgentRun


class PaybondPolicyReloadError(RuntimeError):
    """Structured reload failure (parse, validate, loosening, intent drift)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class PaybondPolicyReloadUnchangedError(Exception):
    """Internal signal when poll/file reload finds an unchanged digest."""


@dataclass(frozen=True, slots=True)
class PaybondPolicyReloadResult:
    applied: bool
    previous_digest: str | None = None
    new_digest: str | None = None
    unchanged: bool = False


class PaybondPolicyReloadOptions(TypedDict, total=False):
    file: str
    remote: bool
    resolve_inheritance: bool
    allow_loosen: bool
    gateway: Any


class PaybondPolicyReloadWatchConfig(TypedDict, total=False):
    debounce_ms: int
    file: str


class PaybondPolicyReloadPollConfig(TypedDict, total=False):
    interval_ms: int
    file: str
    remote: bool
    resolve_inheritance: bool
    gateway: Any


class PaybondPolicyReloadBindConfig(TypedDict, total=False):
    watch: bool | PaybondPolicyReloadWatchConfig
    poll: PaybondPolicyReloadPollConfig


async def load_policy_snapshot_from_file(file_path: str) -> PaybondPolicySnapshot:
    policy = PaybondPolicy.load(file_path)
    registry = policy.to_tool_registry()
    return create_policy_snapshot(document=policy.document, registry=registry, source="file")


async def load_policy_snapshot_from_effective_poll(
    *,
    overlay_path: str,
    gateway: PolicyEffectiveResolveClient,
    current_digest: str | None = None,
) -> tuple[PaybondPolicySnapshot | None, bool]:
    overlay_payload = PaybondPolicy._load_overlay_payload(overlay_path)
    overlay_doc = parse_paybond_policy_document(overlay_payload)
    if not isinstance(overlay_doc, PaybondPolicyDocumentV2) or not is_paybond_policy_overlay(overlay_doc):
        raise PaybondPolicyReloadError(
            "invalid_overlay",
            "poll reload requires a v2 tenant overlay policy with extends.org_policy_id",
        )
    extends = overlay_doc.extends
    org_policy_id = (extends.org_policy_id if extends is not None else "") or ""
    org_policy_id = org_policy_id.strip()
    if not org_policy_id:
        raise PaybondPolicyReloadError(
            "invalid_overlay",
            "poll reload requires extends.org_policy_id on the overlay policy",
        )

    resolved = await gateway.resolve_policy_effective(
        org_policy_id,
        overlay_payload,
        current_digest=current_digest,
    )
    if resolved.unchanged:
        return None, True

    effective = parse_paybond_policy_document_v1(resolved.effective_policy)
    policy = PaybondPolicy.from_document(effective)
    registry = policy.to_tool_registry()
    snapshot = create_policy_snapshot_from_effective(
        document=effective,
        registry=registry,
        effective_policy_digest=resolved.effective_policy_digest,
    )
    return snapshot, False


def _read_max_spend_cents(entry: Any) -> int | None:
    value = getattr(entry, "max_spend_cents", None)
    return int(value) if isinstance(value, int) else None


def detect_policy_loosening(previous: PaybondPolicyDocumentV1, next_: PaybondPolicyDocumentV1) -> list[str]:
    reasons: list[str] = []
    if previous.default_deny and not next_.default_deny:
        reasons.append("default_deny relaxed from true to false")

    for tool_name, next_entry in next_.tools.items():
        prev_entry = previous.tools.get(tool_name)
        if prev_entry is None:
            if next_entry.side_effecting:
                reasons.append(f'new side-effecting tool "{tool_name}"')
            continue

        prev_cap = _read_max_spend_cents(prev_entry)
        next_cap = _read_max_spend_cents(next_entry)
        if prev_cap is not None:
            if next_cap is None:
                reasons.append(f'tool "{tool_name}" max_spend_cents cap removed')
            elif next_cap > prev_cap:
                reasons.append(f'tool "{tool_name}" max_spend_cents increased from {prev_cap} to {next_cap}')

        if not prev_entry.side_effecting and next_entry.side_effecting:
            reasons.append(f'tool "{tool_name}" became side-effecting')

    return reasons


def requires_intent_rebind(document: PaybondPolicyDocumentV1, allowed_tools: tuple[str, ...] | list[str]) -> bool:
    allowed = set(allowed_tools)
    intent = document.intent
    if intent is not None:
        for operation in intent.allowed_tools or []:
            if operation not in allowed:
                return True

    for tool_name, entry in document.tools.items():
        if not entry.side_effecting:
            continue
        operation = (entry.operation or "").strip() or tool_name
        if operation not in allowed:
            return True
    return False


async def _wait_for_in_flight_count(
    in_flight_count: Callable[[], int],
    timeout_s: float = 30.0,
) -> None:
    deadline = asyncio.get_event_loop().time() + timeout_s
    while in_flight_count() > 0:
        if asyncio.get_event_loop().time() > deadline:
            raise PaybondPolicyReloadError(
                "in_flight_timeout",
                "timed out waiting for in-flight tool calls before policy reload",
            )
        await asyncio.sleep(0.01)


async def _wait_for_in_flight_interceptors(run: PaybondAgentRun, timeout_s: float = 30.0) -> None:
    await _wait_for_in_flight_count(lambda: run.interceptor.in_flight_count, timeout_s)


async def _resolve_reload_snapshot_for_handle(
    handle: PolicyReloadHandle,
    options: PaybondPolicyReloadOptions,
) -> PaybondPolicySnapshot:
    file_path = (options.get("file") or handle.policy_file_path or "").strip()
    if not file_path:
        raise PaybondPolicyReloadError(
            "missing_policy_file",
            "reload requires a policy file path (pass file or bind with reload.watch/poll)",
        )

    reload_gateway = options.get("gateway")
    if options.get("resolve_inheritance") and reload_gateway is not None:
        snapshot, unchanged = await load_policy_snapshot_from_effective_poll(
            overlay_path=file_path,
            gateway=reload_gateway,
            current_digest=handle.policy_digest,
        )
        if unchanged:
            raise PaybondPolicyReloadUnchangedError()
        if snapshot is None:
            raise PaybondPolicyReloadError("effective_empty", "effective policy resolution returned no snapshot")
        return snapshot

    snapshot = await load_policy_snapshot_from_file(file_path)
    if handle.policy_digest and handle.policy_digest == snapshot.digest:
        raise PaybondPolicyReloadUnchangedError()
    return snapshot


async def _validate_and_apply_policy_snapshot(
    handle: PolicyReloadHandle,
    snapshot: PaybondPolicySnapshot,
    options: PaybondPolicyReloadOptions,
    allowed_tools: list[str] | tuple[str, ...],
) -> PaybondPolicyReloadResult:
    previous_document = handle.current_snapshot.document if handle.current_snapshot is not None else None
    next_document = snapshot.document
    local_report = PolicyValidator.validate_document(
        next_document,
        PolicyValidatorOptions(strict=PolicyValidator.is_strict_from_env()),
    )
    if not local_report.valid:
        first = local_report.errors[0] if local_report.errors else None
        message = f"{first.path}: {first.message}" if first else "local policy validation failed"
        raise PaybondPolicyReloadError("local_validate_failed", message)

    gateway = options.get("gateway")
    if options.get("remote") and gateway is not None:
        remote_report = await validate_policy_remote(
            next_document,
            gateway,
            options=PolicyRemoteValidateOptions(
                resolve_inheritance=bool(options.get("resolve_inheritance")),
                strict=PolicyValidator.is_strict_from_env(),
            ),
        )
        if not remote_report.valid:
            first = remote_report.errors[0] if remote_report.errors else None
            message = f"{first.path}: {first.message}" if first else "remote policy validation failed"
            raise PaybondPolicyReloadError("remote_validate_failed", message)

    if allowed_tools and requires_intent_rebind(next_document, allowed_tools):
        raise PaybondPolicyReloadError(
            "intent_rebind_required",
            "reloaded policy requires allowed_tools outside the bound intent; re-bind with a new intent",
        )

    if previous_document is not None and not options.get("allow_loosen"):
        loosening = detect_policy_loosening(previous_document, next_document)
        if loosening:
            raise PaybondPolicyReloadError(
                "loosening_denied",
                f"policy loosening denied: {'; '.join(loosening)}",
            )

    if allowed_tools:
        snapshot.registry.validate_for_bind(list(allowed_tools))

    previous_digest = handle.policy_digest
    if previous_digest and previous_digest == snapshot.digest:
        return PaybondPolicyReloadResult(
            applied=False,
            previous_digest=previous_digest,
            new_digest=snapshot.digest,
            unchanged=True,
        )

    handle.apply_policy_snapshot(snapshot)
    return PaybondPolicyReloadResult(
        applied=True,
        previous_digest=previous_digest or snapshot.digest,
        new_digest=snapshot.digest,
    )


class PolicyReloadHandle(Protocol):
    """Mutable policy reload surface shared by agent runs and MCP servers."""

    @property
    def policy_file_path(self) -> str | None: ...

    @property
    def policy_digest(self) -> str | None: ...

    @property
    def current_snapshot(self) -> PaybondPolicySnapshot | None: ...

    @property
    def in_flight_count(self) -> int: ...

    def apply_policy_snapshot(self, snapshot: PaybondPolicySnapshot) -> None: ...


async def reload_policy_on_handle(
    handle: PolicyReloadHandle,
    options: PaybondPolicyReloadOptions | None = None,
    *,
    allowed_tools: list[str] | tuple[str, ...] | None = None,
) -> PaybondPolicyReloadResult:
    opts = options or {}
    await _wait_for_in_flight_count(lambda: handle.in_flight_count)

    try:
        snapshot = await _resolve_reload_snapshot_for_handle(handle, opts)
    except PaybondPolicyReloadUnchangedError:
        return PaybondPolicyReloadResult(
            applied=False,
            previous_digest=handle.policy_digest,
            new_digest=handle.policy_digest,
            unchanged=True,
        )

    resolved_allowed_tools = (
        list(allowed_tools)
        if allowed_tools is not None
        else list(
            handle.current_snapshot.document.intent.allowed_tools
            if handle.current_snapshot is not None
            and handle.current_snapshot.document.intent is not None
            and handle.current_snapshot.document.intent.allowed_tools
            else []
        )
    )
    return await _validate_and_apply_policy_snapshot(handle, snapshot, opts, resolved_allowed_tools)


async def reload_policy_on_run(
    run: PaybondAgentRun,
    options: PaybondPolicyReloadOptions | None = None,
) -> PaybondPolicyReloadResult:
    return await reload_policy_on_handle(
        run,
        options,
        allowed_tools=list(run.allowed_tools),
    )


def apply_policy_snapshot_to_run(run: PaybondAgentRun, snapshot: PaybondPolicySnapshot) -> PaybondPolicyReloadResult:
    previous_digest = run.policy_digest
    if previous_digest and previous_digest == snapshot.digest:
        return PaybondPolicyReloadResult(
            applied=False,
            previous_digest=previous_digest,
            new_digest=snapshot.digest,
            unchanged=True,
        )
    run.apply_policy_snapshot(snapshot)
    return PaybondPolicyReloadResult(
        applied=True,
        previous_digest=previous_digest or snapshot.digest,
        new_digest=snapshot.digest,
    )

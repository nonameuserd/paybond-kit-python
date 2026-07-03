"""Agent middleware CLI commands (parity with kit/ts/src/cli/commands/agent.ts)."""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from paybond_kit.agent.interceptor import PaybondAutoEvidenceSubmitError
from paybond_kit.agent.registry import create_paybond_tool_registry
from paybond_kit.agent.registry_file import (
    AgentRegistryValidationResult,
    build_smoke_registry,
    load_agent_registry_file,
    validate_agent_registry_document,
)
from paybond_kit.agent.run import PaybondAgentRun
from paybond_kit.agent.types import (
    PaybondAgentRunBindConfig,
    PaybondRunBindingAttachInput,
    PaybondRunBindingSandboxBootstrapInput,
    PaybondRunSandboxBinding,
    PaybondToolInputGuardDecision,
    PaybondToolRegistryValidationError,
    PaybondUnregisteredSideEffectingToolError,
)
from paybond_kit.dev.trace_buffer import (
    dev_trace_steps_from_events,
    dev_trace_url,
    find_dev_trace_event_for_run,
    resolve_dev_trace_sink,
)
from paybond_kit.cli.agent_env_write import append_agent_run_env_vars
from paybond_kit.cli.agent_paybond import with_paybond_agent_cli
from paybond_kit.cli.agent_policy_file import resolve_agent_policy_bind, resolve_agent_policy_bind_from_content
from paybond_kit.cli.agent_production_evidence import (
    production_evidence_to_persisted,
    resolve_production_evidence_for_reattach,
    resolve_production_evidence_from_cli,
)
from paybond_kit.cli.agent_run_store import load_agent_run_context, persist_agent_run_context, PersistedAgentRunContext
from paybond_kit.agent.gateway_trace_reporter import (
    create_gateway_agent_run_trace_sink,
    register_gateway_agent_run,
)
from paybond_kit.cli.agent_run_trace_store import (
    agent_run_trace_file_path,
    load_agent_run_trace_if_exists,
    resolve_agent_run_trace_sink,
)
from paybond_kit.cli.agent_run_trace_table import format_agent_run_trace_table
from paybond_kit.policy.reload import PaybondPolicyReloadError, PaybondPolicyReloadOptions
from paybond_kit.policy.sandbox_bootstrap import PaybondPolicySandboxBootstrapError
from paybond_kit import Paybond
from paybond_kit.cli.automation import read_json_body
from paybond_kit.cli.core import (
    CliContext,
    CliError,
    consume_boolean_flag,
    consume_flag,
    parse_optional_non_negative_int,
    parse_required_non_negative_int,
)
from paybond_kit.spend_guard import PaybondSpendApprovalRequiredError, PaybondSpendDeniedError


def _agent_cli_error(
    message: str,
    *,
    code: str,
    exit_code: int = 1,
    category: str = "validation",
    details: dict[str, Any] | None = None,
) -> CliError:
    return CliError(message, category=category, code=code, exit_code=exit_code, details=details)


def _resolve_registry_from_file(registry_file: str, cwd: Path) -> tuple[Any, str, AgentRegistryValidationResult]:
    path = (cwd / registry_file).resolve()
    doc = load_agent_registry_file(path)
    validation = validate_agent_registry_document(doc)
    registry = validation.get("registry")
    if not validation.get("ok") or registry is None:
        message = "; ".join(
            issue["message"]
            for issue in validation.get("issues", [])
            if issue.get("code") != "registry.default_deny_documented"
        )
        raise _agent_cli_error(
            message or "registry validation failed",
            code="cli.agent.registry_invalid",
            details={"issues": validation.get("issues", [])},
        )
    return registry, str(path), validation


def _resolve_registry_for_run(ctx: CliContext, run_id: str) -> tuple[dict[str, Any], Any]:
    stored = load_agent_run_context(ctx.cwd, run_id)
    registry_file = stored.get("registry_file")
    if isinstance(registry_file, str) and registry_file.strip():
        registry, _, _ = _resolve_registry_from_file(registry_file, ctx.cwd)
        return stored, registry
    completion_preset = stored.get("completion_preset")
    operation = stored.get("operation")
    if isinstance(completion_preset, str) and isinstance(operation, str):
        return stored, build_smoke_registry(operation, completion_preset)
    raise _agent_cli_error(
        f"run {run_id} has no registry_file; re-bind with --registry-file",
        code="cli.agent.missing_registry",
    )


def _resolve_bind_trace_sink(ctx: CliContext, run_id: str | None = None, paybond: Any | None = None):
    dev_sink = resolve_dev_trace_sink()
    gateway_sink = (
        create_gateway_agent_run_trace_sink(paybond, run_id)
        if paybond is not None and run_id and run_id.strip()
        else None
    )
    if not run_id or not run_id.strip():
        return gateway_sink or dev_sink
    return resolve_agent_run_trace_sink(ctx.cwd, run_id, None, dev_sink, gateway_sink)


async def _attach_agent_run_from_store(
    paybond: Any,
    ctx: CliContext,
    run_id: str,
    *,
    policy_file: str | None = None,
    payee_signing_seed_hex: str | None = None,
    agent_recognition_signing_seed_hex: str | None = None,
    reattach_command: str = "agent tool execute",
) -> PaybondAgentRun:
    stored = load_agent_run_context(ctx.cwd, run_id)
    policy_path = policy_file or stored.get("registry_file")
    policy_snapshot = None
    policy_file_path: str | None = None
    registry = None

    if stored.get("policy_digest") and isinstance(policy_path, str) and policy_path.strip():
        absolute_policy_path = str((ctx.cwd / policy_path).resolve())
        bind_content = stored.get("policy_bind_content")
        if isinstance(bind_content, str) and bind_content.strip():
            resolved = resolve_agent_policy_bind_from_content(
                policy_path=absolute_policy_path,
                content=bind_content,
                for_attach=True,
            )
        else:
            resolved = resolve_agent_policy_bind(
                cwd=ctx.cwd,
                policy_file=policy_path,
                for_attach=True,
            )
        registry = resolved.registry
        policy_snapshot = resolved.policy_snapshot
        policy_file_path = resolved.policy_path
    else:
        _, registry = _resolve_registry_for_run(ctx, run_id)

    attach: PaybondRunBindingAttachInput = {
        "intent_id": str(stored["intent_id"]),
        "capability_token": str(stored["capability_token"]),
        "allowed_tools": list(stored.get("allowed_tools") or []),
    }
    if stored.get("sandbox"):
        attach["sandbox"] = PaybondRunSandboxBinding(
            operation=str(stored.get("operation", "")),
            requested_spend_cents=int(stored.get("requested_spend_cents") or 0),
            sandbox_lifecycle_status=str(stored.get("sandbox_lifecycle_status") or ""),
        )
    else:
        production_raw = stored.get("production_evidence")
        if not isinstance(production_raw, dict):
            raise _agent_cli_error(
                f"run {run_id} is missing production_evidence; re-bind with production attach flags",
                code="cli.agent.missing_production_evidence",
                category="validation",
            )
        attach["production_evidence"] = resolve_production_evidence_for_reattach(
            cwd=ctx.cwd,
            env_file=ctx.globals.env_file,
            persisted=production_raw,  # type: ignore[arg-type]
            payee_signing_seed_hex=payee_signing_seed_hex,
            agent_recognition_signing_seed_hex=agent_recognition_signing_seed_hex,
            command=reattach_command,
        )
    trace_sink = _resolve_bind_trace_sink(ctx, str(stored["run_id"]), paybond)
    bind_config: PaybondAgentRunBindConfig = {
        "run_id": str(stored["run_id"]),
        "registry": registry,
        "attach": attach,
    }
    if trace_sink is not None:
        bind_config["trace_sink"] = trace_sink
    if policy_snapshot is not None:
        bind_config["policy_snapshot"] = policy_snapshot
    if policy_file_path:
        bind_config["policy_file"] = policy_file_path
    run = await PaybondAgentRun.bind(paybond, bind_config)
    register_gateway_agent_run(
        paybond,
        run,
        completion_preset=str(stored.get("completion_preset") or "") or None,
    )
    return run


def _parse_production_signing_seed_flags(argv: list[str]) -> tuple[str | None, str | None, list[str]]:
    _, payee_seed_hex, argv = consume_flag(argv, "--payee-signing-seed-hex")
    _, recognition_seed_hex, argv = consume_flag(argv, "--agent-recognition-signing-seed-hex")
    return payee_seed_hex, recognition_seed_hex, argv


def _build_reload_status(stored: dict[str, Any]) -> dict[str, Any] | None:
    if not stored.get("reload_watch") and not stored.get("reload_poll") and not stored.get("last_reload_at"):
        return None
    return {
        "watch": bool(stored.get("reload_watch")),
        "poll": bool(stored.get("reload_poll")),
        "last_reload_at": stored.get("last_reload_at"),
    }


def _map_policy_reload_error(err: Exception) -> CliError:
    if isinstance(err, PaybondPolicyReloadError):
        return _agent_cli_error(
            str(err),
            code=f"cli.agent.policy_reload.{err.code}",
            category="validation",
            details={"reload_code": err.code},
        )
    if isinstance(err, CliError):
        return err
    return _agent_cli_error(str(err), code="cli.agent.policy_reload_failed")


def _map_authorization_decision(decision: PaybondToolInputGuardDecision) -> dict[str, Any]:
    if decision.get("kind") == "allow":
        return {
            "allow": True,
            "operation": decision.get("operation"),
            "audit_id": decision.get("audit_id") or decision.get("auditId"),
            "decision_id": decision.get("decision_id") or decision.get("decisionId"),
        }
    return {
        "allow": False,
        "operation": decision.get("operation"),
        "audit_id": decision.get("audit_id") or decision.get("auditId"),
        "decision_id": decision.get("decision_id") or decision.get("decisionId"),
        "message": decision.get("message"),
        "code": decision.get("code"),
    }


def _parse_inline_json(argv: list[str], flag_name: str, file_flag_name: str) -> tuple[dict[str, Any], list[str]]:
    _, inline_value, rest = consume_flag(argv, flag_name)
    _, file_value, rest = consume_flag(rest, file_flag_name)
    if inline_value is not None:
        try:
            parsed = json.loads(inline_value)
        except json.JSONDecodeError as exc:
            raise _agent_cli_error(
                f"invalid {flag_name} JSON",
                code="cli.agent.invalid_json",
                category="usage",
                details={"error": str(exc)},
            ) from exc
        if not isinstance(parsed, dict):
            raise _agent_cli_error(f"invalid {flag_name} JSON", code="cli.agent.invalid_json", category="usage")
        return parsed, rest
    if file_value:
        return read_json_body(file_value, stdin=None), rest
    return {}, rest


def _map_tool_execute_error(err: Exception, *, tool_result: Any) -> CliError:
    if isinstance(err, PaybondSpendDeniedError):
        result = getattr(err, "result", None)
        details: dict[str, Any] = {
            "authorization": {"allow": False, **(result if isinstance(result, dict) else {})},
            "tool_result": tool_result,
        }
        return _agent_cli_error(
            str(err),
            code="cli.agent.authorization_denied",
            exit_code=3,
            category="forbidden",
            details=details,
        )
    if isinstance(err, PaybondSpendApprovalRequiredError):
        result = getattr(err, "result", None)
        return _agent_cli_error(
            str(err),
            code="cli.agent.approval_required",
            exit_code=3,
            category="forbidden",
            details={
                "authorization": {"allow": False, "approval_required": True, **(result if isinstance(result, dict) else {})},
                "tool_result": tool_result,
            },
        )
    if isinstance(err, PaybondUnregisteredSideEffectingToolError):
        return _agent_cli_error(
            str(err),
            code="cli.agent.unregistered_tool",
            exit_code=3,
            category="forbidden",
            details={"tool_result": tool_result},
        )
    if isinstance(err, PaybondAutoEvidenceSubmitError):
        return _agent_cli_error(
            str(err),
            code="cli.agent.evidence_failed",
            exit_code=5,
            category="gateway",
            details={"tool_result": tool_result, "evidence": {"submitted": False}},
        )
    if isinstance(err, PaybondToolRegistryValidationError):
        return _agent_cli_error(str(err), code="cli.agent.registry_invalid", details={"tool_result": tool_result})
    if isinstance(err, CliError):
        return err
    return _agent_cli_error(str(err), code="cli.agent.tool_execute_failed", details={"tool_result": tool_result})


async def handle_agent_run_bind(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    production, argv = consume_boolean_flag(argv, "--production")
    _, argv = consume_boolean_flag(argv, "--sandbox")
    _, policy_file, argv = consume_flag(argv, "--policy-file")
    _, operation, argv = consume_flag(argv, "--operation")
    _, spend_raw, argv = consume_flag(argv, "--requested-spend-cents")
    _, completion_preset, argv = consume_flag(argv, "--completion-preset")
    _, registry_file, argv = consume_flag(argv, "--registry-file")
    _, run_id, argv = consume_flag(argv, "--run-id")
    _, attach_intent_id, argv = consume_flag(argv, "--attach-intent-id")
    _, capability_token, argv = consume_flag(argv, "--capability-token")
    _, payee_did, argv = consume_flag(argv, "--payee-did")
    _, payee_seed_hex, argv = consume_flag(argv, "--payee-signing-seed-hex")
    _, recognition_key_id, argv = consume_flag(argv, "--agent-recognition-key-id")
    _, recognition_seed_hex, argv = consume_flag(argv, "--agent-recognition-signing-seed-hex")
    write_env, argv = consume_boolean_flag(argv, "--write-env")
    _, env_out, argv = consume_flag(argv, "--env-file")
    watch, argv = consume_boolean_flag(argv, "--watch")

    has_attach = bool((attach_intent_id or "").strip() or (capability_token or "").strip())
    if has_attach and (not attach_intent_id or not capability_token):
        raise _agent_cli_error(
            "attach requires both --attach-intent-id and --capability-token",
            code="cli.agent.attach_incomplete",
            category="usage",
        )
    if policy_file and registry_file:
        raise _agent_cli_error(
            "agent run bind accepts --policy-file or --registry-file, not both",
            code="cli.usage.conflicting_args",
            category="usage",
        )
    if watch and not policy_file:
        raise _agent_cli_error(
            "--watch requires --policy-file",
            code="cli.usage.missing_args",
            category="usage",
        )

    async def _bind(paybond: Any, _warnings: list[str]) -> dict[str, Any]:
        registry_path: str | None = None
        policy_path: str | None = None
        default_deny = False
        policy_bootstrap: PaybondRunBindingSandboxBootstrapInput | None = None
        policy_snapshot = None
        resolved_operation = (operation or "").strip()
        resolved_completion_preset = (completion_preset or "").strip() or None

        if policy_file:
            try:
                requested_spend_cents = (
                    parse_required_non_negative_int(spend_raw, field="--requested-spend-cents")
                    if spend_raw is not None
                    else None
                )
                resolved = resolve_agent_policy_bind(
                    cwd=ctx.cwd,
                    policy_file=policy_file,
                    operation=operation,
                    requested_spend_cents=requested_spend_cents,
                    for_attach=has_attach,
                )
            except PaybondPolicySandboxBootstrapError as exc:
                raise _agent_cli_error(
                    str(exc),
                    code="cli.agent.policy_bootstrap_failed",
                    category="validation",
                ) from exc
            registry = resolved.registry
            policy_path = resolved.policy_path
            default_deny = resolved.default_deny
            policy_bootstrap = resolved.bootstrap
            policy_snapshot = resolved.policy_snapshot
            resolved_operation = resolved.operation
            if not resolved_completion_preset and resolved.completion_preset:
                resolved_completion_preset = resolved.completion_preset
        elif registry_file:
            registry, registry_path, validation = _resolve_registry_from_file(registry_file, ctx.cwd)
            default_deny = bool(validation.get("default_deny"))
        elif not has_attach:
            if not operation:
                raise _agent_cli_error(
                    "agent run bind requires --operation, --policy-file, or --attach-intent-id with --capability-token",
                    code="cli.usage.missing_args",
                    category="usage",
                )
            preset = (completion_preset or "cost_and_completion").strip()
            registry = build_smoke_registry(operation, preset)
            default_deny = True
        else:
            registry = create_paybond_tool_registry({"default_deny": False, "side_effecting": {}})

        bind_config: PaybondAgentRunBindConfig = {"registry": registry}
        if policy_snapshot is not None:
            bind_config["policy_snapshot"] = policy_snapshot
        if policy_path:
            bind_config["policy_file"] = policy_path
        if watch and policy_path:
            bind_config["reload"] = {"watch": True}
        if run_id:
            bind_config["run_id"] = run_id
        trace_sink = _resolve_bind_trace_sink(ctx, run_id, paybond)
        if trace_sink is not None:
            bind_config["trace_sink"] = trace_sink
        persisted_production_evidence = None
        if has_attach:
            production_evidence = resolve_production_evidence_from_cli(
                cwd=ctx.cwd,
                env_file=env_out or ctx.globals.env_file,
                payee_did=payee_did,
                payee_signing_seed_hex=payee_seed_hex,
                agent_recognition_key_id=recognition_key_id,
                agent_recognition_signing_seed_hex=recognition_seed_hex,
            )
            persisted_production_evidence = production_evidence_to_persisted(production_evidence)
            bind_config["attach"] = {
                "intent_id": attach_intent_id or "",
                "capability_token": capability_token or "",
                "production_evidence": production_evidence,
            }
        elif policy_bootstrap is not None:
            bind_config["bootstrap"] = policy_bootstrap
        else:
            if not operation or spend_raw is None:
                raise _agent_cli_error(
                    "sandbox bind requires --operation and --requested-spend-cents (or --policy-file)",
                    code="cli.usage.missing_args",
                    category="usage",
                )
            bootstrap: PaybondRunBindingSandboxBootstrapInput = {
                "kind": "sandbox",
                "operation": operation,
                "requested_spend_cents": parse_required_non_negative_int(spend_raw, field="--requested-spend-cents"),
            }
            if completion_preset:
                bootstrap["completion_preset"] = completion_preset
            bind_config["bootstrap"] = bootstrap

        run = await PaybondAgentRun.bind(paybond, bind_config)
        register_gateway_agent_run(
            paybond,
            run,
            completion_preset=resolved_completion_preset
            or (None if registry_path or policy_path or has_attach else "cost_and_completion"),
        )
        sandbox = run.binding.sandbox
        data: dict[str, Any] = {
            "run_id": run.run_id,
            "tenant_id": run.tenant_id,
            "intent_id": str(run.intent_id),
            "capability_token": run.capability_token,
            "operation": sandbox.operation if sandbox else resolved_operation or (run.allowed_tools[0] if run.allowed_tools else ""),
            "sandbox_lifecycle_status": sandbox.sandbox_lifecycle_status if sandbox else "",
            "allowed_tools": list(run.allowed_tools),
        }
        if policy_path:
            data["policy_file"] = policy_path
        if run.policy_digest:
            data["policy_digest"] = run.policy_digest
            data["policy_version"] = run.policy_version
            data["policy_loaded_at"] = run.policy_loaded_at
        if watch and policy_path:
            data["reload"] = {"watch": True}

        policy_bind_content = Path(policy_path).read_text(encoding="utf-8") if policy_path else None

        persist_agent_run_context(
            ctx.cwd,
            PersistedAgentRunContext(
                run_id=run.run_id,
                tenant_id=run.tenant_id,
                intent_id=str(run.intent_id),
                capability_token=run.capability_token,
                operation=str(data["operation"]),
                allowed_tools=list(run.allowed_tools),
                sandbox=bool(sandbox),
                sandbox_lifecycle_status=sandbox.sandbox_lifecycle_status if sandbox else None,
                requested_spend_cents=sandbox.requested_spend_cents if sandbox else None,
                completion_preset=resolved_completion_preset
                or (None if registry_path or policy_path or has_attach else "cost_and_completion"),
                registry_file=registry_path or policy_path,
                default_deny=default_deny,
                policy_digest=run.policy_digest,
                policy_version=run.policy_version,
                policy_loaded_at=run.policy_loaded_at,
                reload_watch=True if watch and policy_path else None,
                policy_bind_content=policy_bind_content,
                production_evidence=persisted_production_evidence,
            ),
        )

        if write_env:
            env_file = env_out or ctx.globals.env_file
            data["env_file"] = append_agent_run_env_vars(
                env_file=env_file,
                cwd=ctx.cwd,
                intent_id=str(run.intent_id),
                capability_token=run.capability_token,
                run_id=run.run_id,
            )
        return data

    return await with_paybond_agent_cli(ctx, production, _bind)


async def handle_agent_run_status(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    _, run_id, _ = consume_flag(argv, "--run-id")
    if not run_id:
        raise _agent_cli_error("agent run status requires --run-id", code="cli.usage.missing_args", category="usage")
    stored = load_agent_run_context(ctx.cwd, run_id)
    reload = _build_reload_status(stored)
    payload: dict[str, Any] = {
        "run_id": stored["run_id"],
        "tenant_id": stored["tenant_id"],
        "intent_id": stored["intent_id"],
        "operation": stored["operation"],
        "allowed_tools": stored.get("allowed_tools") or [],
        "sandbox": stored.get("sandbox"),
        "sandbox_lifecycle_status": stored.get("sandbox_lifecycle_status") or "",
        "registry_file": stored.get("registry_file"),
        "policy_digest": stored.get("policy_digest"),
        "policy_version": stored.get("policy_version"),
        "policy_loaded_at": stored.get("policy_loaded_at"),
    }
    if reload is not None:
        payload["reload"] = reload
    return payload


async def handle_agent_run_trace(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    _, run_id, _ = consume_flag(argv, "--run-id")
    if not run_id:
        raise _agent_cli_error("agent run trace requires --run-id", code="cli.usage.missing_args", category="usage")

    stored = load_agent_run_context(ctx.cwd, run_id)
    persisted = load_agent_run_trace_if_exists(ctx.cwd, run_id)
    dev_event = find_dev_trace_event_for_run(run_id)
    trace_events = (
        persisted.trace_events
        if persisted is not None
        else list(dev_event.get("trace_events") or [])
        if dev_event is not None
        else []
    )
    if not trace_events:
        raise _agent_cli_error(
            f'no trace events for run "{run_id}"; run paybond agent tool execute first',
            code="cli.agent.trace_not_found",
            category="validation",
            details={"run_id": run_id},
        )

    steps = list(dev_event.get("steps") or []) if dev_event is not None else dev_trace_steps_from_events(trace_events)
    trace_lines = format_agent_run_trace_table(
        run_id=str(stored["run_id"]),
        intent_id=str(stored["intent_id"]),
        steps=steps,
        globals=ctx.globals,
    )
    return {
        "run_id": stored["run_id"],
        "intent_id": stored["intent_id"],
        "trace_events": trace_events,
        "steps": steps,
        "trace_lines": trace_lines,
        "trace_url": dev_trace_url(run_id=str(stored["run_id"])),
        "trace_file": str(agent_run_trace_file_path(ctx.cwd, str(stored["run_id"]))) if persisted else None,
        "updated_at": persisted.updated_at if persisted is not None else dev_event.get("recorded_at") if dev_event else None,
    }


async def handle_agent_run_reload_policy(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    production, argv = consume_boolean_flag(argv, "--production")
    _, run_id, argv = consume_flag(argv, "--run-id")
    _, policy_file, argv = consume_flag(argv, "--policy-file")
    remote, argv = consume_boolean_flag(argv, "--remote")
    resolve_inheritance, argv = consume_boolean_flag(argv, "--resolve-inheritance")
    allow_loosen, argv = consume_boolean_flag(argv, "--allow-loosen")
    payee_seed_hex, recognition_seed_hex, _ = _parse_production_signing_seed_flags(argv)

    if not run_id:
        raise _agent_cli_error(
            "agent run reload-policy requires --run-id",
            code="cli.usage.missing_args",
            category="usage",
        )

    stored = load_agent_run_context(ctx.cwd, run_id)
    policy_path = policy_file or stored.get("registry_file")
    if not stored.get("policy_digest") or not isinstance(policy_path, str) or not policy_path.strip():
        raise _agent_cli_error(
            "agent run reload-policy requires a policy-bound run; bind with --policy-file first",
            code="cli.agent.missing_policy",
            category="usage",
        )

    async def _reload(paybond: Paybond, _warnings: list[str]) -> dict[str, Any]:
        run = await _attach_agent_run_from_store(
            paybond,
            ctx,
            run_id,
            policy_file=policy_file or str(policy_path),
            payee_signing_seed_hex=payee_seed_hex,
            agent_recognition_signing_seed_hex=recognition_seed_hex,
            reattach_command="agent run reload-policy",
        )
        reload_options: PaybondPolicyReloadOptions = {
            "allow_loosen": allow_loosen,
        }
        if policy_file:
            reload_options["file"] = str((ctx.cwd / policy_file).resolve())
        if remote:
            reload_options["remote"] = True
        if resolve_inheritance:
            reload_options["resolve_inheritance"] = True
        if remote or resolve_inheritance:
            reload_options["gateway"] = paybond.harbor

        try:
            result = await run.reload_policy(reload_options)
        except Exception as exc:  # noqa: BLE001
            raise _map_policy_reload_error(exc) from exc

        last_reload_at = datetime.now(UTC).isoformat() if result.applied else stored.get("last_reload_at")
        policy_file_on_disk = (ctx.cwd / (policy_file or str(policy_path))).resolve()
        policy_bind_content = (
            policy_file_on_disk.read_text(encoding="utf-8")
            if result.applied
            else stored.get("policy_bind_content")
        )
        persist_agent_run_context(
            ctx.cwd,
            PersistedAgentRunContext(
                run_id=str(stored["run_id"]),
                tenant_id=str(stored["tenant_id"]),
                intent_id=str(stored["intent_id"]),
                capability_token=str(stored["capability_token"]),
                operation=str(stored["operation"]),
                allowed_tools=list(stored.get("allowed_tools") or []),
                sandbox=bool(stored.get("sandbox")),
                sandbox_lifecycle_status=stored.get("sandbox_lifecycle_status"),
                requested_spend_cents=stored.get("requested_spend_cents"),
                completion_preset=stored.get("completion_preset"),
                registry_file=stored.get("registry_file"),
                default_deny=stored.get("default_deny"),
                policy_digest=run.policy_digest,
                policy_version=run.policy_version,
                policy_loaded_at=run.policy_loaded_at,
                reload_watch=stored.get("reload_watch"),
                reload_poll=stored.get("reload_poll"),
                last_reload_at=last_reload_at,
                policy_bind_content=policy_bind_content if isinstance(policy_bind_content, str) else None,
                production_evidence=stored.get("production_evidence")
                if isinstance(stored.get("production_evidence"), dict)
                else None,
                created_at=str(stored.get("created_at") or ""),
            ),
        )
        return {
            "run_id": run.run_id,
            "applied": result.applied,
            "unchanged": result.unchanged or False,
            "previous_digest": result.previous_digest,
            "new_digest": result.new_digest,
            "policy_digest": run.policy_digest,
            "policy_version": run.policy_version,
            "policy_loaded_at": run.policy_loaded_at,
        }

    return await with_paybond_agent_cli(ctx, production, _reload)


async def handle_agent_tool_execute(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    production, argv = consume_boolean_flag(argv, "--production")
    _, run_id, argv = consume_flag(argv, "--run-id")
    _, operation, argv = consume_flag(argv, "--operation")
    _, tool_call_id, argv = consume_flag(argv, "--tool-call-id")
    if not run_id or not operation or not tool_call_id:
        raise _agent_cli_error(
            "agent tool execute requires --run-id, --operation, and --tool-call-id",
            code="cli.usage.missing_args",
            category="usage",
        )

    args, argv = _parse_inline_json(argv, "--arguments", "--arguments-file")
    result_body, argv = _parse_inline_json(argv, "--result-body", "--result-file")
    payee_seed_hex, recognition_seed_hex, _ = _parse_production_signing_seed_flags(argv)
    if not result_body:
        raise _agent_cli_error(
            "agent tool execute requires --result-body or --result-file",
            code="cli.usage.missing_args",
            category="usage",
        )

    async def _execute(paybond: Any, _warnings: list[str]) -> dict[str, Any]:
        run = await _attach_agent_run_from_store(
            paybond,
            ctx,
            run_id,
            payee_signing_seed_hex=payee_seed_hex,
            agent_recognition_signing_seed_hex=recognition_seed_hex,
            reattach_command="agent tool execute",
        )
        try:
            wrapped = await run.interceptor.wrap_execute(
                tool_name=operation,
                tool_call_id=tool_call_id,
                operation=operation,
                arguments=args,
                execute=lambda: result_body,
            )
            evidence = wrapped.evidence
            authorization = wrapped.authorization
            return {
                "authorization": {
                    "allow": True,
                    "audit_id": authorization.get("audit_id") if isinstance(authorization, dict) else None,
                    "decision_id": authorization.get("decision_id") if isinstance(authorization, dict) else None,
                }
                if authorization
                else None,
                "tool_result": wrapped.tool_result,
                "evidence": {
                    "submitted": evidence.submitted,
                    "intent_state": evidence.intent_state,
                    "predicate_passed": evidence.predicate_passed,
                    "sandbox_lifecycle_status": evidence.sandbox_lifecycle_status,
                }
                if evidence is not None
                else None,
            }
        except Exception as exc:  # noqa: BLE001
            raise _map_tool_execute_error(exc, tool_result=result_body) from exc

    return await with_paybond_agent_cli(ctx, production, _execute)


async def handle_agent_tool_validate(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    production, argv = consume_boolean_flag(argv, "--production")
    _, run_id, argv = consume_flag(argv, "--run-id")
    _, operation, argv = consume_flag(argv, "--operation")
    _, spend_raw, argv = consume_flag(argv, "--requested-spend-cents")
    if not run_id or not operation:
        raise _agent_cli_error(
            "agent tool validate requires --run-id and --operation",
            code="cli.usage.missing_args",
            category="usage",
        )
    requested_spend_cents = (
        parse_required_non_negative_int(spend_raw, field="--requested-spend-cents")
        if spend_raw is not None
        else parse_optional_non_negative_int(None, field="--requested-spend-cents")
    )
    args, argv = _parse_inline_json(argv, "--arguments", "--arguments-file")
    payee_seed_hex, recognition_seed_hex, _ = _parse_production_signing_seed_flags(argv)

    async def _validate(paybond: Any, _warnings: list[str]) -> dict[str, Any]:
        run = await _attach_agent_run_from_store(
            paybond,
            ctx,
            run_id,
            payee_signing_seed_hex=payee_seed_hex,
            agent_recognition_signing_seed_hex=recognition_seed_hex,
            reattach_command="agent tool validate",
        )
        decision = await run.interceptor.authorize_tool_call(
            tool_name=operation,
            tool_call_id=f"validate-{int(time.time() * 1000)}",
            operation=operation,
            requested_spend_cents=requested_spend_cents,
            arguments=args,
        )
        authorization = _map_authorization_decision(decision)
        if authorization.get("allow"):
            return {"authorization": authorization}
        raise _agent_cli_error(
            authorization.get("message") or "spend authorization denied",
            code="cli.agent.authorization_denied",
            exit_code=3,
            category="forbidden",
            details={"authorization": authorization},
        )

    return await with_paybond_agent_cli(ctx, production, _validate)


async def handle_agent_registry_validate(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    _, registry_path, _ = consume_flag(argv, "--file")
    if not registry_path:
        raise _agent_cli_error("agent registry validate requires --file", code="cli.usage.missing_args", category="usage")
    doc = load_agent_registry_file((ctx.cwd / registry_path).resolve())
    validation = validate_agent_registry_document(doc)
    return {
        "ok": validation.get("ok"),
        "version": validation.get("version"),
        "default_deny": validation.get("default_deny"),
        "tool_count": validation.get("tool_count"),
        "side_effecting_count": validation.get("side_effecting_count"),
        "issues": validation.get("issues", []),
    }


async def handle_agent_sandbox_smoke(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    production, argv = consume_boolean_flag(argv, "--production")
    _, policy_preset, argv = consume_flag(argv, "--preset")
    _, policy_file, argv = consume_flag(argv, "--policy-file")
    _, operation, argv = consume_flag(argv, "--operation")
    _, spend_raw, argv = consume_flag(argv, "--requested-spend-cents")
    _, evidence_preset, argv = consume_flag(argv, "--evidence-preset")

    resolved_policy_file = policy_file.strip() if policy_file else ""
    solution_preset_id = policy_preset.strip() if policy_preset else ""
    solution_smoke_defaults: dict[str, Any] | None = None
    if solution_preset_id:
        if resolved_policy_file:
            raise _agent_cli_error(
                "agent sandbox smoke accepts --preset or --policy-file, not both",
                code="cli.usage.conflicting_args",
                category="usage",
            )
        try:
            from paybond_kit.policy.presets import resolve_policy_preset_path
            from paybond_kit.solution_catalog import get_solution_smoke_defaults, is_known_solution_id

            resolved_policy_file = resolve_policy_preset_path(solution_preset_id)
            if is_known_solution_id(solution_preset_id):
                solution_smoke_defaults = dict(get_solution_smoke_defaults(solution_preset_id))
        except (ValueError, FileNotFoundError) as exc:
            raise _agent_cli_error(
                str(exc),
                code="cli.agent.policy_preset_invalid",
                category="validation",
            ) from exc

    if resolved_policy_file and (evidence_preset or "").strip():
        raise _agent_cli_error(
            "agent sandbox smoke accepts --policy-file or --evidence-preset, not both; "
            "completion_preset is derived from tool evidence_preset in the policy file",
            code="cli.usage.conflicting_args",
            category="usage",
        )

    resolved_operation = (operation or "").strip() or (
        str(solution_smoke_defaults["operation"]) if solution_smoke_defaults else ""
    )
    resolved_spend = (spend_raw or "").strip() or (
        str(solution_smoke_defaults["requested_spend_cents"]) if solution_smoke_defaults else ""
    )
    resolved_evidence_preset = (evidence_preset or "").strip() or (
        str(solution_smoke_defaults["evidence_preset"]) if solution_smoke_defaults else ""
    )

    if not resolved_policy_file and (not resolved_operation or not resolved_spend or not resolved_evidence_preset):
        raise _agent_cli_error(
            "agent sandbox smoke requires --preset, --policy-file, or "
            "(--operation, --requested-spend-cents, and --evidence-preset)",
            code="cli.usage.missing_args",
            category="usage",
        )
    result_body, _ = _parse_inline_json(argv, "--result-body", "--result-file")
    if not result_body:
        if solution_smoke_defaults:
            result_body = dict(solution_smoke_defaults["result_body"])
        else:
            raise _agent_cli_error(
                "agent sandbox smoke requires --result-body or --result-file",
                code="cli.usage.missing_args",
                category="usage",
            )

    bind_argv: list[str] = []
    if production:
        bind_argv.append("--production")
    if resolved_policy_file:
        bind_argv.extend(["--policy-file", resolved_policy_file])
        if resolved_operation:
            bind_argv.extend(["--operation", resolved_operation])
        if resolved_spend:
            bind_argv.extend(["--requested-spend-cents", resolved_spend])
    else:
        bind_argv.extend(
            [
                "--operation",
                resolved_operation,
                "--requested-spend-cents",
                resolved_spend,
                "--completion-preset",
                resolved_evidence_preset,
            ]
        )
    bind_data = await handle_agent_run_bind(ctx, bind_argv)
    smoke_operation = str(bind_data.get("operation") or resolved_operation or "")
    run_id = str(bind_data["run_id"])
    stored_for_execute = load_agent_run_context(ctx.cwd, run_id)
    execute_argv: list[str] = [
        *(["--production"] if production else []),
        "--run-id",
        run_id,
        "--operation",
        smoke_operation,
        "--tool-call-id",
        "smoke-1",
        "--result-body",
        json.dumps(result_body),
    ]
    bind_spend = stored_for_execute.get("requested_spend_cents")
    if bind_spend is not None:
        execute_argv.extend(["--requested-spend-cents", str(bind_spend)])
    elif resolved_spend:
        execute_argv.extend(["--requested-spend-cents", resolved_spend])
    try:
        execute_data = await handle_agent_tool_execute(ctx, execute_argv)
    except CliError as exc:
        details = dict(exc.details or {})
        details["bind"] = bind_data
        raise CliError(exc.message, category=exc.category, code=exc.code, exit_code=exc.exit_code, details=details) from exc

    from paybond_kit.cli.agent_sandbox_smoke_checklist import format_agent_sandbox_smoke_checklist
    from paybond_kit.cli.smoke_deep_links import (
        append_smoke_deep_link_checklist_lines,
        build_agent_sandbox_smoke_deep_links,
    )
    from paybond_kit.dev.trace_buffer import record_smoke_trace_event

    stored = load_agent_run_context(ctx.cwd, run_id)
    bind_for_checklist = {
        **bind_data,
        "completion_preset": stored.get("completion_preset"),
        "requested_spend_cents": stored.get("requested_spend_cents"),
    }
    checklist_lines = append_smoke_deep_link_checklist_lines(
        format_agent_sandbox_smoke_checklist(
            preset_id=policy_preset,
            bind=bind_for_checklist,
            execute=execute_data,
            result_body=result_body,
            globals_=ctx.globals,
        ),
        build_agent_sandbox_smoke_deep_links(bind_for_checklist),
        ctx.globals,
    )
    deep_links = build_agent_sandbox_smoke_deep_links(bind_for_checklist)
    record_smoke_trace_event(
        preset=policy_preset or "travel",
        bind=bind_for_checklist,
        execute=execute_data,
        result_body=result_body,
        cwd=ctx.cwd,
    )
    return {"bind": bind_data, "execute": execute_data, "checklist_lines": checklist_lines, **deep_links}


async def handle_agent_demo_langgraph_smoke(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    production, argv = consume_boolean_flag(argv, "--production")
    _, runtime_flag, argv = consume_flag(argv, "--runtime")
    _, operation_flag, argv = consume_flag(argv, "--operation")
    _, spend_flag, argv = consume_flag(argv, "--requested-spend-cents")
    _, preset_flag, _ = consume_flag(argv, "--evidence-preset")
    if not operation_flag or not spend_flag or not preset_flag:
        raise _agent_cli_error(
            "agent demo langgraph smoke requires --operation, --requested-spend-cents, and --evidence-preset",
            code="cli.usage.missing_args",
            category="usage",
        )

    runtime = (runtime_flag or "python").strip().lower()
    if runtime != "python":
        raise _agent_cli_error(
            f"agent demo langgraph smoke --runtime {runtime} is not supported in the Python CLI; use @paybond/kit TypeScript CLI",
            code="cli.usage.unsupported_runtime",
            category="usage",
        )

    requested_spend_cents = parse_required_non_negative_int(
        spend_flag,
        field="--requested-spend-cents",
    )

    async def _run(paybond: Paybond, _warnings: list[str]) -> dict[str, Any]:
        from paybond_kit.langgraph_sandbox_demo import run_langgraph_sandbox_demo

        demo = await run_langgraph_sandbox_demo(
            paybond,
            operation=operation_flag,
            requested_spend_cents=requested_spend_cents,
            evidence_preset=preset_flag,
        )

        if not demo.get("authorization", {}).get("allow"):
            raise _agent_cli_error(
                "LangGraph sandbox demo authorization did not pass",
                code="cli.agent.authorization_denied",
                exit_code=3,
                category="forbidden",
                details={"tool_message": demo.get("tool_message")},
            )

        tool_message = demo.get("tool_message") or {}
        if tool_message.get("status") == "error":
            raise _agent_cli_error(
                "LangGraph sandbox demo returned an error tool message",
                code="cli.agent.tool_execute_failed",
                details={"tool_message": tool_message},
            )

        return demo

    return await with_paybond_agent_cli(ctx, production, _run)


async def handle_agent_demo_generic_smoke(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    production, argv = consume_boolean_flag(argv, "--production")
    _, runtime_flag, argv = consume_flag(argv, "--runtime")
    _, operation_flag, argv = consume_flag(argv, "--operation")
    _, spend_flag, argv = consume_flag(argv, "--requested-spend-cents")
    _, preset_flag, _ = consume_flag(argv, "--evidence-preset")
    if not operation_flag or not spend_flag or not preset_flag:
        raise _agent_cli_error(
            "agent demo generic smoke requires --operation, --requested-spend-cents, and --evidence-preset",
            code="cli.usage.missing_args",
            category="usage",
        )

    runtime = (runtime_flag or "python").strip().lower()
    if runtime != "python":
        raise _agent_cli_error(
            f"agent demo generic smoke --runtime {runtime} is not supported in the Python CLI; use @paybond/kit TypeScript CLI",
            code="cli.usage.unsupported_runtime",
            category="usage",
        )

    requested_spend_cents = parse_required_non_negative_int(
        spend_flag,
        field="--requested-spend-cents",
    )

    async def _run(paybond: Paybond, _warnings: list[str]) -> dict[str, Any]:
        from paybond_kit.generic_sandbox_demo import run_generic_sandbox_demo

        demo = await run_generic_sandbox_demo(
            paybond,
            operation=operation_flag,
            requested_spend_cents=requested_spend_cents,
            evidence_preset=preset_flag,
        )

        if not demo.get("authorization", {}).get("allow"):
            raise _agent_cli_error(
                "generic sandbox demo authorization did not pass",
                code="cli.agent.authorization_denied",
                exit_code=3,
                category="forbidden",
                details={"authorization": demo.get("authorization")},
            )

        execute = demo.get("execute") or {}
        if not execute.get("tool_result"):
            raise _agent_cli_error(
                "generic sandbox demo did not produce a paid tool result",
                code="cli.agent.tool_execute_failed",
                details={"execute": execute},
            )

        return demo

    return await with_paybond_agent_cli(ctx, production, _run)


async def handle_agent_demo_claude_agents_smoke(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    production, argv = consume_boolean_flag(argv, "--production")
    _, runtime_flag, argv = consume_flag(argv, "--runtime")
    _, operation_flag, argv = consume_flag(argv, "--operation")
    _, spend_flag, argv = consume_flag(argv, "--requested-spend-cents")
    _, preset_flag, _ = consume_flag(argv, "--evidence-preset")
    if not operation_flag or not spend_flag or not preset_flag:
        raise _agent_cli_error(
            "agent demo claude-agents smoke requires --operation, --requested-spend-cents, and --evidence-preset",
            code="cli.usage.missing_args",
            category="usage",
        )

    runtime = (runtime_flag or "python").strip().lower()
    if runtime != "python":
        raise _agent_cli_error(
            f"agent demo claude-agents smoke --runtime {runtime} is not supported in the Python CLI; use @paybond/kit TypeScript CLI",
            code="cli.usage.unsupported_runtime",
            category="usage",
        )

    requested_spend_cents = parse_required_non_negative_int(
        spend_flag,
        field="--requested-spend-cents",
    )

    async def _run(paybond: Paybond, _warnings: list[str]) -> dict[str, Any]:
        from paybond_kit.claude_agents_sandbox_demo import run_claude_agents_sandbox_demo

        demo = await run_claude_agents_sandbox_demo(
            paybond,
            operation=operation_flag,
            requested_spend_cents=requested_spend_cents,
            evidence_preset=preset_flag,
        )

        if not demo.get("evidence", {}).get("submitted"):
            raise _agent_cli_error(
                "Claude Agents sandbox demo did not submit evidence",
                code="cli.agent.evidence_failed",
                exit_code=5,
                category="gateway",
                details={"tool_result": demo.get("tool_result")},
            )

        if not demo.get("tool_result"):
            raise _agent_cli_error(
                "Claude Agents sandbox demo did not produce a paid tool result",
                code="cli.agent.tool_execute_failed",
                details={"allowed_tools": demo.get("allowed_tools")},
            )

        return demo

    return await with_paybond_agent_cli(ctx, production, _run)


async def handle_agent(ctx: CliContext, group: str, subcommand: str, argv: list[str]) -> dict[str, Any]:
    if group == "run" and subcommand == "bind":
        return await handle_agent_run_bind(ctx, argv)
    if group == "run" and subcommand == "status":
        return await handle_agent_run_status(ctx, argv)
    if group == "run" and subcommand == "trace":
        return await handle_agent_run_trace(ctx, argv)
    if group == "run" and subcommand == "reload-policy":
        return await handle_agent_run_reload_policy(ctx, argv)
    if group == "tool" and subcommand == "execute":
        return await handle_agent_tool_execute(ctx, argv)
    if group == "tool" and subcommand == "validate":
        return await handle_agent_tool_validate(ctx, argv)
    if group == "registry" and subcommand == "validate":
        return await handle_agent_registry_validate(ctx, argv)
    if group == "sandbox" and subcommand == "smoke":
        return await handle_agent_sandbox_smoke(ctx, argv)
    if group == "demo" and subcommand == "langgraph":
        if not argv or argv[0] != "smoke":
            raise _agent_cli_error(
                "agent demo langgraph requires smoke subcommand",
                code="cli.usage.unknown_command",
                category="usage",
            )
        return await handle_agent_demo_langgraph_smoke(ctx, argv[1:])
    if group == "demo" and subcommand == "generic":
        if not argv or argv[0] != "smoke":
            raise _agent_cli_error(
                "agent demo generic requires smoke subcommand",
                code="cli.usage.unknown_command",
                category="usage",
            )
        return await handle_agent_demo_generic_smoke(ctx, argv[1:])
    if group == "demo" and subcommand == "claude-agents":
        if not argv or argv[0] != "smoke":
            raise _agent_cli_error(
                "agent demo claude-agents requires smoke subcommand",
                code="cli.usage.unknown_command",
                category="usage",
            )
        return await handle_agent_demo_claude_agents_smoke(ctx, argv[1:])
    raise _agent_cli_error(
        f"unknown agent subcommand: agent {group} {subcommand}",
        code="cli.usage.unknown_command",
        category="usage",
    )

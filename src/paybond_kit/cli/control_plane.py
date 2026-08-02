"""Tier C control-plane commands: status, open, shell, control."""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

from paybond_kit.cli.core import (
    EXIT_SUCCESS,
    CliContext,
    CliError,
    consume_flag,
    gateway_request,
    resolve_api_key_with_meta,
)
from paybond_kit.cli.next_actions import KIT_HAPPY_PATH_COMMANDS, with_next_actions
from paybond_kit.login import mask_api_key
from paybond_kit.cli.tty import must_be_non_interactive
from paybond_kit.dev.trace_buffer import (
    DEV_AUDIT_FILE,
    DEV_DEFAULT_POLICY_FILE,
    DEV_TRACE_DEFAULT_PORT,
    DEV_TRACE_FILE,
    dev_trace_url,
    list_dev_trace_events,
)

DEFAULT_CONSOLE_ORIGIN = "http://127.0.0.1:3000"
SHELL_BLOCKED = frozenset({"shell", "control"})


def _file_meta(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"path": str(path), "present": False}
    st = path.stat()
    return {
        "path": str(path),
        "present": True,
        "mtime": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat().replace("+00:00", "Z"),
        "bytes": st.st_size,
    }


def _last_jsonl(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        return None
    try:
        parsed = json.loads(lines[-1])
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


async def handle_status(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    if argv and argv[0] in ("--help", "-h"):
        raise CliError("help", code="cli.help")
    present, policy_file, rest = consume_flag(argv, "--policy-file")
    del present
    if rest:
        raise CliError(f"unexpected arguments: {' '.join(rest)}", code="cli.usage.unexpected_args")

    policy_path = (ctx.cwd / (policy_file or DEV_DEFAULT_POLICY_FILE)).resolve()
    env_path = (ctx.cwd / ctx.globals.env_file).resolve()
    audit_path = ctx.cwd / DEV_AUDIT_FILE
    trace_path = ctx.cwd / DEV_TRACE_FILE
    trace_url = dev_trace_url(DEV_TRACE_DEFAULT_PORT)

    auth: dict[str, Any] = {
        "authenticated": False,
        "source": "none",
        "env_file": str(env_path),
        "gateway": ctx.globals.gateway,
    }
    try:
        api_key, _cred_warnings = resolve_api_key_with_meta(ctx.globals, ctx.cwd)
        auth = {
            "authenticated": True,
            "source": "process_env" if (os.environ.get("PAYBOND_API_KEY") or "").strip() else "env_file",
            "env_file": str(env_path),
            "gateway": ctx.globals.gateway,
            "key_masked": mask_api_key(api_key),
            "profile": ctx.globals.profile,
        }
        try:
            principal = gateway_request(ctx, "GET", "/v1/auth/principal")
            auth.update(
                {
                    "tenant_id": principal.get("tenant_id") or principal.get("tenantId"),
                    "tenant_uuid": principal.get("tenant_uuid") or principal.get("tenantUuid"),
                    "environment": principal.get("environment"),
                    "service_account_role": principal.get("service_account_role") or principal.get("role"),
                }
            )
        except Exception:
            auth["principal_error"] = "unable to resolve principal; run paybond whoami"
    except CliError:
        auth["next"] = "paybond login"

    events = list_dev_trace_events(ctx.cwd)
    last_event = events[-1] if events else None
    last_audit = _last_jsonl(audit_path)
    last_smoke = None
    if last_event or last_audit:
        src = last_event or last_audit or {}
        last_smoke = {
            "recorded_at": str(src.get("recorded_at") or ""),
            "operation": str(src.get("operation") or ""),
            "authorized": bool(src.get("authorized")),
            "run_id": src.get("run_id"),
            "intent_id": src.get("intent_id"),
            "source": "dev-trace" if last_event else "dev-audit",
        }

    next_commands = (
        ["paybond agent sandbox smoke --help", "paybond control", "paybond dev trace"]
        if auth.get("authenticated")
        else ["paybond login", "paybond init", "paybond status"]
    )
    return {
        "auth": auth,
        "policy": _file_meta(policy_path),
        "last_smoke": last_smoke,
        "trace": {
            "url": trace_url,
            "port": DEV_TRACE_DEFAULT_PORT,
            **_file_meta(trace_path),
            "event_count": len(events),
        },
        "audit_log": _file_meta(audit_path),
        "happy_path": list(KIT_HAPPY_PATH_COMMANDS),
        "next_commands": next_commands,
    }


def resolve_open_target(resource: str, resource_id: str | None = None, port: int | None = None) -> dict[str, str]:
    kind = resource.strip().lower()
    console = (os.environ.get("PAYBOND_CONSOLE_BASE_URL") or os.environ.get("PAYBOND_PUBLIC_BASE_URL") or DEFAULT_CONSOLE_ORIGIN).rstrip("/")
    docs = (os.environ.get("PAYBOND_DOCS_BASE_URL") or "https://paybond.ai/docs").rstrip("/")
    if kind == "console":
        return {"kind": kind, "url": f"{console}/console", "purpose": "Tenant admin console home (billing, SSO/SCIM, operators)"}
    if kind == "billing":
        return {"kind": kind, "url": f"{console}/console/configuration/billing", "purpose": "Billing and plan management (console-only)"}
    if kind == "sso":
        return {"kind": kind, "url": f"{console}/console/configuration/identity/sso", "purpose": "SSO federation configuration (console-only)"}
    if kind == "scim":
        return {"kind": kind, "url": f"{console}/console/configuration/identity/scim", "purpose": "SCIM provisioning configuration (console-only)"}
    if kind == "compliance-exports":
        return {"kind": kind, "url": f"{console}/console/investigations/compliance-exports", "purpose": "Compliance export investigation workspace (console)"}
    if kind == "docs":
        return {"kind": kind, "url": f"{docs}/kit", "purpose": "Kit documentation"}
    if kind == "trace":
        return {"kind": kind, "url": dev_trace_url(port or DEV_TRACE_DEFAULT_PORT, resource_id), "purpose": "Local terminal-native trace dashboard"}
    if kind == "intent":
        if not resource_id:
            raise CliError(
                "open intent requires <intent_id>",
                code="cli.usage.missing_intent_id",
                details=with_next_actions(None, what="missing intent id", why="console intent deep links need a Harbor intent UUID", next="paybond open intent <intent_id>"),
            )
        return {
            "kind": kind,
            "url": f"{console}/console/operations/intents/{quote(resource_id, safe='')}",
            "purpose": "Intent dossier in console (admin investigation)",
        }
    if kind == "export":
        if not resource_id:
            raise CliError(
                "open export requires <job_id>",
                code="cli.usage.missing_job_id",
                details=with_next_actions(None, what="missing export job id", why="compliance export deep links need a job id", next="paybond audit exports list --format json"),
            )
        return {
            "kind": kind,
            "url": f"{console}/console/investigations/compliance-exports?job={quote(resource_id, safe='')}",
            "purpose": "Compliance export job in console",
        }
    raise CliError(
        f"unknown open resource: {resource} (expected console|billing|sso|scim|intent|export|trace|compliance-exports|docs)",
        code="cli.usage.invalid_open_resource",
        details=with_next_actions(None, what="unknown resource", why=f"{resource} is not a supported deep-link target", next="paybond open --help"),
    )


def _open_browser(url: str) -> bool:
    if sys.platform == "darwin":
        cmd = ["open", url]
    elif sys.platform == "win32":
        cmd = ["cmd", "/c", "start", "", url]
    else:
        cmd = ["xdg-open", url]
    try:
        completed = subprocess.run(cmd, check=False, capture_output=True)
        return completed.returncode == 0
    except OSError:
        return False


async def handle_open(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    if not argv or argv[0] in ("--help", "-h"):
        raise CliError("help", code="cli.help")
    present, port_raw, rest = consume_flag(argv, "--port")
    del present
    no_open = "--no-open" in rest
    positionals = [part for part in rest if part != "--no-open" and not part.startswith("-")]
    unknown = [part for part in rest if part.startswith("-") and part != "--no-open"]
    if unknown:
        raise CliError(f"unexpected flag: {unknown[0]}", code="cli.usage.unknown_flag")
    if len(positionals) > 2:
        raise CliError(f"unexpected arguments: {' '.join(positionals[2:])}", code="cli.usage.unexpected_args")
    if not positionals:
        raise CliError(
            "open requires <resource>",
            code="cli.usage.missing_open_resource",
            details=with_next_actions(None, what="missing resource", why="open needs an explicit deep-link target", next="paybond open console"),
        )
    port = None
    if port_raw:
        port = int(port_raw)
        if port < 1 or port > 65535:
            raise CliError("open --port must be a valid TCP port", code="cli.usage.invalid_port")
    target = resolve_open_target(positionals[0], positionals[1] if len(positionals) > 1 else None, port)
    warnings: list[str] = []
    should_open = not ctx.globals.no_open and not no_open
    opened = False
    if should_open:
        opened = _open_browser(target["url"])
        if not opened:
            warnings.append("browser open failed; copy the URL manually")
    else:
        warnings.append("browser open skipped (--no-open)")
    return {
        "resource": target["kind"],
        "url": target["url"],
        "purpose": target["purpose"],
        "opened": opened,
        "note": "Console deep links are for rare admin tasks (billing, SSO/SCIM). Prefer paybond status / control / shell for Kit work.",
        "warnings": warnings,
    }


async def handle_shell(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    if argv and argv[0] in ("--help", "-h"):
        raise CliError("help", code="cli.help")
    present, exec_cmd, rest = consume_flag(argv, "--exec")
    del present
    if rest:
        raise CliError(
            f"unexpected arguments: {' '.join(rest)}",
            code="cli.usage.unexpected_args",
            details=with_next_actions(None, what="unexpected shell args", why="use --exec for one-shot", next='paybond shell --exec "status"'),
        )

    sticky_flags = ["--gateway", ctx.globals.gateway, "--env-file", ctx.globals.env_file]
    if ctx.globals.profile:
        sticky_flags.extend(["--profile", ctx.globals.profile])

    from paybond_kit.cli.router import run_cli

    async def _run_line(line: str) -> tuple[int, list[str]]:
        try:
            tokens = shlex.split(line, posix=True)
        except ValueError as exc:
            raise CliError("unclosed quote in shell input", code="cli.shell.unclosed_quote") from exc
        if not tokens:
            return EXIT_SUCCESS, []
        if tokens[0] in {"exit", "quit"}:
            return EXIT_SUCCESS, ["exit"]
        if tokens[0] in SHELL_BLOCKED:
            raise CliError(
                f"refusing to nest '{tokens[0]}' inside paybond shell",
                code="cli.shell.nested_forbidden",
                details=with_next_actions(None, what="nested interactive command", why="shell already provides sticky context", next="type status, whoami, or help <command>"),
            )
        code = await run_cli([*sticky_flags, *tokens], stdout=ctx.stdout, stderr=ctx.stderr)
        return code, tokens

    if exec_cmd is not None:
        code, tokens = await _run_line(exec_cmd)
        if tokens and tokens[0] == "exit":
            return {"mode": "exec", "exited": True, "exit_code": EXIT_SUCCESS}
        return {
            "mode": "exec",
            "command": exec_cmd,
            "exit_code": code,
            "sticky": {
                "gateway": ctx.globals.gateway,
                "env_file": ctx.globals.env_file,
                "profile": ctx.globals.profile,
            },
        }

    if must_be_non_interactive(ctx.globals):
        raise CliError(
            'paybond shell requires an interactive TTY; use --exec "<command>" in CI/non-TTY',
            code="cli.shell.non_interactive",
            details=with_next_actions(None, what="non-interactive shell", why="REPL would hang without a TTY", next='paybond shell --exec "status --format json"'),
        )

    if ctx.globals.format != "json":
        ctx.stdout.write(
            f"Paybond shell (sticky gateway={ctx.globals.gateway} env-file={ctx.globals.env_file}). Type help, status, or exit.\n"
        )
    commands_run = 0
    profile = f" profile={ctx.globals.profile}" if ctx.globals.profile else ""
    while True:
        try:
            line = input(f"paybond{profile}> ")
        except EOFError:
            break
        try:
            code, tokens = await _run_line(line)
        except CliError as exc:
            ctx.stderr.write(f"{exc.message}\n")
            continue
        if tokens and tokens[0] == "exit":
            break
        if tokens:
            commands_run += 1
            if code != EXIT_SUCCESS and ctx.globals.format != "json":
                ctx.stderr.write(f"[exit {code}]\n")
    return {
        "mode": "repl",
        "commands_run": commands_run,
        "sticky": {
            "gateway": ctx.globals.gateway,
            "env_file": ctx.globals.env_file,
            "profile": ctx.globals.profile,
        },
    }


def _as_object_rows(body: dict[str, Any], keys: list[str]) -> list[dict[str, Any]]:
    for key in keys:
        value = body.get(key)
        if isinstance(value, list):
            return [row for row in value if isinstance(row, dict)]
    return []


def _is_denial_outcome(outcome: Any) -> bool:
    if not isinstance(outcome, str):
        return False
    normalized = outcome.strip().lower()
    return normalized in {"deny", "denied", "reject", "rejected"} or "deny" in normalized


def _map_decision_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row.get("id"),
        "intent_id": row.get("intent_id"),
        "operation": row.get("operation"),
        "amount_cents": row.get("amount_cents"),
        "currency": row.get("currency"),
        "outcome": row.get("outcome"),
        "remaining_cents": row.get("remaining_cents"),
        "reason_codes": row.get("reason_codes") or [],
        "tool_name": row.get("tool_name"),
        "created_at": row.get("created_at"),
    }


def _unavailable_spend(next_cmd: str) -> dict[str, Any]:
    return {
        "source": "unavailable",
        "decisions": [],
        "active_reservations": [],
        "policy": None,
        "latest_remaining_cents": None,
        "next": next_cmd,
    }


def _gather_snapshot(ctx: CliContext, *, policy_file: str | None, limit: int) -> dict[str, Any]:
    """Live gateway snapshot for control panels. Tenant scope comes from credentials only."""
    limitations: list[str] = []
    policy_path = (ctx.cwd / (policy_file or DEV_DEFAULT_POLICY_FILE)).resolve()
    tenant_id = None
    environment = None
    intents: list[dict[str, Any]] = []
    receipts: list[dict[str, Any]] = []
    spend = _unavailable_spend("paybond login")
    denials: list[dict[str, Any]] = []

    policy: dict[str, Any] = {"path": str(policy_path), "present": policy_path.exists(), "source": "local_file"}
    if policy_path.exists():
        body = policy_path.read_text(encoding="utf-8")
        policy["bytes"] = len(body)
        name_match = re.search(r'^\s*name:\s*["\']?([^"\'\n]+)', body, re.M)
        op_match = re.search(r'^\s*operation:\s*["\']?([^"\'\n]+)', body, re.M)
        if name_match:
            policy["name"] = name_match.group(1).strip()
        if op_match:
            policy["operation"] = op_match.group(1).strip()

    try:
        principal = gateway_request(ctx, "GET", "/v1/auth/principal")
        tenant_id = principal.get("tenant_id")
        environment = principal.get("environment")
    except CliError as exc:
        if exc.category == "auth":
            limitations.append("not authenticated — run paybond login")
            return {
                "tenant_id": tenant_id,
                "environment": environment,
                "gateway": ctx.globals.gateway,
                "trace_url": dev_trace_url(DEV_TRACE_DEFAULT_PORT),
                "panels": {
                    "intents": intents,
                    "receipts": receipts,
                    "policy": policy,
                    "spend": spend,
                    "denials": denials,
                },
                "generated_at": datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z"),
                "limitations": limitations,
            }
        limitations.append(f"principal lookup failed: {exc.message}")
    except Exception as exc:  # noqa: BLE001
        limitations.append(f"principal lookup failed: {exc}")

    try:
        body = gateway_request(ctx, "GET", f"/harbor/operator/v1/intents?limit={limit}")
        for row in _as_object_rows(body, ["intents", "items", "data"])[:limit]:
            intents.append(
                {
                    "intent_id": row.get("intent_id") or row.get("id"),
                    "status": row.get("status"),
                    "amount_cents": row.get("amount_cents") or row.get("amount"),
                    "created_at": row.get("created_at"),
                }
            )
    except Exception:  # noqa: BLE001
        limitations.append("intents list unavailable (gateway path or RBAC) — need harbor.read / operator")

    try:
        body = gateway_request(ctx, "GET", f"/protocol/v2/agent-receipts?limit={limit}")
        rows = _as_object_rows(body, ["items", "receipts", "data"])
        if not rows:
            limitations.append("no agent receipts yet for this tenant")
        for row in rows[:limit]:
            receipts.append(
                {
                    "receipt_id": row.get("receipt_id") or row.get("id"),
                    "scope": row.get("scope"),
                    "intent_id": row.get("intent_id"),
                    "tool_call_id": row.get("tool_call_id"),
                    "message_digest_sha256_hex": row.get("message_digest_sha256_hex"),
                    "created_at": row.get("created_at"),
                    "source": "gateway",
                }
            )
    except Exception:  # noqa: BLE001
        limitations.append(
            "receipts list unavailable — need GET /protocol/v2/agent-receipts (harbor.read or harbor.write)"
        )

    decisions: list[dict[str, Any]] = []
    spend_policy: dict[str, Any] | None = None
    reservations: list[dict[str, Any]] = []
    decisions_loaded = False
    try:
        body = gateway_request(ctx, "GET", f"/v1/admin/spend-controls/decisions?limit={limit}")
        decisions = [_map_decision_row(row) for row in _as_object_rows(body, ["items", "data"])[:limit]]
        decisions_loaded = True
    except Exception:  # noqa: BLE001
        limitations.append(
            "spend decisions unavailable — need GET /v1/admin/spend-controls/decisions (harbor.read)"
        )

    try:
        body = gateway_request(ctx, "GET", "/v1/admin/spend-controls/policy")
        spend_policy = {
            "source": body.get("source", "gateway"),
            "configured": body.get("configured", False),
            "mode": body.get("mode"),
            "policy_version": body.get("policy_version"),
            "updated_at": body.get("updated_at"),
        }
    except Exception:  # noqa: BLE001
        limitations.append("spend policy unavailable (optional panel enrichment)")

    try:
        body = gateway_request(
            ctx, "GET", f"/v1/admin/spend-controls/reservations?status=active&limit={limit}"
        )
        for row in _as_object_rows(body, ["items", "data"])[:limit]:
            reservations.append(
                {
                    "id": row.get("id"),
                    "intent_id": row.get("intent_id"),
                    "amount_cents": row.get("amount_cents"),
                    "currency": row.get("currency"),
                    "status": row.get("status"),
                    "expires_at": row.get("expires_at"),
                }
            )
    except Exception:  # noqa: BLE001
        pass

    denials = [row for row in decisions if _is_denial_outcome(row.get("outcome"))]
    if decisions_loaded and not decisions:
        limitations.append("no spend authorization decisions yet for this tenant")
    if decisions and not denials:
        limitations.append("no denied spend decisions in the latest page")

    latest_remaining = next(
        (row.get("remaining_cents") for row in decisions if isinstance(row.get("remaining_cents"), int)),
        None,
    )
    if not decisions_loaded:
        spend = _unavailable_spend("paybond doctor --agent")
        spend["policy"] = spend_policy
    else:
        spend = {
            "source": "gateway",
            "decisions": decisions,
            "active_reservations": reservations,
            "policy": spend_policy,
            "latest_remaining_cents": latest_remaining,
            "note": (
                "Budget remaining for a specific intent: "
                "paybond spend budget-remaining --intent-id <id> --operation <op> --requested-spend-cents <n>"
            ),
        }

    return {
        "tenant_id": tenant_id,
        "environment": environment,
        "gateway": ctx.globals.gateway,
        "trace_url": dev_trace_url(DEV_TRACE_DEFAULT_PORT),
        "panels": {
            "intents": intents,
            "receipts": receipts,
            "policy": policy,
            "spend": spend,
            "denials": denials,
        },
        "generated_at": datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z"),
        "limitations": limitations,
    }


def _truncate(value: str, max_len: int) -> str:
    if len(value) <= max_len:
        return value
    return value[: max(0, max_len - 1)] + "…"


def _render_control_panel_lines(active: str, snapshot: dict[str, Any]) -> list[str]:
    panels = snapshot.get("panels") or {}
    lines = [
        f"Paybond control · {active}",
        f"tenant={snapshot.get('tenant_id')} env={snapshot.get('environment')}",
        f"gateway={snapshot.get('gateway')}",
        "",
    ]
    data = panels.get(active)
    if active == "intents":
        rows = data if isinstance(data, list) else []
        if not rows:
            lines.append("(no intents)")
        else:
            for row in rows:
                lines.append(
                    f"{_truncate(str(row.get('intent_id') or ''), 36)}  {row.get('status') or '-'}  {row.get('amount_cents') or '-'}"
                )
    elif active == "receipts":
        rows = data if isinstance(data, list) else []
        if not rows:
            lines.append("(no receipts)")
        else:
            for row in rows:
                lines.append(
                    f"{_truncate(str(row.get('receipt_id') or ''), 28)}  {row.get('scope') or '-'}  intent={_truncate(str(row.get('intent_id') or ''), 36)}"
                )
    elif active == "policy":
        policy = data if isinstance(data, dict) else {}
        lines.extend(
            [
                f"path: {policy.get('path')}",
                f"present: {policy.get('present')}",
                f"source: {policy.get('source') or 'local_file'}",
            ]
        )
        if policy.get("name"):
            lines.append(f"name: {policy['name']}")
        if policy.get("operation"):
            lines.append(f"operation: {policy['operation']}")
    elif active == "spend":
        spend = data if isinstance(data, dict) else {}
        source = str(spend.get("source") or "unavailable")
        lines.append(f"source: {source}")
        lines.append(f"latest_remaining_cents: {spend.get('latest_remaining_cents') or '-'}")
        if source == "unavailable":
            lines.append(f"next: {spend.get('next') or 'paybond login'}")
        else:
            decisions = spend.get("decisions") if isinstance(spend.get("decisions"), list) else []
            if not decisions:
                lines.append("(no recent spend decisions)")
            else:
                for row in decisions[:12]:
                    if not isinstance(row, dict):
                        continue
                    lines.append(
                        f"{row.get('created_at') or '-'}  {row.get('outcome') or '-'}  "
                        f"{row.get('operation') or '-'}  {row.get('amount_cents') or '-'}¢  "
                        f"rem={row.get('remaining_cents') or '-'}"
                    )
    elif active == "denials":
        rows = data if isinstance(data, list) else []
        if not rows:
            lines.append("(no recent denials from gateway spend decisions)")
        else:
            for row in rows:
                reasons = row.get("reason_codes") if isinstance(row.get("reason_codes"), list) else []
                lines.append(
                    f"{row.get('created_at') or '-'}  {row.get('operation') or '-'}  "
                    f"{row.get('outcome') or '-'}  {','.join(str(r) for r in reasons) or '-'}"
                )
    for note in (snapshot.get("limitations") or [])[:6]:
        lines.append(f"- {note}")
    lines.append("")
    lines.append("←/→ or 1-5 panels · r refresh · q quit")
    return lines


def _read_control_key() -> str:
    """Read a single keypress (including arrow escapes) without requiring Enter."""
    import termios
    import tty

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
        if ch == "\x1b":
            rest = sys.stdin.read(2)
            if rest == "[C":
                return "right"
            if rest == "[D":
                return "left"
            return "esc"
        if ch in ("\x03", "\x04"):
            return "quit"
        return ch
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


async def handle_control(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    if argv and argv[0] in ("--help", "-h"):
        raise CliError("help", code="cli.help")
    _, policy_file, rest = consume_flag(argv, "--policy-file")
    _, limit_raw, rest = consume_flag(rest, "--limit")
    once = "--once" in rest
    rest = [part for part in rest if part != "--once"]
    if rest:
        raise CliError(f"unexpected arguments: {' '.join(rest)}", code="cli.usage.unexpected_args")
    limit = int(limit_raw) if limit_raw else 10
    if limit < 1:
        raise CliError("control --limit must be a positive integer", code="cli.usage.invalid_limit")

    snapshot = _gather_snapshot(ctx, policy_file=policy_file, limit=limit)
    if must_be_non_interactive(ctx.globals) or once or ctx.globals.format == "json":
        return {
            "mode": "snapshot",
            **snapshot,
            "active_panel": "intents",
            "next_commands": [
                "paybond status",
                'paybond shell --exec "intents list"',
                "paybond open billing",
            ],
        }

    panels = ["intents", "receipts", "policy", "spend", "denials"]
    active = "intents"
    current = snapshot
    while True:
        sys.stdout.write("\x1b[2J\x1b[H")
        for line in _render_control_panel_lines(active, current):
            sys.stdout.write(f"{line}\n")
        sys.stdout.flush()
        try:
            key = _read_control_key()
        except Exception:  # noqa: BLE001 — raw mode unavailable on some platforms / tests
            try:
                key = input("> ").strip().lower() or "quit"
            except EOFError:
                key = "quit"
        if key in {"q", "quit", "exit", "\x03"}:
            break
        if key in {"r", "refresh"}:
            current = _gather_snapshot(ctx, policy_file=policy_file, limit=limit)
            continue
        if key in {"right", "l", "\t"}:
            active = panels[(panels.index(active) + 1) % len(panels)]
            continue
        if key in {"left", "h"}:
            active = panels[(panels.index(active) - 1) % len(panels)]
            continue
        mapping = {"1": "intents", "2": "receipts", "3": "policy", "4": "spend", "5": "denials"}
        if key in mapping:
            active = mapping[key]
        elif key in panels:
            active = key
    return {"mode": "tui", "active_panel": active, **current}

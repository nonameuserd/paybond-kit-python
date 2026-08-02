from __future__ import annotations

import asyncio
import json
import sys
import traceback
from pathlib import Path
from typing import Any

from paybond_kit.cli import commands
from paybond_kit.cli.core import (
    EXIT_AUTH,
    EXIT_SUCCESS,
    EXIT_INTERRUPT,
    EXIT_FAILURE,
    EXIT_ENVIRONMENT,
    CliContext,
    CliError,
    cli_debug_from_argv,
    default_globals,
    exit_code_for_http_status,
    failure_envelope,
    output_format_from_argv,
    parse_cli_argv,
    request_id_from_argv,
    success_envelope,
    write_success_output,
)
from paybond_kit.cli.http_error_message import (
    format_gateway_auth_cli_message,
    format_sdk_http_error_message,
    summarize_gateway_http_error,
    resolve_cli_gateway_error_message,
)
from paybond_kit.credentials import GatewayAuthError
from paybond_kit.harbor import HarborHttpError
from paybond_kit.cli.automation import deprecated_alias_warning
from paybond_kit.cli.help_text import help_for_command
from paybond_kit.cli.policy import (
    handle_policy_extend,
    handle_policy_import_mcp_receipt,
    handle_policy_import_x402_receipt,
    handle_policy_init,
    handle_policy_init_org,
    handle_policy_presets_list,
    handle_policy_presets_show,
    handle_policy_preview,
    handle_policy_templates,
    handle_policy_validate_evidence,
    handle_policy_validate_tools,
)
from paybond_kit.cli.agent import handle_agent
from paybond_kit.cli.adyen import handle_adyen
from paybond_kit.cli.flutterwave import handle_flutterwave
from paybond_kit.cli.paystack import handle_paystack
from paybond_kit.cli.plaid import handle_plaid, handle_plaid_banks
from paybond_kit.cli.dev import handle_dev
from paybond_kit.cli.shopify import handle_shopify
from paybond_kit.cli.suggest import format_unknown_command_message
from paybond_kit.cli.ux import (
    handle_completion_command,
    handle_examples_command,
    handle_help_command,
    handle_onboarding,
)
from paybond_kit.cli.control_plane import (
    handle_control,
    handle_open,
    handle_shell,
    handle_status,
)
from paybond_kit.cli.next_actions import format_human_error_lines


def _is_help(command: list[str]) -> bool:
    return not command or "--help" in command or "-h" in command


def _help_path(command: list[str]) -> str:
    return " ".join(part for part in command if part not in ("--help", "-h"))


async def _dispatch(ctx: CliContext, command: list[str]) -> tuple[str, dict[str, Any]]:
    head = command[0] if command else ""
    second = command[1] if len(command) > 1 else ""
    third = command[2] if len(command) > 2 else ""
    rest = command[3:] if len(command) > 3 else command[2:] if len(command) > 2 else command[1:]

    if head == "help":
        return "help", handle_help_command(command[1:])
    if head == "examples":
        return "examples", handle_examples_command(command[1:])
    if head == "completion" and second:
        return "completion", handle_completion_command(command[1:])
    if head == "onboarding":
        return "onboarding", await handle_onboarding(ctx, command[1:])
    if head == "login":
        return "login", await commands.handle_login(ctx, command[1:])
    if head == "status":
        return "status", await handle_status(ctx, command[1:])
    if head == "open":
        return "open", await handle_open(ctx, command[1:])
    if head == "shell":
        return "shell", await handle_shell(ctx, command[1:])
    if head == "control":
        return "control", await handle_control(ctx, command[1:])
    if head == "init" and second == "guardrail":
        return "init guardrail", commands.handle_init_guardrail(ctx, command[2:])
    if head == "init" and second == "agent-middleware":
        return "init agent-middleware", commands.handle_init_agent_middleware(ctx, command[2:])
    if head == "init" and second == "completion":
        return "init completion", commands.handle_init_completion(ctx, command[2:])
    if head == "init":
        return "init", commands.handle_init_wizard(ctx, command[1:])
    if head == "mcp" and second == "serve":
        return "mcp serve", commands.handle_mcp_serve(ctx, command[2:])
    if head == "mcp" and second == "install":
        return "mcp install", commands.handle_mcp_install(ctx, command[2:])
    if head == "mcp" and second == "tools":
        return "mcp tools", commands.handle_mcp_tools(ctx)
    if head == "mcp" and second == "verify-config":
        return "mcp verify-config", commands.handle_mcp_verify_config(ctx, command[2:])
    if head == "doctor":
        return "doctor", await commands.handle_doctor(ctx, command[1:])
    if head == "shopify" and second:
        is_payments_session_show = second == "payments" and third == "session"
        fourth = command[3] if is_payments_session_show and len(command) > 3 else None
        parts = ["shopify", second]
        if third:
            parts.append(third)
        if fourth:
            parts.append(fourth)
        argv_start = 4 if is_payments_session_show else (3 if third else 2)
        return " ".join(parts), await handle_shopify(ctx, second, third, fourth, command[argv_start:])
    if head == "adyen" and second:
        return f"adyen {second}", await handle_adyen(ctx, second, command[2:])
    if head == "flutterwave" and second:
        return f"flutterwave {second}", await handle_flutterwave(ctx, second, command[2:])
    if head == "paystack" and second:
        return f"paystack {second}", await handle_paystack(ctx, second, command[2:])
    if head == "plaid" and second == "banks" and third:
        return f"plaid banks {third}", await handle_plaid_banks(ctx, third, command[3:])
    if head == "plaid" and second:
        return f"plaid {second}", await handle_plaid(ctx, second, command[2:])
    if head == "dev" and second:
        return f"dev {second}", await handle_dev(ctx, second, command[2:])
    if head == "version":
        return "version", commands.handle_version(ctx, command[1:])
    if head == "diagnose":
        return "diagnose", commands.handle_diagnose(ctx, command[1:])
    if head == "config" and second:
        return f"config {second}", commands.handle_config(ctx, second, command[2:])
    if head == "whoami":
        return "whoami", commands.handle_whoami(ctx)
    if head == "keys" and second:
        return f"keys {second}", commands.handle_keys(ctx, second, command[2:])
    if head == "intents" and second:
        return f"intents {second}", await commands.handle_intents(ctx, second, command[2:])
    if head == "guardrails" and second:
        return f"guardrails {second}", commands.handle_guardrails(ctx, second, command[2:])
    if head == "spend" and second == "authorize":
        return "spend authorize", commands.handle_spend_authorize(ctx, command[2:])
    if head == "spend" and second == "budget-remaining":
        return "spend budget-remaining", commands.handle_spend_budget_remaining(ctx, command[2:])
    if head == "spend" and second == "explain-policy":
        return "spend explain-policy", commands.handle_spend_explain_policy(ctx, command[2:])
    if head == "signal" and second:
        return f"signal {second}", commands.handle_signal(ctx, second, command[2:])
    if head == "receipts" and second:
        return f"receipts {second}", commands.handle_receipts(ctx, second, command[2:])
    if head == "mandates" and second:
        return f"mandates {second}", commands.handle_mandates(ctx, second, command[2:])
    if head == "a2a" and second:
        return f"a2a {second}", commands.handle_a2a(ctx, second, command[2:])
    if head == "audit" and second == "exports" and third:
        return f"audit exports {third}", commands.handle_audit_exports(ctx, third, rest)
    if head == "policy" and second == "presets" and third == "list":
        return "policy presets list", handle_policy_presets_list(ctx, command[3:])
    if head == "policy" and second == "presets" and third == "show":
        return "policy presets show", handle_policy_presets_show(ctx, command[3:])
    if head == "policy" and second == "templates":
        return "policy templates", handle_policy_templates(ctx, command[2:])
    if head == "policy" and second == "preview":
        return "policy preview", handle_policy_preview(ctx, command[2:])
    if head == "policy" and second == "import-mcp-receipt":
        return "policy import-mcp-receipt", handle_policy_import_mcp_receipt(ctx, command[2:])
    if head == "policy" and second == "import-x402-receipt":
        return "policy import-x402-receipt", handle_policy_import_x402_receipt(ctx, command[2:])
    if head == "policy" and second == "validate-evidence":
        return "policy validate-evidence", handle_policy_validate_evidence(ctx, command[2:])
    if head == "policy" and second == "init-org":
        return "policy init-org", handle_policy_init_org(ctx, command[2:])
    if head == "policy" and second == "extend":
        return "policy extend", handle_policy_extend(ctx, command[2:])
    if head == "policy" and second == "init":
        return "policy init", handle_policy_init(ctx, command[2:])
    if head == "policy" and second == "validate-tools":
        return "policy validate-tools", handle_policy_validate_tools(ctx, command[2:])
    if head == "agent" and second and third:
        return f"agent {second} {third}", await handle_agent(ctx, second, third, command[3:])
    raise CliError(format_unknown_command_message(" ".join(command)), code="cli.usage.unknown_command")


def _cli_error_from_harbor_http_error(err: HarborHttpError) -> CliError:
    exit_code, category = exit_code_for_http_status(err.status_code)
    _, details = summarize_gateway_http_error(err.status_code, err.body_text)
    gateway_code = details.get("gateway_code")
    return CliError(
        format_sdk_http_error_message(str(err), err.status_code, err.body_text),
        category=category,
        code=str(gateway_code or f"cli.gateway.http_{err.status_code}"),
        exit_code=exit_code,
        details=details,
    )


def _cli_error_from_gateway_auth_error(err: GatewayAuthError) -> CliError:
    """Convert SDK principal failures into stable, non-secret CLI errors."""
    message = format_gateway_auth_cli_message(str(err), err.status_code, err.body_text)
    if err.status_code is None:
        return CliError(
            message,
            category="auth",
            code="cli.auth.gateway_principal_invalid",
            exit_code=EXIT_AUTH,
        )
    exit_code, category = exit_code_for_http_status(err.status_code)
    body_text = err.body_text or ""
    _, details = summarize_gateway_http_error(err.status_code, body_text)
    gateway_code = details.get("gateway_code")
    return CliError(
        message,
        category=category,
        code=str(gateway_code or f"cli.gateway.http_{err.status_code}"),
        exit_code=exit_code,
        details=details,
    )


# head -> (code, category, actionable hint) for validation-style errors that
# reach the CLI boundary from library helpers without a CliError of their own.
_COMMAND_BOUNDARY_HINTS: dict[str, tuple[str, str, str]] = {
    "agent": ("cli.agent.validation", "validation", "check the command flags or run paybond doctor --agent"),
    "doctor": ("cli.doctor.validation", "validation", "run paybond doctor"),
    "diagnose": ("cli.diagnose.validation", "validation", "run paybond diagnose --redacted"),
    "whoami": ("cli.whoami.validation", "validation", "run paybond login, then paybond whoami"),
    "login": ("cli.login.validation", "validation", "run paybond login --help"),
    "init": ("cli.init.validation", "validation", "check the flags or run paybond init --help"),
    "policy": ("cli.policy.validation", "validation", "check your policy file or run paybond policy validate-tools"),
    "mcp": ("cli.mcp.validation", "validation", "run paybond mcp verify-config"),
    "spend": ("cli.spend.validation", "validation", "check spend flags or run paybond spend explain-policy"),
    "intents": ("cli.intents.validation", "validation", "check the command flags or run paybond doctor"),
    "keys": ("cli.keys.validation", "validation", "check the command flags"),
}


def _boundary_validation_cli_error(canonical: str, exc: BaseException) -> CliError:
    """Map an unconverted validation-style error to an actionable CLI error.

    Handlers convert their own known failures to :class:`CliError`; this covers
    the residual ``ValueError``/``TypeError``/``RuntimeError`` that bubble from
    shared library helpers, attaching a per-command recovery hint.
    """
    message = str(exc) or "invalid input"
    head = canonical.split(" ", 1)[0] if canonical else ""
    code, category, hint = _COMMAND_BOUNDARY_HINTS.get(head, ("cli.validation", "validation", ""))
    if hint and hint not in message:
        message = f"{message}; {hint}"
    return CliError(message, category=category, code=code, exit_code=EXIT_FAILURE)


def _write_debug_traceback(stderr: Any, enabled: bool) -> None:
    """Emit the active exception's traceback to stderr when debug mode is on."""
    if enabled:
        stderr.write(traceback.format_exc())


async def run_cli(argv: list[str] | None = None, *, stdout: Any = None, stderr: Any = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    try:
        globals_, command = parse_cli_argv(argv)
    except CliError as exc:
        _write_debug_traceback(stderr, cli_debug_from_argv(argv))
        if output_format_from_argv(argv) == "json":
            globals_ = default_globals()
            globals_.format = "json"
            globals_.request_id = request_id_from_argv(argv)
            stdout.write(f"{json.dumps(failure_envelope('paybond', globals_, exc), indent=2)}\n")
        else:
            for line in format_human_error_lines(exc.message, exc.details):
                stderr.write(f"{line}\n")
        return exc.exit_code
    ctx = CliContext(
        globals=globals_,
        cwd=Path.cwd(),
        stdout=stdout,
        stderr=stderr,
    )
    alias_warning = deprecated_alias_warning(sys.argv[0])
    if alias_warning:
        stderr.write(f"{alias_warning}\n")
    help_path = _help_path(command)
    if _is_help(command):
        ctx.stdout.write(f"{help_for_command(help_path)}\n")
        return EXIT_SUCCESS

    canonical = help_path or "paybond"
    try:
        canonical, data = await _dispatch(ctx, command)
        write_success_output(ctx, canonical, data)
        return EXIT_SUCCESS
    except CliError as exc:
        if exc.message == "help":
            ctx.stdout.write(f"{help_for_command(help_path)}\n")
            return EXIT_SUCCESS
        _write_debug_traceback(ctx.stderr, globals_.debug)
        if globals_.format == "json":
            ctx.stdout.write(f"{json.dumps(failure_envelope(canonical, globals_, exc), indent=2)}\n")
        else:
            for line in format_human_error_lines(exc.message, exc.details):
                ctx.stderr.write(f"{line}\n")
        return exc.exit_code
    except HarborHttpError as exc:
        _write_debug_traceback(ctx.stderr, globals_.debug)
        cli_exc = _cli_error_from_harbor_http_error(exc)
        if globals_.format == "json":
            ctx.stdout.write(f"{json.dumps(failure_envelope(canonical, globals_, cli_exc), indent=2)}\n")
        else:
            ctx.stderr.write(f"{cli_exc.message}\n")
        return cli_exc.exit_code
    except GatewayAuthError as exc:
        _write_debug_traceback(ctx.stderr, globals_.debug)
        cli_exc = _cli_error_from_gateway_auth_error(exc)
        if globals_.format == "json":
            ctx.stdout.write(f"{json.dumps(failure_envelope(canonical, globals_, cli_exc), indent=2)}\n")
        else:
            ctx.stderr.write(f"{cli_exc.message}\n")
        return cli_exc.exit_code
    except SystemExit as exc:
        # argparse/usage exits raise SystemExit with an int (or None) code after
        # already printing their own message. Preserve that behavior — the caller
        # exits with that status — instead of emitting a bare numeric message.
        if exc.code is None or isinstance(exc.code, int):
            raise
        _write_debug_traceback(ctx.stderr, globals_.debug)
        # Otherwise the code carries a human-readable message from a lower-level
        # helper (e.g. MCP tooling); map it to a structured CLI error.
        text = str(exc.code) or "process exited"
        # Special-case missing API key messages produced by MCP helpers.
        if "PAYBOND_API_KEY" in text:
            message = f"{text}; run paybond login"
            cli_exc = CliError(message, category="auth", code="cli.auth.missing_api_key", exit_code=EXIT_AUTH)
        else:
            cli_exc = CliError(text, category="environment", code="cli.environment.exit", exit_code=EXIT_ENVIRONMENT)
        if globals_.format == "json":
            ctx.stdout.write(f"{json.dumps(failure_envelope(canonical, globals_, cli_exc), indent=2)}\n")
        else:
            ctx.stderr.write(f"{cli_exc.message}\n")
        return cli_exc.exit_code
    except (ValueError, TypeError, RuntimeError) as exc:
        _write_debug_traceback(ctx.stderr, globals_.debug)
        # Map residual validation-style exceptions from library helpers to a
        # friendly, command-aware CLI validation error.
        cli_exc = _boundary_validation_cli_error(canonical, exc)
        if globals_.format == "json":
            ctx.stdout.write(f"{json.dumps(failure_envelope(canonical, globals_, cli_exc), indent=2)}\n")
        else:
            ctx.stderr.write(f"{cli_exc.message}\n")
        return cli_exc.exit_code
    except Exception as exc:  # Catch-all for unexpected errors — sanitize output.
        _write_debug_traceback(ctx.stderr, globals_.debug)
        # Prefer to extract a safe gateway message when available.
        try:
            safe = resolve_cli_gateway_error_message(exc)
        except Exception:
            safe = None
        base = safe or "unexpected internal error"
        hint = "run paybond doctor"
        message = f"{base}; {hint}"
        cli_exc = CliError(message, category="internal", code="cli.internal", exit_code=EXIT_FAILURE)
        if globals_.format == "json":
            ctx.stdout.write(f"{json.dumps(failure_envelope(canonical, globals_, cli_exc), indent=2)}\n")
        else:
            ctx.stderr.write(f"{cli_exc.message}\n")
        return cli_exc.exit_code


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    alias_warning = deprecated_alias_warning(sys.argv[0])
    if alias_warning:
        sys.stderr.write(f"{alias_warning}\n")
    if commands.mcp_serve_argv_matches(argv):
        return commands.run_mcp_serve_command_sync(argv, stdout=sys.stdout, stderr=sys.stderr)
    try:
        return asyncio.run(run_cli(argv))
    except KeyboardInterrupt:
        return EXIT_INTERRUPT

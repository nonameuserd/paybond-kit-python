from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from paybond_kit.cli import commands
from paybond_kit.cli.core import (
    EXIT_SUCCESS,
    CliContext,
    CliError,
    default_globals,
    failure_envelope,
    output_format_from_argv,
    parse_cli_argv,
    request_id_from_argv,
    success_envelope,
    write_success_output,
)
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
from paybond_kit.cli.dev import handle_dev
from paybond_kit.cli.suggest import format_unknown_command_message
from paybond_kit.cli.ux import (
    handle_completion_command,
    handle_examples_command,
    handle_help_command,
    handle_onboarding,
)


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
        return f"intents {second}", commands.handle_intents(ctx, second, command[2:])
    if head == "guardrails" and second:
        return f"guardrails {second}", commands.handle_guardrails(ctx, second, command[2:])
    if head == "spend" and second == "authorize":
        return "spend authorize", commands.handle_spend_authorize(ctx, command[2:])
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


async def run_cli(argv: list[str] | None = None, *, stdout: Any = None, stderr: Any = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    try:
        globals_, command = parse_cli_argv(argv)
    except CliError as exc:
        if output_format_from_argv(argv) == "json":
            globals_ = default_globals()
            globals_.format = "json"
            globals_.request_id = request_id_from_argv(argv)
            stdout.write(f"{json.dumps(failure_envelope('paybond', globals_, exc), indent=2)}\n")
        else:
            stderr.write(f"{exc.message}\n")
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
        if globals_.format == "json":
            ctx.stdout.write(f"{json.dumps(failure_envelope(canonical, globals_, exc), indent=2)}\n")
        else:
            ctx.stderr.write(f"{exc.message}\n")
        return exc.exit_code


def main(argv: list[str] | None = None) -> int:
    return asyncio.run(run_cli(argv))

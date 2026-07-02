from __future__ import annotations

from pathlib import Path
from typing import Any

from paybond_kit.cli.command_spec import COMMAND_EXAMPLES, COMPLETION_SCRIPTS, WORKFLOWS
from paybond_kit.cli.commands import handle_doctor
from paybond_kit.cli.core import CliContext, CliError, consume_flag, resolve_api_key
from paybond_kit.login import mask_api_key
from paybond_kit.cli.help_text import help_for_command
from paybond_kit.cli.mcp_install import (
    parse_mcp_install_format,
    parse_mcp_install_host,
    parse_mcp_install_scope,
    plan_mcp_install,
)


def resolve_help_path(argv: list[str]) -> str:
    return " ".join(part for part in argv if part not in ("--help", "-h"))


def render_help_text(path: str) -> str:
    return help_for_command(path)


def handle_help_command(argv: list[str]) -> dict[str, Any]:
    help_path = resolve_help_path(argv)
    return {"text": render_help_text(help_path), "path": help_path or "paybond"}


def handle_examples_command(argv: list[str]) -> dict[str, Any]:
    filter_path = resolve_help_path(argv)
    lines: list[str] = []
    if not filter_path:
        lines.append("Workflows:")
        for workflow in WORKFLOWS:
            lines.extend(["", workflow["title"]])
            description = workflow.get("description")
            if description:
                lines.append(str(description))
            for example in workflow.get("examples", []):
                lines.append(f"  $ {example}")
            if workflow.get("next"):
                lines.append(f"  Next: {workflow['next']}")
        lines.extend(["", "Commands:"])

    if filter_path:
        entries = [
            (command_path, examples)
            for command_path, examples in COMMAND_EXAMPLES.items()
            if command_path == filter_path or command_path.startswith(f"{filter_path} ")
        ]
    else:
        entries = list(COMMAND_EXAMPLES.items())

    if filter_path and not entries:
        raise CliError(f"no examples found for: {filter_path}", code="cli.usage.unknown_command")

    for command_path, examples in entries:
        lines.extend(["", f"paybond {command_path}"])
        for example in examples:
            lines.append(f"  $ {example}")

    text = "\n".join(lines).strip()
    return {"text": text, "filter": filter_path or None, "count": len(entries)}


def handle_completion_command(argv: list[str]) -> dict[str, Any]:
    shell = argv[0] if argv else ""
    if not shell or shell in ("--help", "-h"):
        raise CliError("completion requires bash|zsh|fish", code="cli.usage.missing_completion_shell")
    script = COMPLETION_SCRIPTS.get(shell)
    if not script:
        raise CliError(
            f"unsupported completion shell: {shell} (expected bash|zsh|fish)",
            code="cli.usage.invalid_completion_shell",
        )
    return {"shell": shell, "script": script}


async def handle_onboarding(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    _, host, _rest = consume_flag(argv, "--host")
    try:
        install_host = parse_mcp_install_host(host) if host else "generic"
    except ValueError as exc:
        raise CliError(str(exc), code="cli.usage.invalid_mcp_install") from exc

    steps: list[dict[str, Any]] = [
        {"name": "runtime", "ok": True, "message": f"python {__import__('sys').version.split()[0]}"},
    ]

    env_path = Path(ctx.globals.env_file) if Path(ctx.globals.env_file).is_absolute() else ctx.cwd / ctx.globals.env_file
    logged_in = False
    try:
        api_key = resolve_api_key(ctx.globals, ctx.cwd)
        logged_in = True
        steps.append(
            {
                "name": "login",
                "ok": True,
                "message": f"credentials found ({mask_api_key(api_key)})",
            }
        )
    except CliError as exc:
        steps.append(
            {
                "name": "login",
                "ok": False,
                "message": exc.message,
                "command": "paybond login",
            }
        )

    guardrail_path = ctx.cwd / "paybond_paid_tool_guard.py"
    guardrail_exists = guardrail_path.is_file()
    steps.append(
        {
            "name": "guardrail",
            "ok": guardrail_exists,
            "message": f"found {guardrail_path}" if guardrail_exists else f"guardrail file not found ({guardrail_path})",
            **({} if guardrail_exists else {"command": "paybond init guardrail"}),
        }
    )

    plan = plan_mcp_install(
        host=install_host,
        scope=parse_mcp_install_scope("local"),
        fmt=parse_mcp_install_format(None, host=install_host),
        env_file=ctx.globals.env_file,
        out=None,
        cwd=ctx.cwd,
        home=Path.home(),
    )
    steps.append(
        {
            "name": "mcp_config",
            "ok": True,
            "message": f"preview ready for host={plan.host} (non-destructive --scope local)",
            "command": f"paybond mcp install --host {plan.host} --scope local",
        }
    )

    doctor = await handle_doctor(ctx, ["--agent"] if logged_in else [])
    doctor_ok = doctor.get("summary") == "pass"
    steps.append(
        {
            "name": "doctor",
            "ok": doctor_ok,
            "message": f"doctor {doctor.get('summary')}",
            **({} if doctor_ok else {"command": "paybond doctor --agent"}),
        }
    )

    summary = "pass" if all(step["ok"] for step in steps) else "fail"
    return {
        "steps": steps,
        "summary": summary,
        "env_file": str(env_path),
        "mcp_preview": plan.payload if plan.printed else None,
        "doctor_checks": doctor.get("checks"),
    }

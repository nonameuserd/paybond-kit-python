"""Doctor check: agent middleware sandbox smoke."""

from __future__ import annotations

from paybond_kit.cli.agent import handle_agent_sandbox_smoke
from paybond_kit.cli.agent_paybond import api_key_environment
from paybond_kit.cli.core import CliContext, CliError
from paybond_kit.cli.doctor_agent import DoctorCheck

AGENT_MIDDLEWARE_SMOKE_NEXT = (
    "paybond agent sandbox smoke --operation paid-tool --requested-spend-cents 100 "
    "--evidence-preset cost_and_completion --result-body '{\"status\":\"ok\",\"cost_cents\":100}' "
    "--format json"
)


async def run_agent_middleware_doctor_check(ctx: CliContext, api_key: str) -> DoctorCheck:
    if not api_key:
        return DoctorCheck(
            name="agent_middleware_smoke",
            ok=False,
            message="skipped (missing API key)",
            details={"next_command": AGENT_MIDDLEWARE_SMOKE_NEXT},
        )
    if api_key_environment(api_key) == "live":
        return DoctorCheck(
            name="agent_middleware_smoke",
            ok=True,
            message="skipped (live API key; smoke uses sandbox guardrails bootstrap)",
            details={"next_command": AGENT_MIDDLEWARE_SMOKE_NEXT},
        )

    try:
        await handle_agent_sandbox_smoke(
            ctx,
            [
                "--operation",
                "paid-tool",
                "--requested-spend-cents",
                "100",
                "--evidence-preset",
                "cost_and_completion",
                "--result-body",
                '{"status":"ok","cost_cents":100}',
            ],
        )
        return DoctorCheck(
            name="agent_middleware_smoke",
            ok=True,
            message="bind, authorize, execute, and auto-evidence succeeded",
        )
    except CliError as exc:
        return DoctorCheck(
            name="agent_middleware_smoke",
            ok=False,
            message=exc.message,
            details={"next_command": AGENT_MIDDLEWARE_SMOKE_NEXT},
        )
    except Exception as exc:  # noqa: BLE001
        return DoctorCheck(
            name="agent_middleware_smoke",
            ok=False,
            message=str(exc),
            details={"next_command": AGENT_MIDDLEWARE_SMOKE_NEXT},
        )

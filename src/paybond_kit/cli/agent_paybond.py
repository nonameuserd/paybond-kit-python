"""Open Paybond sessions for agent CLI commands."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

from paybond_kit.cli.core import CliContext, CliError, resolve_api_key
from paybond_kit.paybond import Paybond

T = TypeVar("T")


def api_key_environment(api_key: str) -> str:
    if "_sandbox_" in api_key:
        return "sandbox"
    if "_live_" in api_key:
        return "live"
    return "unknown"


def assert_agent_sandbox_default(api_key: str, production: bool) -> None:
    if production:
        return
    if api_key_environment(api_key) == "live":
        raise CliError(
            "agent commands default to sandbox-only; pass --production to use live credentials",
            category="validation",
            code="cli.agent.production_required",
        )


async def with_paybond_agent_cli(
    ctx: CliContext,
    production: bool,
    handler: Callable[[Paybond, list[str]], Awaitable[T]],
) -> T:
    """Open Paybond and run gateway-backed middleware work inside one session."""
    api_key = resolve_api_key(ctx.globals, ctx.cwd)
    assert_agent_sandbox_default(api_key, production)
    expected_environment = None if production else "sandbox"
    paybond = await Paybond.open(
        api_key=api_key,
        gateway_base_url=ctx.globals.gateway,
        expected_environment=expected_environment,
    )
    return await handler(paybond, [])


async def open_paybond_for_agent_cli(ctx: CliContext, production: bool) -> Paybond:
    """Backward-compatible helper; prefer with_paybond_agent_cli for bind/execute paths."""

    async def _return_paybond(paybond: Paybond, _warnings: list[str]) -> Paybond:
        return paybond

    return await with_paybond_agent_cli(ctx, production, _return_paybond)

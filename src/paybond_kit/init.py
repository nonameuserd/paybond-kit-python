"""Command-line scaffolder for Paybond guardrail integrations."""

from __future__ import annotations

import argparse
from pathlib import Path

FRAMEWORK_NOTES = {
    "generic": "Wrap the returned function around any side-effecting tool handler.",
    "provider-agnostic": "Use the guarded handler with OpenAI, Gemini, Claude/Anthropic, local models, or any custom runtime.",
    "openai": "Call the guarded handler before the OpenAI tool call performs paid or external work.",
    "claude": "Call the guarded handler before the Claude tool-use action performs paid or external work.",
    "anthropic": "Call the guarded handler before the Anthropic tool-use action performs paid or external work.",
    "gemini": "Call the guarded handler before the Gemini function call performs paid or external work.",
    "google-ai": "Call the guarded handler before the Google AI function call performs paid or external work.",
    "vercel-ai": "Call the guarded handler from your Vercel AI SDK tool execute function.",
    "langgraph": "Call the guarded handler from the LangGraph node or tool wrapper that performs paid work.",
    "mcp": "Use the same operation name in your MCP tool handler before executing paid work.",
}

PRESETS = ("paid-tool-guard",)


def _template(framework: str) -> str:
    note = FRAMEWORK_NOTES[framework]
    return f'''import os
from pathlib import Path
from collections.abc import Awaitable, Callable, Mapping
from typing import Any, TypeVar

from paybond_kit import (
    Paybond,
    SandboxGuardrailBootstrapResult,
    SandboxGuardrailEvidenceResult,
)

# Production integration helpers only. Add your paid-tool handler in
# application code and pass it to wrap_paid_tool(...).
DEFAULT_OPERATION = "paid_tool.operation"
DEFAULT_REQUESTED_SPEND_CENTS = 500

TInput = TypeVar("TInput")
TResult = TypeVar("TResult")
PaidToolHandler = Callable[[TInput], TResult | Awaitable[TResult]]


def _read_env_value(body: str, key: str) -> str | None:
    prefix = f"{{key}}="
    export_prefix = f"export {{key}}="
    for raw_line in body.splitlines():
        line = raw_line.strip()
        if line.startswith(export_prefix):
            value = line[len(export_prefix):].strip()
        elif line.startswith(prefix):
            value = line[len(prefix):].strip()
        else:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\\"":
            value = value[1:-1]
        return value.strip() or None
    return None


def load_paybond_env_file(env_file: str = ".env.local") -> None:
    if os.environ.get("PAYBOND_API_KEY", "").strip():
        return
    path = Path(env_file)
    try:
        body = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return
    api_key = _read_env_value(body, "PAYBOND_API_KEY")
    if api_key:
        os.environ["PAYBOND_API_KEY"] = api_key


async def open_paybond_from_env(env_file: str | None = ".env.local") -> Paybond:
    if env_file is not None:
        load_paybond_env_file(env_file)
    api_key = os.environ.get("PAYBOND_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("PAYBOND_API_KEY is required; run paybond-kit-login or configure your agent host to pass it")

    return await Paybond.open(
        api_key=api_key,
        gateway_base_url=os.environ.get("PAYBOND_GATEWAY_BASE_URL") or "https://api.paybond.ai",
        expected_environment="sandbox",
    )


async def bootstrap_sandbox_guardrail_intent(
    paybond: Paybond,
    *,
    operation: str = DEFAULT_OPERATION,
    requested_spend_cents: int = DEFAULT_REQUESTED_SPEND_CENTS,
    currency: str = "usd",
    evidence_schema: Mapping[str, Any] | None = None,
    metadata: Mapping[str, Any] | None = None,
    idempotency_key: str | None = None,
) -> SandboxGuardrailBootstrapResult:
    return await paybond.guardrails.bootstrap_sandbox(
        operation=operation,
        requested_spend_cents=requested_spend_cents,
        currency=currency,
        evidence_schema=evidence_schema
        or {{
            "type": "object",
            "required": ["confirmation_id", "charged_cents"],
            "properties": {{
                "confirmation_id": {{"type": "string"}},
                "charged_cents": {{"type": "integer"}},
            }},
        }},
        metadata=metadata,
        idempotency_key=idempotency_key,
    )


def wrap_paid_tool(
    paybond: Paybond,
    guardrail: SandboxGuardrailBootstrapResult,
    handler: PaidToolHandler[TInput, TResult],
) -> Callable[[TInput], Awaitable[TResult]]:
    if not guardrail.capability_token.strip():
        raise RuntimeError("sandbox guardrail bootstrap did not return a capability token")

    guard = paybond.spend_guard(guardrail.intent_id, guardrail.capability_token)

    # {note}
    return guard.guard_tool(
        operation=guardrail.operation,
        requested_spend_cents=guardrail.requested_spend_cents,
        handler=handler,
    )


async def submit_sandbox_evidence(
    paybond: Paybond,
    guardrail: SandboxGuardrailBootstrapResult,
    payload: Mapping[str, Any],
    *,
    operation: str | None = None,
    requested_spend_cents: int | None = None,
    artifacts: list[str] | None = None,
    metadata: Mapping[str, Any] | None = None,
    idempotency_key: str | None = None,
) -> SandboxGuardrailEvidenceResult:
    return await paybond.guardrails.submit_sandbox_evidence(
        guardrail.intent_id,
        payload,
        artifacts=artifacts,
        operation=operation if operation is not None else guardrail.operation,
        requested_spend_cents=(
            requested_spend_cents
            if requested_spend_cents is not None
            else guardrail.requested_spend_cents
        ),
        metadata=metadata,
        idempotency_key=idempotency_key,
    )
'''


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Scaffold a production-shaped Paybond guardrail integration helper."
    )
    parser.add_argument(
        "--preset",
        choices=PRESETS,
        default="paid-tool-guard",
    )
    parser.add_argument(
        "--framework",
        choices=sorted(FRAMEWORK_NOTES),
        default="provider-agnostic",
    )
    parser.add_argument("--out", default="paybond_paid_tool_guard.py")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)

    out = Path(args.out)
    if out.exists() and not args.force:
        parser.error(f"{out} already exists; pass --force to overwrite")
    out.write_text(_template(args.framework), encoding="utf-8")
    print(f"Created Paybond guardrail integration: {out}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

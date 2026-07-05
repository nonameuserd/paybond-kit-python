"""Command-line scaffolder for Paybond guardrail and agent middleware integrations."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from paybond_kit.completion_catalog import get_completion_preset

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
    "crewai": "Register guarded CrewAI @tool / BaseTool instances on your crew agents.",
    "mcp": "Use the same operation name in your MCP tool handler before executing paid work.",
}

PRESETS = ("paid-tool-guard", "agent-middleware")
AGENT_MIDDLEWARE_FRAMEWORKS = (
    "generic",
    "claude-agents",
    "crewai",
    "openai",
    "langgraph",
    "vercel-ai",
    "mcp",
)
AGENT_MIDDLEWARE_FRAMEWORK_ALIASES = {"provider-agnostic": "generic"}
PRESET_DEFAULT_OUT = {
    "paid-tool-guard": "paybond_paid_tool_guard.py",
    "agent-middleware": "paybond_agent_middleware.py",
}


def _env_helpers_block() -> str:
    return '''def _read_env_value(body: str, key: str) -> str | None:
    prefix = f"{key}="
    export_prefix = f"export {key}="
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
        gateway_base_url=(
            os.environ.get("PAYBOND_GATEWAY_URL")
            or os.environ.get("PAYBOND_GATEWAY_BASE_URL")
            or "https://api.paybond.ai"
        ),
        expected_environment="sandbox",
    )'''


def _normalize_agent_middleware_framework(framework: str) -> str:
    normalized = AGENT_MIDDLEWARE_FRAMEWORK_ALIASES.get(framework, framework)
    if normalized not in AGENT_MIDDLEWARE_FRAMEWORKS:
        raise ValueError("invalid --framework for agent-middleware preset")
    return normalized


def _production_policy_binding_comments(harbor_template_id: str) -> str:
    return f"""# Production (signing v7): publish managed template head for {harbor_template_id}, then create a funded intent.
# from paybond_kit.policy import PaybondPolicy
# policy = await PaybondPolicy.load("./paybond.policy.yaml")
# intent_input = policy.to_intent_create_input(
#     principal_did=principal_did,
#     principal_signing_seed=principal_seed,
#     payee_did=payee_did,
#     payee_signing_seed=payee_seed,
#     deadline_rfc3339=deadline_rfc3339,
#     settlement_rail="stripe_connect",
#     recognition_proof=recognition_proof,
#     materialized_predicate=published_head["materialized_predicate"],
#     policy_template_id=published_head["template_id"],
#     policy_version_seq=published_head["version_seq"],
#     policy_content_digest_hex=published_head["digest_hex"],
# )
# created = await paybond.intents.create_with_policy_binding(**intent_input.__dict__)
# Fund if needed, then attach middleware via paybond.agent_run.bind(attach=...)"""


def _agent_middleware_header_comments(framework: str) -> str:
    smoke_commands = {
        "generic": (
            "paybond agent sandbox smoke --operation travel.book_hotel "
            "--requested-spend-cents 20000 --evidence-preset cost_and_completion "
            '--result-body \'{"reservation":{"status":"confirmed","price_cents":20000}}\''
        ),
        "claude-agents": (
            "paybond agent demo claude-agents smoke --operation travel.book_hotel "
            "--requested-spend-cents 20000 --evidence-preset cost_and_completion --format json"
        ),
        "crewai": (
            "paybond agent demo crewai smoke --operation procurement.submit_po "
            "--requested-spend-cents 12000 --evidence-preset cost_and_completion --format json"
        ),
        "openai": (
            "paybond agent demo openai smoke --operation travel.book_hotel "
            "--requested-spend-cents 20000 --evidence-preset cost_and_completion --format json"
        ),
        "langgraph": (
            "paybond agent demo langgraph smoke --operation travel.book_hotel "
            "--requested-spend-cents 20000 --evidence-preset cost_and_completion --format json"
        ),
        "vercel-ai": (
            "paybond agent demo vercel-ai smoke --operation travel.book_hotel "
            "--requested-spend-cents 20000 --evidence-preset cost_and_completion --format json"
        ),
        "mcp": (
            "paybond agent demo mcp smoke --operation travel.book_hotel "
            "--requested-spend-cents 20000 --evidence-preset cost_and_completion --format json"
        ),
    }
    normalized = _normalize_agent_middleware_framework(framework)
    return "\n".join(
        [
            "# Paybond for paid tools; provider-native limits for LLM token caps only.",
            "# Policy: ./paybond.policy.yaml (scaffold with paybond policy init).",
            f"# Smoke: {smoke_commands[normalized]}",
            "# Production: create_with_policy_binding after publishing the managed template head — see block below.",
        ]
    )


def _agent_middleware_framework_block(framework: str) -> str:
    if framework == "claude-agents":
        return '''import json

from claude_agent_sdk import tool
from paybond_kit.agent.guarded_agent import (
    CreateGuardedAgentInput,
    CreateGuardedAgentResult,
    create_guarded_agent,
    create_guarded_agent_runner,
)

TRAVEL_AGENT_POLICY = {
    "version": 1,
    "name": "travel-agent-v1",
    "default_deny": True,
    "tools": {
        "travel.book_hotel": {
            "side_effecting": True,
            "max_spend_cents": DEFAULT_REQUESTED_SPEND_CENTS,
            "evidence_preset": COMPLETION_PRESET_ID,
        },
        "search.web": {
            "side_effecting": False,
        },
    },
    "intent": {
        "allowed_tools": ["travel.book_hotel"],
        "budget": {"currency": "usd", "max_spend_usd": 200},
    },
}


async def create_claude_agents_guarded_runner(paybond: Paybond) -> CreateGuardedAgentResult:
    """Policy-driven Claude Agent SDK wiring: bind run, wrap tool() handlers, expose MCP server config."""

    async def book_hotel_handler(args: Mapping[str, Any], _extra: Any) -> dict[str, Any]:
        payload = await book_hotel(args)
        return {
            "content": [{"type": "text", "text": json.dumps(payload)}],
            "structuredContent": payload,
        }

    sdk_tools = [
        tool(
            "travel.book_hotel",
            "Book a hotel room",
            {"city": str, "estimated_price_cents": int},
            book_hotel_handler,
        ),
    ]
    return await create_guarded_agent(
        paybond,
        CreateGuardedAgentInput(
            policy=TRAVEL_AGENT_POLICY,
            framework="claude-agents",
            tools=sdk_tools,
            bootstrap={
                "operation": DEFAULT_OPERATION,
                "requested_spend_cents": DEFAULT_REQUESTED_SPEND_CENTS,
                "completion_preset": COMPLETION_PRESET_ID,
            },
        ),
    )


create_claude_agents_guarded_agent_runner = create_claude_agents_guarded_runner'''
    if framework == "crewai":
        return '''from crewai.tools import tool

from paybond_kit.agent.guarded_agent import (
    CreateGuardedAgentInput,
    CreateGuardedAgentResult,
    create_guarded_agent,
)
from paybond_kit.crewai import create_paybond_crewai_config


PROCUREMENT_AGENT_POLICY = {
    "version": 1,
    "name": "procurement-agent-v1",
    "default_deny": True,
    "tools": {
        "procurement.submit_po": {
            "side_effecting": True,
            "max_spend_cents": DEFAULT_REQUESTED_SPEND_CENTS,
            "evidence_preset": COMPLETION_PRESET_ID,
        },
        "procurement.search_catalog": {
            "side_effecting": False,
        },
    },
    "intent": {
        "allowed_tools": ["procurement.submit_po"],
        "budget": {"currency": "usd", "max_spend_usd": 500},
    },
}


def submit_po(vendor_id: str, amount_cents: int) -> dict[str, Any]:
    return {"status": "completed", "cost_cents": amount_cents, "vendor_id": vendor_id}


async def create_crewai_guarded_runner(paybond: Paybond) -> CreateGuardedAgentResult:
    """Policy-driven CrewAI wiring: bind run, wrap @tool handlers, return guarded tools."""

    @tool("procurement.submit_po")
    def submit_po_tool(vendor_id: str, amount_cents: int) -> str:
        """Submit a purchase order to a vendor."""
        import json

        return json.dumps(submit_po(vendor_id, amount_cents))

    result = await create_guarded_agent(
        paybond,
        CreateGuardedAgentInput(
            policy=PROCUREMENT_AGENT_POLICY,
            framework="crewai",
            tools=[submit_po_tool],
            bootstrap={
                "operation": "procurement.submit_po",
                "requested_spend_cents": DEFAULT_REQUESTED_SPEND_CENTS,
                "completion_preset": COMPLETION_PRESET_ID,
            },
        ),
    )
    return result


def wrap_crewai_tools(run: PaybondAgentRun, tools: list[Any]) -> list[Any]:
    """Wrap CrewAI @tool / BaseTool instances when you already bound a PaybondAgentRun."""
    return create_paybond_crewai_config(run, tools).tools'''
    if framework == "openai":
        return '''from paybond_kit.agent import create_tool_input_guard_adapter


def wrap_openai_agent_tools(run: PaybondAgentRun, tools: list[dict[str, Any]]) -> list[Any]:
    """Wrap provider-agnostic tool executors for OpenAI-style agent runtimes."""
    guard = create_tool_input_guard_adapter(run)
    return guard.wrap_executors(tools)'''
    if framework == "langgraph":
        return '''from paybond_kit.langgraph_hooks import paybond_awrap_tool_call


def create_langgraph_tool_call_wrapper(run: PaybondAgentRun):
    """LangGraph ToolNode hook — pass to ToolNode(..., awrap_tool_call=wrapper)."""
    return paybond_awrap_tool_call(run)'''
    if framework == "vercel-ai":
        return '''async def execute_guarded_vercel_tool(
    run: PaybondAgentRun,
    *,
    tool_name: str,
    tool_call_id: str,
    arguments: Mapping[str, Any],
    execute: Callable[[Mapping[str, Any]], Awaitable[Any] | Any],
) -> Any:
    """Wire Paybond middleware into a Vercel AI SDK tool execute handler."""
    wrapped = await run.interceptor.wrap_execute(
        tool_name=tool_name,
        tool_call_id=tool_call_id,
        arguments=dict(arguments),
        execute=lambda: execute(arguments),
    )
    return wrapped.tool_result


def create_guarded_vercel_book_hotel_tool(run: PaybondAgentRun):
    """Example factory — adapt to your Vercel AI SDK tool() registration."""
    async def _execute(args: Mapping[str, Any], *, tool_call_id: str) -> Any:
        return await execute_guarded_vercel_tool(
            run,
            tool_name="travel.book_hotel",
            tool_call_id=tool_call_id,
            arguments=args,
            execute=book_hotel,
        )

    return _execute'''
    if framework == "mcp":
        return '''from paybond_kit.mcp_tool_surface import create_paybond_mcp_tool_surface


def create_mcp_tool_surface(run: PaybondAgentRun) -> Any:
    """Stdio MCP host config — bind a run first, then paybond mcp install for coding-agent hosts."""
    return create_paybond_mcp_tool_surface(run, env_file=".env.local")'''
    return '''from paybond_kit.agent import create_paybond_generic_agent_config


def create_generic_agent_config(run: PaybondAgentRun, tools: list[dict[str, Any]]) -> Any:
    """Recommended default when the agent framework is unknown."""
    return create_paybond_generic_agent_config(run, tools)


def wrap_agent_tools(run: PaybondAgentRun, tools: list[dict[str, Any]]) -> list[Any]:
    """Wrap {name, execute} tools for any agent-agnostic runtime."""
    return create_generic_agent_config(run, tools).tools'''


def _agent_middleware_template(framework: str) -> str:
    completion_preset = get_completion_preset("cost_and_completion")
    evidence_schema = json.dumps(completion_preset["evidence_schema"], indent=4)
    normalized_framework = _normalize_agent_middleware_framework(framework)
    framework_block = _agent_middleware_framework_block(normalized_framework)
    header_comments = _agent_middleware_header_comments(normalized_framework)
    return f'''import os
from collections.abc import Awaitable, Callable, Mapping
from pathlib import Path
from typing import Any

from paybond_kit import Paybond
from paybond_kit.agent import PaybondAgentRun, create_paybond_tool_registry

{_env_helpers_block()}

{header_comments}

# Agent middleware preset maps to completion catalog archetype: cost_and_completion ({completion_preset["harbor_template_id"]}).
COMPLETION_PRESET_ID = "cost_and_completion"
DEFAULT_OPERATION = "travel.book_hotel"
DEFAULT_REQUESTED_SPEND_CENTS = 20_000

_COMPLETION_EVIDENCE_SCHEMA: dict[str, Any] = {evidence_schema}


async def book_hotel(args: Mapping[str, Any]) -> dict[str, Any]:
    estimated_price_cents = int(args["estimated_price_cents"])
    return {{
        "reservation": {{
            "status": "confirmed",
            "price_cents": estimated_price_cents,
            "city": str(args["city"]),
        }},
    }}


async def search_web(args: Mapping[str, Any]) -> dict[str, Any]:
    query = str(args["query"])
    return {{"hits": [{{"title": query, "url": "https://example.com"}}]}}


def create_agent_tool_registry() -> Any:
    return create_paybond_tool_registry(
        {{
            "side_effecting": {{
                "travel.book_hotel": {{
                    "spend_cents": lambda args: int(args["estimated_price_cents"]),
                    "evidence_preset": COMPLETION_PRESET_ID,
                    "evidence_mapper": lambda result, _ctx: {{
                        "status": (
                            "completed"
                            if result["reservation"]["status"] == "confirmed"
                            else result["reservation"]["status"]
                        ),
                        "cost_cents": result["reservation"]["price_cents"],
                    }},
                }},
            }},
            "default_deny": True,
        }}
    )


async def bind_agent_run(
    paybond: Paybond,
    registry: Any,
    *,
    operation: str = DEFAULT_OPERATION,
    requested_spend_cents: int = DEFAULT_REQUESTED_SPEND_CENTS,
    evidence_schema: Mapping[str, Any] | None = None,
    run_id: str | None = None,
) -> PaybondAgentRun:
    return await paybond.agent_run.bind(
        {{
            "bootstrap": {{
                "kind": "sandbox",
                "operation": operation,
                "requested_spend_cents": requested_spend_cents,
                "completion_preset": COMPLETION_PRESET_ID,
                "evidence_schema": evidence_schema or _COMPLETION_EVIDENCE_SCHEMA,
            }},
            "registry": registry,
            "run_id": run_id,
        }}
    )


{_production_policy_binding_comments(completion_preset["harbor_template_id"])}


{framework_block}
'''


def _paid_tool_guard_template(framework: str) -> str:
    note = FRAMEWORK_NOTES[framework]
    completion_preset = get_completion_preset("cost_and_completion")
    evidence_schema = json.dumps(completion_preset["evidence_schema"], indent=4)
    parameters = json.dumps(completion_preset["parameters"], indent=4)
    return f'''import os
from pathlib import Path
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any, TypeVar

from paybond_kit import (
    Paybond,
    SandboxGuardrailBootstrapResult,
    SandboxGuardrailEvidenceResult,
)

# Paid-tool guardrail preset maps to completion catalog archetype: cost_and_completion ({completion_preset["harbor_template_id"]}).
COMPLETION_PRESET_ID = "cost_and_completion"
HARBOR_TEMPLATE_ID = "{completion_preset["harbor_template_id"]}"


@dataclass(frozen=True)
class CompletionEvidence:
    status: str
    cost_cents: int


def build_completion_evidence(fields: CompletionEvidence) -> dict[str, Any]:
    return {{"status": fields.status, "cost_cents": fields.cost_cents}}


# Production: version_seq and digest_hex are assigned after publishing the managed template head.
policy_binding_stub = {{
    "template_id": HARBOR_TEMPLATE_ID,
    "parameters": {parameters},
}}

{_production_policy_binding_comments(completion_preset["harbor_template_id"])}

_COMPLETION_EVIDENCE_SCHEMA: dict[str, Any] = {evidence_schema}

DEFAULT_OPERATION = "paid_tool.operation"
DEFAULT_REQUESTED_SPEND_CENTS = 500

TInput = TypeVar("TInput")
TResult = TypeVar("TResult")
PaidToolHandler = Callable[[TInput], TResult | Awaitable[TResult]]

{_env_helpers_block()}


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
        evidence_schema=evidence_schema or _COMPLETION_EVIDENCE_SCHEMA,
        completion_preset=COMPLETION_PRESET_ID,
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


# Prefer build_completion_evidence(CompletionEvidence(status="completed", cost_cents=10)) for catalog-aligned evidence.
'''


def _scaffold_body(preset: str, framework: str) -> str:
    if preset == "agent-middleware":
        return _agent_middleware_template(framework)
    return _paid_tool_guard_template(framework)


def _scaffold_label(preset: str) -> str:
    if preset == "agent-middleware":
        return "agent middleware integration"
    return "guardrail integration"


def _validate_framework_for_preset(preset: str, framework: str) -> None:
    if preset == "agent-middleware":
        _normalize_agent_middleware_framework(framework)


def run_init_scaffold(argv: list[str] | None = None) -> int:
    import sys

    parser = argparse.ArgumentParser(
        description="Scaffold a production-shaped Paybond guardrail or agent middleware integration helper."
    )
    parser.add_argument(
        "--preset",
        choices=PRESETS,
        default="paid-tool-guard",
    )
    parser.add_argument(
        "--framework",
        choices=sorted(set(FRAMEWORK_NOTES) | set(AGENT_MIDDLEWARE_FRAMEWORKS)),
        default=None,
    )
    parser.add_argument("--out", default=None)
    parser.add_argument("--force", action="store_true")
    try:
        args = parser.parse_args(argv)
        if args.framework is None:
            args.framework = "generic" if args.preset == "agent-middleware" else "provider-agnostic"
        _validate_framework_for_preset(args.preset, args.framework)
    except SystemExit as exc:
        return 0 if exc.code == 0 else 2
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    out_path = Path(args.out or PRESET_DEFAULT_OUT[args.preset])
    if out_path.exists() and not args.force:
        parser.error(f"{out_path} already exists; pass --force to overwrite")
    out_path.write_text(_scaffold_body(args.preset, args.framework), encoding="utf-8")
    print(f"Created Paybond {_scaffold_label(args.preset)}: {out_path}")
    return 0


def run_init_guardrail(argv: list[str] | None = None) -> int:
    return run_init_scaffold(argv)


def run_init_agent_middleware(argv: list[str] | None = None) -> int:
    import sys

    preset_args = ["--preset", "agent-middleware", *(argv if argv is not None else [])]
    return run_init_scaffold(preset_args)


def main(argv: list[str] | None = None) -> int:
    import sys

    from paybond_kit.cli.router import main as cli_main

    return cli_main(["init", "guardrail", *(argv if argv is not None else sys.argv[1:])])


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

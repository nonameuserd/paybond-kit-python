# `paybond-kit`

<!-- mcp-name: io.github.nonameuserd/paybond -->

Paybond Kit for Python is the PyPI package for tenant-bound Paybond integrations and delegated agent spend controls. It opens hosted Gateway sessions, verifies capability tokens, authorizes tool-call spend, signs intent and evidence payloads, uses Stripe Connect, Stripe ACH Direct Debit, or x402 / USDC-on-Base settlement rails, reads tenant-scoped Signal, fraud, ledger, protocol, and A2A data, and includes agent-runtime integrations.

Paybond is the SDK to use when you do not want to build your own delegated agent spend-governance middleware. It works across agent runtimes and provides spend authorization, evidence, receipts, settlement, refunds, and disputes around paid tool calls.

## Install

Core SDK:

```bash
pip install paybond-kit
```

Optional integrations — install only the extras your runtime needs:

```bash
pip install "paybond-kit[langgraph]"
pip install "paybond-kit[claude-agents]"
pip install "paybond-kit[mcp]"
pip install "paybond-kit[langgraph,mcp]"
```

| Extra | Enables |
| --- | --- |
| `langgraph` | LangGraph tool wrapper and `agent demo langgraph smoke` |
| `claude-agents` | Claude Agent SDK in-process MCP helpers and `agent demo claude-agents smoke` |
| `mcp` | `paybond-mcp-server` CLI |

Runtime-neutral guard helpers, policy files, and `paybond agent sandbox smoke` are included in the core package. Vercel AI and OpenAI Agents sandbox demos are TypeScript-only today.

## Open source

`paybond-kit` is distributed as open-source software under the Apache 2.0 license. The source repo and published artifacts include the full license text in `LICENSE`.

## Requirements

- Python 3.11+
- A `paybond_sk_sandbox_...` or `paybond_sk_live_...` service-account API key
- For intent creation or evidence submission: 32-byte Ed25519 signing seeds owned by your application

Published wheels bundle the `paybond_kit._native` extension. `maturin develop` is only required when building from a local checkout.

Create a sandbox key for local development:

```bash
paybond-kit-login
```

`paybond-kit-login` writes a sandbox `PAYBOND_API_KEY` to `.env.local` with file mode `0600`, adds the default `.env.local` target to `.gitignore` when needed, and refuses to overwrite an existing key unless `--force` is passed. Custom env-file paths inside a git repo must already be ignored. Live production keys are created by tenant admins in Console and stored in deployment secret managers.

## CLI

The package ships the `paybond` CLI (`paybond`, `paybond-kit-init`, `paybond-kit-login`, `paybond-mcp-server`).

Scaffold a starter project from bundled templates:

```bash
paybond init --template invoice-agent
pip install -r requirements.txt
paybond agent sandbox smoke --policy-file paybond.policy.yaml \
  --operation saas.provision_seat \
  --requested-spend-cents 2900 \
  --evidence-preset cost_and_completion \
  --result-body '{"status":"completed","cost_cents":2900}' \
  --format json
```

End-to-end sandbox smoke (bind + execute + evidence) with no app code:

```bash
paybond agent sandbox smoke \
  --operation paid-tool \
  --requested-spend-cents 100 \
  --evidence-preset cost_and_completion \
  --result-body '{"status":"ok","cost_cents":100}' \
  --format json
```

`agent sandbox smoke` only requires `paybond-kit`. Framework demo commands load their optional extras on demand.

## First guardrail scaffold

Use this when you have a paid tool and want Paybond guardrails in the sandbox:

```bash
paybond-kit-init \
  --preset paid-tool-guard \
  --framework provider-agnostic \
  --out paybond_paid_tool_guard.py
```

The generated integration opens Paybond from the environment, loads `.env.local` when `PAYBOND_API_KEY` is not already present, bootstraps a sandbox guardrail intent, wraps your paid-tool handler, and submits sandbox evidence. It does not generate a paid-tool implementation. Free Developer is sandbox-only; live settlement rails start on paid production plans.

## Tenant isolation

Every session is bound to the tenant realm echoed by gateway-authenticated service-account introspection.

- Do not pass tenant ids by hand for normal SDK usage.
- Construct one `Paybond` session per tenant/service account.
- Treat any tenant or intent echo mismatch from Harbor as a severity-zero defect.

## Quick start

```python
import asyncio
import os

from paybond_kit import Paybond


def required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"missing {name}")
    return value


async def main() -> None:
    paybond = await Paybond.open(
        api_key=required_env("PAYBOND_API_KEY"),
        expected_environment="sandbox",
    )
    try:
        print("tenant realm:", paybond.harbor.tenant_id)
    finally:
        await paybond.aclose()


asyncio.run(main())
```

## Agent spend controls

Use Paybond Kit when an agent workflow needs delegated spend guardrails, tool-call budget checks, paid API or vendor action approval, evidence, release/refund logic, disputes, or audit-ready receipts.

```python
import asyncio
import os

from paybond_kit import Paybond


async def main() -> None:
    paybond = await Paybond.open(
        api_key=os.environ["PAYBOND_API_KEY"],
        expected_environment="sandbox",
    )
    try:
        guardrail = await paybond.guardrails.bootstrap_sandbox(
            operation="travel.book_hotel",
            requested_spend_cents=20_000,
            currency="usd",
        )

        guard = paybond.spend_guard(guardrail.intent_id, guardrail.capability_token)
        guarded_tool = guard.guard_tool(
            operation=guardrail.operation,
            requested_spend_cents=guardrail.requested_spend_cents,
            handler=book_hotel,
        )

        result = await guarded_tool({"hotel_id": "hotel_123", "max_price_cents": 20_000})
        await paybond.guardrails.submit_sandbox_evidence(
            guardrail.intent_id,
            {"result": result, "sandbox": True},
        )
    finally:
        await paybond.aclose()


asyncio.run(main())
```

The `paybond.harbor` and `paybond.guardrails` clients are created by `Paybond.open(...)` and bound to the tenant resolved from the service-account API key. Production integrations read `capability_token` from `paybond.intents.create(...)`, or from `paybond.intents.fund(...)` after an `x402_usdc_base` payment challenge is satisfied.

## What the package includes

Core SDK:

- `Paybond.open(...)` for API-key-only, tenant-derived hosted sessions
- `HarborClient` for capability verification, intent creation, x402 funding, evidence submission, and ledger reads
- `paybond.signal` and `paybond.fraud` on `Paybond` sessions opened from one service-account API key
- `PaybondIntents` helpers for principal-side signing, x402 funding, and payee-side signing flows
- `PaybondSpendGuard`, `authorize_spend`, and `guard_tool` for spend-named wrappers around capability verification
- Runtime-neutral and framework aliases: `paybond_agent_tool_spend_guard`, `paybond_runtime_neutral_tool_spend_guard`, `paybond_langgraph_tool_spend_guard`, and `paybond_mcp_tool_spend_guard`
- `paybond_runtime_tool_call_adapter` for agent SDKs and custom runtimes that expose a tool-call object plus an application-owned executor

Agent middleware and CLI:

- `PaybondAgentRun`, tool registry, interceptor, and policy-file binding
- `paybond init`, `paybond agent run bind`, `paybond agent tool execute`, and `paybond agent sandbox smoke`
- Optional LangGraph, Claude Agents, and MCP integrations via extras (see table above)

Gateway and trust helpers:

- `GatewaySignalClient` and `ServiceAccountSignalSession` for tenant-scoped Signal reads and signed portfolio artifacts
- `GatewayFraudClient` and `ServiceAccountFraudSession` for tenant-scoped fraud assessments, review queues, review events, metrics, and release-gate config
- Protocol-v2 helpers for mandate verification, replay-safe recognition proof verification, receipt reads, and A2A discovery
- `paybond-kit-login` for sandbox device approval and local `.env.local` API-key setup
- `paybond-kit-init` for generating a Paybond guardrail integration helper

Agent-facing surfaces are model-provider agnostic. Paybond verifies tool operations and tenant scope, not whether a tool call came from OpenAI, Anthropic, Gemini, a local model, or another runtime.

`allowed_tools` values are your own tool or operation names, not a Paybond-owned catalog. Harbor enforces string matching against whatever names you chose when creating the intent.

`settlement_rail` on intent creation is a principal-signed rail request. Stripe destinations and x402 receive addresses stay tenant-owned server-side config and are never supplied by the SDK caller.

The protocol-v2 surface is trust-first: signed mandates, recognition proofs, and receipts work across supported settlement adapters instead of treating any single rail as the product boundary.

Gateway-backed protocol helpers raise `ProtocolHttpError` with parsed `error_code` and `error_message` fields when the gateway returns a JSON error envelope. Recognition-gated flows surface `unregistered_key`, `revoked_key`, `mandate_agent_key_mismatch`, and `protocol_binding_mismatch` explicitly.

## What it does not include

- No operator-tier settlement or console workflows
- No bundled LLM or model runtime — bring your own agent framework and install optional extras when needed
- No model-provider-specific MCP wrapper; the MCP server is host-agnostic and works with any MCP-compatible runtime

## Source build

For local development from this directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
maturin develop
```

Use this path when you are editing the package itself or rebuilding the bundled native extension locally.

## Docs

- Long-form docs: https://paybond.ai/docs/kit
- Agent quickstart: https://paybond.ai/docs/kit/quickstart-agent
- One-command guardrails: https://paybond.ai/docs/kit/one-command-guardrails
- Python quickstart: https://paybond.ai/docs/kit/quickstart-python
- Python SDK reference: https://paybond.ai/docs/kit/sdk-reference-python
- Agent integrations: https://paybond.ai/docs/kit/agent-integrations
- MCP server guide: https://paybond.ai/docs/kit/mcp-server
- Agent runtime tutorial: https://paybond.ai/docs/kit/agent-runtime-tutorial-python
- Python example projects: https://paybond.ai/docs/kit/examples-python
- LangGraph patterns: https://paybond.ai/docs/kit/quickstart-python#agent-framework-integrations

## Release verification

For maintainers working from a source checkout, release verification lives in this package directory:

```bash
python3 scripts/verify_release.py
```

This builds wheel and sdist artifacts, inspects them for stray local files, validates metadata/extras, and smoke-installs the built wheel in a temporary virtual environment.

## Publish to PyPI

For maintainers only:

```bash
export MATURIN_PYPI_TOKEN="pypi-..."
./scripts/publish_release.sh
```

This reruns release verification and then publishes the sdist and wheel with `maturin publish --non-interactive`.

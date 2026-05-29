# `paybond-kit`

Paybond Kit for Python is the PyPI package for tenant-bound Paybond integrations. It opens hosted Gateway sessions, verifies capability tokens, signs intent and evidence payloads, uses Stripe Connect or x402 / USDC-on-Base settlement rails, reads tenant-scoped Signal, fraud, ledger, protocol, and A2A data, and includes optional agent-runtime integrations.

## Install

Core SDK:

```bash
pip install paybond-kit
```

Optional integrations:

```bash
pip install "paybond-kit[agents]"
pip install "paybond-kit[langgraph]"
pip install "paybond-kit[mcp]"
pip install "paybond-kit[agents,langgraph]"
```

Install only the extras your runtime needs. The `agents` extra enables the generic tool-guardrail helper for agent runtimes, `langgraph` enables the LangGraph tool wrapper, and `mcp` enables the `paybond-mcp-server` CLI.

## Open source

`paybond-kit` is distributed as open-source software under the Apache 2.0 license. The source repo and published artifacts include the full license text in `LICENSE`.

## Requirements

- Python 3.11+
- A `paybond_sk_sandbox_...` or `paybond_sk_live_...` service-account API key
- For capability verification: a funded intent id and a capability token minted for that intent
- For intent creation or evidence submission: 32-byte Ed25519 signing seeds owned by your application

Published wheels bundle the `paybond_kit._native` extension. `maturin develop` is only required when building from a local checkout.

Minimal environment for the quick start:

```bash
export PAYBOND_API_KEY="paybond_sk_sandbox_..."
```

Optional, if you want the quick start to verify a capability:

```bash
export PAYBOND_INTENT_ID="00000000-0000-0000-0000-000000000000"
export PAYBOND_CAPABILITY="base64-biscuit-token"
```

## Tenant isolation

Every session is bound to the tenant realm echoed by gateway-authenticated service-account introspection.

- Do not pass tenant ids by hand for normal SDK usage.
- Construct one `Paybond` session per tenant/service account.
- Treat any tenant or intent echo mismatch from Harbor as a severity-zero defect.

## Quick start

```python
import asyncio
import os
from uuid import UUID

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

        intent_id = os.environ.get("PAYBOND_INTENT_ID")
        capability = os.environ.get("PAYBOND_CAPABILITY")
        if intent_id and capability:
            verified = await paybond.harbor.verify_capability(
                intent_id=UUID(intent_id),
                token=capability,
                operation="payments.capture",
                requested_spend_cents=18_700,
            )
            if not verified.allow:
                raise RuntimeError(
                    f"verify denied: {verified.code or 'deny'} {verified.message or ''}".strip()
                )
            print("capability verified:", verified.audit_id)
    finally:
        await paybond.aclose()


asyncio.run(main())
```

## What the package includes

Core SDK:

- `Paybond.open(...)` for API-key-only, tenant-derived hosted sessions
- `HarborClient` for capability verification, intent creation, x402 funding, evidence submission, and ledger reads
- `paybond.signal` and `paybond.fraud` on `Paybond` sessions opened from one service-account API key
- `PaybondIntents` helpers for principal-side signing, x402 funding, and payee-side signing flows

Gateway and trust helpers:

- `GatewaySignalClient` and `ServiceAccountSignalSession` for tenant-scoped Signal reads and signed portfolio artifacts
- `GatewayFraudClient` and `ServiceAccountFraudSession` for tenant-scoped fraud assessments, review queues, review events, metrics, and release-gate config
- Protocol-v2 helpers for mandate verification, replay-safe recognition proof verification, receipt reads, and A2A discovery

Optional integrations:

- Optional extras for `agents` and `langgraph`
- Optional extra for `mcp` with the tenant-bound `paybond-mcp-server` CLI

Agent-facing surfaces are model-provider agnostic. Paybond verifies tool operations and tenant scope, not whether a tool call came from OpenAI, Anthropic, Gemini, a local model, or another runtime.

`allowed_tools` values are your own tool or operation names, not a Paybond-owned catalog. Harbor enforces string matching against whatever names you chose when creating the intent.

`settlement_rail` on intent creation is a principal-signed rail request. Stripe destinations and x402 receive addresses stay tenant-owned server-side config and are never supplied by the SDK caller.

The protocol-v2 surface is trust-first: signed mandates, recognition proofs, and receipts work across supported settlement adapters instead of treating any single rail as the product boundary.

Gateway-backed protocol helpers raise `ProtocolHttpError` with parsed `error_code` and `error_message` fields when the gateway returns a JSON error envelope. Recognition-gated flows surface `unregistered_key`, `revoked_key`, `mandate_agent_key_mismatch`, and `protocol_binding_mismatch` explicitly.

## What it does not include

- No operator-tier settlement or console workflows
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
- Python quickstart: https://paybond.ai/docs/kit/quickstart-python
- Python SDK reference: https://paybond.ai/docs/kit/sdk-reference-python
- Agent integrations: https://paybond.ai/docs/kit/agent-integrations
- MCP server guide: https://paybond.ai/docs/kit/mcp-server
- Agent runtime tutorial: https://paybond.ai/docs/kit/agent-runtime-tutorial-python
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

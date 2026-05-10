# `paybond-kit`

Paybond Kit for Python provides a tenant-bound Harbor client, gateway-authenticated service-account sessions, canonical signing for intent creation and evidence submission, x402 / USDC-on-Base intent funding helpers, tenant-scoped ledger provenance reads, tenant-scoped Signal analytics and reputation reads, plus first-party hooks for the OpenAI Agents SDK and LangGraph.

Install the public package with:

```bash
pip install "paybond-kit[agents,langgraph]"
```

## Open source

`paybond-kit` is distributed as open-source software under the Apache 2.0 license. The source repo and published artifacts include the full license text in `LICENSE`.

## Requirements

- Python 3.11+
- A `paybond_sk_...` service-account API key
- Reachable Gateway and Harbor base URLs

Published wheels bundle the `paybond_kit._native` extension. `maturin develop` is only required when building from a local checkout.

## Tenant isolation

Every session is bound to the tenant realm echoed by gateway-authenticated service-account introspection and Harbor access exchange flows.

- Do not pass tenant ids by hand for normal SDK usage.
- Construct one `Paybond` session per tenant/service account.
- Treat any tenant or intent echo mismatch from Harbor as a severity-zero defect.

## Quick start

```python
import asyncio
import os
from uuid import UUID

from paybond_kit import Paybond


async def main() -> None:
    paybond = await Paybond.open(
        gateway_base_url="https://gateway.example.com",
        api_key=os.environ["PAYBOND_API_KEY"],
        harbor_base_url="https://harbor.example.com",
    )
    try:
        verified = await paybond.harbor.verify_capability(
            intent_id=UUID(os.environ["PAYBOND_INTENT_ID"]),
            token=os.environ["PAYBOND_CAPABILITY"],
            operation="payments.capture",
            requested_spend_cents=18_700,
        )
        if not verified.allow:
            raise RuntimeError(f"verify denied: {verified.code or 'deny'} {verified.message or ''}")
    finally:
        await paybond.aclose()


asyncio.run(main())
```

## What the package includes

- `Paybond.open(...)` for gateway-authenticated, tenant-derived Harbor sessions
- `HarborClient` for capability verification, intent creation, x402 funding, evidence submission, and ledger reads
- `GatewaySignalClient` and `ServiceAccountSignalSession` for tenant-scoped Signal reads
- `paybond.signal` on `Paybond` sessions opened from one service-account API key
- `PaybondIntents` helpers for principal-side signing, x402 funding, and payee-side signing flows
- Optional extras for `agents` and `langgraph`

`allowed_tools` values are your own tool or operation names, not a Paybond-owned catalog. Harbor enforces string matching against whatever names you chose when creating the intent.

`settlement_rail` on intent creation is only a rail request. Stripe destinations and x402 receive addresses stay tenant-owned server-side config and are never supplied by the SDK caller.

## What it does not include

- No operator-tier settlement or console workflows

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

- Long-form docs: `docs/kit/`
- Python quickstart: `docs/kit/quickstart-python.md`
- Python SDK reference: `docs/kit/sdk-reference-python.md`
- OpenAI Agents example: `examples/paybond-kit-openai-agents-python/`
- LangGraph example: `examples/paybond-kit-langgraph-python/`

## Release verification

From `kit/python`:

```bash
python3 scripts/verify_release.py
```

This builds wheel and sdist artifacts, inspects them for stray local files, validates metadata/extras, and smoke-installs the built wheel in a temporary virtual environment.

## Publish to PyPI

From `kit/python`:

```bash
export MATURIN_PYPI_TOKEN="pypi-..."
./scripts/publish_release.sh
```

This reruns release verification and then publishes the sdist and wheel with `maturin publish --non-interactive`.

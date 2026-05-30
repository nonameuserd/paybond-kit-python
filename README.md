# `paybond-kit`

Paybond Kit for Python is the PyPI package for tenant-bound Paybond integrations and delegated agent spend controls. It opens hosted Gateway sessions, verifies capability tokens, authorizes tool-call spend, signs intent and evidence payloads, uses Stripe Connect or x402 / USDC-on-Base settlement rails, reads tenant-scoped Signal, fraud, ledger, protocol, and A2A data, and includes agent-runtime integrations.

## Install

Core SDK:

```bash
pip install paybond-kit
```

Optional integrations:

```bash
pip install "paybond-kit[langgraph]"
pip install "paybond-kit[mcp]"
pip install "paybond-kit[langgraph,mcp]"
```

Install only the extras your runtime needs. The `langgraph` extra enables the LangGraph tool wrapper, and `mcp` enables the `paybond-mcp-server` CLI. Runtime-neutral guard helpers are included in the core package.

## Open source

`paybond-kit` is distributed as open-source software under the Apache 2.0 license. The source repo and published artifacts include the full license text in `LICENSE`.

## Requirements

- Python 3.11+
- A `paybond_sk_sandbox_...` or `paybond_sk_live_...` service-account API key
- For intent creation or evidence submission: 32-byte Ed25519 signing seeds owned by your application
- For Gateway-backed Harbor mutations: a runtime signer that can issue a fresh `AgentRecognitionProofV1` for each request
- For `x402_usdc_base` funding: an x402 wallet or facilitator that can sign Harbor's payment challenge

Published wheels bundle the `paybond_kit._native` extension. `maturin develop` is only required when building from a local checkout.

Minimal environment for the quick start:

```bash
export PAYBOND_API_KEY="paybond_sk_sandbox_..."
```

`PAYBOND_API_KEY` is the only long-lived environment variable in the basic quick start. Local sandbox/live quick-start scripts may load `PAYBOND_*_RECOGNITION_PROOF_JSON` or `PAYBOND_X402_PAYMENT_SIGNATURE`, but production integrations should generate those values per request.

## Tenant isolation

Every session is bound to the tenant realm echoed by gateway-authenticated service-account introspection.

- Do not pass tenant ids by hand for normal SDK usage.
- Construct one `Paybond` session per tenant/service account.
- Treat any tenant or intent echo mismatch from Harbor as a severity-zero defect.

## Quick start

```python
import asyncio
import json
import os
from uuid import UUID, uuid4

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
import os
from uuid import UUID

from paybond_kit import Paybond


paybond = await Paybond.open(
    api_key=os.environ["PAYBOND_API_KEY"],
    expected_environment="sandbox",
)

intent_id = uuid4()
create_recognition_proof = json.loads(os.environ["PAYBOND_CREATE_RECOGNITION_PROOF_JSON"])
created = await paybond.intents.create(
    # principal, payee, budget, predicate, evidence schema, deadline...
    recognition_proof=create_recognition_proof,
    allowed_tools=["travel.book_hotel"],
    settlement_rail="stripe_connect",
    intent_id=intent_id,
    idempotency_key=f"intent:{intent_id}",
)

created_intent_id = UUID(str(created["intent_id"]))
if created_intent_id != intent_id:
    raise RuntimeError(f"intent mismatch: requested={intent_id} gateway={created_intent_id}")

capability_token = str(created.get("capability_token") or "")
if not capability_token:
    raise RuntimeError("fund the intent before guarding tools")

guard = paybond.spend_guard(intent_id, capability_token)
verified = await guard.authorize_spend(
    operation="travel.book_hotel",
    requested_spend_cents=20_000,
)
if not verified.allow:
    raise RuntimeError(f"verify denied: {verified.code or 'deny'} {verified.message or ''}".strip())

# Only run the real action after Paybond authorizes the agent to do it.
booking = await book_hotel(...)
```

The `paybond.harbor` client is created by `Paybond.open(...)` and bound to the tenant resolved from the service-account API key. Normal integrations read `capability_token` from `paybond.intents.create(...)`, or from `paybond.intents.fund(...)` after an `x402_usdc_base` payment challenge is satisfied.

## Recognition proofs and x402 signatures

Gateway-backed Harbor mutations such as `paybond.intents.create(...)`, `paybond.intents.fund(...)`, and `paybond.intents.submit_evidence(...)` require `recognition_proof`. Think of it as a short-lived signature that says: "this tenant-registered agent key is authorizing this exact Gateway request right now."

Paybond does not create or hand this proof to your app, and Kit does not generate it automatically. A tenant admin registers the agent runtime's Ed25519 public key in Paybond's trusted agent key registry with a stable `key_id`. Your trusted backend, KMS-backed signer, wallet service, or agent runner keeps the matching private key and signs a fresh `AgentRecognitionProofV1` immediately before each protected mutation.

Kit only transports the finished object: it encodes `recognition_proof` and sends it as `x-paybond-agent-recognition-proof`. Gateway verifies the signature against the registered public key, checks tenant/purpose/request binding, and rejects replayed nonces.

Generate the proof after the request body is fixed. It should bind the request purpose, method, path, SHA-256 body digest, `verifier_context.tenant_id=paybond.harbor.tenant_id`, `verifier_context.verifier_id="paybond-gateway"`, the tenant-registered `key_id`, a unique nonce, a short expiry window, and the Ed25519 digest/signature fields. If your signer cannot reproduce the exact body built by a high-level helper, prebuild the body and call the lower-level `paybond.harbor` method directly.

`PAYBOND_FUND_RETRY_RECOGNITION_PROOF_JSON` is a local quick-start placeholder for the second `/fund` call, not a static value an operator should provision. The first `/fund` call and the retry each need a different proof because proof nonces are single-use.

`PAYBOND_X402_PAYMENT_SIGNATURE` is also only a local quick-start stand-in. In production, ask your x402 wallet or facilitator to sign the `payment_required` challenge returned by Harbor, then pass that result as `payment_signature`.

```python
fund_proof = await issue_agent_recognition_proof_v1(
    purpose="harbor.intent.fund",
    method="POST",
    path=f"/harbor/intents/{intent_id}/fund",
    body={},
)
first = await paybond.intents.fund(intent_id, recognition_proof=fund_proof)

if first.status_code == 402:
    if not first.payment_required:
        raise RuntimeError("missing PAYMENT-REQUIRED challenge")

    payment_signature = await x402_wallet.sign_payment(first.payment_required)
    retry_proof = await issue_agent_recognition_proof_v1(
        purpose="harbor.intent.fund",
        method="POST",
        path=f"/harbor/intents/{intent_id}/fund",
        body={},
    )
    await paybond.intents.fund(
        intent_id,
        recognition_proof=retry_proof,
        payment_signature=payment_signature,
    )
```

`issue_agent_recognition_proof_v1(...)` and `x402_wallet.sign_payment(...)` are application-owned helpers, not Kit exports.

Scaffold a wrapper:

```bash
paybond-kit-init --framework provider-agnostic --out paybond_spend_guard.py
```

## What the package includes

Core SDK:

- `Paybond.open(...)` for API-key-only, tenant-derived hosted sessions
- `HarborClient` for capability verification, intent creation, x402 funding, evidence submission, and ledger reads
- `paybond.signal` and `paybond.fraud` on `Paybond` sessions opened from one service-account API key
- `PaybondIntents` helpers for principal-side signing, x402 funding, and payee-side signing flows
- `PaybondSpendGuard`, `authorize_spend`, and `guard_tool` for spend-named wrappers around capability verification
- Runtime-neutral and framework aliases: `paybond_agent_tool_spend_guard`, `paybond_runtime_neutral_tool_spend_guard`, `paybond_langgraph_tool_spend_guard`, and `paybond_mcp_tool_spend_guard`
- `paybond_runtime_tool_call_adapter` for agent SDKs and custom runtimes that expose a tool-call object plus an application-owned executor

Gateway and trust helpers:

- `GatewaySignalClient` and `ServiceAccountSignalSession` for tenant-scoped Signal reads and signed portfolio artifacts
- `GatewayFraudClient` and `ServiceAccountFraudSession` for tenant-scoped fraud assessments, review queues, review events, metrics, and release-gate config
- Protocol-v2 helpers for mandate verification, replay-safe recognition proof verification, receipt reads, and A2A discovery

Optional integrations:

- Optional extras for `agents` and `langgraph`
- Optional extra for `mcp` with the tenant-bound `paybond-mcp-server` CLI
- `paybond-kit-init` for generating a small spend guard wrapper

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

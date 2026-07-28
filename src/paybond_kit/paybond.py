"""High-level :class:`Paybond` API over hosted Gateway-backed sessions."""

from __future__ import annotations

import inspect
import json
from dataclasses import dataclass
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any, Mapping
from uuid import UUID, uuid4

from paybond_kit.a2a import GatewayA2AClient
from paybond_kit.audit.exports import PaybondAudit, PaybondAuditExports, GatewayAuditExportsClientOptions
from paybond_kit.credentials import DEFAULT_PAYBOND_GATEWAY_BASE_URL, PaybondEnvironment
from paybond_kit.fraud import GatewayFraudClient
from paybond_kit.guardrails import GatewaySandboxGuardrailsClient
from paybond_kit.harbor import (
    FundIntentResult,
    GatewayHarborClient,
    HarborClient,
    SettlementRail,
    validate_settlement_rail,
)
from paybond_kit.protocol import GatewayProtocolClient
from paybond_kit.signal import GatewaySignalClient, _resolve_gateway_tenant_id

if TYPE_CHECKING:
    from paybond_kit.agent import PaybondToolRegistry, PaybondToolRegistryConfig
    from paybond_kit.agent.guarded_agent import (
        CreateGuardedAgentInput,
        CreateGuardedAgentResult,
        GuardedAgentFramework,
    )
    from paybond_kit.agent.instrument import (
        PaybondInstrumentBuilder,
        PaybondInstrumented,
        PaybondInstrumentRuntime,
    )
    from paybond_kit.agent.receipt_client import PaybondAgentFacade
    from paybond_kit.agent.run import PaybondAgentRun
    from paybond_kit.mpp_funding import MppFundPollOptions
    from paybond_kit.policy.load import PaybondPolicyLoadSource
    from paybond_kit.x402_funding import FundRequestEnvelope, X402FundPollOptions


@dataclass
class PaybondIntents:
    """Tenant-scoped intent helpers (principal-signed intent create, x402 funding, payee evidence, settlement)."""

    _harbor: HarborClient | GatewayHarborClient
    _tenant_id: str

    async def create(
        self,
        *,
        principal_did: str,
        principal_signing_seed: bytes,
        payee_did: str,
        payee_signing_seed: bytes,
        budget: Mapping[str, Any],
        predicate: Mapping[str, Any],
        currency: str,
        amount_cents: int,
        evidence_schema: Mapping[str, Any],
        deadline_rfc3339: str,
        allowed_tools: list[str],
        settlement_rail: SettlementRail,
        recognition_proof: Mapping[str, Any],
        intent_id: UUID | None = None,
        predicate_ref: str = "",
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """
        Build a principal-signed ``POST /intents`` body and submit it to Harbor.

        ``principal_signing_seed`` must be 32 bytes. ``tenant_id`` comes from the gateway exchange
        and must match ``x-tenant-id`` on the Harbor request (enforced by :class:`HarborClient`).
        ``settlement_rail`` is part of the principal signature and requests one allowed rail;
        Harbor resolves the destination from canonical tenant settlement config.
        """
        settlement_rail = validate_settlement_rail(
            settlement_rail,
            field="settlement_rail",
        )
        try:
            from paybond_kit import _native
        except ImportError as exc:
            raise ImportError(
                "paybond_kit._native is required for intent creation. Install a published wheel "
                "with `pip install paybond-kit`, or from a checkout run "
                "`maturin develop` (Rust toolchain required)."
            ) from exc

        if len(principal_signing_seed) != 32:
            raise ValueError("principal_signing_seed must be exactly 32 bytes")
        if len(payee_signing_seed) != 32:
            raise ValueError("payee_signing_seed must be exactly 32 bytes")
        iid = intent_id or uuid4()
        wire = _native.build_signed_create_intent_json(
            self._tenant_id,
            principal_signing_seed,
            payee_signing_seed,
            str(iid),
            principal_did,
            payee_did,
            json.dumps(dict(budget)),
            currency,
            int(amount_cents),
            json.dumps(dict(evidence_schema)),
            deadline_rfc3339,
            json.dumps(dict(predicate)),
            predicate_ref,
            json.dumps(allowed_tools),
            settlement_rail,
        )
        body = json.loads(wire)
        return await self._harbor.create_intent(
            body,
            recognition_proof=recognition_proof,  # type: ignore[call-arg]
            idempotency_key=idempotency_key,
        )

    async def create_with_policy_binding(
        self,
        *,
        principal_did: str,
        principal_signing_seed: bytes,
        payee_did: str,
        payee_signing_seed: bytes,
        budget: Mapping[str, Any],
        currency: str,
        amount_cents: int,
        evidence_schema: Mapping[str, Any],
        deadline_rfc3339: str,
        allowed_tools: list[str],
        settlement_rail: SettlementRail,
        recognition_proof: Mapping[str, Any],
        policy_template_id: str,
        policy_version_seq: int,
        materialized_predicate: Mapping[str, Any],
        policy_content_digest_hex: str,
        intent_id: UUID | None = None,
        predicate_ref: str = "",
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """Build a signing-v5 ``POST /intents`` body bound to a published managed-policy head."""
        settlement_rail = validate_settlement_rail(
            settlement_rail,
            field="settlement_rail",
        )
        try:
            from paybond_kit import _native
        except ImportError as exc:
            raise ImportError(
                "paybond_kit._native is required for intent creation. Install a published wheel "
                "with `pip install paybond-kit`, or from a checkout run "
                "`maturin develop` (Rust toolchain required)."
            ) from exc

        if len(principal_signing_seed) != 32:
            raise ValueError("principal_signing_seed must be exactly 32 bytes")
        if len(payee_signing_seed) != 32:
            raise ValueError("payee_signing_seed must be exactly 32 bytes")
        iid = intent_id or uuid4()
        wire = _native.build_signed_create_intent_with_policy_binding_json(
            self._tenant_id,
            principal_signing_seed,
            payee_signing_seed,
            str(iid),
            principal_did,
            payee_did,
            json.dumps(dict(budget)),
            currency,
            int(amount_cents),
            json.dumps(dict(evidence_schema)),
            deadline_rfc3339,
            json.dumps(dict(materialized_predicate)),
            predicate_ref,
            json.dumps(allowed_tools),
            settlement_rail,
            policy_template_id,
            int(policy_version_seq),
            policy_content_digest_hex,
        )
        body = json.loads(wire)
        return await self._harbor.create_intent(
            body,
            recognition_proof=recognition_proof,  # type: ignore[call-arg]
            idempotency_key=idempotency_key,
        )

    async def create_spend_intent(self, **kwargs: Any) -> dict[str, Any]:
        return await self.create(**kwargs)

    async def fund(
        self,
        intent_id: UUID,
        *,
        recognition_proof: Mapping[str, Any],
        payment_signature: str | None = None,
        payment_authorization: str | None = None,
        idempotency_key: str | None = None,
    ) -> FundIntentResult:
        """
        Advance Harbor ``POST /intents/{intent_id}/fund`` for x402 / USDC-on-Base intents.

        When Harbor responds with ``402``, use the returned ``payment_required`` challenge with
        your x402 wallet or facilitator, then retry with ``payment_signature=...``.

        For MPP Payment Auth through the gateway, pass ``payment_authorization``; Kit sends it as
        ``x-paybond-payment-authorization: Payment …`` so ``Authorization: Bearer`` stays free.
        """
        return await self._harbor.fund_intent(
            intent_id,
            recognition_proof=recognition_proof,  # type: ignore[call-arg]
            payment_signature=payment_signature,
            payment_authorization=payment_authorization,
            idempotency_key=idempotency_key,
        )

    async def fund_with_x402(
        self,
        intent_id: UUID,
        *,
        recognition_proof: Mapping[str, Any],
        sign_payment: Callable[[str], Awaitable[str]],
        issue_recognition_proof: Callable[
            ["FundRequestEnvelope"], Awaitable[Mapping[str, Any]]
        ],
        poll_options: "X402FundPollOptions | None" = None,
        idempotency_key: str | None = None,
    ) -> FundIntentResult:
        """
        One-call x402 fund flow: sign 402 challenges, retry with ``payment-signature``, poll until funded.

        Wallet keys stay app-owned — pass injectable ``sign_payment`` and ``issue_recognition_proof``.
        """
        from paybond_kit.x402_funding import execute_fund_with_x402

        return await execute_fund_with_x402(
            intent_id=intent_id,
            recognition_proof=recognition_proof,
            sign_payment=sign_payment,
            issue_recognition_proof=issue_recognition_proof,
            poll_options=poll_options,
            fund=lambda **kwargs: self.fund(
                intent_id,
                idempotency_key=idempotency_key,
                **kwargs,
            ),
        )

    async def fund_with_mpp_charge(
        self,
        intent_id: UUID,
        *,
        recognition_proof: Mapping[str, Any],
        create_payment_credential: Callable[[str], Awaitable[str]],
        issue_recognition_proof: Callable[
            ["FundRequestEnvelope"], Awaitable[Mapping[str, Any]]
        ],
        poll_options: "MppFundPollOptions | None" = None,
        idempotency_key: str | None = None,
    ) -> FundIntentResult:
        """
        One-shot Stripe MPP charge fund flow: create Payment Auth credentials from 402 challenges,
        retry with ``payment_authorization``, and poll until funded.

        MPP wallet and SPT secrets stay app-owned — pass injectable ``create_payment_credential``
        and ``issue_recognition_proof``.
        """
        from paybond_kit.mpp_funding import execute_fund_with_mpp_charge

        return await execute_fund_with_mpp_charge(
            intent_id=intent_id,
            recognition_proof=recognition_proof,
            create_payment_credential=create_payment_credential,
            issue_recognition_proof=issue_recognition_proof,
            poll_options=poll_options,
            fund=lambda **kwargs: self.fund(
                intent_id,
                idempotency_key=idempotency_key,
                **kwargs,
            ),
        )

    async def fund_with_mpp_session(
        self,
        intent_id: UUID,
        *,
        recognition_proof: Mapping[str, Any],
        create_payment_credential: Callable[[str], Awaitable[str]],
        issue_recognition_proof: Callable[
            ["FundRequestEnvelope"], Awaitable[Mapping[str, Any]]
        ],
        poll_options: "MppFundPollOptions | None" = None,
        idempotency_key: str | None = None,
    ) -> FundIntentResult:
        """
        Tempo MPP session fund flow: open a session channel deposit via Payment Auth credentials,
        retry with ``payment_authorization``, and poll until the intent is funded.

        MPP wallet and SPT secrets stay app-owned — pass injectable ``create_payment_credential``
        and ``issue_recognition_proof``.
        """
        from paybond_kit.mpp_funding import execute_fund_with_mpp_session

        return await execute_fund_with_mpp_session(
            intent_id=intent_id,
            recognition_proof=recognition_proof,
            create_payment_credential=create_payment_credential,
            issue_recognition_proof=issue_recognition_proof,
            poll_options=poll_options,
            fund=lambda **kwargs: self.fund(
                intent_id,
                idempotency_key=idempotency_key,
                **kwargs,
            ),
        )

    async def submit_evidence(
        self,
        intent_id: UUID,
        payload: Mapping[str, Any],
        *,
        payee_did: str,
        payee_signing_seed: bytes,
        recognition_proof: Mapping[str, Any],
        artifacts_blake3_hex: list[str] | None = None,
        submitted_at_rfc3339: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """
        Sign payee evidence with :func:`paybond_kit.signing.sign_payee_evidence_binding` and POST it.

        ``payee_signing_seed`` must be 32 bytes and match the payee key bound on the intent.
        """
        from datetime import datetime, timezone

        from paybond_kit.signing import sign_payee_evidence_binding

        if len(payee_signing_seed) != 32:
            raise ValueError("payee_signing_seed must be exactly 32 bytes")
        ts = submitted_at_rfc3339 or datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        wire = sign_payee_evidence_binding(
            tenant_id=self._tenant_id,
            intent_id=intent_id,
            payee_did=payee_did,
            payload=dict(payload),
            artifacts_blake3_hex=artifacts_blake3_hex or [],
            submitted_at_rfc3339=ts,
            payee_signing_seed=payee_signing_seed,
        )
        return await self._harbor.submit_evidence(
            intent_id,
            wire,
            recognition_proof=recognition_proof,  # type: ignore[call-arg]
            idempotency_key=idempotency_key,
        )

    async def confirm_settlement(
        self,
        intent_id: UUID | str,
        *,
        recognition_proof: Mapping[str, Any],
        body: Mapping[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """
        Confirm Harbor settlement via Gateway ``POST /harbor/intents/{intent_id}/settlement/confirm``.

        Confirms the settlement action implied by stored evidence; does not choose release vs refund.
        """
        iid = intent_id if isinstance(intent_id, UUID) else UUID(str(intent_id))
        payload = dict(body or {})
        return await self._harbor.confirm_settlement(
            iid,
            payload,
            recognition_proof=recognition_proof,  # type: ignore[call-arg]
            idempotency_key=idempotency_key,
        )


@dataclass
class Paybond:
    """
    Hosted Gateway + Harbor proxy session with ergonomic :attr:`intents` helpers.
    """

    harbor: GatewayHarborClient
    guardrails: GatewaySandboxGuardrailsClient
    signal: GatewaySignalClient
    fraud: GatewayFraudClient
    a2a: GatewayA2AClient
    protocol: GatewayProtocolClient
    intents: PaybondIntents
    audit: PaybondAudit

    @classmethod
    async def open(
        cls,
        *,
        api_key: str,
        gateway_base_url: str = DEFAULT_PAYBOND_GATEWAY_BASE_URL,
        principal_path: str = "/v1/auth/principal",
        expected_environment: PaybondEnvironment | None = None,
        max_retries: int = 3,
    ) -> Paybond:
        tenant = await _resolve_gateway_tenant_id(
            gateway_base_url=gateway_base_url,
            api_key=api_key,
            principal_path=principal_path,
            expected_environment=expected_environment,
            max_retries=max_retries,
        )
        harbor = GatewayHarborClient(
            gateway_base_url,
            tenant,
            static_gateway_bearer_token=api_key,
            max_retries=max_retries,
        )
        return cls(
            harbor=harbor,
            guardrails=GatewaySandboxGuardrailsClient(
                gateway_base_url,
                tenant,
                static_gateway_bearer_token=api_key,
                max_retries=max_retries,
            ),
            signal=GatewaySignalClient(
                gateway_base_url,
                tenant,
                static_gateway_bearer_token=api_key,
                max_retries=max_retries,
            ),
            fraud=GatewayFraudClient(
                gateway_base_url,
                tenant,
                static_gateway_bearer_token=api_key,
                max_retries=max_retries,
            ),
            a2a=GatewayA2AClient(
                gateway_base_url,
                static_gateway_bearer_token=api_key,
                max_retries=max_retries,
            ),
            protocol=GatewayProtocolClient(
                gateway_base_url,
                tenant,
                static_gateway_bearer_token=api_key,
                max_retries=max_retries,
            ),
            intents=PaybondIntents(harbor, tenant),
            audit=PaybondAudit(
                PaybondAuditExports.open(
                    gateway_base_url,
                    tenant,
                    options=GatewayAuditExportsClientOptions(
                        static_gateway_bearer_token=api_key,
                        max_retries=max_retries,
                    ),
                )
            ),
        )

    async def aclose(self) -> None:
        await self.harbor.aclose()
        await self.guardrails.aclose()
        await self.protocol.aclose()
        await self.a2a.aclose()
        await self.fraud.aclose()
        await self.signal.aclose()
        exports_gateway = self.audit.exports._gateway
        exports_aclose = getattr(exports_gateway, "aclose", None)
        if callable(exports_aclose):
            maybe_awaitable = exports_aclose()
            if inspect.isawaitable(maybe_awaitable):
                await maybe_awaitable

    def spend_guard(self, intent_id: UUID, capability_token: str):
        from paybond_kit.spend_guard import PaybondSpendGuard

        return PaybondSpendGuard(
            harbor=self.harbor,
            intent_id=intent_id,
            capability_token=capability_token,
        )

    async def authorize_spend(
        self,
        *,
        intent_id: UUID,
        token: str,
        operation: str,
        requested_spend_cents: int = 0,
    ):
        return await self.harbor.authorize_spend(
            intent_id=intent_id,
            token=token,
            operation=operation,
            requested_spend_cents=requested_spend_cents,
        )

    def tool_registry(
        self,
        config: PaybondToolRegistryConfig | None = None,
    ) -> PaybondToolRegistry:
        from paybond_kit.agent import PaybondToolRegistry

        return PaybondToolRegistry(config)

    async def create_guarded_agent(self, input_: "CreateGuardedAgentInput") -> "CreateGuardedAgentResult":
        from paybond_kit.agent.guarded_agent import CreateGuardedAgentInput, CreateGuardedAgentResult, create_guarded_agent

        return await create_guarded_agent(self, input_)

    async def create_guarded_agent_runner(self, input_: "CreateGuardedAgentInput") -> "CreateGuardedAgentResult":
        from paybond_kit.agent.guarded_agent import create_guarded_agent_runner

        return await create_guarded_agent_runner(self, input_)

    async def instrument(
        self,
        agent_or_config: Any = None,
        /,
        *,
        policy: "PaybondPolicyLoadSource | Mapping[str, Any] | None" = None,
        tools: Any | None = None,
        framework: "GuardedAgentFramework | None" = None,
        bootstrap: Any | None = None,
        attach: Any | None = None,
        run_id: str | None = None,
        validate_policy: bool | Mapping[str, Any] | None = None,
        sandbox: bool | None = None,
        context: Any | None = None,
        **kwargs: Any,
    ) -> Any:
        from paybond_kit.agent.discover import is_instrumentable_agent_object
        from paybond_kit.agent.instrument import instrument_paybond_agent

        if agent_or_config is not None and is_instrumentable_agent_object(agent_or_config):
            return await instrument_paybond_agent(
                self,
                agent_or_config,
                framework=framework,
                policy=policy,
                sandbox=sandbox,
                context=context,
            )

        payload: dict[str, Any] = {**kwargs}
        if agent_or_config is not None and isinstance(agent_or_config, Mapping):
            payload = {**dict(agent_or_config), **payload}
        if policy is not None:
            payload["policy"] = policy
        if tools is not None:
            payload["tools"] = tools
        if framework is not None:
            payload["framework"] = framework
        if bootstrap is not None:
            payload["bootstrap"] = bootstrap
        if attach is not None:
            payload["attach"] = attach
        if run_id is not None:
            payload["run_id"] = run_id
        if validate_policy is not None:
            payload["validate_policy"] = validate_policy
        if sandbox is not None:
            payload["sandbox"] = sandbox
        if context is not None:
            payload["context"] = context
        return await instrument_paybond_agent(
            self,
            payload,
            framework=framework,
            policy=policy,
            sandbox=sandbox,
            context=context,
        )

    def policy(self, source: "PaybondPolicyLoadSource | Mapping[str, Any]") -> "PaybondInstrumentBuilder":
        from paybond_kit.agent.facade import resolve_agent_policy_source
        from paybond_kit.agent.instrument import PaybondInstrumentBuilder

        resolved = resolve_agent_policy_source(source) if isinstance(source, str) else source
        return PaybondInstrumentBuilder(paybond=self, policy=resolved)

    def use_policy(self, preset_id: str) -> "PaybondInstrumentBuilder":
        return self.policy(preset_id)

    async def instrument_langgraph(self, **kwargs: Any) -> "PaybondInstrumented | PaybondInstrumentRuntime":
        from paybond_kit.agent.instrument import instrument_paybond_langgraph

        return await instrument_paybond_langgraph(self, kwargs)

    async def instrument_openai(self, **kwargs: Any) -> "PaybondInstrumented | PaybondInstrumentRuntime":
        from paybond_kit.agent.instrument import instrument_paybond_openai

        return await instrument_paybond_openai(self, kwargs)

    async def instrument_vercel(self, **kwargs: Any) -> "PaybondInstrumented | PaybondInstrumentRuntime":
        from paybond_kit.agent.instrument import instrument_paybond_vercel

        return await instrument_paybond_vercel(self, kwargs)

    async def instrument_claude_agents(self, **kwargs: Any) -> "PaybondInstrumented | PaybondInstrumentRuntime":
        from paybond_kit.agent.instrument import instrument_paybond_claude_agents

        return await instrument_paybond_claude_agents(self, kwargs)

    async def instrument_crewai(self, **kwargs: Any) -> "PaybondInstrumented | PaybondInstrumentRuntime":
        from paybond_kit.agent.instrument import instrument_paybond_crewai

        return await instrument_paybond_crewai(self, kwargs)

    async def instrument_pydantic_ai(self, **kwargs: Any) -> "PaybondInstrumented | PaybondInstrumentRuntime":
        from paybond_kit.agent.instrument import instrument_paybond_pydantic_ai

        return await instrument_paybond_pydantic_ai(self, kwargs)

    async def instrument_google_adk(self, **kwargs: Any) -> "PaybondInstrumented | PaybondInstrumentRuntime":
        from paybond_kit.agent.instrument import instrument_paybond_google_adk

        return await instrument_paybond_google_adk(self, kwargs)

    async def instrument_microsoft_agent_framework(
        self, **kwargs: Any
    ) -> "PaybondInstrumented | PaybondInstrumentRuntime":
        from paybond_kit.agent.instrument import instrument_paybond_microsoft_agent_framework

        return await instrument_paybond_microsoft_agent_framework(self, kwargs)

    async def instrument_mcp(self, **kwargs: Any) -> "PaybondInstrumented | PaybondInstrumentRuntime":
        from paybond_kit.agent.instrument import instrument_paybond_mcp

        return await instrument_paybond_mcp(self, kwargs)

    @property
    def agent(self) -> "PaybondAgentFacade":
        from paybond_kit.agent.receipt_client import PaybondAgentFacade

        return PaybondAgentFacade(self, self.protocol)

    def wrap_tools(
        self,
        run: "PaybondAgentRun",
        tools: Any,
        *,
        framework: "GuardedAgentFramework" = "generic",
    ) -> Any:
        from paybond_kit.agent.facade import wrap_paybond_tools

        return wrap_paybond_tools(run, tools, framework=framework)

    @property
    def policy_presets(self):
        from paybond_kit.policy.policy_api import paybond_policy_presets

        return paybond_policy_presets

    @property
    def solution(self):
        from paybond_kit.solution_api import paybond_solution_presets

        return paybond_solution_presets

    @property
    def agent_run(self):
        from paybond_kit.agent.run import PaybondAgentRunFacade

        return PaybondAgentRunFacade(self)

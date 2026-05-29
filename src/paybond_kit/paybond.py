"""High-level :class:`Paybond` API over hosted Gateway-backed sessions."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping
from uuid import UUID, uuid4

from paybond_kit.a2a import GatewayA2AClient
from paybond_kit.credentials import DEFAULT_PAYBOND_GATEWAY_BASE_URL, PaybondEnvironment
from paybond_kit.fraud import GatewayFraudClient
from paybond_kit.harbor import (
    FundIntentResult,
    GatewayHarborClient,
    HarborClient,
    SettlementRail,
    validate_settlement_rail,
)
from paybond_kit.protocol import GatewayProtocolClient
from paybond_kit.signal import GatewaySignalClient, _resolve_gateway_tenant_id


@dataclass
class PaybondIntents:
    """Tenant-scoped intent helpers (principal-signed intent create, x402 funding, payee evidence)."""

    _harbor: HarborClient | GatewayHarborClient
    _tenant_id: str

    async def create(
        self,
        *,
        principal_did: str,
        principal_signing_seed: bytes,
        payee_did: str,
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
        iid = intent_id or uuid4()
        wire = _native.build_signed_create_intent_json(
            self._tenant_id,
            principal_signing_seed,
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

    async def create_spend_intent(self, **kwargs: Any) -> dict[str, Any]:
        return await self.create(**kwargs)

    async def fund(
        self,
        intent_id: UUID,
        *,
        recognition_proof: Mapping[str, Any],
        payment_signature: str | None = None,
        idempotency_key: str | None = None,
    ) -> FundIntentResult:
        """
        Advance Harbor ``POST /intents/{intent_id}/fund`` for x402 / USDC-on-Base intents.

        When Harbor responds with ``402``, use the returned ``payment_required`` challenge with
        your x402 wallet or facilitator, then retry with ``payment_signature=...``.
        """
        return await self._harbor.fund_intent(
            intent_id,
            recognition_proof=recognition_proof,  # type: ignore[call-arg]
            payment_signature=payment_signature,
            idempotency_key=idempotency_key,
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


@dataclass
class Paybond:
    """
    Hosted Gateway + Harbor proxy session with ergonomic :attr:`intents` helpers.
    """

    harbor: GatewayHarborClient
    signal: GatewaySignalClient
    fraud: GatewayFraudClient
    a2a: GatewayA2AClient
    protocol: GatewayProtocolClient
    intents: PaybondIntents

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
        )

    async def aclose(self) -> None:
        await self.harbor.aclose()
        await self.protocol.aclose()
        await self.a2a.aclose()
        await self.fraud.aclose()
        await self.signal.aclose()

    def spend_guard(self, intent_id: UUID, capability_token: str):
        from paybond_kit.capability_binding import PaybondCapabilityBinding
        from paybond_kit.spend_guard import PaybondSpendGuard

        return PaybondSpendGuard(
            PaybondCapabilityBinding(
                harbor=self.harbor,
                intent_id=intent_id,
                capability_token=capability_token,
            )
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

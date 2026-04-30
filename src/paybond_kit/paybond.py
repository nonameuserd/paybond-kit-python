"""High-level :class:`Paybond` API over gateway-backed Harbor sessions."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping
from uuid import UUID, uuid4

from paybond_kit.credentials import ServiceAccountHarborSession
from paybond_kit.harbor import HarborClient
from paybond_kit.signal import GatewaySignalClient


@dataclass
class PaybondIntents:
    """Tenant-scoped intent helpers (principal-signed intent create, payee evidence)."""

    _harbor: HarborClient
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
        intent_id: UUID | None = None,
        predicate_ref: str = "",
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """
        Build a principal-signed ``POST /intents`` body and submit it to Harbor.

        ``principal_signing_seed`` must be 32 bytes. ``tenant_id`` comes from the gateway exchange
        and must match ``x-tenant-id`` on the Harbor request (enforced by :class:`HarborClient`).
        """
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
        )
        body = json.loads(wire)
        return await self._harbor.create_intent(body, idempotency_key=idempotency_key)

    async def submit_evidence(
        self,
        intent_id: UUID,
        payload: Mapping[str, Any],
        *,
        payee_did: str,
        payee_signing_seed: bytes,
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
            intent_id, wire, idempotency_key=idempotency_key
        )


@dataclass
class Paybond:
    """
    Gateway + Harbor session with ergonomic :attr:`intents` helpers.

    This is a thin wrapper over :class:`ServiceAccountHarborSession` (same JWT lifecycle and
    tenant binding).
    """

    harbor: HarborClient
    signal: GatewaySignalClient
    intents: PaybondIntents
    _session: ServiceAccountHarborSession

    @classmethod
    async def open(
        cls,
        *,
        gateway_base_url: str,
        api_key: str,
        harbor_base_url: str,
        harbor_access_path: str = "/v1/auth/harbor-access",
        clock_skew_seconds: float = 90.0,
        max_retries: int = 3,
    ) -> Paybond:
        session = await ServiceAccountHarborSession.open(
            gateway_base_url=gateway_base_url,
            api_key=api_key,
            harbor_base_url=harbor_base_url,
            harbor_access_path=harbor_access_path,
            clock_skew_seconds=clock_skew_seconds,
            max_retries=max_retries,
        )
        tenant = session.harbor.tenant_id
        return cls(
            harbor=session.harbor,
            signal=GatewaySignalClient(
                gateway_base_url,
                tenant,
                static_gateway_bearer_token=api_key,
                max_retries=max_retries,
            ),
            intents=PaybondIntents(session.harbor, tenant),
            _session=session,
        )

    async def rotate_harbor_token(self) -> None:
        await self._session.rotate_harbor_token()

    async def aclose(self) -> None:
        await self.signal.aclose()
        await self._session.aclose()

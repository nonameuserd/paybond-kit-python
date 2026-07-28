"""Operator/backend-only Plaid Auth bank helpers (H5 P2). **Not for agents.**

Plaid Auth is a tenant-scoped *bank-verification input* to the existing
``stripe_ach_debit`` settlement rail. Stripe moves the money and Harbor controls
funding; Plaid never becomes a settlement rail here. See
``docs/operations/plaid-account-verification-setup.md`` and
``.cursor/plans/hardened-plaid-auth-paybond-integration.plan.md``.

Boundary this module deliberately preserves
-------------------------------------------
* **Operators link and fund. Agents spend only on already funded intents.** These
  helpers are backend/service code you call from your own trusted server with an
  operator or service-account credential — never from agent middleware, an MCP
  tool, an agent template, or anything reachable by model-authored input.
* Nothing here is re-exported from :mod:`paybond_kit.agent`, registered as an MCP
  tool, or wired into the agent tool registry. ``tests/test_plaid_backend_helpers.py``
  asserts that boundary so it cannot regress silently.
* There is no Link flow in Kit. This module never accepts or emits
  ``link_token``, ``public_token``, ``access_token``, Stripe processor tokens
  (``btok_``/``processor-``), Plaid Identity details, or raw balances. Link and
  token exchange happen server-side in the Gateway only.
* Every call derives tenant scope from the authenticated credential via
  ``GET /v1/auth/principal``. No helper accepts a caller-supplied tenant ID, and
  the Gateway independently re-derives tenant and role from the bearer token, so
  a cross-tenant bank or intent is rejected server-side (404/403) even if a
  caller guesses an ID.

Typical backend use::

    from paybond_kit.plaid import fund_ach_with_plaid_bank, list_plaid_banks

    inventory = await list_plaid_banks(api_key=OPERATOR_API_KEY, ready_only=True)
    bank = inventory.bank_accounts[0]
    result = await fund_ach_with_plaid_bank(
        intent_id,
        bank.id,
        api_key=OPERATOR_API_KEY,
    )

Readiness reason codes are the stable strings shared by Gateway, Admin console,
and CLI (``go/gateway/internal/rails/plaid/reasons.go``).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final
from urllib.parse import quote
from uuid import UUID

import httpx

from paybond_kit.credentials import (
    DEFAULT_PAYBOND_GATEWAY_BASE_URL,
    GatewayAuthError,
    PaybondEnvironment,
    _assert_expected_environment,
    _normalize_expected_environment,
    normalize_gateway_base_url,
)
from paybond_kit.gateway_retry import httpx_with_gateway_retries
from paybond_kit.harbor import TenantBindingError

_DEFAULT_PRINCIPAL_PATH: Final[str] = "/v1/auth/principal"
_BANK_ACCOUNTS_PATH: Final[str] = "/v1/admin/plaid/bank-accounts"

#: Stable readiness / fund-block reason codes shared with the Gateway, Admin
#: console, and ``paybond plaid`` CLI. Prefer these over free-form messages.
PLAID_READINESS_REASONS: Final[tuple[str, ...]] = (
    "ready",
    "pending_automatic_verification",
    "attach_pending",
    "attach_retryable",
    "attach_failed",
    "relink_required",
    "revoked",
    "verification_expired",
    "error",
    "not_ready",
    "risk_check_required",
    "risk_check_failed",
    "feature_disabled",
    "production_not_allowlisted",
    "plaid_bank_not_found",
    "plaid_bank_not_ready",
    "plaid_bank_relink_required",
    "stripe_bank_token_pi_not_enabled",
)

# Too generic to identify a Plaid failure inside free-form error prose.
_GENERIC_REASON_CODES: Final[frozenset[str]] = frozenset({"ready", "error", "not_ready"})

_READINESS_MESSAGES: Final[dict[str, str]] = {
    "ready": "Bank is ready for ACH debit.",
    "pending_automatic_verification": (
        "Pending micro-deposit verification; ACH debit is blocked until Plaid verifies."
    ),
    "attach_pending": "Stripe attach is in progress; refresh shortly.",
    "attach_retryable": "Stripe attach incomplete; retry attach or refresh.",
    "attach_failed": "Stripe attach failed; relink the bank or use Financial Connections.",
    "relink_required": "Bank login required; use Relink (Plaid Link update mode).",
    "plaid_bank_relink_required": "Bank login required; use Relink (Plaid Link update mode).",
    "revoked": "Revoked; link a new bank or use Financial Connections.",
    "verification_expired": "Verification expired; relink required.",
    "error": "Bank link error; relink or use Financial Connections.",
    "risk_check_required": "Additional risk checks are required before ACH debit.",
    "risk_check_failed": "Risk checks failed; use Financial Connections or contact support.",
    "feature_disabled": "Plaid Auth is disabled on this deployment.",
    "production_not_allowlisted": "Plaid Auth is not enabled for this tenant.",
    "plaid_bank_not_found": "Linked bank not found.",
    "plaid_bank_not_ready": "Linked bank is not ready for ACH debit.",
    "stripe_bank_token_pi_not_enabled": (
        "Stripe Payment Intents for Plaid bank tokens are not enabled on this platform account."
    ),
}

#: Wire fields this module is allowed to surface for a linked bank. Acts as a
#: closed allowlist: if the Gateway response ever grows a secret-bearing field,
#: it is dropped here instead of reaching caller code, logs, or storage.
_SAFE_BANK_FIELDS: Final[tuple[str, ...]] = (
    "id",
    "environment",
    "institution_id",
    "verification_status",
    "auth_method",
    "bank_name",
    "bank_mask",
    "bank_last4",
    "account_type",
    "account_subtype",
    "status",
    "ready",
    "readiness_reason",
    "stripe_attach_status",
    "stripe_attach_error_code",
    "relink_required",
    "bank_link_source",
    "created_at",
    "updated_at",
)

#: Field names that must never appear in a public representation produced by this
#: module. Enforced by :func:`assert_no_plaid_secret_fields` on every public dict.
FORBIDDEN_PUBLIC_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "access_token",
        "public_token",
        "link_token",
        "processor_token",
        "bank_account_token",
        "stripe_bank_account_token",
        "capability_token",
        "client_secret",
        "item_access_token",
        "account_number",
        "routing_number",
        "wire_routing_number",
        "identity",
        "identity_match",
        "owners",
        "balances",
        "available_balance",
        "current_balance",
    }
)

#: Value prefixes that indicate Plaid Link / Stripe processor material. Rejected
#: on input so a caller can never smuggle a token through an ID parameter.
_SECRET_VALUE_PREFIXES: Final[tuple[str, ...]] = (
    "public-",
    "access-",
    "link-",
    "processor-",
    "btok_",
    "pk_",
    "sk_",
)


class PlaidOperatorError(RuntimeError):
    """Base class for operator-facing Plaid helper failures."""


class PlaidSecretMaterialError(PlaidOperatorError, ValueError):
    """Raised when Plaid Link / token material is passed to a helper argument.

    Kit has no Link or token-exchange surface. Link tokens, public tokens, access
    tokens, and Stripe processor tokens are handled server-side by the Gateway
    only, so receiving one here means the caller is on the wrong code path.
    """


class PlaidOperatorHttpError(PlaidOperatorError):
    """Raised for non-success HTTP responses from Gateway Plaid/ACH operator routes.

    ``reason_code`` carries the stable Gateway reason string when one is present
    (see :data:`PLAID_READINESS_REASONS`); otherwise it is ``None``.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int,
        url: str,
        body_text: str,
        reason_code: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code: int = status_code
        self.url: str = url
        self.body_text: str = body_text
        self.reason_code: str | None = reason_code


class PlaidBankNotFoundError(PlaidOperatorError):
    """Raised when no bank with the requested id is visible to the caller's tenant.

    The Gateway answers unknown, foreign-tenant, and revoked banks identically so
    a caller cannot probe another tenant's inventory. Treat this as "not yours or
    not there", never as proof the bank does not exist somewhere else.
    """

    def __init__(self, bank_account_id: str) -> None:
        super().__init__(f"linked bank not found: {bank_account_id}")
        self.bank_account_id: str = bank_account_id
        self.reason_code: str = "plaid_bank_not_found"


class PlaidBankNotReadyError(PlaidOperatorError):
    """Raised before funding when a linked bank is not in a debitable ``ready`` state."""

    def __init__(self, bank_account_id: str, readiness_reason: str) -> None:
        reason = readiness_reason or "not_ready"
        super().__init__(
            f"linked bank {bank_account_id} is not ready for ACH debit "
            f"({reason}): {plaid_readiness_message(reason)}"
        )
        self.bank_account_id: str = bank_account_id
        self.readiness_reason: str = reason
        self.reason_code: str = "plaid_bank_not_ready"


def plaid_readiness_message(reason_code: str | None) -> str:
    """Return a short operator-safe description for a readiness reason code.

    Mirrors ``plaid.ReasonMessage`` in ``go/gateway/internal/rails/plaid/reasons.go`` so
    backend callers render the same wording as the console and CLI.
    """
    return _READINESS_MESSAGES.get((reason_code or "").strip(), "Not ready for ACH debit.")


def assert_no_plaid_secret_fields(payload: Mapping[str, Any], *, source: str) -> None:
    """Fail closed if a public representation carries a forbidden secret field.

    This is a runtime backstop for the allowlist projections below: public dicts
    are built from :data:`_SAFE_BANK_FIELDS`, so a violation means a code change
    broke the boundary rather than a caller doing something wrong.
    """
    leaked = sorted(FORBIDDEN_PUBLIC_FIELDS.intersection(payload.keys()))
    if leaked:
        raise PlaidSecretMaterialError(
            f"{source} public representation would leak forbidden field(s): {', '.join(leaked)}"
        )


def _assert_no_secret_material(value: str, *, field: str) -> None:
    lowered = value.strip().lower()
    for prefix in _SECRET_VALUE_PREFIXES:
        if lowered.startswith(prefix):
            raise PlaidSecretMaterialError(
                f"{field} looks like Plaid Link or Stripe token material ({prefix}…); "
                "Paybond never accepts Link tokens, public tokens, access tokens, or "
                "processor tokens outside the server-side Gateway exchange"
            )


def _coerce_uuid(value: str | UUID, *, field: str) -> UUID:
    if isinstance(value, UUID):
        return value
    candidate = str(value).strip()
    if not candidate:
        raise PlaidOperatorError(f"{field} is required")
    _assert_no_secret_material(candidate, field=field)
    try:
        return UUID(candidate)
    except ValueError as exc:
        raise PlaidOperatorError(f"{field} must be a canonical UUID") from exc


@dataclass(frozen=True, slots=True)
class PlaidBankAccount:
    """Safe operator view of one tenant-scoped Plaid-linked bank.

    Contains only what the Admin console already renders for the same operator:
    institution, masked account, verification/attach state, and a stable readiness
    reason. Internal Plaid Item IDs, Plaid account IDs, Stripe customer/bank-account
    IDs, access tokens, and processor tokens are intentionally absent.
    """

    id: str
    environment: str
    ready: bool
    status: str
    verification_status: str
    readiness_reason: str | None = None
    institution_id: str | None = None
    auth_method: str | None = None
    bank_name: str | None = None
    bank_mask: str | None = None
    bank_last4: str | None = None
    account_type: str | None = None
    account_subtype: str | None = None
    stripe_attach_status: str | None = None
    stripe_attach_error_code: str | None = None
    relink_required: bool = False
    bank_link_source: str | None = None
    created_at: str | None = None
    updated_at: str | None = None

    @property
    def readiness_message(self) -> str:
        """Operator-safe description of :attr:`readiness_reason`."""
        return plaid_readiness_message("ready" if self.ready else self.readiness_reason)

    def to_public_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict containing only allowlisted, non-secret fields."""
        payload: dict[str, Any] = {
            "id": self.id,
            "environment": self.environment,
            "ready": self.ready,
            "status": self.status,
            "verification_status": self.verification_status,
            "readiness_reason": self.readiness_reason,
            "readiness_message": self.readiness_message,
            "institution_id": self.institution_id,
            "auth_method": self.auth_method,
            "bank_name": self.bank_name,
            "bank_mask": self.bank_mask,
            "bank_last4": self.bank_last4,
            "account_type": self.account_type,
            "account_subtype": self.account_subtype,
            "stripe_attach_status": self.stripe_attach_status,
            "stripe_attach_error_code": self.stripe_attach_error_code,
            "relink_required": self.relink_required,
            "bank_link_source": self.bank_link_source,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }
        assert_no_plaid_secret_fields(payload, source="PlaidBankAccount")
        return payload


@dataclass(frozen=True, slots=True)
class PlaidBankInventory:
    """Tenant-scoped inventory of linked Plaid banks visible to the caller."""

    tenant_id: str
    environment: str
    bank_accounts: tuple[PlaidBankAccount, ...]

    @property
    def ready_bank_accounts(self) -> tuple[PlaidBankAccount, ...]:
        """Banks currently debitable through ``stripe_ach_debit``."""
        return tuple(bank for bank in self.bank_accounts if bank.ready)

    def to_public_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict containing only allowlisted, non-secret fields."""
        payload: dict[str, Any] = {
            "tenant_id": self.tenant_id,
            "environment": self.environment,
            "bank_accounts": [bank.to_public_dict() for bank in self.bank_accounts],
            "count": len(self.bank_accounts),
        }
        assert_no_plaid_secret_fields(payload, source="PlaidBankInventory")
        return payload


@dataclass(frozen=True, slots=True)
class PlaidAchFundingResult:
    """Safe operator view of an ACH fund attempt that used a Plaid-verified bank.

    Deliberately omits ``capability_token`` (an agent spend credential the Gateway
    may echo on this route), Stripe ``client_secret``, Stripe customer/payment
    method IDs, and every Plaid token. Funding is only final when Harbor observes
    the Stripe PaymentIntent terminal event; ``funded`` reflects Harbor state at
    response time, not settlement.
    """

    tenant_id: str
    intent_id: UUID
    plaid_bank_account_id: UUID
    state: str
    funded: bool
    settlement_rail: str
    currency: str
    amount_cents: int
    status_code: int
    stripe_payment_intent_id: str | None = None
    expected_debit_date: str | None = None

    def to_public_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict containing only allowlisted, non-secret fields."""
        payload: dict[str, Any] = {
            "tenant_id": self.tenant_id,
            "intent_id": str(self.intent_id),
            "plaid_bank_account_id": str(self.plaid_bank_account_id),
            "state": self.state,
            "funded": self.funded,
            "settlement_rail": self.settlement_rail,
            "currency": self.currency,
            "amount_cents": self.amount_cents,
            "status_code": self.status_code,
            "stripe_payment_intent_id": self.stripe_payment_intent_id,
            "expected_debit_date": self.expected_debit_date,
        }
        assert_no_plaid_secret_fields(payload, source="PlaidAchFundingResult")
        return payload


def _optional_string(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value
    return None


def _parse_bank_account(raw: Mapping[str, Any]) -> PlaidBankAccount:
    """Project a Gateway bank-account wire object onto the safe allowlist."""
    safe = {key: raw[key] for key in _SAFE_BANK_FIELDS if key in raw}
    bank_id = _optional_string(safe.get("id"))
    if bank_id is None:
        raise PlaidOperatorError("gateway bank-account entry missing id")
    return PlaidBankAccount(
        id=bank_id,
        environment=_optional_string(safe.get("environment")) or "unknown",
        ready=safe.get("ready") is True,
        status=_optional_string(safe.get("status")) or "unknown",
        verification_status=_optional_string(safe.get("verification_status")) or "unknown",
        readiness_reason=_optional_string(safe.get("readiness_reason")),
        institution_id=_optional_string(safe.get("institution_id")),
        auth_method=_optional_string(safe.get("auth_method")),
        bank_name=_optional_string(safe.get("bank_name")),
        bank_mask=_optional_string(safe.get("bank_mask")),
        bank_last4=_optional_string(safe.get("bank_last4")),
        account_type=_optional_string(safe.get("account_type")),
        account_subtype=_optional_string(safe.get("account_subtype")),
        stripe_attach_status=_optional_string(safe.get("stripe_attach_status")),
        stripe_attach_error_code=_optional_string(safe.get("stripe_attach_error_code")),
        relink_required=safe.get("relink_required") is True,
        bank_link_source=_optional_string(safe.get("bank_link_source")),
        created_at=_optional_string(safe.get("created_at")),
        updated_at=_optional_string(safe.get("updated_at")),
    )


def _reason_code_from_error_body(body_text: str) -> str | None:
    """Extract a stable Gateway reason code from an error body, or ``None``.

    Matches whole tokens only, and skips the generic ``ready``/``error``/``not_ready``
    codes, so prose like "already funded" or "internal error" is not misreported as
    a Plaid readiness reason.
    """
    lowered = body_text.strip().lower()
    if not lowered:
        return None
    for reason in PLAID_READINESS_REASONS:
        if reason in _GENERIC_REASON_CODES:
            continue
        if re.search(rf"(?<![a-z0-9_]){re.escape(reason)}(?![a-z0-9_])", lowered):
            return reason
    return None


class OperatorPlaidBankClient:
    """Tenant-bound Gateway client for operator Plaid bank inventory and ACH funding.

    **Backend/operator use only.** Construct it in trusted server code with an
    operator or service-account bearer token; never hand an instance (or its
    token) to an agent, an MCP tool, or model-authored code.

    The ``tenant_id`` argument is a *binding assertion*, not an authorization
    input: the Gateway re-derives tenant and role from the bearer token on every
    request, and responses that echo a different tenant raise
    :class:`~paybond_kit.harbor.TenantBindingError`. Prefer
    :meth:`ServiceAccountPlaidSession.open` (or the module-level helpers), which
    resolve the tenant from ``GET /v1/auth/principal`` instead of trusting a
    caller-supplied value.
    """

    def __init__(
        self,
        gateway_base_url: str,
        tenant_id: str,
        *,
        static_gateway_bearer_token: str,
        max_retries: int = 3,
        request_timeout_sec: float = 30.0,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base: str = normalize_gateway_base_url(gateway_base_url) + "/"
        self._tenant: str = tenant_id.strip()
        self._bearer: str = static_gateway_bearer_token.strip()
        self._max_retries: int = max(1, int(max_retries))
        self._owns_client: bool = http_client is None
        self._client: httpx.AsyncClient = http_client or httpx.AsyncClient(
            timeout=request_timeout_sec
        )

    @property
    def tenant_id(self) -> str:
        """Tenant this client is bound to (derived from the authenticated credential)."""
        return self._tenant

    async def aclose(self) -> None:
        """Close the underlying HTTP client when this client owns it."""
        if self._owns_client:
            await self._client.aclose()

    def _headers(self, *, idempotency_key: str | None = None) -> dict[str, str]:
        headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "authorization": f"Bearer {self._bearer}",
        }
        if idempotency_key is not None and idempotency_key.strip():
            headers["idempotency-key"] = idempotency_key.strip()
        return headers

    async def list_bank_accounts(self, *, ready_only: bool = False) -> PlaidBankInventory:
        """List Plaid-linked banks owned by this tenant.

        Args:
            ready_only: Return only banks currently debitable through ``stripe_ach_debit``.

        Returns:
            A :class:`PlaidBankInventory` of safe metadata (institution, masked
            account, readiness reason). Never any Plaid or Stripe token.

        Raises:
            PlaidOperatorHttpError: The Gateway rejected the call (403 role, 404
                ``feature_disabled`` / ``production_not_allowlisted``, and so on).
        """
        url = f"{self._base}{_BANK_ACCOUNTS_PATH.lstrip('/')}"
        response = await httpx_with_gateway_retries(
            lambda: self._client.get(url, headers=self._headers()),
            max_retries=self._max_retries,
        )
        if response.status_code >= 400:
            raise PlaidOperatorHttpError(
                f"Gateway Plaid bank-accounts HTTP {response.status_code}",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
                reason_code=_reason_code_from_error_body(response.text),
            )
        body = response.json()
        if not isinstance(body, dict):
            raise PlaidOperatorHttpError(
                "Gateway Plaid bank-accounts response was not a JSON object",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        banks = tuple(
            _parse_bank_account(entry)
            for entry in body.get("bank_accounts", [])
            if isinstance(entry, Mapping)
        )
        if ready_only:
            banks = tuple(bank for bank in banks if bank.ready)
        return PlaidBankInventory(
            tenant_id=self._tenant,
            environment=_optional_string(body.get("environment")) or "unknown",
            bank_accounts=banks,
        )

    async def get_bank_account(self, bank_account_id: str | UUID) -> PlaidBankAccount:
        """Fetch one tenant-owned bank by id.

        Issues a single tenant-scoped ``GET /v1/admin/plaid/bank-accounts/{id}``
        rather than downloading the whole inventory, so readiness checks stay
        O(1) for tenants with many linked banks.

        Raises:
            PlaidBankNotFoundError: The id is unknown to this tenant. Unknown and
                cross-tenant ids are indistinguishable by design: the Gateway
                answers both with the same 404, so this cannot probe another
                tenant's inventory.
            PlaidOperatorHttpError: Any other non-success Gateway response
                (403 role, 404 ``feature_disabled`` / ``production_not_allowlisted``).
        """
        resolved = _coerce_uuid(bank_account_id, field="bank_account_id")
        path = f"{_BANK_ACCOUNTS_PATH.lstrip('/')}/{quote(str(resolved), safe='')}"
        url = f"{self._base}{path}"
        response = await httpx_with_gateway_retries(
            lambda: self._client.get(url, headers=self._headers()),
            max_retries=self._max_retries,
        )
        if response.status_code == 404:
            # Distinguish "no such bank for this tenant" from a feature/rollout
            # gate, which also answers 404 but with its own reason code.
            reason = _reason_code_from_error_body(response.text)
            if reason in (None, "plaid_bank_not_found"):
                raise PlaidBankNotFoundError(str(resolved))
            raise PlaidOperatorHttpError(
                f"Gateway Plaid bank-account HTTP {response.status_code}",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
                reason_code=reason,
            )
        if response.status_code >= 400:
            raise PlaidOperatorHttpError(
                f"Gateway Plaid bank-account HTTP {response.status_code}",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
                reason_code=_reason_code_from_error_body(response.text),
            )
        body = response.json()
        if not isinstance(body, Mapping):
            raise PlaidOperatorHttpError(
                "Gateway Plaid bank-account response was not a JSON object",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        bank = _parse_bank_account(body)
        if bank.id != str(resolved):
            raise PlaidOperatorHttpError(
                f"Gateway Plaid bank-account id mismatch: requested={resolved} gateway={bank.id}",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        return bank

    async def fund_ach_intent_with_bank(
        self,
        intent_id: str | UUID,
        plaid_bank_account_id: str | UUID,
        *,
        require_ready: bool = True,
        idempotency_key: str | None = None,
    ) -> PlaidAchFundingResult:
        """Fund a ``stripe_ach_debit`` intent using a tenant-owned, ready Plaid bank.

        The Gateway is the authorization boundary: it re-derives tenant and role
        from the bearer token, verifies the bank *and* the intent belong to that
        tenant, refuses pending/attach-failed/relink/revoked/risk-blocked banks,
        and forwards only the resolved Stripe customer/payment-method reference to
        Harbor. This helper adds a client-side pre-check and response binding
        checks; it never widens what the Gateway allows.

        Args:
            intent_id: Harbor intent to fund. Must belong to the caller's tenant.
            plaid_bank_account_id: Gateway bank-account id from
                :meth:`list_bank_accounts`. Never a Plaid or Stripe token.
            require_ready: Pre-check readiness client-side and raise
                :class:`PlaidBankNotReadyError` before any funding call. The
                pre-check costs one tenant-scoped ``GET`` for this bank, not a
                full inventory listing. Pass ``False`` when you already hold a
                fresh :meth:`list_bank_accounts` result (or want the Gateway's
                own reason code instead of a client-side refusal).
            idempotency_key: Optional ``idempotency-key`` header for duplicate-safe
                retries.

        Returns:
            A :class:`PlaidAchFundingResult` with safe funding metadata. Any
            capability token echoed by the Gateway is discarded, not returned.

        Raises:
            PlaidSecretMaterialError: An argument carried Link/token material.
            PlaidBankNotFoundError: The bank id is not visible to this tenant.
            PlaidBankNotReadyError: ``require_ready`` and the bank is not ready.
            PlaidOperatorHttpError: The Gateway or Harbor rejected the funding call.
            TenantBindingError: The response echoed a different tenant or intent.
        """
        resolved_intent = _coerce_uuid(intent_id, field="intent_id")
        resolved_bank = _coerce_uuid(plaid_bank_account_id, field="plaid_bank_account_id")

        if require_ready:
            bank = await self.get_bank_account(resolved_bank)
            if not bank.ready:
                raise PlaidBankNotReadyError(bank.id, bank.readiness_reason or "not_ready")

        path = (
            "v1/admin/settlement/stripe/ach/intents/"
            f"{quote(str(resolved_intent), safe='')}/fund"
        )
        url = f"{self._base}{path}"
        payload = {"plaid_bank_account_id": str(resolved_bank)}
        response = await httpx_with_gateway_retries(
            lambda: self._client.post(
                url,
                headers=self._headers(idempotency_key=idempotency_key),
                json=payload,
            ),
            max_retries=self._max_retries,
        )
        if response.status_code >= 400:
            raise PlaidOperatorHttpError(
                f"Gateway Plaid ACH fund HTTP {response.status_code}",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
                reason_code=_reason_code_from_error_body(response.text),
            )
        body = response.json()
        if not isinstance(body, dict):
            raise PlaidOperatorHttpError(
                "Gateway Plaid ACH fund response was not a JSON object",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        return self._parse_funding_result(
            body,
            intent_id=resolved_intent,
            bank_account_id=resolved_bank,
            status_code=response.status_code,
            url=url,
            body_text=response.text,
        )

    def _parse_funding_result(
        self,
        body: Mapping[str, Any],
        *,
        intent_id: UUID,
        bank_account_id: UUID,
        status_code: int,
        url: str,
        body_text: str,
    ) -> PlaidAchFundingResult:
        tenant = str(body.get("tenant", "")).strip()
        if tenant != self._tenant:
            raise TenantBindingError(
                f"plaid ach fund tenant mismatch: client={self._tenant!r} gateway={tenant!r}"
            )
        echoed_intent_raw = str(body.get("intent_id", "")).strip()
        try:
            echoed_intent = UUID(echoed_intent_raw)
        except ValueError as exc:
            raise PlaidOperatorHttpError(
                "Gateway Plaid ACH fund response missing intent_id",
                status_code=status_code,
                url=url,
                body_text=body_text,
            ) from exc
        if echoed_intent != intent_id:
            raise TenantBindingError(
                f"plaid ach fund intent mismatch: requested={intent_id} gateway={echoed_intent}"
            )

        state = _optional_string(body.get("state"))
        settlement_rail = _optional_string(body.get("settlement_rail"))
        currency = _optional_string(body.get("currency"))
        amount_cents = body.get("amount_cents")
        if state is None or settlement_rail is None or currency is None:
            raise PlaidOperatorHttpError(
                "Gateway Plaid ACH fund response missing state/settlement_rail/currency",
                status_code=status_code,
                url=url,
                body_text=body_text,
            )
        if not isinstance(amount_cents, int) or isinstance(amount_cents, bool):
            raise PlaidOperatorHttpError(
                "Gateway Plaid ACH fund response missing amount_cents",
                status_code=status_code,
                url=url,
                body_text=body_text,
            )

        funding = body.get("funding")
        funding_map: Mapping[str, Any] = funding if isinstance(funding, Mapping) else {}
        return PlaidAchFundingResult(
            tenant_id=tenant,
            intent_id=echoed_intent,
            plaid_bank_account_id=bank_account_id,
            state=state,
            funded=body.get("funded") is True,
            settlement_rail=settlement_rail,
            currency=currency,
            amount_cents=amount_cents,
            status_code=status_code,
            stripe_payment_intent_id=_optional_string(
                funding_map.get("stripe_payment_intent_id")
            ),
            expected_debit_date=_optional_string(funding_map.get("expected_debit_date")),
        )


@dataclass
class ServiceAccountPlaidSession:
    """Operator/backend Plaid session bound to one authenticated credential.

    The tenant is resolved from ``GET /v1/auth/principal`` using the supplied API
    key, so tenant scope always comes from the credential and never from caller
    input. Backend use only — do not expose this session to agents or MCP tools.
    """

    plaid: OperatorPlaidBankClient

    @classmethod
    async def open(
        cls,
        *,
        api_key: str,
        gateway_base_url: str = DEFAULT_PAYBOND_GATEWAY_BASE_URL,
        principal_path: str = _DEFAULT_PRINCIPAL_PATH,
        expected_environment: PaybondEnvironment | None = None,
        max_retries: int = 3,
    ) -> ServiceAccountPlaidSession:
        """Open a tenant-bound session for an operator/service-account API key."""
        tenant_id = await _resolve_gateway_tenant_id(
            gateway_base_url=gateway_base_url,
            api_key=api_key,
            principal_path=principal_path,
            expected_environment=expected_environment,
            max_retries=max_retries,
        )
        client = OperatorPlaidBankClient(
            gateway_base_url,
            tenant_id,
            static_gateway_bearer_token=api_key,
            max_retries=max_retries,
        )
        return cls(plaid=client)

    async def aclose(self) -> None:
        """Close the underlying Gateway client."""
        await self.plaid.aclose()


async def list_plaid_banks(
    *,
    api_key: str,
    gateway_base_url: str = DEFAULT_PAYBOND_GATEWAY_BASE_URL,
    expected_environment: PaybondEnvironment | None = None,
    ready_only: bool = False,
    max_retries: int = 3,
) -> PlaidBankInventory:
    """List the calling tenant's Plaid-linked banks (operator/backend only).

    Tenant scope is derived from ``api_key`` via ``GET /v1/auth/principal``; there
    is no tenant parameter to spoof. Returns safe metadata only — no Link tokens,
    public tokens, access tokens, Stripe processor tokens, identity details, or
    balances.

    Args:
        api_key: Operator or service-account Gateway API key. Never an agent
            capability token and never a Plaid token.
        gateway_base_url: Gateway origin (HTTPS, or loopback for local dev).
        expected_environment: Assert the credential's environment (``"live"`` or
            ``"sandbox"``) before issuing any Plaid call.
        ready_only: Return only banks currently debitable through ``stripe_ach_debit``.
        max_retries: Retry budget for transient 429/5xx responses.

    Raises:
        GatewayAuthError: The credential is rejected or the environment mismatches.
        PlaidOperatorHttpError: The Gateway rejected the bank-inventory call.
    """
    session = await ServiceAccountPlaidSession.open(
        api_key=api_key,
        gateway_base_url=gateway_base_url,
        expected_environment=expected_environment,
        max_retries=max_retries,
    )
    try:
        return await session.plaid.list_bank_accounts(ready_only=ready_only)
    finally:
        await session.aclose()


async def fund_ach_with_plaid_bank(
    intent_id: str | UUID,
    plaid_bank_account_id: str | UUID,
    *,
    api_key: str,
    gateway_base_url: str = DEFAULT_PAYBOND_GATEWAY_BASE_URL,
    expected_environment: PaybondEnvironment | None = None,
    require_ready: bool = True,
    idempotency_key: str | None = None,
    max_retries: int = 3,
) -> PlaidAchFundingResult:
    """Fund a ``stripe_ach_debit`` intent with a ready Plaid bank (operator/backend only).

    This is the operator half of the funding boundary: an authorized human or
    backend service funds the intent, and agents may then spend against it through
    the normal capability path. Agents must never call this helper, and it is not
    exported from :mod:`paybond_kit.agent` or exposed as an MCP tool.

    Both the bank and the intent must belong to the tenant behind ``api_key``. The
    Gateway enforces that server-side and answers foreign ids the same way it
    answers unknown ones, so this helper cannot be used to probe another tenant.

    Args:
        intent_id: Harbor intent to fund.
        plaid_bank_account_id: Bank id from :func:`list_plaid_banks`.
        api_key: Operator or service-account Gateway API key.
        gateway_base_url: Gateway origin (HTTPS, or loopback for local dev).
        expected_environment: Assert the credential's environment before funding.
        require_ready: Pre-check bank readiness before attempting to fund. Costs
            one ``GET`` for the single bank; callers that already hold inventory
            from :func:`list_plaid_banks` can reuse
            :class:`OperatorPlaidBankClient` with ``require_ready=False`` to skip
            the extra round trip.
        idempotency_key: Optional ``idempotency-key`` header for safe retries.
        max_retries: Retry budget for transient 429/5xx responses.

    Raises:
        PlaidSecretMaterialError: An argument carried Plaid/Stripe token material.
        PlaidBankNotFoundError: The bank is not visible to this tenant.
        PlaidBankNotReadyError: The bank is not debitable yet.
        PlaidOperatorHttpError: The Gateway or Harbor rejected the funding call.
        TenantBindingError: The response echoed a different tenant or intent.
    """
    session = await ServiceAccountPlaidSession.open(
        api_key=api_key,
        gateway_base_url=gateway_base_url,
        expected_environment=expected_environment,
        max_retries=max_retries,
    )
    try:
        return await session.plaid.fund_ach_intent_with_bank(
            intent_id,
            plaid_bank_account_id,
            require_ready=require_ready,
            idempotency_key=idempotency_key,
        )
    finally:
        await session.aclose()


async def _resolve_gateway_tenant_id(
    *,
    gateway_base_url: str,
    api_key: str,
    principal_path: str,
    expected_environment: PaybondEnvironment | None,
    max_retries: int,
) -> str:
    retries = max(1, int(max_retries))
    normalized_environment = _normalize_expected_environment(expected_environment)
    client = httpx.AsyncClient(timeout=30.0)
    try:
        path = principal_path if principal_path.startswith("/") else f"/{principal_path}"
        url = normalize_gateway_base_url(gateway_base_url) + path
        response = await httpx_with_gateway_retries(
            lambda: client.get(
                url,
                headers={
                    "accept": "application/json",
                    "authorization": f"Bearer {api_key.strip()}",
                },
            ),
            max_retries=retries,
        )
        if response.status_code >= 400:
            raise GatewayAuthError(
                f"gateway principal HTTP {response.status_code}",
                status_code=response.status_code,
                body_text=response.text,
            )
        body = response.json()
        if not isinstance(body, dict):
            raise GatewayAuthError(
                "gateway principal response was not a JSON object",
                body_text=response.text,
            )
        tenant = str(body.get("tenant_id", "")).strip()
        if not tenant:
            raise GatewayAuthError(
                "gateway principal JSON missing tenant_id",
                body_text=response.text,
            )
        _assert_expected_environment(
            source="gateway principal",
            body=body,
            expected_environment=normalized_environment,
            body_text=response.text,
        )
        return tenant
    finally:
        await client.aclose()


__all__ = [
    "FORBIDDEN_PUBLIC_FIELDS",
    "PLAID_READINESS_REASONS",
    "OperatorPlaidBankClient",
    "PlaidAchFundingResult",
    "PlaidBankAccount",
    "PlaidBankInventory",
    "PlaidBankNotFoundError",
    "PlaidBankNotReadyError",
    "PlaidOperatorError",
    "PlaidOperatorHttpError",
    "PlaidSecretMaterialError",
    "ServiceAccountPlaidSession",
    "assert_no_plaid_secret_fields",
    "fund_ach_with_plaid_bank",
    "list_plaid_banks",
    "plaid_readiness_message",
]

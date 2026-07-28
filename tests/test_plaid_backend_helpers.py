"""Boundary tests for the operator/backend-only Plaid helpers (H5 P2).

Two invariants matter more than behaviour here:

1. Public representations cannot serialize Plaid Link / Stripe token material,
   even when the Gateway wire object contains extra fields.
2. Tenant scope comes from the authenticated credential, and a response that
   claims a different tenant or intent is rejected rather than trusted.
"""

from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID, uuid4

import httpx
import pytest
import respx

import paybond_kit
import paybond_kit.agent as paybond_agent
from paybond_kit.harbor import TenantBindingError
from paybond_kit.plaid import (
    FORBIDDEN_PUBLIC_FIELDS,
    OperatorPlaidBankClient,
    PlaidBankNotFoundError,
    PlaidBankNotReadyError,
    PlaidOperatorError,
    PlaidOperatorHttpError,
    PlaidSecretMaterialError,
    ServiceAccountPlaidSession,
    assert_no_plaid_secret_fields,
    fund_ach_with_plaid_bank,
    list_plaid_banks,
)

GATEWAY = "https://gateway.test"
API_KEY = "paybond_sk_" + "a" * 32 + "_" + "b" * 64
TENANT_A = "tenant-a"
TENANT_B = "tenant-b"

READY_BANK_ID = "11111111-1111-4111-8111-111111111111"
PENDING_BANK_ID = "22222222-2222-4222-8222-222222222222"
FOREIGN_BANK_ID = "33333333-3333-4333-8333-333333333333"

# Values a compromised or buggy Gateway response might carry. None of them may
# reach a public representation.
LEAKY_SECRETS = {
    "access_token": "access-sandbox-leaked-token",
    "public_token": "public-sandbox-leaked-token",
    "link_token": "link-sandbox-leaked-token",
    "processor_token": "processor-sandbox-leaked-token",
    "stripe_bank_account_token": "btok_leakedbanktoken",
    "account_number": "000123456789",
    "routing_number": "110000000",
    "balances": {"available": 4200.0, "current": 4200.0},
    "identity": {"owners": [{"names": ["Ada Lovelace"]}]},
}


def _ready_bank_wire() -> dict[str, object]:
    return {
        "id": READY_BANK_ID,
        "environment": "sandbox",
        "item_id": "item-internal-id",
        "account_id": "plaid-account-id",
        "institution_id": "ins_109508",
        "verification_status": "automatically_verified",
        "auth_method": "INSTANT_AUTH",
        "bank_name": "First Platypus Bank",
        "bank_mask": "0000",
        "bank_last4": "0000",
        "account_type": "depository",
        "account_subtype": "checking",
        "status": "active",
        "ready": True,
        "readiness_reason": "ready",
        "stripe_attach_status": "attached",
        "stripe_customer_id": "cus_leaked",
        "stripe_bank_account_id": "ba_leaked",
        "relink_required": False,
        "bank_link_source": "plaid_auth",
        "created_at": "2026-07-01T00:00:00Z",
        "updated_at": "2026-07-02T00:00:00Z",
        **LEAKY_SECRETS,
    }


def _pending_bank_wire() -> dict[str, object]:
    return {
        "id": PENDING_BANK_ID,
        "environment": "sandbox",
        "institution_id": "ins_109508",
        "verification_status": "pending_automatic_verification",
        "bank_name": "First Platypus Bank",
        "bank_mask": "1111",
        "status": "active",
        "ready": False,
        "readiness_reason": "pending_automatic_verification",
        "stripe_attach_status": "attach_pending",
    }


def _mock_principal(tenant_id: str = TENANT_A, environment: str = "sandbox") -> None:
    respx.get(f"{GATEWAY}/v1/auth/principal").mock(
        return_value=httpx.Response(200, json={"tenant_id": tenant_id, "environment": environment})
    )


def _mock_bank_list(*banks: dict[str, object]) -> respx.Route:
    return respx.get(f"{GATEWAY}/v1/admin/plaid/bank-accounts").mock(
        return_value=httpx.Response(
            200, json={"environment": "sandbox", "bank_accounts": list(banks)}
        )
    )


def _mock_bank_get(*banks: dict[str, object]) -> dict[str, respx.Route]:
    """Mock the dedicated per-id GET the way the Gateway serves it.

    Every id the tenant does not own — including ids belonging to another tenant
    — answers the same 404 reason code, mirroring
    ``getPlaidBankAccountHandler`` in the Go gateway.
    """
    routes: dict[str, respx.Route] = {}
    for bank in banks:
        bank_id = str(bank["id"])
        routes[bank_id] = respx.get(
            f"{GATEWAY}/v1/admin/plaid/bank-accounts/{bank_id}"
        ).mock(return_value=httpx.Response(200, json=bank))
    routes["__miss__"] = respx.get(
        url__regex=rf"{GATEWAY}/v1/admin/plaid/bank-accounts/[0-9a-fA-F-]+$"
    ).mock(
        return_value=httpx.Response(
            404,
            json={"error": "plaid_bank_not_found", "message": "Linked bank not found."},
        )
    )
    return routes


def _mock_banks(*banks: dict[str, object]) -> respx.Route:
    """Mock both inventory surfaces so tests can assert which one a helper used."""
    list_route = _mock_bank_list(*banks)
    _mock_bank_get(*banks)
    return list_route


def _client(tenant_id: str = TENANT_A) -> OperatorPlaidBankClient:
    return OperatorPlaidBankClient(
        GATEWAY, tenant_id, static_gateway_bearer_token=API_KEY, max_retries=1
    )


def _fund_route(intent_id: UUID) -> str:
    return f"{GATEWAY}/v1/admin/settlement/stripe/ach/intents/{intent_id}/fund"


def _fund_response_body(
    intent_id: UUID, *, tenant: str = TENANT_A, funded: bool = True
) -> dict[str, object]:
    return {
        "tenant": tenant,
        "intent_id": str(intent_id),
        "state": "funded" if funded else "funding_pending",
        "settlement_rail": "stripe_ach_debit",
        "currency": "usd",
        "amount_cents": 5000,
        "funded": funded,
        # The Gateway may echo an agent spend credential and Stripe secrets on this
        # route; the helper must never surface them to backend callers.
        "capability_token": "cap_leaked_token",
        "funding": {
            "stripe_payment_intent_id": "pi_123",
            "client_secret": "pi_123_secret_leaked",
            "stripe_customer_id": "cus_leaked",
            "payment_method_id": "pm_leaked",
            "expected_debit_date": "2026-07-29",
            "bank_last4": "0000",
        },
    }


# --- secret-serialization boundary -------------------------------------------------


@respx.mock
async def test_bank_public_representation_cannot_serialize_secrets() -> None:
    _mock_bank_list(_ready_bank_wire())
    client = _client()
    try:
        inventory = await client.list_bank_accounts()
    finally:
        await client.aclose()

    bank = inventory.bank_accounts[0]
    public = bank.to_public_dict()

    assert not FORBIDDEN_PUBLIC_FIELDS.intersection(public.keys())
    # Internal Plaid/Stripe identifiers are dropped alongside outright secrets.
    for dropped in ("item_id", "account_id", "stripe_customer_id", "stripe_bank_account_id"):
        assert dropped not in public
        assert not hasattr(bank, dropped)

    serialized = json.dumps(inventory.to_public_dict())
    for secret in ("access-sandbox", "public-sandbox", "link-sandbox", "btok_", "cus_", "ba_"):
        assert secret not in serialized
    assert "000123456789" not in serialized
    assert "Ada Lovelace" not in serialized
    # repr() is the most common accidental-logging path.
    assert "access-sandbox" not in repr(bank)

    assert public["bank_last4"] == "0000"
    assert public["readiness_reason"] == "ready"
    assert public["readiness_message"] == "Bank is ready for ACH debit."
    # Account type is display-only metadata an operator needs to pick the right
    # bank; it must survive the allowlist alongside institution and mask.
    assert public["account_type"] == "depository"
    assert public["account_subtype"] == "checking"


def test_assert_no_plaid_secret_fields_fails_closed() -> None:
    with pytest.raises(PlaidSecretMaterialError, match="access_token"):
        assert_no_plaid_secret_fields({"id": READY_BANK_ID, "access_token": "x"}, source="test")


@respx.mock
async def test_funding_result_drops_capability_token_and_client_secret() -> None:
    intent_id = uuid4()
    _mock_banks(_ready_bank_wire())
    respx.post(_fund_route(intent_id)).mock(
        return_value=httpx.Response(200, json=_fund_response_body(intent_id))
    )

    client = _client()
    try:
        result = await client.fund_ach_intent_with_bank(intent_id, READY_BANK_ID)
    finally:
        await client.aclose()

    public = result.to_public_dict()
    assert not FORBIDDEN_PUBLIC_FIELDS.intersection(public.keys())
    assert not hasattr(result, "capability_token")
    serialized = json.dumps(public)
    assert "cap_leaked_token" not in serialized
    assert "secret_leaked" not in serialized
    assert "pm_leaked" not in serialized
    assert "cap_leaked_token" not in repr(result)

    assert result.funded is True
    assert result.settlement_rail == "stripe_ach_debit"
    assert result.plaid_bank_account_id == UUID(READY_BANK_ID)
    assert result.stripe_payment_intent_id == "pi_123"


# --- credential-derived tenant scope -----------------------------------------------


@respx.mock
async def test_session_derives_tenant_from_credential_not_caller_input() -> None:
    _mock_principal(tenant_id="realm-from-credential")
    session = await ServiceAccountPlaidSession.open(
        api_key=API_KEY, gateway_base_url=GATEWAY, expected_environment="sandbox"
    )
    try:
        assert session.plaid.tenant_id == "realm-from-credential"
    finally:
        await session.aclose()


@respx.mock
async def test_list_plaid_banks_sends_only_the_bearer_credential() -> None:
    _mock_principal()
    route = _mock_bank_list(_ready_bank_wire(), _pending_bank_wire())

    inventory = await list_plaid_banks(api_key=API_KEY, gateway_base_url=GATEWAY, ready_only=True)

    assert inventory.tenant_id == TENANT_A
    assert [bank.id for bank in inventory.bank_accounts] == [READY_BANK_ID]
    request = route.calls.last.request
    assert request.headers["authorization"] == f"Bearer {API_KEY}"
    # No tenant is asserted on the wire: the Gateway derives it from the token.
    assert "x-tenant-id" not in request.headers


@respx.mock
async def test_fund_rejects_response_echoing_a_different_tenant() -> None:
    intent_id = uuid4()
    _mock_banks(_ready_bank_wire())
    respx.post(_fund_route(intent_id)).mock(
        return_value=httpx.Response(200, json=_fund_response_body(intent_id, tenant=TENANT_B))
    )

    client = _client(TENANT_A)
    try:
        with pytest.raises(TenantBindingError, match="tenant mismatch"):
            await client.fund_ach_intent_with_bank(intent_id, READY_BANK_ID)
    finally:
        await client.aclose()


@respx.mock
async def test_fund_rejects_response_echoing_a_different_intent() -> None:
    intent_id = uuid4()
    _mock_banks(_ready_bank_wire())
    respx.post(_fund_route(intent_id)).mock(
        return_value=httpx.Response(200, json=_fund_response_body(uuid4()))
    )

    client = _client()
    try:
        with pytest.raises(TenantBindingError, match="intent mismatch"):
            await client.fund_ach_intent_with_bank(intent_id, READY_BANK_ID)
    finally:
        await client.aclose()


@respx.mock
async def test_cross_tenant_bank_is_not_visible_and_never_funds() -> None:
    """A foreign bank id 404s on the tenant-scoped GET, so funding stops locally."""
    intent_id = uuid4()
    list_route = _mock_banks(_ready_bank_wire())
    fund_route = respx.post(_fund_route(intent_id)).mock(
        return_value=httpx.Response(200, json=_fund_response_body(intent_id))
    )

    client = _client()
    try:
        with pytest.raises(PlaidBankNotFoundError) as excinfo:
            await client.fund_ach_intent_with_bank(intent_id, FOREIGN_BANK_ID)
    finally:
        await client.aclose()

    assert excinfo.value.reason_code == "plaid_bank_not_found"
    assert not fund_route.called
    # Readiness is resolved by the per-id GET, never by listing the tenant's banks.
    assert not list_route.called


@respx.mock
async def test_gateway_cross_tenant_rejection_is_surfaced_with_reason_code() -> None:
    """The Gateway remains the authorization boundary even with readiness checks off."""
    intent_id = uuid4()
    respx.post(_fund_route(intent_id)).mock(
        return_value=httpx.Response(404, text="linked bank not found: plaid_bank_not_found")
    )

    client = _client()
    try:
        with pytest.raises(PlaidOperatorHttpError) as excinfo:
            await client.fund_ach_intent_with_bank(
                intent_id, FOREIGN_BANK_ID, require_ready=False
            )
    finally:
        await client.aclose()

    assert excinfo.value.status_code == 404
    assert excinfo.value.reason_code == "plaid_bank_not_found"


@respx.mock
async def test_generic_error_prose_is_not_reported_as_a_readiness_reason() -> None:
    intent_id = uuid4()
    respx.post(_fund_route(intent_id)).mock(
        return_value=httpx.Response(409, text="intent is already funded")
    )
    client = _client()
    try:
        with pytest.raises(PlaidOperatorHttpError) as excinfo:
            await client.fund_ach_intent_with_bank(intent_id, READY_BANK_ID, require_ready=False)
    finally:
        await client.aclose()
    assert excinfo.value.reason_code is None


@respx.mock
async def test_risk_policy_rejection_maps_to_its_reason_code() -> None:
    intent_id = uuid4()
    respx.post(_fund_route(intent_id)).mock(
        return_value=httpx.Response(422, text="risk_check_required for this amount")
    )
    client = _client()
    try:
        with pytest.raises(PlaidOperatorHttpError) as excinfo:
            await client.fund_ach_intent_with_bank(intent_id, READY_BANK_ID, require_ready=False)
    finally:
        await client.aclose()
    assert excinfo.value.reason_code == "risk_check_required"


@respx.mock
async def test_forbidden_role_is_surfaced_not_retried_into_success() -> None:
    respx.get(f"{GATEWAY}/v1/admin/plaid/bank-accounts").mock(
        return_value=httpx.Response(403, text="Harbor intent mutation access required")
    )
    client = _client()
    try:
        with pytest.raises(PlaidOperatorHttpError) as excinfo:
            await client.list_bank_accounts()
    finally:
        await client.aclose()
    assert excinfo.value.status_code == 403


# --- readiness and input guards ----------------------------------------------------


@respx.mock
async def test_pending_bank_blocks_funding_before_any_gateway_call() -> None:
    intent_id = uuid4()
    _mock_banks(_pending_bank_wire())
    fund_route = respx.post(_fund_route(intent_id)).mock(
        return_value=httpx.Response(200, json=_fund_response_body(intent_id))
    )

    client = _client()
    try:
        with pytest.raises(PlaidBankNotReadyError) as excinfo:
            await client.fund_ach_intent_with_bank(intent_id, PENDING_BANK_ID)
    finally:
        await client.aclose()

    assert excinfo.value.readiness_reason == "pending_automatic_verification"
    assert not fund_route.called


@pytest.mark.parametrize(
    "token",
    [
        "access-sandbox-1234",
        "public-sandbox-1234",
        "link-sandbox-1234",
        "processor-sandbox-1234",
        "btok_1234",
    ],
)
async def test_helpers_reject_plaid_link_and_processor_material(token: str) -> None:
    client = _client()
    try:
        with pytest.raises(PlaidSecretMaterialError):
            await client.fund_ach_intent_with_bank(uuid4(), token)
        with pytest.raises(PlaidSecretMaterialError):
            await client.get_bank_account(token)
    finally:
        await client.aclose()


@respx.mock
async def test_get_bank_account_uses_the_dedicated_per_id_route() -> None:
    """One tenant-scoped GET, not a full inventory download."""
    list_route = _mock_bank_list(_ready_bank_wire(), _pending_bank_wire())
    get_routes = _mock_bank_get(_ready_bank_wire(), _pending_bank_wire())

    client = _client()
    try:
        bank = await client.get_bank_account(READY_BANK_ID)
    finally:
        await client.aclose()

    assert bank.id == READY_BANK_ID
    assert bank.ready is True
    assert not list_route.called
    assert get_routes[READY_BANK_ID].call_count == 1
    request = get_routes[READY_BANK_ID].calls.last.request
    assert request.headers["authorization"] == f"Bearer {API_KEY}"
    assert "x-tenant-id" not in request.headers
    # The per-id projection drops the same secret fields the list projection does.
    assert not FORBIDDEN_PUBLIC_FIELDS.intersection(bank.to_public_dict().keys())
    assert "access-sandbox" not in json.dumps(bank.to_public_dict())


@respx.mock
async def test_require_ready_precheck_costs_one_get_and_no_list() -> None:
    intent_id = uuid4()
    list_route = _mock_bank_list(_ready_bank_wire())
    get_routes = _mock_bank_get(_ready_bank_wire())
    fund_route = respx.post(_fund_route(intent_id)).mock(
        return_value=httpx.Response(200, json=_fund_response_body(intent_id))
    )

    client = _client()
    try:
        await client.fund_ach_intent_with_bank(intent_id, READY_BANK_ID, require_ready=True)
    finally:
        await client.aclose()

    assert get_routes[READY_BANK_ID].call_count == 1
    assert not list_route.called
    assert fund_route.call_count == 1


@respx.mock
async def test_require_ready_false_skips_the_readiness_lookup_entirely() -> None:
    """Callers holding fresh inventory can fund without any extra bank lookup."""
    intent_id = uuid4()
    list_route = _mock_bank_list(_ready_bank_wire())
    get_routes = _mock_bank_get(_ready_bank_wire())
    fund_route = respx.post(_fund_route(intent_id)).mock(
        return_value=httpx.Response(200, json=_fund_response_body(intent_id))
    )

    client = _client()
    try:
        await client.fund_ach_intent_with_bank(intent_id, READY_BANK_ID, require_ready=False)
    finally:
        await client.aclose()

    assert not list_route.called
    assert not get_routes[READY_BANK_ID].called
    assert fund_route.call_count == 1


@respx.mock
async def test_get_bank_account_rejects_a_response_for_a_different_bank() -> None:
    """A Gateway answer that echoes another id is refused, not silently trusted."""
    respx.get(f"{GATEWAY}/v1/admin/plaid/bank-accounts/{PENDING_BANK_ID}").mock(
        return_value=httpx.Response(200, json=_ready_bank_wire())
    )
    client = _client()
    try:
        with pytest.raises(PlaidOperatorHttpError, match="id mismatch"):
            await client.get_bank_account(PENDING_BANK_ID)
    finally:
        await client.aclose()


@respx.mock
async def test_feature_disabled_404_is_not_reported_as_bank_not_found() -> None:
    """The rollout gate also answers 404; it must keep its own reason code."""
    respx.get(f"{GATEWAY}/v1/admin/plaid/bank-accounts/{READY_BANK_ID}").mock(
        return_value=httpx.Response(
            404,
            json={"error": "production_not_allowlisted", "message": "not enabled"},
        )
    )
    client = _client()
    try:
        with pytest.raises(PlaidOperatorHttpError) as excinfo:
            await client.get_bank_account(READY_BANK_ID)
    finally:
        await client.aclose()
    assert excinfo.value.status_code == 404
    assert excinfo.value.reason_code == "production_not_allowlisted"


async def test_non_uuid_bank_id_is_rejected_before_any_request() -> None:
    client = _client()
    try:
        with pytest.raises(PlaidOperatorError, match="canonical UUID"):
            await client.get_bank_account("not-a-uuid")
    finally:
        await client.aclose()


@respx.mock
async def test_module_level_fund_helper_posts_only_the_bank_id() -> None:
    intent_id = uuid4()
    _mock_principal()
    _mock_banks(_ready_bank_wire())
    fund_route = respx.post(_fund_route(intent_id)).mock(
        return_value=httpx.Response(200, json=_fund_response_body(intent_id))
    )

    result = await fund_ach_with_plaid_bank(
        intent_id,
        READY_BANK_ID,
        api_key=API_KEY,
        gateway_base_url=GATEWAY,
        idempotency_key="fund-once",
    )

    assert result.tenant_id == TENANT_A
    request = fund_route.calls.last.request
    assert json.loads(request.content) == {"plaid_bank_account_id": READY_BANK_ID}
    assert request.headers["idempotency-key"] == "fund-once"


# --- agent / MCP boundary ----------------------------------------------------------


PLAID_HELPER_NAMES = (
    "list_plaid_banks",
    "fund_ach_with_plaid_bank",
    "OperatorPlaidBankClient",
    "ServiceAccountPlaidSession",
    "PlaidBankAccount",
    "PlaidBankInventory",
    "PlaidAchFundingResult",
)


def test_agent_namespace_does_not_export_plaid_helpers() -> None:
    exported = set(getattr(paybond_agent, "__all__", ()))
    for name in PLAID_HELPER_NAMES:
        assert name not in exported
        assert not hasattr(paybond_agent, name)
    # The helpers stay reachable from the backend namespace.
    for name in PLAID_HELPER_NAMES:
        assert hasattr(paybond_kit, name)


def test_agent_middleware_mcp_and_templates_do_not_import_plaid_helpers() -> None:
    package_root = Path(paybond_kit.__file__).resolve().parent
    surfaces = [
        *sorted((package_root / "agent").rglob("*.py")),
        package_root / "mcp_server.py",
        package_root / "mcp_tool_surface.py",
        package_root / "spend_guard.py",
        package_root / "agent_adapters.py",
    ]
    offenders = [
        str(path.relative_to(package_root))
        for path in surfaces
        if path.exists() and "paybond_kit.plaid" in path.read_text(encoding="utf-8")
    ]
    assert offenders == [], (
        "agent middleware / MCP surfaces must not import operator Plaid helpers: "
        f"{offenders}"
    )


def test_agent_templates_do_not_reference_plaid_helpers() -> None:
    templates_root = Path(paybond_kit.__file__).resolve().parent / "data" / "templates"
    if not templates_root.exists():
        pytest.skip("templates data directory is not packaged in this build")
    offenders: list[str] = []
    for path in templates_root.rglob("*"):
        if not path.is_file() or "node_modules" in path.parts:
            continue
        if path.suffix not in (".py", ".ts", ".tsx", ".js", ".mjs", ".json", ".md"):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if "list_plaid_banks" in text or "fund_ach_with_plaid_bank" in text:
            offenders.append(str(path.relative_to(templates_root)))
    assert offenders == []

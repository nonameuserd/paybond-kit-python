"""Type stubs for the ``paybond_kit._native`` maturin/PyO3 extension.

The runtime module is compiled from ``rust/src/lib.rs`` and shipped as a
platform wheel; this stub mirrors the ``#[pymodule] _native`` exports so
static type checkers (pyright) can resolve imports and signatures without the
compiled artifact being introspectable.
"""

def sign_payee_evidence_binding_json(
    tenant_id: str,
    intent_id: str,
    payee_did: str,
    payload_json: str,
    artifacts_hex: list[str],
    submitted_at_rfc3339: str,
    secret_seed: bytes,
) -> str: ...
def encode_evidence_sign_v1_hex(
    tenant_id: str,
    intent_id: str,
    payee_did: str,
    payload_json: str,
    artifacts_hex: list[str],
    submitted_at_rfc3339: str,
) -> str: ...
def build_signed_create_intent_json(
    tenant_id: str,
    principal_seed: bytes,
    payee_seed: bytes,
    intent_id: str,
    principal_did: str,
    payee_did: str,
    budget_json: str,
    currency: str,
    amount_cents: int,
    evidence_schema_json: str,
    deadline_rfc3339: str,
    predicate_json: str,
    predicate_ref: str,
    allowed_tools_json: str,
    settlement_rail: str,
) -> str: ...
def build_signed_create_intent_with_policy_binding_json(
    tenant_id: str,
    principal_seed: bytes,
    payee_seed: bytes,
    intent_id: str,
    principal_did: str,
    payee_did: str,
    budget_json: str,
    currency: str,
    amount_cents: int,
    evidence_schema_json: str,
    deadline_rfc3339: str,
    materialized_predicate_json: str,
    predicate_ref: str,
    allowed_tools_json: str,
    settlement_rail: str,
    policy_template_id: str,
    policy_version_seq: int,
    policy_content_digest_hex: str,
) -> str: ...
def verify_ed25519_sha256_hex(
    digest_hex: str,
    signature_hex: str,
    public_key_hex: str,
) -> bool: ...

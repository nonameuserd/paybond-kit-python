//! PyO3 extension: principal intent creation signing, payee evidence signing (`paybond-evidence`),
//! and Harbor wire helpers.

#![forbid(unsafe_code)]

mod intent_creation;
mod wire_golden;

use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use intent_creation::{intent_creation_sign_bytes_raw, intent_creation_sign_bytes_with_policy_binding};
use paybond_evidence::payee::sign_payee_evidence_request;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::Bound;
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

/// Returns a JSON string for `POST /intents/{intent_id}/evidence` (payload + signatures).
///
/// `secret_seed` must be exactly 32 bytes (Ed25519 seed).
#[pyfunction]
#[pyo3(signature = (
    tenant_id,
    intent_id,
    payee_did,
    payload_json,
    artifacts_hex,
    submitted_at_rfc3339,
    secret_seed,
))]
fn sign_payee_evidence_binding_json(
    tenant_id: String,
    intent_id: String,
    payee_did: String,
    payload_json: String,
    artifacts_hex: Vec<String>,
    submitted_at_rfc3339: String,
    secret_seed: Vec<u8>,
) -> PyResult<String> {
    if secret_seed.len() != 32 {
        return Err(PyValueError::new_err(
            "secret_seed must be exactly 32 bytes (Ed25519 signing key seed)",
        ));
    }
    let mut seed = [0_u8; 32];
    seed.copy_from_slice(&secret_seed);
    let key = SigningKey::from_bytes(&seed);
    let iid = Uuid::parse_str(&intent_id)
        .map_err(|e| PyValueError::new_err(format!("intent_id: {e}")))?;
    let payload: Value = serde_json::from_str(&payload_json)
        .map_err(|e| PyValueError::new_err(format!("payload_json: {e}")))?;
    let ts = OffsetDateTime::parse(
        &submitted_at_rfc3339,
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|e| PyValueError::new_err(format!("submitted_at_rfc3339: {e}")))?;
    let wire = sign_payee_evidence_request(
        &tenant_id,
        iid,
        &payee_did,
        &payload,
        &artifacts_hex,
        ts,
        &key,
    )
    .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    serde_json::to_string(&wire).map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

/// Returns hex-encoded EvidenceSignV1 signing bytes (parity helper for wire goldens).
#[pyfunction]
#[pyo3(signature = (
    tenant_id,
    intent_id,
    payee_did,
    payload_json,
    artifacts_hex,
    submitted_at_rfc3339,
))]
fn encode_evidence_sign_v1_hex(
    tenant_id: String,
    intent_id: String,
    payee_did: String,
    payload_json: String,
    artifacts_hex: Vec<String>,
    submitted_at_rfc3339: String,
) -> PyResult<String> {
    let payload: Value = serde_json::from_str(&payload_json)
        .map_err(|e| PyValueError::new_err(format!("payload_json: {e}")))?;
    wire_golden::encode_evidence_sign_v1_hex(
        &tenant_id,
        &intent_id,
        &payee_did,
        &payload,
        &artifacts_hex,
        &submitted_at_rfc3339,
    )
    .map_err(PyRuntimeError::new_err)
}

/// Returns a JSON string for ``POST /intents`` (principal-signed ``CreateIntentRequest``, raw ``predicate_dsl``).
///
/// ``principal_seed`` must be exactly 32 bytes (Ed25519 seed). ``allowed_tools_json`` must be a JSON
/// array of strings (non-empty per Harbor).
#[pyfunction]
#[pyo3(signature = (
    tenant_id,
    principal_seed,
    payee_seed,
    intent_id,
    principal_did,
    payee_did,
    budget_json,
    currency,
    amount_cents,
    evidence_schema_json,
    deadline_rfc3339,
    predicate_json,
    predicate_ref,
    allowed_tools_json,
    settlement_rail,
))]
fn build_signed_create_intent_json(
    tenant_id: String,
    principal_seed: Vec<u8>,
    payee_seed: Vec<u8>,
    intent_id: String,
    principal_did: String,
    payee_did: String,
    budget_json: String,
    currency: String,
    amount_cents: i64,
    evidence_schema_json: String,
    deadline_rfc3339: String,
    predicate_json: String,
    predicate_ref: String,
    allowed_tools_json: String,
    settlement_rail: String,
) -> PyResult<String> {
    if principal_seed.len() != 32 {
        return Err(PyValueError::new_err(
            "principal_seed must be exactly 32 bytes (Ed25519 signing key seed)",
        ));
    }
    if payee_seed.len() != 32 {
        return Err(PyValueError::new_err(
            "payee_seed must be exactly 32 bytes (Ed25519 signing key seed)",
        ));
    }
    let intent_uuid = Uuid::parse_str(intent_id.trim())
        .map_err(|e| PyValueError::new_err(format!("intent_id: {e}")))?;
    let budget: Value = serde_json::from_str(&budget_json)
        .map_err(|e| PyValueError::new_err(format!("budget_json: {e}")))?;
    let evidence_schema: Value = serde_json::from_str(&evidence_schema_json)
        .map_err(|e| PyValueError::new_err(format!("evidence_schema_json: {e}")))?;
    let predicate: Value = serde_json::from_str(&predicate_json)
        .map_err(|e| PyValueError::new_err(format!("predicate_json: {e}")))?;
    let allowed_tools: Vec<String> = serde_json::from_str(&allowed_tools_json).map_err(|e| {
        PyValueError::new_err(format!(
            "allowed_tools_json must be a JSON array of strings: {e}"
        ))
    })?;
    if allowed_tools.is_empty() {
        return Err(PyValueError::new_err("allowed_tools must be non-empty"));
    }
    let settlement_rail = match settlement_rail.trim() {
        "stripe_connect"
        | "stripe_ach_debit"
        | "stripe_mpp"
        | "adyen_manual_capture"
        | "x402_usdc_base" => settlement_rail.trim().to_string(),
        _ => {
            return Err(PyValueError::new_err(
                "settlement_rail must be one of stripe_connect, stripe_ach_debit, stripe_mpp, adyen_manual_capture, x402_usdc_base",
            ))
        }
    };
    let deadline_ot = OffsetDateTime::parse(
        &deadline_rfc3339,
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|e| PyValueError::new_err(format!("deadline_rfc3339: {e}")))?;

    let mut payee_seed_arr = [0_u8; 32];
    payee_seed_arr.copy_from_slice(&payee_seed);
    let payee_sk = SigningKey::from_bytes(&payee_seed_arr);
    let payee_pubkey = payee_sk.verifying_key().to_bytes();

    let msg = intent_creation_sign_bytes_raw(
        &tenant_id,
        intent_uuid,
        &principal_did,
        &payee_did,
        Some(payee_pubkey),
        amount_cents,
        &currency,
        deadline_ot,
        &budget,
        &evidence_schema,
        &predicate,
        &predicate_ref,
        &allowed_tools,
        &settlement_rail,
        None,
    )
    .map_err(PyValueError::new_err)?;

    let mut seed = [0_u8; 32];
    seed.copy_from_slice(&principal_seed);
    let sk = SigningKey::from_bytes(&seed);
    let sig = sk.sign(&msg);

    let mut body = serde_json::json!({
        "intent_id": intent_uuid,
        "principal_did": principal_did,
        "principal_pubkey": STANDARD.encode(sk.verifying_key().to_bytes()),
        "principal_signature": STANDARD.encode(sig.to_bytes()),
        "payee_did": payee_did,
        "payee_pubkey": STANDARD.encode(payee_pubkey),
        "budget": budget,
        "currency": currency,
        "amount_cents": amount_cents,
        "evidence_schema": evidence_schema,
        "deadline": deadline_rfc3339,
        "predicate_dsl": predicate,
        "settlement_rail": settlement_rail,
        "signing_version": 6,
        "policy_binding": serde_json::Value::Null,
        "allowed_tools": allowed_tools,
    });
    if !predicate_ref.trim().is_empty() {
        body["predicate_ref"] = serde_json::Value::String(predicate_ref);
    }
    serde_json::to_string(&body).map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

/// Returns a JSON string for ``POST /intents`` with signing v5 and a published managed-policy head.
#[pyfunction]
#[pyo3(signature = (
    tenant_id,
    principal_seed,
    payee_seed,
    intent_id,
    principal_did,
    payee_did,
    budget_json,
    currency,
    amount_cents,
    evidence_schema_json,
    deadline_rfc3339,
    materialized_predicate_json,
    predicate_ref,
    allowed_tools_json,
    settlement_rail,
    policy_template_id,
    policy_version_seq,
    policy_content_digest_hex,
))]
fn build_signed_create_intent_with_policy_binding_json(
    tenant_id: String,
    principal_seed: Vec<u8>,
    payee_seed: Vec<u8>,
    intent_id: String,
    principal_did: String,
    payee_did: String,
    budget_json: String,
    currency: String,
    amount_cents: i64,
    evidence_schema_json: String,
    deadline_rfc3339: String,
    materialized_predicate_json: String,
    predicate_ref: String,
    allowed_tools_json: String,
    settlement_rail: String,
    policy_template_id: String,
    policy_version_seq: u32,
    policy_content_digest_hex: String,
) -> PyResult<String> {
    if principal_seed.len() != 32 {
        return Err(PyValueError::new_err(
            "principal_seed must be exactly 32 bytes (Ed25519 signing key seed)",
        ));
    }
    if payee_seed.len() != 32 {
        return Err(PyValueError::new_err(
            "payee_seed must be exactly 32 bytes (Ed25519 signing key seed)",
        ));
    }
    let intent_uuid = Uuid::parse_str(intent_id.trim())
        .map_err(|e| PyValueError::new_err(format!("intent_id: {e}")))?;
    let budget: Value = serde_json::from_str(&budget_json)
        .map_err(|e| PyValueError::new_err(format!("budget_json: {e}")))?;
    let evidence_schema: Value = serde_json::from_str(&evidence_schema_json)
        .map_err(|e| PyValueError::new_err(format!("evidence_schema_json: {e}")))?;
    let materialized_predicate: Value = serde_json::from_str(&materialized_predicate_json)
        .map_err(|e| PyValueError::new_err(format!("materialized_predicate_json: {e}")))?;
    let allowed_tools: Vec<String> = serde_json::from_str(&allowed_tools_json).map_err(|e| {
        PyValueError::new_err(format!(
            "allowed_tools_json must be a JSON array of strings: {e}"
        ))
    })?;
    if allowed_tools.is_empty() {
        return Err(PyValueError::new_err("allowed_tools must be non-empty"));
    }
    let settlement_rail = match settlement_rail.trim() {
        "stripe_connect"
        | "stripe_ach_debit"
        | "stripe_mpp"
        | "adyen_manual_capture"
        | "x402_usdc_base" => settlement_rail.trim().to_string(),
        _ => {
            return Err(PyValueError::new_err(
                "settlement_rail must be one of stripe_connect, stripe_ach_debit, stripe_mpp, adyen_manual_capture, x402_usdc_base",
            ))
        }
    };
    let deadline_ot = OffsetDateTime::parse(
        &deadline_rfc3339,
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|e| PyValueError::new_err(format!("deadline_rfc3339: {e}")))?;

    let mut payee_seed_arr = [0_u8; 32];
    payee_seed_arr.copy_from_slice(&payee_seed);
    let payee_sk = SigningKey::from_bytes(&payee_seed_arr);
    let payee_pubkey = payee_sk.verifying_key().to_bytes();

    let msg = intent_creation_sign_bytes_with_policy_binding(
        &tenant_id,
        intent_uuid,
        &principal_did,
        &payee_did,
        Some(payee_pubkey),
        amount_cents,
        &currency,
        deadline_ot,
        &budget,
        &evidence_schema,
        &materialized_predicate,
        &predicate_ref,
        &allowed_tools,
        &settlement_rail,
        &policy_template_id,
        policy_version_seq,
        &policy_content_digest_hex,
        None,
    )
    .map_err(PyValueError::new_err)?;

    let mut seed = [0_u8; 32];
    seed.copy_from_slice(&principal_seed);
    let sk = SigningKey::from_bytes(&seed);
    let sig = sk.sign(&msg);

    let mut body = serde_json::json!({
        "intent_id": intent_uuid,
        "principal_did": principal_did,
        "principal_pubkey": STANDARD.encode(sk.verifying_key().to_bytes()),
        "principal_signature": STANDARD.encode(sig.to_bytes()),
        "payee_did": payee_did,
        "payee_pubkey": STANDARD.encode(payee_pubkey),
        "budget": budget,
        "currency": currency,
        "amount_cents": amount_cents,
        "evidence_schema": evidence_schema,
        "deadline": deadline_rfc3339,
        "settlement_rail": settlement_rail,
        "signing_version": 7,
        "policy_binding": {
            "template_id": policy_template_id,
            "version_seq": policy_version_seq,
        },
        "allowed_tools": allowed_tools,
    });
    if !predicate_ref.trim().is_empty() {
        body["predicate_ref"] = serde_json::Value::String(predicate_ref);
    }
    serde_json::to_string(&body).map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

/// Verify an Ed25519 signature over a SHA-256 digest (audit export manifest verification).
#[pyfunction]
fn verify_ed25519_sha256_hex(
    digest_hex: String,
    signature_hex: String,
    public_key_hex: String,
) -> PyResult<bool> {
    let digest = hex::decode(digest_hex.trim())
        .map_err(|e| PyValueError::new_err(format!("digest_hex: {e}")))?;
    if digest.len() != 32 {
        return Err(PyValueError::new_err("digest_hex must decode to 32 bytes"));
    }
    let sig_bytes = hex::decode(signature_hex.trim())
        .map_err(|e| PyValueError::new_err(format!("signature_hex: {e}")))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| PyValueError::new_err(format!("signature_hex: {e}")))?;
    let pub_bytes = hex::decode(public_key_hex.trim())
        .map_err(|e| PyValueError::new_err(format!("public_key_hex: {e}")))?;
    let pub_array: [u8; 32] = pub_bytes
        .as_slice()
        .try_into()
        .map_err(|_| PyValueError::new_err("public_key_hex must decode to 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&pub_array)
        .map_err(|e| PyValueError::new_err(format!("public_key_hex: {e}")))?;
    let digest_array: [u8; 32] = digest
        .as_slice()
        .try_into()
        .map_err(|_| PyValueError::new_err("digest_hex must decode to 32 bytes"))?;
    Ok(verifying_key.verify(&digest_array, &signature).is_ok())
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(sign_payee_evidence_binding_json, m)?)?;
    m.add_function(wrap_pyfunction!(encode_evidence_sign_v1_hex, m)?)?;
    m.add_function(wrap_pyfunction!(build_signed_create_intent_json, m)?)?;
    m.add_function(wrap_pyfunction!(
        build_signed_create_intent_with_policy_binding_json,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(verify_ed25519_sha256_hex, m)?)?;
    Ok(())
}

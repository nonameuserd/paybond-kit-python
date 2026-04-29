//! Payee Ed25519 signatures over [`EvidenceSignV1`] for Harbor evidence submission.

use crate::{artifacts_digest, encode_evidence_sign_v1, json_value_digest, EvidenceSignV1};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

/// Wire body for `POST /intents/{id}/evidence` after signing.
#[derive(Debug, Clone, Serialize)]
pub struct PayeeEvidenceRequest {
    pub payload: Value,
    pub artifacts: Vec<String>,
    pub payee_did: String,
    pub payee_pubkey: String,
    pub payee_signature: String,
    pub submitted_at: String,
}

/// Payee signing or artifact parsing failure.
#[derive(Debug, Error)]
pub enum PayeeEvidenceError {
    #[error("artifact[{index}]: {message}")]
    BadArtifact { index: usize, message: String },
    #[error("evidence signing payload: {0}")]
    Encode(String),
    #[error("submitted_at: {0}")]
    SubmittedAt(String),
}

fn parse_hex32(name: &str, index: usize, hex: &str) -> Result<[u8; 32], PayeeEvidenceError> {
    let s = hex.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| PayeeEvidenceError::BadArtifact {
        index,
        message: format!("{name}: bad hex ({e})"),
    })?;
    if bytes.len() != 32 {
        return Err(PayeeEvidenceError::BadArtifact {
            index,
            message: format!("{name}: expected 32 bytes, got {}", bytes.len()),
        });
    }
    let mut out = [0_u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Builds a Harbor-ready evidence request with a detached Ed25519 signature over [`EvidenceSignV1`].
pub fn sign_payee_evidence_request(
    tenant_id: &str,
    intent_id: Uuid,
    payee_did: &str,
    payload: &Value,
    artifacts_blake3_hex: &[String],
    submitted_at: OffsetDateTime,
    signing_key: &SigningKey,
) -> Result<PayeeEvidenceRequest, PayeeEvidenceError> {
    let mut parsed: Vec<[u8; 32]> = Vec::with_capacity(artifacts_blake3_hex.len());
    for (i, h) in artifacts_blake3_hex.iter().enumerate() {
        parsed.push(parse_hex32("artifact", i, h)?);
    }
    let payload_digest = json_value_digest(payload);
    let artifacts_digest = artifacts_digest(&parsed);
    let submitted_at_str = submitted_at
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| PayeeEvidenceError::SubmittedAt(e.to_string()))?;
    let sign_payload = EvidenceSignV1 {
        version: 1,
        tenant_id: tenant_id.to_string(),
        intent_id,
        payee_did: payee_did.to_string(),
        payload_digest,
        artifacts_digest,
        submitted_at,
    };
    let msg = encode_evidence_sign_v1(&sign_payload).map_err(PayeeEvidenceError::Encode)?;
    let sig = signing_key.sign(&msg);
    let artifacts_wire: Vec<String> = parsed.iter().map(hex::encode).collect();
    Ok(PayeeEvidenceRequest {
        payload: payload.clone(),
        artifacts: artifacts_wire,
        payee_did: payee_did.to_string(),
        payee_pubkey: STANDARD.encode(signing_key.verifying_key().to_bytes()),
        payee_signature: STANDARD.encode(sig.to_bytes()),
        submitted_at: submitted_at_str,
    })
}

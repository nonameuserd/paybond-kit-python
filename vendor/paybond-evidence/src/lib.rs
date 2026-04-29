//! Canonical evidence payload hashing and [`EvidenceSignV1`] bytes for payee signatures.
//!
//! Harbor (`POST /intents/{id}/evidence`) and Paybond Kit must serialize identical signing payloads.

#![forbid(unsafe_code)]

#[cfg(feature = "sign")]
pub mod payee;

use serde::Serialize;
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

/// Versioned payload the payee signs when binding evidence to an intent.
#[derive(Debug, Serialize)]
pub struct EvidenceSignV1 {
    pub version: u8,
    pub tenant_id: String,
    pub intent_id: Uuid,
    pub payee_did: String,
    pub payload_digest: [u8; 32],
    pub artifacts_digest: [u8; 32],
    #[serde(with = "time::serde::rfc3339")]
    pub submitted_at: OffsetDateTime,
}

/// Builds deterministic signing bytes for [`EvidenceSignV1`] (bincode v1 default encoding).
pub fn encode_evidence_sign_v1(payload: &EvidenceSignV1) -> Result<Vec<u8>, String> {
    bincode::serialize(payload).map_err(|e| format!("bincode evidence sign payload: {e}"))
}

/// BLAKE3 digest over canonical JSON (sorted object keys, compact) for evidence payload hashing.
#[must_use]
pub fn json_value_digest(value: &Value) -> [u8; 32] {
    let normalized = normalize_json(value);
    *blake3::hash(serde_json::to_string(&normalized).unwrap_or_default().as_bytes()).as_bytes()
}

fn normalize_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<_> = map.keys().cloned().collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for k in keys {
                if let Some(v) = map.get(&k) {
                    out.insert(k, normalize_json(v));
                }
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(normalize_json).collect()),
        _ => value.clone(),
    }
}

/// Digest of artifact hash list (empty list hashes to zeros after hashing empty concatenation).
#[must_use]
pub fn artifacts_digest(artifacts: &[[u8; 32]]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    for a in artifacts {
        h.update(a);
    }
    *h.finalize().as_bytes()
}

//! Canonical evidence payload hashing and [`EvidenceSignV1`] bytes for payee signatures.
//!
//! Harbor (`POST /intents/{id}/evidence`) and Paybond Kit must serialize identical signing payloads.

#![forbid(unsafe_code)]

#[cfg(feature = "sign")]
pub mod payee;
pub mod wire;

use serde::Serialize;
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

pub use wire::encode_wire;

/// Signed payload revision; bump when the bincode frame changes.
pub const EVIDENCE_SIGN_VERSION: u8 = 2;

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

/// Builds deterministic signing bytes for [`EvidenceSignV1`] (bincode 2 standard encoding).
///
/// # Errors
///
/// Returns an error when bincode serialization fails.
pub fn encode_evidence_sign_v1(payload: &EvidenceSignV1) -> Result<Vec<u8>, String> {
    encode_wire(payload).map_err(|e| format!("bincode evidence sign payload: {e}"))
}

/// BLAKE3 digest over canonical JSON (sorted object keys, compact) for evidence payload hashing.
#[must_use]
pub fn json_value_digest(value: &Value) -> [u8; 32] {
    let normalized = normalize_json(value);
    *blake3::hash(
        serde_json::to_string(&normalized)
            .unwrap_or_default()
            .as_bytes(),
    )
    .as_bytes()
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn json_digest_stable_under_key_reorder() {
        let a = json!({"b": 2, "a": 1});
        let b = json!({"a": 1, "b": 2});
        assert_eq!(json_value_digest(&a), json_value_digest(&b));
    }
}

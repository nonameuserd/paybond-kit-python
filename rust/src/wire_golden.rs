//! Evidence signing helpers shared by the PyO3 extension and wire golden tests.

use paybond_evidence::{
    artifacts_digest, encode_evidence_sign_v1, json_value_digest, EvidenceSignV1,
    EVIDENCE_SIGN_VERSION,
};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

/// Returns hex-encoded EvidenceSignV1 signing bytes.
pub fn encode_evidence_sign_v1_hex(
    tenant_id: &str,
    intent_id: &str,
    payee_did: &str,
    payload: &Value,
    artifacts_hex: &[String],
    submitted_at_rfc3339: &str,
) -> Result<String, String> {
    let iid = Uuid::parse_str(intent_id).map_err(|e| format!("intent_id: {e}"))?;
    let mut parsed: Vec<[u8; 32]> = Vec::with_capacity(artifacts_hex.len());
    for (i, h) in artifacts_hex.iter().enumerate() {
        let s = h.trim().strip_prefix("0x").unwrap_or(h);
        let bytes = hex::decode(s).map_err(|e| format!("artifacts_hex[{i}]: bad hex ({e})"))?;
        if bytes.len() != 32 {
            return Err(format!(
                "artifacts_hex[{i}]: expected 32 bytes, got {}",
                bytes.len()
            ));
        }
        let mut out = [0_u8; 32];
        out.copy_from_slice(&bytes);
        parsed.push(out);
    }
    let submitted_at = OffsetDateTime::parse(
        submitted_at_rfc3339,
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|e| format!("submitted_at_rfc3339: {e}"))?;
    let sign_payload = EvidenceSignV1 {
        version: EVIDENCE_SIGN_VERSION,
        tenant_id: tenant_id.to_string(),
        intent_id: iid,
        payee_did: payee_did.to_string(),
        payload_digest: json_value_digest(payload),
        artifacts_digest: artifacts_digest(&parsed),
        submitted_at,
    };
    let msg = encode_evidence_sign_v1(&sign_payload)?;
    Ok(hex::encode(msg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::path::PathBuf;

    #[derive(Debug, Deserialize)]
    struct EvidenceSignV1Golden {
        input: EvidenceSignV1GoldenInput,
        expected: EvidenceSignV1GoldenExpected,
    }

    #[derive(Debug, Deserialize)]
    struct EvidenceSignV1GoldenInput {
        tenant_id: String,
        intent_id: String,
        payee_did: String,
        payload: Value,
        artifacts_blake3_hex: Vec<String>,
        submitted_at_rfc3339: String,
    }

    #[derive(Debug, Deserialize)]
    struct EvidenceSignV1GoldenExpected {
        sign_bytes_hex: String,
    }

    #[test]
    fn evidence_sign_v1_matches_wire_golden() {
        let golden = load_evidence_sign_v1_golden();
        let got = encode_evidence_sign_v1_hex(
            &golden.input.tenant_id,
            &golden.input.intent_id,
            &golden.input.payee_did,
            &golden.input.payload,
            &golden.input.artifacts_blake3_hex,
            &golden.input.submitted_at_rfc3339,
        )
        .unwrap();
        assert_eq!(got, golden.expected.sign_bytes_hex);
    }

    fn load_evidence_sign_v1_golden() -> EvidenceSignV1Golden {
        let path = repo_root().join("kit/wire-goldens/evidence_sign_v1.json");
        let raw = std::fs::read_to_string(path).expect("read evidence_sign_v1 golden");
        serde_json::from_str(&raw).expect("decode evidence_sign_v1 golden")
    }

    fn repo_root() -> PathBuf {
        let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        loop {
            if dir.join("kit/wire-goldens/evidence_sign_v1.json").is_file() {
                return dir;
            }
            if !dir.pop() {
                panic!("could not find kit/wire-goldens/evidence_sign_v1.json");
            }
        }
    }
}

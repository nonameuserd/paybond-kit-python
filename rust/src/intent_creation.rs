//! Principal intent creation signing for raw `predicate_dsl` (no managed-policy binding).
//! Kept in sync with `crates/harbor-intent-escrow/src/signing.rs` (`intent_creation_sign_bytes_raw`).

use paybond_evidence::{encode_wire, json_value_digest};
use serde::Serialize;
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
enum IntentSigningCommitment {
    V4 { settlement_rail: String },
    V5 {
        settlement_rail: String,
        policy_template_id: String,
        policy_version_seq: u32,
        policy_content_digest: [u8; 32],
    },
    V6 {
        settlement_rail: String,
        payee_pubkey: [u8; 32],
    },
    V7 {
        settlement_rail: String,
        policy_template_id: String,
        policy_version_seq: u32,
        policy_content_digest: [u8; 32],
        payee_pubkey: [u8; 32],
    },
}

#[derive(Debug, Serialize)]
struct IntentCreationSignV4 {
    version: u8,
    tenant_id: String,
    intent_id: Uuid,
    principal_did: String,
    payee_did: String,
    amount_cents: i64,
    currency: String,
    #[serde(with = "time::serde::rfc3339")]
    deadline: OffsetDateTime,
    budget_digest: [u8; 32],
    evidence_schema_digest: [u8; 32],
    predicate_dsl_digest: [u8; 32],
    predicate_ref: String,
    allowed_tools_digest: [u8; 32],
    settlement_rail: String,
}

#[derive(Debug, Serialize)]
struct IntentCreationSignV5 {
    version: u8,
    tenant_id: String,
    intent_id: Uuid,
    principal_did: String,
    payee_did: String,
    amount_cents: i64,
    currency: String,
    #[serde(with = "time::serde::rfc3339")]
    deadline: OffsetDateTime,
    budget_digest: [u8; 32],
    evidence_schema_digest: [u8; 32],
    predicate_dsl_digest: [u8; 32],
    predicate_ref: String,
    allowed_tools_digest: [u8; 32],
    settlement_rail: String,
    policy_template_id: String,
    policy_version_seq: u32,
    policy_content_digest: [u8; 32],
}

#[derive(Debug, Serialize)]
struct IntentCreationSignV6 {
    version: u8,
    tenant_id: String,
    intent_id: Uuid,
    principal_did: String,
    payee_did: String,
    amount_cents: i64,
    currency: String,
    #[serde(with = "time::serde::rfc3339")]
    deadline: OffsetDateTime,
    budget_digest: [u8; 32],
    evidence_schema_digest: [u8; 32],
    predicate_dsl_digest: [u8; 32],
    predicate_ref: String,
    allowed_tools_digest: [u8; 32],
    settlement_rail: String,
    payee_pubkey: [u8; 32],
}

#[derive(Debug, Serialize)]
struct IntentCreationSignV7 {
    version: u8,
    tenant_id: String,
    intent_id: Uuid,
    principal_did: String,
    payee_did: String,
    amount_cents: i64,
    currency: String,
    #[serde(with = "time::serde::rfc3339")]
    deadline: OffsetDateTime,
    budget_digest: [u8; 32],
    evidence_schema_digest: [u8; 32],
    predicate_dsl_digest: [u8; 32],
    predicate_ref: String,
    allowed_tools_digest: [u8; 32],
    settlement_rail: String,
    policy_template_id: String,
    policy_version_seq: u32,
    policy_content_digest: [u8; 32],
    payee_pubkey: [u8; 32],
}

fn encode_intent_creation_sign_v4(payload: &IntentCreationSignV4) -> Result<Vec<u8>, String> {
    encode_wire(payload).map_err(|e| format!("bincode intent sign v4 payload: {e}"))
}

fn encode_intent_creation_sign_v5(payload: &IntentCreationSignV5) -> Result<Vec<u8>, String> {
    encode_wire(payload).map_err(|e| format!("bincode intent sign v5 payload: {e}"))
}

fn encode_intent_creation_sign_v6(payload: &IntentCreationSignV6) -> Result<Vec<u8>, String> {
    encode_wire(payload).map_err(|e| format!("bincode intent sign v6 payload: {e}"))
}

fn encode_intent_creation_sign_v7(payload: &IntentCreationSignV7) -> Result<Vec<u8>, String> {
    encode_wire(payload).map_err(|e| format!("bincode intent sign v7 payload: {e}"))
}

fn dsl_digest(dsl: Option<&Value>) -> [u8; 32] {
    match dsl {
        None => [0_u8; 32],
        Some(v) => json_value_digest(v),
    }
}

fn allowed_tools_digest(tools: &[String]) -> [u8; 32] {
    let mut sorted: Vec<String> = tools
        .iter()
        .map(|s| s.trim().to_ascii_lowercase())
        .collect();
    sorted.sort();
    sorted.dedup();
    let arr = Value::Array(sorted.into_iter().map(Value::String).collect());
    json_value_digest(&arr)
}

fn intent_creation_canonical_bytes(
    tenant_id: &str,
    intent_id: Uuid,
    principal_did: &str,
    payee_did: &str,
    amount_cents: i64,
    currency: &str,
    deadline: OffsetDateTime,
    budget_digest: [u8; 32],
    evidence_schema_digest: [u8; 32],
    effective_predicate_dsl: &Value,
    predicate_ref: &str,
    allowed_tools_digest_val: [u8; 32],
    commitment: &IntentSigningCommitment,
) -> Result<Vec<u8>, String> {
    let dsl_d = dsl_digest(Some(effective_predicate_dsl));
    match commitment {
        IntentSigningCommitment::V4 { settlement_rail } => {
            let sign_payload = IntentCreationSignV4 {
                version: 4,
                tenant_id: tenant_id.to_string(),
                intent_id,
                principal_did: principal_did.to_string(),
                payee_did: payee_did.to_string(),
                amount_cents,
                currency: currency.to_string(),
                deadline,
                budget_digest,
                evidence_schema_digest,
                predicate_dsl_digest: dsl_d,
                predicate_ref: predicate_ref.to_string(),
                allowed_tools_digest: allowed_tools_digest_val,
                settlement_rail: settlement_rail.clone(),
            };
            encode_intent_creation_sign_v4(&sign_payload)
        }
        IntentSigningCommitment::V5 {
            settlement_rail,
            policy_template_id,
            policy_version_seq,
            policy_content_digest,
        } => {
            let sign_payload = IntentCreationSignV5 {
                version: 5,
                tenant_id: tenant_id.to_string(),
                intent_id,
                principal_did: principal_did.to_string(),
                payee_did: payee_did.to_string(),
                amount_cents,
                currency: currency.to_string(),
                deadline,
                budget_digest,
                evidence_schema_digest,
                predicate_dsl_digest: dsl_d,
                predicate_ref: predicate_ref.to_string(),
                allowed_tools_digest: allowed_tools_digest_val,
                settlement_rail: settlement_rail.clone(),
                policy_template_id: policy_template_id.clone(),
                policy_version_seq: *policy_version_seq,
                policy_content_digest: *policy_content_digest,
            };
            encode_intent_creation_sign_v5(&sign_payload)
        }
        IntentSigningCommitment::V6 {
            settlement_rail,
            payee_pubkey,
        } => {
            let sign_payload = IntentCreationSignV6 {
                version: 6,
                tenant_id: tenant_id.to_string(),
                intent_id,
                principal_did: principal_did.to_string(),
                payee_did: payee_did.to_string(),
                amount_cents,
                currency: currency.to_string(),
                deadline,
                budget_digest,
                evidence_schema_digest,
                predicate_dsl_digest: dsl_d,
                predicate_ref: predicate_ref.to_string(),
                allowed_tools_digest: allowed_tools_digest_val,
                settlement_rail: settlement_rail.clone(),
                payee_pubkey: *payee_pubkey,
            };
            encode_intent_creation_sign_v6(&sign_payload)
        }
        IntentSigningCommitment::V7 {
            settlement_rail,
            policy_template_id,
            policy_version_seq,
            policy_content_digest,
            payee_pubkey,
        } => {
            let sign_payload = IntentCreationSignV7 {
                version: 7,
                tenant_id: tenant_id.to_string(),
                intent_id,
                principal_did: principal_did.to_string(),
                payee_did: payee_did.to_string(),
                amount_cents,
                currency: currency.to_string(),
                deadline,
                budget_digest,
                evidence_schema_digest,
                predicate_dsl_digest: dsl_d,
                predicate_ref: predicate_ref.to_string(),
                allowed_tools_digest: allowed_tools_digest_val,
                settlement_rail: settlement_rail.clone(),
                policy_template_id: policy_template_id.clone(),
                policy_version_seq: *policy_version_seq,
                policy_content_digest: *policy_content_digest,
                payee_pubkey: *payee_pubkey,
            };
            encode_intent_creation_sign_v7(&sign_payload)
        }
    }
}

#[derive(Debug, Serialize)]
struct CompletionContractSignV1 {
    version: u8,
    completion_preset_id: String,
    vendor_contract_provider: String,
    vendor_api_version: String,
    vendor_schema_digest: [u8; 32],
    canonical_schema_digest: [u8; 32],
}

#[derive(Clone, Debug)]
pub(crate) struct CompletionContractSigningFields {
    pub completion_preset_id: String,
    pub vendor_contract_provider: String,
    pub vendor_api_version: String,
    pub vendor_schema_digest: [u8; 32],
    pub canonical_schema_digest: [u8; 32],
}

fn encode_completion_contract_sign_v1(
    fields: &CompletionContractSigningFields,
) -> Result<Vec<u8>, String> {
    let payload = CompletionContractSignV1 {
        version: 2,
        completion_preset_id: fields.completion_preset_id.clone(),
        vendor_contract_provider: fields.vendor_contract_provider.clone(),
        vendor_api_version: fields.vendor_api_version.clone(),
        vendor_schema_digest: fields.vendor_schema_digest,
        canonical_schema_digest: fields.canonical_schema_digest,
    };
    encode_wire(&payload).map_err(|e| format!("bincode completion contract sign v1: {e}"))
}

fn append_completion_contract_sign_extension(
    base: &[u8],
    fields: &CompletionContractSigningFields,
) -> Result<Vec<u8>, String> {
    let mut out = base.to_vec();
    out.extend(encode_completion_contract_sign_v1(fields)?);
    Ok(out)
}

pub(crate) fn intent_creation_sign_bytes_raw(
    tenant_id: &str,
    intent_id: Uuid,
    principal_did: &str,
    payee_did: &str,
    payee_pubkey: Option<[u8; 32]>,
    amount_cents: i64,
    currency: &str,
    deadline: OffsetDateTime,
    budget: &Value,
    evidence_schema: &Value,
    predicate_dsl: &Value,
    predicate_ref: &str,
    allowed_tools: &[String],
    settlement_rail: &str,
    completion_contract: Option<&CompletionContractSigningFields>,
) -> Result<Vec<u8>, String> {
    let budget_digest = json_value_digest(budget);
    let evidence_schema_digest = json_value_digest(evidence_schema);
    let allowed_digest = allowed_tools_digest(allowed_tools);
    let commitment = match payee_pubkey {
        Some(pk) => IntentSigningCommitment::V6 {
            settlement_rail: settlement_rail.to_string(),
            payee_pubkey: pk,
        },
        None => IntentSigningCommitment::V4 {
            settlement_rail: settlement_rail.to_string(),
        },
    };
    let base = intent_creation_canonical_bytes(
        tenant_id,
        intent_id,
        principal_did,
        payee_did,
        amount_cents,
        currency,
        deadline,
        budget_digest,
        evidence_schema_digest,
        predicate_dsl,
        predicate_ref,
        allowed_digest,
        &commitment,
    )?;
    match completion_contract {
        Some(fields) => append_completion_contract_sign_extension(&base, fields),
        None => Ok(base),
    }
}

/// Same semantics as Harbor signing v5 for managed-policy intent creation.
pub(crate) fn intent_creation_sign_bytes_with_policy_binding(
    tenant_id: &str,
    intent_id: Uuid,
    principal_did: &str,
    payee_did: &str,
    payee_pubkey: Option<[u8; 32]>,
    amount_cents: i64,
    currency: &str,
    deadline: OffsetDateTime,
    budget: &Value,
    evidence_schema: &Value,
    materialized_predicate: &Value,
    predicate_ref: &str,
    allowed_tools: &[String],
    settlement_rail: &str,
    policy_template_id: &str,
    policy_version_seq: u32,
    policy_content_digest_hex: &str,
    completion_contract: Option<&CompletionContractSigningFields>,
) -> Result<Vec<u8>, String> {
    let digest = hex::decode(policy_content_digest_hex.trim())
        .map_err(|e| format!("policy_content_digest_hex: {e}"))?;
    let digest: [u8; 32] = digest
        .as_slice()
        .try_into()
        .map_err(|_| "policy_content_digest_hex must decode to 32 bytes".to_string())?;
    let budget_digest = json_value_digest(budget);
    let evidence_schema_digest = json_value_digest(evidence_schema);
    let allowed_digest = allowed_tools_digest(allowed_tools);
    let commitment = match payee_pubkey {
        Some(pk) => IntentSigningCommitment::V7 {
            settlement_rail: settlement_rail.to_string(),
            policy_template_id: policy_template_id.to_string(),
            policy_version_seq,
            policy_content_digest: digest,
            payee_pubkey: pk,
        },
        None => IntentSigningCommitment::V5 {
            settlement_rail: settlement_rail.to_string(),
            policy_template_id: policy_template_id.to_string(),
            policy_version_seq,
            policy_content_digest: digest,
        },
    };
    let base = intent_creation_canonical_bytes(
        tenant_id,
        intent_id,
        principal_did,
        payee_did,
        amount_cents,
        currency,
        deadline,
        budget_digest,
        evidence_schema_digest,
        materialized_predicate,
        predicate_ref,
        allowed_digest,
        &commitment,
    )?;
    match completion_contract {
        Some(fields) => append_completion_contract_sign_extension(&base, fields),
        None => Ok(base),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use serde_json::json;

    #[test]
    fn matches_harbor_intent_escrow_golden() {
        let tenant = "tenant-golden";
        let intent_id = Uuid::parse_str("7f2a9b1e-2f66-4f4f-9c6e-8f4b8e85c401").unwrap();
        let deadline = OffsetDateTime::parse(
            "2030-01-02T15:04:05Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        let budget = json!({"max": 100, "a": 1});
        let evidence_schema = json!({"type": "object"});
        let predicate_dsl = json!({"version": 1, "root": {"op": "true"}});
        let allowed = vec!["Harbor.Evidence_Submit".into(), "harbor.describe".into()];
        let bytes = intent_creation_sign_bytes_raw(
            tenant,
            intent_id,
            "did:principal:1",
            "did:payee:1",
            None,
            100,
            "usd",
            deadline,
            &budget,
            &evidence_schema,
            &predicate_dsl,
            "",
            &allowed,
            "stripe_connect",
            None,
        )
        .unwrap();
        let golden = hex::encode(bytes);
        assert_eq!(
            golden,
            "040d74656e616e742d676f6c64656e107f2a9b1e2f664f4f9c6e8f4b8e85c4010f6469643a7072696e636970616c3a310b6469643a70617965653a31c80375736414323033302d30312d30325431353a30343a30355afe9931de397b3817d06aeeb9877163cea9964adc4609fd0f1d715542a7f9c65769b254eacefe89c7b9b29305b06ec5983871a03cc20db0b4747905ecdddd7f29c366a1c38aad99370b12e7197e0fe5590e2d20763c9b4550a738313f484757e5006ba1f5bfb6266e05ed626dd8a1a318e8f9a38272186eb855bf717cede2c5b1040e7374726970655f636f6e6e656374"
        );
    }

    #[test]
    fn matches_harbor_intent_escrow_signing_v5_golden() {
        let tenant = "tenant-golden";
        let intent_id = Uuid::parse_str("7f2a9b1e-2f66-4f4f-9c6e-8f4b8e85c401").unwrap();
        let deadline = OffsetDateTime::parse(
            "2030-01-02T15:04:05Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        let budget = json!({"max": 100, "a": 1});
        let evidence_schema = json!({"type": "object"});
        let predicate_dsl = json!({"version": 1, "root": {"op": "true"}});
        let allowed = vec!["Harbor.Evidence_Submit".into(), "harbor.describe".into()];
        let bytes = intent_creation_sign_bytes_with_policy_binding(
            tenant,
            intent_id,
            "did:principal:1",
            "did:payee:1",
            None,
            100,
            "usd",
            deadline,
            &budget,
            &evidence_schema,
            &predicate_dsl,
            "",
            &allowed,
            "stripe_connect",
            "completion_v1",
            3,
            &"ab".repeat(32),
            None,
        )
        .unwrap();
        let golden = hex::encode(bytes);
        assert_eq!(
            golden,
            "050d74656e616e742d676f6c64656e107f2a9b1e2f664f4f9c6e8f4b8e85c4010f6469643a7072696e636970616c3a310b6469643a70617965653a31c80375736414323033302d30312d30325431353a30343a30355afe9931de397b3817d06aeeb9877163cea9964adc4609fd0f1d715542a7f9c65769b254eacefe89c7b9b29305b06ec5983871a03cc20db0b4747905ecdddd7f29c366a1c38aad99370b12e7197e0fe5590e2d20763c9b4550a738313f484757e5006ba1f5bfb6266e05ed626dd8a1a318e8f9a38272186eb855bf717cede2c5b1040e7374726970655f636f6e6e6563740d636f6d706c6574696f6e5f763103abababababababababababababababababababababababababababababababab"
        );
    }
}

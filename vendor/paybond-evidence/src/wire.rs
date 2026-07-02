//! Shared bincode 2 wire encoding for Paybond signing payloads.

use serde::Serialize;

/// Encodes `value` with the canonical Paybond bincode 2 wire format.
///
/// # Errors
///
/// Returns [`bincode::error::EncodeError`] when serialization fails.
pub fn encode_wire<T: Serialize>(value: &T) -> Result<Vec<u8>, bincode::error::EncodeError> {
    bincode::serde::encode_to_vec(value, bincode::config::standard())
}

#[cfg(test)]
mod wire_probe {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn dump_bincode2_primitives() {
        let intent_id = Uuid::parse_str("7f2a9b1e-2f66-4f4f-9c6e-8f4b8e85c401").unwrap();
        eprintln!("u8: {}", hex::encode(encode_wire(&6u8).unwrap()));
        eprintln!(
            "str tenant: {}",
            hex::encode(encode_wire(&"tenant-golden".to_string()).unwrap())
        );
        eprintln!("uuid: {}", hex::encode(encode_wire(&intent_id).unwrap()));
        eprintln!("i64 100: {}", hex::encode(encode_wire(&100i64).unwrap()));
        eprintln!("i64 1000: {}", hex::encode(encode_wire(&1000i64).unwrap()));
        eprintln!("i64 -1: {}", hex::encode(encode_wire(&-1i64).unwrap()));
        eprintln!("u32 3: {}", hex::encode(encode_wire(&3u32).unwrap()));
        eprintln!("u32 300: {}", hex::encode(encode_wire(&300u32).unwrap()));
        eprintln!(
            "[u8;32] ab: {}",
            hex::encode(encode_wire(&[0xab_u8; 32]).unwrap())
        );
    }
}

use std::{collections::BTreeSet, str::FromStr};

use proptest::prelude::*;
use reproit_core::{
    canonical,
    crypto::{NonceRegistry, decrypt_chunk, derive_chunk_key, encrypt_chunk, secret_key},
    identity::{CaptureId, Digest, Timestamp},
    model::{ChunkKeyContext, Proof},
};
use secrecy::ExposeSecret;
use serde_json::{Map, Value, json};

proptest! {
    #[test]
    fn digest_text_round_trips(bytes in any::<[u8; 32]>()) {
        let digest = Digest::from_bytes(bytes);
        prop_assert_eq!(Digest::from_str(&digest.to_string()).unwrap(), digest);
    }

    #[test]
    fn canonical_object_order_does_not_change_bytes(
        entries in prop::collection::btree_map("[a-z]{1,12}", any::<i32>(), 0..32)
    ) {
        let forward = Value::Object(
            entries.iter().map(|(key, value)| (key.clone(), Value::from(*value))).collect::<Map<_, _>>()
        );
        let reverse = Value::Object(
            entries.iter().rev().map(|(key, value)| (key.clone(), Value::from(*value))).collect::<Map<_, _>>()
        );
        prop_assert_eq!(
            canonical::canonical_bytes(&forward).unwrap(),
            canonical::canonical_bytes(&reverse).unwrap()
        );
    }

    #[test]
    fn encryption_round_trips_exact_bytes(
        key in any::<[u8; 32]>(),
        nonce in any::<[u8; 12]>(),
        plaintext in prop::collection::vec(any::<u8>(), 0..4096)
    ) {
        let context: ChunkKeyContext = serde_json::from_value(json!({
            "chunk_count": 1,
            "chunk_index": 0,
            "format": "reproit.chunk-key-context.v1",
            "object_context_digest": format!("sha256:{}", "a".repeat(64)),
            "plain_size": plaintext.len()
        })).unwrap();
        let chunk_key = derive_chunk_key(&secret_key(key), &context).unwrap();
        let stored = encrypt_chunk(&chunk_key, nonce, &plaintext, &context).unwrap();
        let decrypted = decrypt_chunk(&chunk_key, &stored, &context).unwrap();
        prop_assert_eq!(decrypted, plaintext);
        prop_assert_eq!(chunk_key.expose_secret().len(), 32);
    }

    #[test]
    fn nonce_registry_matches_a_set(nonces in prop::collection::vec(any::<[u8; 12]>(), 0..1024)) {
        let mut registry = NonceRegistry::default();
        let mut model = BTreeSet::new();
        for nonce in nonces {
            let expected = model.insert(nonce);
            prop_assert_eq!(registry.register(nonce).is_ok(), expected);
        }
    }
}

#[test]
fn strict_json_rejects_disallowed_numbers_and_duplicate_keys() {
    for value in [
        br#"{"value":1.0}"#.as_slice(),
        br#"{"value":-0}"#.as_slice(),
        br#"{"value":9007199254740992}"#.as_slice(),
        br#"{"value":1,"value":2}"#.as_slice(),
        br#"{"value":"\ud800"}"#.as_slice(),
    ] {
        assert!(canonical::parse_strict::<Value>(value).is_err());
    }
}

#[test]
fn canonicalization_rejects_non_integer_values_from_memory() {
    assert!(canonical::canonical_bytes(&json!({"value": 1.5})).is_err());
    assert!(canonical::canonical_bytes(&json!({"value": -0.0})).is_err());
    assert!(canonical::canonical_bytes(&json!({"value": 9_007_199_254_740_992_u64})).is_err());
}

#[test]
fn timestamps_require_canonical_utc_milliseconds() {
    assert!(Timestamp::from_str("2026-01-01T00:00:00.000Z").is_ok());
    for timestamp in [
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:00.000+00:00",
        "2026-01-01t00:00:00.000z",
        "2026-02-30T00:00:00.000Z",
    ] {
        assert!(Timestamp::from_str(timestamp).is_err(), "{timestamp}");
    }
}

#[test]
fn strict_typed_json_rejects_unknown_fields() {
    let value = br#"{
        "capsule_digest":"sha256:e85afd86082b9a948caf2cda0c149041c0f7cb21d27b50968e10954e2017c175",
        "executor_capabilities_digest":"sha256:b2dc2e7c9dd93ba1fe6b83944a06ceeb1c3006f32cfed77ce5fd4eaa07de5614",
        "failure_digest":"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "format":"reproit.proof.v1",
        "perturbation_digest":"sha256:18c451c833345f2c63a0247deeda4c4a553e67c96acbf5340608358d3f2f72bc",
        "result":"TARGET_REPRODUCED",
        "run_index":0,
        "subject_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "trigger_digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222",
        "world_digest":"sha256:3333333333333333333333333333333333333333333333333333333333333333",
        "unknown":true
    }"#;
    assert!(canonical::parse_strict::<Proof>(value).is_err());
}

#[test]
fn typed_ids_reject_wrong_prefix_case_and_version() {
    assert!(CaptureId::from_str("CAP_01890f3e-7b1c-7cc0-8a1b-123456789abc").is_err());
    assert!(CaptureId::from_str("cap_01890F3E-7B1C-7CC0-8A1B-123456789ABC").is_err());
    assert!(CaptureId::from_str("cap_01890f3e-7b1c-4cc0-8a1b-123456789abc").is_err());
}

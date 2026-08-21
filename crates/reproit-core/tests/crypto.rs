use std::str::FromStr;

use aes_gcm::{
    Aes256Gcm, Key,
    aead::{Aead, KeyInit, Payload, array::Array},
};
use hkdf::Hkdf;
use reproit_core::{
    ErrorCode, canonical,
    crypto::{
        NonceRegistry, SecretKey, ciphertext_digest, decode_base64url, decode_base64url_bytes,
        decrypt_chunk, derive_chunk_key, derive_object_key, encrypt_chunk, failure_fingerprint,
        secret_key, verify_signed_value,
    },
    identity::{CaptureId, Digest},
    model::{
        CaptureBatchManifest, ChunkKeyContext, FailureGrouping, LogicalObjectRole,
        ObjectKeyContext, UploadEnvelope, Validate, validate_manifest_binding,
    },
};
use secrecy::ExposeSecret;
use serde_json::Value;
use sha2::Sha256;

const CRYPTO_VECTORS: &str = include_str!("../../../specs/v1/crypto-vectors.json");
const CORE_VECTORS: &str = include_str!("../../../specs/v1/vectors.json");
const PROTOCOL_VECTORS: &str = include_str!("../../../specs/v1/protocol-vectors.json");

#[test]
fn rfc_5869_vector_matches() {
    let vectors = parse(CRYPTO_VECTORS);
    let vector = &vectors["hkdf_rfc5869_case_1"];
    let ikm = bytes(&vector["ikm"]);
    let salt = bytes(&vector["salt"]);
    let info = bytes(&vector["info"]);
    let (prk, hkdf) = Hkdf::<Sha256>::extract(Some(&salt), &ikm);
    assert_eq!(hex::encode(prk), text(&vector["prk"]));
    let mut output = vec![0_u8; usize::try_from(vector["length"].as_u64().unwrap()).unwrap()];
    hkdf.expand(&info, &mut output)
        .expect("the vector length must be valid");
    assert_eq!(hex::encode(output), text(&vector["okm"]));
}

#[test]
fn nist_aes_256_gcm_vector_matches() {
    let vectors = parse(CRYPTO_VECTORS);
    let vector = &vectors["aes_256_gcm_nist_zero_vector"];
    let key: [u8; 32] = bytes(&vector["key"]).try_into().unwrap();
    let nonce: [u8; 12] = bytes(&vector["nonce"]).try_into().unwrap();
    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(key));
    let encrypted = cipher
        .encrypt(
            &Array(nonce),
            Payload {
                msg: &bytes(&vector["plaintext"]),
                aad: &bytes(&vector["aad"]),
            },
        )
        .expect("the standard vector must encrypt");
    let expected = format!("{}{}", text(&vector["ciphertext"]), text(&vector["tag"]));
    assert_eq!(hex::encode(encrypted), expected);
}

#[test]
fn product_key_and_chunk_vector_matches() {
    let vectors = parse(CRYPTO_VECTORS);
    let vector = &vectors["reproit_chunk_vector"];
    let capture_id = CaptureId::from_str(text(&vector["object_context"]["capture_id"]))
        .expect("the capture ID must be valid");
    let object_context: ObjectKeyContext = decode(&vector["object_context"]);
    let chunk_context: ChunkKeyContext = decode(&vector["chunk_context"]);
    let occurrence_key: [u8; 32] = bytes(&vector["occurrence_data_key"]).try_into().unwrap();
    let object_key = derive_object_key(&secret_key(occurrence_key), capture_id, &object_context)
        .expect("the object key must derive");
    assert_eq!(
        hex::encode(object_key.expose_secret()),
        text(&vector["object_key"])
    );
    let chunk_key =
        derive_chunk_key(&object_key, &chunk_context).expect("the chunk key must derive");
    assert_eq!(
        hex::encode(chunk_key.expose_secret()),
        text(&vector["chunk_key"])
    );

    let nonce: [u8; 12] = bytes(&vector["nonce"]).try_into().unwrap();
    let plaintext = bytes(&vector["plaintext"]);
    let stored = encrypt_chunk(&chunk_key, nonce, &plaintext, &chunk_context)
        .expect("the product vector must encrypt");
    assert_eq!(hex::encode(&stored), text(&vector["stored_bytes"]));
    assert_eq!(
        ciphertext_digest(&stored).to_string(),
        text(&vector["stored_digest"])
    );
    assert_eq!(
        decrypt_chunk(&chunk_key, &stored, &chunk_context)
            .expect("the product vector must decrypt"),
        plaintext
    );
}

#[test]
fn cryptographic_context_mutations_fail() {
    let vectors = parse(CRYPTO_VECTORS);
    let vector = &vectors["reproit_chunk_vector"];
    let key = secret_key(bytes(&vector["chunk_key"]).try_into().unwrap());
    let context: ChunkKeyContext = decode(&vector["chunk_context"]);
    let mut stored = bytes(&vector["stored_bytes"]);
    stored[12] ^= 1;
    assert_authentication_error(decrypt_chunk(&key, &stored, &context));

    let mut changed_context = vector["chunk_context"].clone();
    changed_context["plain_size"] = Value::from(23);
    let changed_context: ChunkKeyContext = decode(&changed_context);
    let stored = bytes(&vector["stored_bytes"]);
    assert_authentication_error(decrypt_chunk(&key, &stored, &changed_context));

    let final_index = stored.len() - 1;
    let mut changed_tag = stored;
    changed_tag[final_index] ^= 1;
    assert_authentication_error(decrypt_chunk(&key, &changed_tag, &context));
}

#[test]
fn nonce_registry_rejects_reuse() {
    let mut registry = NonceRegistry::default();
    registry
        .register([7_u8; 12])
        .expect("the first nonce must register");
    let error = registry
        .register([7_u8; 12])
        .expect_err("the second nonce must fail");
    assert_eq!(error.code, ErrorCode::NonceReuse);
}

#[test]
fn clean_download_decrypts_manifest_from_signed_inputs() {
    let vectors = parse(CRYPTO_VECTORS);
    let core = parse(CORE_VECTORS);
    let protocol = parse(PROTOCOL_VECTORS);
    let vector = &vectors["clean_download_manifest"];
    assert_eq!(
        vector["signed_envelope"],
        protocol["positive"]["upload_envelope"]["value"]
    );

    let envelope: UploadEnvelope = decode(&vector["signed_envelope"]);
    envelope.validate().expect("the envelope must be valid");
    let verification_key = decode_base64url::<32>(text(&vector["verification_key"]))
        .expect("the verification key must decode");
    verify_signed_value(&vector["signed_envelope"], &verification_key)
        .expect("the envelope signature must verify");

    let occurrence_key = unwrap_conformance_key(&envelope, &vector["key_provider_fixture"]);
    let stored = bytes(&vector["downloaded_manifest_ciphertext"]);
    assert_eq!(
        u64::try_from(stored.len()).unwrap(),
        envelope.manifest_object.cipher_size
    );
    assert_eq!(
        ciphertext_digest(&stored),
        envelope.manifest_object.cipher_digest
    );
    assert_eq!(
        reproit_core::crypto::encode_base64url(&stored[..12]),
        envelope.manifest_object.nonce
    );

    let object_context = envelope.manifest_object_context();
    assert_eq!(object_context.role, LogicalObjectRole::CaptureBatchManifest);
    let object_key = derive_object_key(&occurrence_key, envelope.capture_id, &object_context)
        .expect("the manifest object key must derive");
    let chunk_context = envelope
        .manifest_chunk_context()
        .expect("the manifest chunk context must derive");
    assert_eq!(chunk_context.chunk_index, 0);
    assert_eq!(chunk_context.chunk_count, 1);
    assert_eq!(
        chunk_context.plain_size,
        envelope.manifest_object.cipher_size - 28
    );
    let chunk_key =
        derive_chunk_key(&object_key, &chunk_context).expect("the manifest chunk key must derive");
    let plaintext = decrypt_chunk(&chunk_key, &stored, &chunk_context)
        .expect("the downloaded manifest must decrypt");
    let manifest: CaptureBatchManifest =
        canonical::parse_strict(&plaintext).expect("the downloaded manifest must decode strictly");
    validate_manifest_binding(
        &manifest,
        &envelope.manifest_object,
        envelope.replay_capsule_digest,
    )
    .expect("the manifest object ID must be separate from payload IDs");
    assert_eq!(
        canonical::digest(&manifest).unwrap().to_string(),
        text(&vector["expected_manifest_canonical_sha256"])
    );
    let expected: CaptureBatchManifest = decode(&core["capture_batch_manifest"]["value"]);
    assert_eq!(manifest, expected);
}

#[test]
fn manifest_context_and_object_id_mutations_fail() {
    let vectors = parse(CRYPTO_VECTORS);
    let vector = &vectors["clean_download_manifest"];
    let envelope: UploadEnvelope = decode(&vector["signed_envelope"]);
    let occurrence_key = unwrap_conformance_key(&envelope, &vector["key_provider_fixture"]);
    let stored = bytes(&vector["downloaded_manifest_ciphertext"]);

    let mut wrong_object_context = envelope.manifest_object_context();
    wrong_object_context.role = LogicalObjectRole::ReplayCapsuleManifest;
    let wrong_object_key =
        derive_object_key(&occurrence_key, envelope.capture_id, &wrong_object_context).unwrap();
    let chunk_context = envelope.manifest_chunk_context().unwrap();
    let wrong_chunk_key = derive_chunk_key(&wrong_object_key, &chunk_context).unwrap();
    assert_authentication_error(decrypt_chunk(&wrong_chunk_key, &stored, &chunk_context));

    for (chunk_count, chunk_index, plain_size) in [
        (2, 0, chunk_context.plain_size),
        (2, 1, chunk_context.plain_size),
        (1, 0, chunk_context.plain_size - 1),
    ] {
        let mut changed = chunk_context.clone();
        changed.chunk_count = chunk_count;
        changed.chunk_index = chunk_index;
        changed.plain_size = plain_size;
        let key = derive_chunk_key(
            &derive_object_key(
                &occurrence_key,
                envelope.capture_id,
                &envelope.manifest_object_context(),
            )
            .unwrap(),
            &changed,
        )
        .unwrap();
        assert_authentication_error(decrypt_chunk(&key, &stored, &changed));
    }

    let plaintext = decrypt_manifest(&envelope, &occurrence_key, &stored);
    let mut collision: CaptureBatchManifest = canonical::parse_strict(&plaintext).unwrap();
    collision.objects.last_mut().unwrap().descriptor.object_id = envelope.manifest_object.object_id;
    let error = validate_manifest_binding(
        &collision,
        &envelope.manifest_object,
        envelope.replay_capsule_digest,
    )
    .expect_err("a manifest object ID collision must fail");
    assert_eq!(error.code, ErrorCode::SchemaInvalid);

    let manifest: CaptureBatchManifest = canonical::parse_strict(&plaintext).unwrap();
    let error = validate_manifest_binding(
        &manifest,
        &envelope.manifest_object,
        Digest::of(b"different capsule"),
    )
    .expect_err("a safe-envelope capsule digest mismatch must fail");
    assert_eq!(error.code, ErrorCode::SchemaInvalid);
}

#[test]
fn signatures_and_grouping_vector_match() {
    let vectors = parse(PROTOCOL_VECTORS);
    for (name, key_id) in [
        ("deployment", "customer-deployment-test"),
        ("support_registry", "reproit-release-test"),
        ("upload_envelope", "customer-admission-test"),
    ] {
        let key = decode_base64url::<32>(text(&vectors["verification_keys"][key_id]))
            .expect("the verification key must decode");
        verify_signed_value(&vectors["positive"][name]["value"], &key)
            .unwrap_or_else(|error| panic!("{name} signature failed: {error:?}"));
    }

    let grouping_key = secret_key(
        decode_base64url::<32>(text(
            &vectors["grouping_vector"]["organization_grouping_key"],
        ))
        .expect("the grouping key must decode"),
    );
    let grouping: FailureGrouping = decode(&vectors["positive"]["failure_grouping"]["value"]);
    let fingerprint =
        failure_fingerprint(&grouping_key, &grouping).expect("the fingerprint must derive");
    assert_eq!(
        fingerprint,
        text(&vectors["grouping_vector"]["fingerprint"])
    );
}

#[test]
fn noncanonical_base64url_fails() {
    for value in ["AA==", "A+", "A/", "AB"] {
        assert!(decode_base64url::<1>(value).is_err(), "{value} must fail");
    }
    assert_eq!(decode_base64url::<1>("AA").unwrap(), [0]);
}

fn unwrap_conformance_key(envelope: &UploadEnvelope, fixture: &Value) -> SecretKey {
    let context = &fixture["wrap_context"];
    assert_eq!(context["algorithm"], envelope.wrapped_key.algorithm);
    assert_eq!(context["capture_id"], envelope.capture_id.to_string());
    assert_eq!(context["cipher_suite"], envelope.cipher_suite);
    assert_eq!(
        context["context_version"],
        envelope.wrapped_key.context_version
    );
    assert_eq!(context["key_reference"], envelope.wrapped_key.key_reference);
    assert_eq!(
        context["organization_id"],
        envelope.organization_id.to_string()
    );
    assert_eq!(context["project_id"], envelope.project_id.to_string());
    assert_eq!(context["provider_id"], envelope.wrapped_key.provider_id);
    assert_eq!(context["service_id"], envelope.service_id.to_string());

    let provider_key: [u8; 32] = bytes(&fixture["provider_key"]).try_into().unwrap();
    let wrapped = decode_base64url_bytes(&envelope.wrapped_key.wrapped_bytes).unwrap();
    let (nonce, ciphertext) = wrapped.split_at(12);
    let nonce: [u8; 12] = nonce.try_into().unwrap();
    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(provider_key));
    let plaintext = cipher
        .decrypt(
            &Array(nonce),
            Payload {
                msg: ciphertext,
                aad: &canonical::canonical_bytes(context).unwrap(),
            },
        )
        .expect("the conformance provider must unwrap the occurrence key");
    secret_key(
        plaintext
            .try_into()
            .expect("the occurrence key must be 32 bytes"),
    )
}

fn decrypt_manifest(
    envelope: &UploadEnvelope,
    occurrence_key: &SecretKey,
    stored: &[u8],
) -> Vec<u8> {
    let object_key = derive_object_key(
        occurrence_key,
        envelope.capture_id,
        &envelope.manifest_object_context(),
    )
    .unwrap();
    let context = envelope.manifest_chunk_context().unwrap();
    let chunk_key = derive_chunk_key(&object_key, &context).unwrap();
    decrypt_chunk(&chunk_key, stored, &context).unwrap()
}

fn assert_authentication_error(result: Result<Vec<u8>, reproit_core::Error>) {
    assert_eq!(
        result.unwrap_err().code,
        ErrorCode::DecryptionAuthentication
    );
}

fn parse(value: &str) -> Value {
    serde_json::from_str(value).expect("the checked-in JSON must parse")
}

fn decode<T>(value: &Value) -> T
where
    T: for<'de> serde::Deserialize<'de>,
{
    reproit_core::canonical::parse_strict(
        &serde_json::to_vec(value).expect("the vector must serialize"),
    )
    .expect("the vector must decode")
}

fn bytes(value: &Value) -> Vec<u8> {
    hex::decode(text(value)).expect("the vector must contain hexadecimal bytes")
}

fn text(value: &Value) -> &str {
    value.as_str().expect("the vector value must be a string")
}

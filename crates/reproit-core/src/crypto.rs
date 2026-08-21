use std::collections::{BTreeMap, BTreeSet};

use aes_gcm::{
    Aes256Gcm, Key,
    aead::{Aead, KeyInit, Payload, array::Array},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit as HmacKeyInit, Mac};
use secrecy::{ExposeSecret, SecretBox};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::{
    Error, canonical,
    error::ErrorCode,
    identity::{CaptureId, Digest, ObjectId},
    model::{
        Candidate, CandidateStagingEnvelope, CandidateStagingIdentity, ChunkKeyContext,
        ChunkKeyContextFormat, EncryptedObject, FailureGrouping, LogicalObjectRole,
        ManagedCandidateCiphertextIdentity, ManagedCandidateManifest, ObjectKeyContext,
        ObjectKeyContextFormat, ProcessingMode, UploadEnvelope, Validate,
    },
};

pub type SecretKey = SecretBox<[u8; 32]>;

#[derive(Default)]
pub struct NonceRegistry {
    used: BTreeSet<[u8; 12]>,
}

impl NonceRegistry {
    pub fn register(&mut self, nonce: [u8; 12]) -> Result<(), Error> {
        if self.used.insert(nonce) {
            return Ok(());
        }
        Err(Error::new(
            ErrorCode::NonceReuse,
            "An occurrence cannot reuse an encryption nonce.",
        ))
    }
}

pub fn secret_key(bytes: [u8; 32]) -> SecretKey {
    SecretBox::new(Box::new(bytes))
}

pub fn derive_object_key(
    occurrence_key: &SecretKey,
    capture_id: CaptureId,
    object_context: &ObjectKeyContext,
) -> Result<SecretKey, Error> {
    object_context.validate()?;
    if capture_id != object_context.capture_id {
        return Err(Error::schema_invalid());
    }
    let context = canonical::canonical_bytes(object_context)?;
    let (_, hkdf) = Hkdf::<Sha256>::extract(
        Some(&capture_id.uuid_bytes()),
        occurrence_key.expose_secret(),
    );
    let mut output = [0_u8; 32];
    hkdf.expand(&context, &mut output)
        .map_err(|_| Error::schema_invalid())?;
    Ok(secret_key(output))
}

pub fn derive_chunk_key(
    object_key: &SecretKey,
    chunk_context: &ChunkKeyContext,
) -> Result<SecretKey, Error> {
    chunk_context.validate()?;
    let context = canonical::canonical_bytes(chunk_context)?;
    let hkdf = Hkdf::<Sha256>::from_prk(object_key.expose_secret())
        .map_err(|_| Error::schema_invalid())?;
    let mut output = [0_u8; 32];
    hkdf.expand(&context, &mut output)
        .map_err(|_| Error::schema_invalid())?;
    Ok(secret_key(output))
}

pub fn encrypt_chunk(
    chunk_key: &SecretKey,
    nonce: [u8; 12],
    plaintext: &[u8],
    chunk_context: &ChunkKeyContext,
) -> Result<Vec<u8>, Error> {
    chunk_context.validate()?;
    if plaintext.len() > 8 * 1024 * 1024
        || chunk_context.plain_size != u64::try_from(plaintext.len()).unwrap_or(u64::MAX)
    {
        return Err(Error::schema_invalid());
    }
    let aad = canonical::canonical_bytes(chunk_context)?;
    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*chunk_key.expose_secret()));
    let nonce_array = Array(nonce);
    let encrypted = cipher
        .encrypt(
            &nonce_array,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| decryption_error())?;
    let mut stored = Vec::with_capacity(12 + encrypted.len());
    stored.extend_from_slice(&nonce);
    stored.extend_from_slice(&encrypted);
    Ok(stored)
}

pub fn decrypt_chunk(
    chunk_key: &SecretKey,
    stored: &[u8],
    chunk_context: &ChunkKeyContext,
) -> Result<Vec<u8>, Error> {
    chunk_context.validate()?;
    if !(28..=(8 * 1024 * 1024 + 28)).contains(&stored.len()) {
        return Err(decryption_error());
    }
    let expected_stored_size = usize::try_from(chunk_context.plain_size)
        .ok()
        .and_then(|size| size.checked_add(28));
    if expected_stored_size != Some(stored.len()) {
        return Err(decryption_error());
    }
    let (nonce, ciphertext_and_tag) = stored.split_at(12);
    let nonce: [u8; 12] = nonce.try_into().map_err(|_| decryption_error())?;
    let aad = canonical::canonical_bytes(chunk_context)?;
    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*chunk_key.expose_secret()));
    cipher
        .decrypt(
            &Array(nonce),
            Payload {
                msg: ciphertext_and_tag,
                aad: &aad,
            },
        )
        .map_err(|_| decryption_error())
}

pub fn seal_authenticated_record(
    key: &SecretKey,
    nonce: [u8; 12],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, Error> {
    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key.expose_secret()));
    let encrypted = cipher
        .encrypt(
            &Array(nonce),
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .map_err(|_| decryption_error())?;
    let mut stored = Vec::with_capacity(12 + encrypted.len());
    stored.extend_from_slice(&nonce);
    stored.extend_from_slice(&encrypted);
    Ok(stored)
}

pub fn open_authenticated_record(
    key: &SecretKey,
    stored: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, Error> {
    if stored.len() < 28 {
        return Err(decryption_error());
    }
    let (nonce, ciphertext_and_tag) = stored.split_at(12);
    let nonce: [u8; 12] = nonce.try_into().map_err(|_| decryption_error())?;
    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key.expose_secret()));
    cipher
        .decrypt(
            &Array(nonce),
            Payload {
                msg: ciphertext_and_tag,
                aad: associated_data,
            },
        )
        .map_err(|_| decryption_error())
}

pub fn seal_candidate_staging(
    key: &SecretKey,
    nonce: [u8; 12],
    candidate: &Candidate,
    identity: CandidateStagingIdentity,
) -> Result<CandidateStagingEnvelope, Error> {
    identity.matches_candidate(candidate)?;
    let plaintext = canonical::canonical_bytes(candidate)?;
    if plaintext.len() > 1_048_576 {
        return Err(Error::new(
            ErrorCode::RuntimeQuota,
            "The complete candidate exceeds the staging limit.",
        ));
    }
    let associated_data = canonical::canonical_bytes(&identity)?;
    let stored = seal_authenticated_record(key, nonce, &plaintext, &associated_data)?;
    CandidateStagingEnvelope::new(identity, &stored)
}

pub fn open_candidate_staging(
    key: &SecretKey,
    envelope: &CandidateStagingEnvelope,
) -> Result<Candidate, Error> {
    envelope.validate()?;
    let plaintext = open_authenticated_record(key, &envelope.stored_bytes()?, &envelope.aad()?)?;
    if plaintext.len() > 1_048_576 {
        return Err(Error::new(
            ErrorCode::RuntimeQuota,
            "The complete candidate exceeds the staging limit.",
        ));
    }
    let candidate: Candidate = canonical::parse_strict(&plaintext)?;
    candidate.validate()?;
    envelope.identity.matches_candidate(&candidate)?;
    Ok(candidate)
}

pub fn validate_ciphertext_closure(
    envelope: &UploadEnvelope,
    ciphertext: &BTreeMap<Digest, Vec<u8>>,
) -> Result<(), Error> {
    envelope.validate()?;
    let mut expected = BTreeMap::from([(
        envelope.manifest_object.cipher_digest,
        (
            envelope.manifest_object.cipher_size,
            envelope.manifest_object.nonce.as_str(),
        ),
    )]);
    for object in &envelope.objects {
        if expected
            .insert(
                object.cipher_digest,
                (object.cipher_size, object.nonce.as_str()),
            )
            .is_some()
        {
            return Err(Error::schema_invalid());
        }
    }
    if expected.len() != ciphertext.len() {
        return Err(Error::object_digest_mismatch());
    }
    for (digest, (size, nonce)) in expected {
        let stored = ciphertext
            .get(&digest)
            .ok_or_else(Error::object_digest_mismatch)?;
        if Digest::of(stored) != digest
            || u64::try_from(stored.len()).map_err(|_| Error::schema_invalid())? != size
            || stored.get(..12) != Some(&decode_base64url::<12>(nonce)?)
        {
            return Err(Error::object_digest_mismatch());
        }
    }
    Ok(())
}

pub fn open_managed_candidate<F>(
    candidate_key: &SecretKey,
    identity: &ManagedCandidateCiphertextIdentity,
    ciphertext: &BTreeMap<Digest, Vec<u8>>,
    mut consume_chunk: F,
) -> Result<ManagedCandidateManifest, Error>
where
    F: FnMut(&crate::model::LogicalObject, u32, &[u8]) -> Result<(), Error>,
{
    identity.validate()?;
    validate_managed_ciphertext(identity, ciphertext)?;
    let manifest_context = managed_object_context(
        identity,
        identity.manifest_object.object_id,
        LogicalObjectRole::CaptureBatchManifest,
    );
    let manifest_plain_size = identity
        .manifest_object
        .cipher_size
        .checked_sub(28)
        .ok_or_else(Error::schema_invalid)?;
    let manifest_chunk_context = ChunkKeyContext {
        chunk_count: 1,
        chunk_index: 0,
        format: ChunkKeyContextFormat::V1,
        object_context_digest: canonical::digest(&manifest_context)?,
        plain_size: manifest_plain_size,
    };
    let manifest_object_key =
        derive_object_key(candidate_key, identity.capture_id, &manifest_context)?;
    let manifest_chunk_key = derive_chunk_key(&manifest_object_key, &manifest_chunk_context)?;
    let manifest_stored = ciphertext
        .get(&identity.manifest_object.cipher_digest)
        .ok_or_else(Error::object_digest_mismatch)?;
    let manifest_bytes = decrypt_chunk(
        &manifest_chunk_key,
        manifest_stored,
        &manifest_chunk_context,
    )?;
    let manifest: ManagedCandidateManifest = canonical::parse_strict(&manifest_bytes)?;
    validate_managed_manifest_binding(&manifest, identity)?;

    for encrypted in &identity.objects {
        open_managed_object(
            candidate_key,
            identity,
            encrypted,
            ciphertext,
            &mut consume_chunk,
        )?;
    }
    Ok(manifest)
}

fn validate_managed_ciphertext(
    identity: &ManagedCandidateCiphertextIdentity,
    ciphertext: &BTreeMap<Digest, Vec<u8>>,
) -> Result<(), Error> {
    let mut expected = BTreeMap::from([(
        identity.manifest_object.cipher_digest,
        (
            identity.manifest_object.cipher_size,
            identity.manifest_object.nonce.as_str(),
        ),
    )]);
    for object in &identity.objects {
        for chunk in &object.chunks {
            if expected
                .insert(
                    chunk.cipher_digest,
                    (chunk.cipher_size, chunk.nonce.as_str()),
                )
                .is_some()
            {
                return Err(Error::schema_invalid());
            }
        }
    }
    if expected.len() != ciphertext.len() {
        return Err(Error::object_digest_mismatch());
    }
    for (digest, (size, nonce)) in expected {
        let stored = ciphertext
            .get(&digest)
            .ok_or_else(Error::object_digest_mismatch)?;
        if Digest::of(stored) != digest
            || u64::try_from(stored.len()).map_err(|_| Error::schema_invalid())? != size
            || stored.get(..12) != Some(&decode_base64url::<12>(nonce)?)
        {
            return Err(Error::object_digest_mismatch());
        }
    }
    Ok(())
}

fn validate_managed_manifest_binding(
    manifest: &ManagedCandidateManifest,
    identity: &ManagedCandidateCiphertextIdentity,
) -> Result<(), Error> {
    manifest.validate()?;
    let expected_descriptors = identity
        .objects
        .iter()
        .map(|object| &object.descriptor)
        .collect::<Vec<_>>();
    if manifest.candidate_identity_digest != identity.candidate_identity_digest
        || manifest.candidate_key_reference != identity.candidate_key_reference
        || manifest.cipher_suite != identity.cipher_suite
        || manifest.candidate_identity.capture_id != identity.capture_id
        || manifest.candidate_identity.organization_id != identity.organization_id
        || manifest.candidate_identity.processing_mode != identity.processing_mode
        || manifest.candidate_identity.project_id != identity.project_id
        || manifest.candidate_identity.required_capabilities != identity.required_capabilities
        || manifest.candidate_identity.service_id != identity.service_id
        || manifest.candidate_identity.objects.len() != expected_descriptors.len()
        || !manifest
            .candidate_identity
            .objects
            .iter()
            .zip(expected_descriptors)
            .all(|(plain, encrypted)| plain == encrypted)
    {
        return Err(Error::object_digest_mismatch());
    }
    Ok(())
}

fn open_managed_object<F>(
    candidate_key: &SecretKey,
    identity: &ManagedCandidateCiphertextIdentity,
    encrypted: &EncryptedObject,
    ciphertext: &BTreeMap<Digest, Vec<u8>>,
    consume_chunk: &mut F,
) -> Result<(), Error>
where
    F: FnMut(&crate::model::LogicalObject, u32, &[u8]) -> Result<(), Error>,
{
    let object_context = managed_object_context(
        identity,
        encrypted.descriptor.object_id,
        encrypted.descriptor.role,
    );
    let object_key = derive_object_key(candidate_key, identity.capture_id, &object_context)?;
    let object_context_digest = canonical::digest(&object_context)?;
    let chunk_count = u32::try_from(encrypted.chunks.len()).map_err(|_| Error::schema_invalid())?;
    let mut total_plaintext_bytes = 0_u64;
    let mut plain_hasher = Sha256::new();
    for chunk in &encrypted.chunks {
        let plain_size = chunk
            .cipher_size
            .checked_sub(28)
            .ok_or_else(Error::schema_invalid)?;
        let chunk_context = ChunkKeyContext {
            chunk_count,
            chunk_index: chunk.index,
            format: ChunkKeyContextFormat::V1,
            object_context_digest,
            plain_size,
        };
        let chunk_key = derive_chunk_key(&object_key, &chunk_context)?;
        let stored = ciphertext
            .get(&chunk.cipher_digest)
            .ok_or_else(Error::object_digest_mismatch)?;
        let plaintext = decrypt_chunk(&chunk_key, stored, &chunk_context)?;
        total_plaintext_bytes = total_plaintext_bytes
            .checked_add(u64::try_from(plaintext.len()).map_err(|_| Error::schema_invalid())?)
            .ok_or_else(Error::schema_invalid)?;
        if total_plaintext_bytes > encrypted.descriptor.plain_size {
            return Err(Error::object_digest_mismatch());
        }
        sha2::Digest::update(&mut plain_hasher, &plaintext);
        consume_chunk(&encrypted.descriptor, chunk.index, &plaintext)?;
    }
    if total_plaintext_bytes != encrypted.descriptor.plain_size
        || Digest::from_bytes(sha2::Digest::finalize(plain_hasher).into())
            != encrypted.descriptor.plain_digest
    {
        return Err(Error::object_digest_mismatch());
    }
    Ok(())
}

fn managed_object_context(
    identity: &ManagedCandidateCiphertextIdentity,
    object_id: ObjectId,
    role: LogicalObjectRole,
) -> ObjectKeyContext {
    ObjectKeyContext {
        capture_batch_format: "reproit.capture-batch.v1".to_owned(),
        capture_id: identity.capture_id,
        format: ObjectKeyContextFormat::V1,
        object_id,
        organization_id: identity.organization_id,
        processing_mode: ProcessingMode::Managed,
        project_id: identity.project_id,
        role,
        service_id: identity.service_id,
    }
}

pub fn ciphertext_digest(stored: &[u8]) -> Digest {
    Digest::of(stored)
}

pub fn failure_fingerprint(
    grouping_key: &SecretKey,
    grouping: &FailureGrouping,
) -> Result<String, Error> {
    let bytes = canonical::canonical_bytes(grouping)?;
    let mut mac = <Hmac<Sha256> as HmacKeyInit>::new_from_slice(grouping_key.expose_secret())
        .map_err(|_| Error::schema_invalid())?;
    mac.update(&bytes);
    Ok(format!(
        "hmac-sha256:{}",
        hex::encode(mac.finalize().into_bytes())
    ))
}

pub fn verify_signed_value(value: &Value, public_key: &[u8; 32]) -> Result<(), Error> {
    let mut unsigned = value.clone();
    let signature_text = unsigned
        .as_object()
        .and_then(|object| object.get("signature"))
        .and_then(Value::as_str)
        .ok_or_else(Error::schema_invalid)?
        .to_owned();
    unsigned["signature"] = Value::String(String::new());
    let signature_bytes = decode_base64url::<64>(&signature_text)?;
    let signature = Signature::from_bytes(&signature_bytes);
    let verifying_key = VerifyingKey::from_bytes(public_key).map_err(|_| attestation_error())?;
    verifying_key
        .verify_strict(&canonical::canonical_bytes(&unsigned)?, &signature)
        .map_err(|_| attestation_error())
}

pub fn sign_bytes(bytes: &[u8], signing_key: &SecretKey) -> String {
    let key = SigningKey::from_bytes(signing_key.expose_secret());
    encode_base64url(&key.sign(bytes).to_bytes())
}

pub fn verification_key(signing_key: &SecretKey) -> [u8; 32] {
    SigningKey::from_bytes(signing_key.expose_secret())
        .verifying_key()
        .to_bytes()
}

pub fn decode_base64url<const N: usize>(value: &str) -> Result<[u8; N], Error> {
    decode_base64url_bytes(value)?
        .try_into()
        .map_err(|_| Error::schema_invalid())
}

pub fn decode_base64url_bytes(value: &str) -> Result<Vec<u8>, Error> {
    if value.contains('=') || !value.bytes().all(is_base64url_byte) {
        return Err(Error::schema_invalid());
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| Error::schema_invalid())?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(Error::schema_invalid());
    }
    Ok(bytes)
}

pub fn encode_base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn is_base64url_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

fn decryption_error() -> Error {
    Error::new(
        ErrorCode::DecryptionAuthentication,
        "Ciphertext authentication failed.",
    )
}

fn attestation_error() -> Error {
    Error::new(
        ErrorCode::AttestationScope,
        "The signature is invalid for this attestation.",
    )
}

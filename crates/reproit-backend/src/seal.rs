use std::collections::{BTreeMap, BTreeSet};

use reproit_core::{
    Error, ErrorCode, canonical,
    crypto::{
        NonceRegistry, SecretKey, ciphertext_digest, decode_base64url, decrypt_chunk,
        derive_chunk_key, derive_object_key, encode_base64url, encrypt_chunk, failure_fingerprint,
        verify_signed_value,
    },
    identity::{CaptureId, Digest, ObjectId, OrganizationId, ProjectId, ServiceId, Timestamp},
    model::{
        AdmissionAttestation, CaptureBatchFormat, CaptureBatchIdentity, CaptureBatchIdentityFormat,
        CaptureBatchManifest, ChunkKeyContext, ChunkKeyContextFormat, EncryptedChunk,
        EncryptedObject, LogicalObject, LogicalObjectRole, ManifestUploadObject, ObjectKeyContext,
        ObjectKeyContextFormat, UploadEnvelope, UploadEnvelopeFormat, UploadObject, Validate,
        WrappedKey, validate_manifest_binding,
    },
    proof,
};

use crate::{AdmissionInput, AdmittedCandidate};

const CHUNK_BYTES: usize = 8 * 1024 * 1024;

pub trait NonceSource {
    fn next_nonce(&mut self) -> Result<[u8; 12], Error>;
}

pub trait AdmissionSigner {
    fn signer_key_id(&self) -> &str;
    fn sign(&self, canonical_unsigned_envelope: &[u8]) -> Result<String, Error>;
}

pub struct SealingIds {
    pub capsule_object_id: ObjectId,
    pub manifest_object_id: ObjectId,
    pub proof_object_ids: [ObjectId; 3],
}

pub struct UploadMetadata {
    pub capture_id: CaptureId,
    pub organization_id: OrganizationId,
    pub project_id: ProjectId,
    pub repository_id: String,
    pub service_id: ServiceId,
    pub service_path: String,
    pub signature_time: Timestamp,
    pub source_revision: String,
    pub wrapped_key: WrappedKey,
}

pub struct SealedUpload {
    pub ciphertext: BTreeMap<Digest, Vec<u8>>,
    pub envelope: UploadEnvelope,
    pub manifest: CaptureBatchManifest,
}

pub struct OpenedCapture {
    pub manifest: CaptureBatchManifest,
    pub objects: BTreeMap<ObjectId, Vec<u8>>,
}

pub fn open_capture(
    envelope: &UploadEnvelope,
    verification_key: &[u8; 32],
    occurrence_key: &SecretKey,
    ciphertext: &BTreeMap<Digest, Vec<u8>>,
) -> Result<OpenedCapture, Error> {
    validate_ciphertext_closure(envelope, ciphertext)?;
    let manifest_stored = &ciphertext[&envelope.manifest_object.cipher_digest];
    let manifest = open_manifest(envelope, verification_key, occurrence_key, manifest_stored)?;

    let mut objects = BTreeMap::new();
    for encrypted in &manifest.objects {
        let plaintext = decrypt_object(envelope, occurrence_key, encrypted, ciphertext)?;
        if objects
            .insert(encrypted.descriptor.object_id, plaintext)
            .is_some()
        {
            return Err(Error::schema_invalid());
        }
    }
    Ok(OpenedCapture { manifest, objects })
}

pub fn open_manifest(
    envelope: &UploadEnvelope,
    verification_key: &[u8; 32],
    occurrence_key: &SecretKey,
    manifest_stored: &[u8],
) -> Result<CaptureBatchManifest, Error> {
    envelope.validate()?;
    let value = serde_json::to_value(envelope).map_err(|_| Error::schema_invalid())?;
    verify_signed_value(&value, verification_key)?;
    validate_manifest_ciphertext(envelope, manifest_stored)?;
    let object_key = derive_object_key(
        occurrence_key,
        envelope.capture_id,
        &envelope.manifest_object_context(),
    )?;
    let chunk_context = envelope.manifest_chunk_context()?;
    let chunk_key = derive_chunk_key(&object_key, &chunk_context)?;
    let manifest_bytes = decrypt_chunk(&chunk_key, manifest_stored, &chunk_context)?;
    let manifest: CaptureBatchManifest = canonical::parse_strict(&manifest_bytes)?;
    validate_manifest_binding(
        &manifest,
        &envelope.manifest_object,
        envelope.replay_capsule_digest,
    )?;
    validate_envelope_manifest_binding(envelope, &manifest)?;
    validate_payload_uploads(envelope, &manifest)?;
    Ok(manifest)
}

pub fn open_capture_object(
    envelope: &UploadEnvelope,
    occurrence_key: &SecretKey,
    manifest: &CaptureBatchManifest,
    object_id: ObjectId,
    ciphertext: &BTreeMap<Digest, Vec<u8>>,
) -> Result<Vec<u8>, Error> {
    validate_envelope_manifest_binding(envelope, manifest)?;
    validate_payload_uploads(envelope, manifest)?;
    let encrypted = manifest
        .objects
        .iter()
        .find(|object| object.descriptor.object_id == object_id)
        .ok_or_else(Error::object_digest_mismatch)?;
    let expected = encrypted
        .chunks
        .iter()
        .map(|chunk| chunk.cipher_digest)
        .collect::<BTreeSet<_>>();
    if expected.len() != encrypted.chunks.len()
        || ciphertext.keys().copied().collect::<BTreeSet<_>>() != expected
    {
        return Err(Error::object_digest_mismatch());
    }
    decrypt_object(envelope, occurrence_key, encrypted, ciphertext)
}

pub struct SealRequest<'a> {
    pub admitted: &'a AdmittedCandidate,
    pub grouping_key: &'a SecretKey,
    pub ids: SealingIds,
    pub input: &'a AdmissionInput,
    pub metadata: UploadMetadata,
    pub occurrence_key: &'a SecretKey,
    pub signer: &'a dyn AdmissionSigner,
}

pub fn seal_upload(
    request: SealRequest<'_>,
    nonce_source: &mut impl NonceSource,
) -> Result<SealedUpload, Error> {
    validate_sealing_ids(&request)?;
    let mut nonce_registry = NonceRegistry::default();
    let mut material = encrypt_capture_objects(&request, nonce_source, &mut nonce_registry)?;
    let manifest = build_manifest(&request, material.encrypted_objects)?;
    let manifest_bytes = canonical::canonical_bytes(&manifest)?;
    let encrypted_manifest =
        encrypt_manifest(&request, &manifest_bytes, nonce_source, &mut nonce_registry)?;
    append_ciphertext(
        &encrypted_manifest,
        &mut material.ciphertext,
        &mut Vec::new(),
    )?;
    material
        .upload_objects
        .sort_by_key(|object| (object.cipher_digest, object.nonce.clone()));
    let manifest_upload = &encrypted_manifest.uploads[0];
    let manifest_object = ManifestUploadObject {
        cipher_digest: manifest_upload.cipher_digest,
        cipher_size: manifest_upload.cipher_size,
        nonce: manifest_upload.nonce.clone(),
        object_id: request.ids.manifest_object_id,
    };
    let envelope = build_envelope(request, &manifest, manifest_object, material.upload_objects)?;
    Ok(SealedUpload {
        ciphertext: material.ciphertext,
        envelope,
        manifest,
    })
}

struct CaptureMaterial {
    ciphertext: BTreeMap<Digest, Vec<u8>>,
    encrypted_objects: Vec<EncryptedObject>,
    upload_objects: Vec<UploadObject>,
}

fn encrypt_capture_objects(
    request: &SealRequest<'_>,
    nonce_source: &mut impl NonceSource,
    nonce_registry: &mut NonceRegistry,
) -> Result<CaptureMaterial, Error> {
    let mut plaintext = request.input.objects.all().clone();
    let mut descriptors = request.input.capsule.objects.clone();
    add_capsule(request, &mut plaintext, &mut descriptors)?;
    add_proofs(request, &mut plaintext, &mut descriptors)?;
    descriptors.sort_by_key(|descriptor| descriptor.object_id);
    let mut ciphertext = BTreeMap::new();
    let mut upload_objects = Vec::new();
    let mut encrypted_objects = Vec::with_capacity(descriptors.len());
    for descriptor in descriptors {
        let bytes = plaintext
            .get(&descriptor.object_id)
            .ok_or_else(world_not_closed)?;
        let encrypted = encrypt_object(request, descriptor, bytes, nonce_source, nonce_registry)?;
        append_ciphertext(&encrypted, &mut ciphertext, &mut upload_objects)?;
        encrypted_objects.push(encrypted.object);
    }
    encrypted_objects.sort_by_key(|object| object.descriptor.object_id);
    Ok(CaptureMaterial {
        ciphertext,
        encrypted_objects,
        upload_objects,
    })
}

fn build_manifest(
    request: &SealRequest<'_>,
    encrypted_objects: Vec<EncryptedObject>,
) -> Result<CaptureBatchManifest, Error> {
    let proof_digests = request
        .admitted
        .proofs
        .iter()
        .map(canonical::digest)
        .collect::<Result<Vec<_>, _>>()?;
    let manifest = CaptureBatchManifest {
        capture_id: request.metadata.capture_id,
        encryption_context_version: 1,
        format: CaptureBatchFormat::V1,
        objects: encrypted_objects,
        organization_id: request.metadata.organization_id,
        processing_mode: request.input.capsule.processing_mode,
        profile: "backend".to_owned(),
        profile_format: 1,
        project_id: request.metadata.project_id,
        proof_digests,
        replay_capsule_digest: request.admitted.capsule_digest,
        replay_capsule_object_id: request.ids.capsule_object_id,
        repository_id: request.metadata.repository_id.clone(),
        required_capabilities: request.input.capsule.required_capabilities.clone(),
        service_id: request.metadata.service_id,
        service_path: request.metadata.service_path.clone(),
        source_revision: request.metadata.source_revision.clone(),
    };
    proof::validate_capture_manifest(
        &manifest,
        request.admitted.capsule_digest,
        &request.admitted.proofs,
    )?;
    Ok(manifest)
}

fn encrypt_manifest(
    request: &SealRequest<'_>,
    manifest_bytes: &[u8],
    nonce_source: &mut impl NonceSource,
    nonce_registry: &mut NonceRegistry,
) -> Result<EncryptedMaterial, Error> {
    let manifest_descriptor = LogicalObject {
        media_type: "application/reproit-capture-batch+json".to_owned(),
        object_id: request.ids.manifest_object_id,
        plain_digest: Digest::of(manifest_bytes),
        plain_size: u64::try_from(manifest_bytes.len()).map_err(|_| upload_limit())?,
        role: LogicalObjectRole::CaptureBatchManifest,
    };
    let encrypted_manifest = encrypt_object(
        request,
        manifest_descriptor,
        manifest_bytes,
        nonce_source,
        nonce_registry,
    )?;
    if encrypted_manifest.uploads.len() != 1 {
        return Err(upload_limit());
    }
    Ok(encrypted_manifest)
}

fn build_envelope(
    request: SealRequest<'_>,
    manifest: &CaptureBatchManifest,
    manifest_object: ManifestUploadObject,
    upload_objects: Vec<UploadObject>,
) -> Result<UploadEnvelope, Error> {
    validate_manifest_binding(manifest, &manifest_object, manifest.replay_capsule_digest)?;
    let capture_identity = CaptureBatchIdentity {
        capture_id: request.metadata.capture_id,
        cipher_suite: "AES-256-GCM+HKDF-SHA-256".to_owned(),
        format: CaptureBatchIdentityFormat::V1,
        manifest_object: manifest_object.clone(),
        objects: upload_objects.clone(),
        processing_mode: manifest.processing_mode,
    };
    capture_identity.validate()?;
    let grouping = request.input.expected_failure.grouping()?;
    let (failure_summary, trigger_summary) = request
        .input
        .expected_failure
        .safe_summaries(manifest.processing_mode);
    let mut envelope = UploadEnvelope {
        admission: AdmissionAttestation {
            proof_digests: manifest.proof_digests.clone(),
            run_count: 3,
            signer_key_id: request.signer.signer_key_id().to_owned(),
        },
        capture_batch_digest: canonical::digest(&capture_identity)?,
        capture_id: request.metadata.capture_id,
        cipher_suite: "AES-256-GCM+HKDF-SHA-256".to_owned(),
        failure_fingerprint: failure_fingerprint(request.grouping_key, &grouping)?,
        failure_summary,
        format: UploadEnvelopeFormat::V1,
        manifest_object,
        objects: upload_objects,
        organization_id: request.metadata.organization_id,
        processing_mode: manifest.processing_mode,
        profile: "backend".to_owned(),
        profile_format: 1,
        project_id: request.metadata.project_id,
        replay_capsule_digest: manifest.replay_capsule_digest,
        required_capabilities: request.input.capsule.required_capabilities.clone(),
        service_id: request.metadata.service_id,
        signature: String::new(),
        signed_at: request.metadata.signature_time,
        source_revision: request.metadata.source_revision,
        trigger_summary,
        wrapped_key: request.metadata.wrapped_key,
    };
    let unsigned = canonical::canonical_bytes(&envelope)?;
    envelope.signature = request.signer.sign(&unsigned)?;
    envelope.validate()?;
    Ok(envelope)
}

struct EncryptedMaterial {
    object: EncryptedObject,
    stored: Vec<Vec<u8>>,
    uploads: Vec<UploadObject>,
}

fn encrypt_object(
    request: &SealRequest<'_>,
    descriptor: LogicalObject,
    bytes: &[u8],
    nonce_source: &mut impl NonceSource,
    nonce_registry: &mut NonceRegistry,
) -> Result<EncryptedMaterial, Error> {
    if descriptor.plain_digest != Digest::of(bytes)
        || descriptor.plain_size != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
    {
        return Err(Error::object_digest_mismatch());
    }
    let object_context = ObjectKeyContext {
        capture_batch_format: "reproit.capture-batch.v1".to_owned(),
        capture_id: request.metadata.capture_id,
        format: ObjectKeyContextFormat::V1,
        object_id: descriptor.object_id,
        organization_id: request.metadata.organization_id,
        processing_mode: request.input.capsule.processing_mode,
        project_id: request.metadata.project_id,
        role: descriptor.role,
        service_id: request.metadata.service_id,
    };
    let object_key = derive_object_key(
        request.occurrence_key,
        request.metadata.capture_id,
        &object_context,
    )?;
    let object_context_digest = canonical::digest(&object_context)?;
    let chunk_count = bytes.len().max(1).div_ceil(CHUNK_BYTES);
    if chunk_count > 32_767 {
        return Err(upload_limit());
    }
    let chunks = if bytes.is_empty() {
        vec![&[][..]]
    } else {
        bytes.chunks(CHUNK_BYTES).collect()
    };
    let mut encrypted_chunks = Vec::with_capacity(chunks.len());
    let mut stored_chunks = Vec::with_capacity(chunks.len());
    let mut uploads = Vec::with_capacity(chunks.len());
    for (chunk_index, plaintext) in chunks.iter().enumerate() {
        let nonce = nonce_source.next_nonce()?;
        nonce_registry.register(nonce)?;
        let context = ChunkKeyContext {
            chunk_count: u32::try_from(chunk_count).map_err(|_| upload_limit())?,
            chunk_index: u32::try_from(chunk_index).map_err(|_| upload_limit())?,
            format: ChunkKeyContextFormat::V1,
            object_context_digest,
            plain_size: u64::try_from(plaintext.len()).map_err(|_| upload_limit())?,
        };
        let chunk_key = derive_chunk_key(&object_key, &context)?;
        let stored = encrypt_chunk(&chunk_key, nonce, plaintext, &context)?;
        let cipher_digest = ciphertext_digest(&stored);
        let cipher_size = u64::try_from(stored.len()).map_err(|_| upload_limit())?;
        let nonce = encode_base64url(&nonce);
        encrypted_chunks.push(EncryptedChunk {
            cipher_digest,
            cipher_size,
            index: context.chunk_index,
            nonce: nonce.clone(),
        });
        uploads.push(UploadObject {
            cipher_digest,
            cipher_size,
            nonce,
        });
        stored_chunks.push(stored);
    }
    Ok(EncryptedMaterial {
        object: EncryptedObject {
            chunks: encrypted_chunks,
            descriptor,
        },
        stored: stored_chunks,
        uploads,
    })
}

fn append_ciphertext(
    encrypted: &EncryptedMaterial,
    ciphertext: &mut BTreeMap<Digest, Vec<u8>>,
    uploads: &mut Vec<UploadObject>,
) -> Result<(), Error> {
    for (upload, stored) in encrypted.uploads.iter().zip(&encrypted.stored) {
        if ciphertext
            .insert(upload.cipher_digest, stored.clone())
            .is_some()
        {
            return Err(Error::new(
                ErrorCode::NonceReuse,
                "A ciphertext digest was reused in one capture batch.",
            ));
        }
        uploads.push(upload.clone());
    }
    Ok(())
}

fn add_capsule(
    request: &SealRequest<'_>,
    plaintext: &mut BTreeMap<ObjectId, Vec<u8>>,
    descriptors: &mut Vec<LogicalObject>,
) -> Result<(), Error> {
    let bytes = canonical::canonical_bytes(&request.input.capsule)?;
    add_plain_object(
        plaintext,
        descriptors,
        LogicalObject {
            media_type: "application/reproit-replay-capsule+json".to_owned(),
            object_id: request.ids.capsule_object_id,
            plain_digest: request.admitted.capsule_digest,
            plain_size: u64::try_from(bytes.len()).map_err(|_| upload_limit())?,
            role: LogicalObjectRole::ReplayCapsuleManifest,
        },
        bytes,
    )
}

fn add_proofs(
    request: &SealRequest<'_>,
    plaintext: &mut BTreeMap<ObjectId, Vec<u8>>,
    descriptors: &mut Vec<LogicalObject>,
) -> Result<(), Error> {
    for (proof, object_id) in request
        .admitted
        .proofs
        .iter()
        .zip(request.ids.proof_object_ids)
    {
        let bytes = canonical::canonical_bytes(proof)?;
        add_plain_object(
            plaintext,
            descriptors,
            LogicalObject {
                media_type: "application/reproit-proof+json".to_owned(),
                object_id,
                plain_digest: canonical::digest(proof)?,
                plain_size: u64::try_from(bytes.len()).map_err(|_| upload_limit())?,
                role: LogicalObjectRole::AdmissionProof,
            },
            bytes,
        )?;
    }
    Ok(())
}

fn add_plain_object(
    plaintext: &mut BTreeMap<ObjectId, Vec<u8>>,
    descriptors: &mut Vec<LogicalObject>,
    descriptor: LogicalObject,
    bytes: Vec<u8>,
) -> Result<(), Error> {
    if plaintext.insert(descriptor.object_id, bytes).is_some()
        || descriptors
            .iter()
            .any(|existing| existing.object_id == descriptor.object_id)
    {
        return Err(Error::schema_invalid());
    }
    descriptors.push(descriptor);
    Ok(())
}

fn validate_manifest_ciphertext(
    envelope: &UploadEnvelope,
    manifest_stored: &[u8],
) -> Result<(), Error> {
    let expected_nonce = decode_base64url::<12>(&envelope.manifest_object.nonce)?;
    if Digest::of(manifest_stored) != envelope.manifest_object.cipher_digest
        || u64::try_from(manifest_stored.len()).map_err(|_| upload_limit())?
            != envelope.manifest_object.cipher_size
        || manifest_stored.get(..12) != Some(expected_nonce.as_slice())
    {
        return Err(Error::object_digest_mismatch());
    }
    Ok(())
}

fn validate_ciphertext_closure(
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
            || u64::try_from(stored.len()).map_err(|_| upload_limit())? != size
            || stored.get(..12) != Some(decode_base64url::<12>(nonce)?.as_slice())
        {
            return Err(Error::object_digest_mismatch());
        }
    }
    Ok(())
}

fn validate_envelope_manifest_binding(
    envelope: &UploadEnvelope,
    manifest: &CaptureBatchManifest,
) -> Result<(), Error> {
    if manifest.capture_id != envelope.capture_id
        || manifest.organization_id != envelope.organization_id
        || manifest.processing_mode != envelope.processing_mode
        || manifest.project_id != envelope.project_id
        || manifest.service_id != envelope.service_id
        || manifest.profile != envelope.profile
        || manifest.profile_format != envelope.profile_format
        || manifest.proof_digests != envelope.admission.proof_digests
        || manifest.replay_capsule_digest != envelope.replay_capsule_digest
        || manifest.required_capabilities != envelope.required_capabilities
        || manifest.source_revision != envelope.source_revision
    {
        return Err(Error::schema_invalid());
    }
    Ok(())
}

fn validate_payload_uploads(
    envelope: &UploadEnvelope,
    manifest: &CaptureBatchManifest,
) -> Result<(), Error> {
    let mut uploads = manifest
        .objects
        .iter()
        .flat_map(|object| &object.chunks)
        .map(|chunk| UploadObject {
            cipher_digest: chunk.cipher_digest,
            cipher_size: chunk.cipher_size,
            nonce: chunk.nonce.clone(),
        })
        .collect::<Vec<_>>();
    uploads.sort_by_key(|object| (object.cipher_digest, object.nonce.clone()));
    if uploads != envelope.objects {
        return Err(Error::object_digest_mismatch());
    }
    Ok(())
}

fn decrypt_object(
    envelope: &UploadEnvelope,
    occurrence_key: &SecretKey,
    encrypted: &EncryptedObject,
    ciphertext: &BTreeMap<Digest, Vec<u8>>,
) -> Result<Vec<u8>, Error> {
    let object_context = ObjectKeyContext {
        capture_batch_format: "reproit.capture-batch.v1".to_owned(),
        capture_id: envelope.capture_id,
        format: ObjectKeyContextFormat::V1,
        object_id: encrypted.descriptor.object_id,
        organization_id: envelope.organization_id,
        processing_mode: envelope.processing_mode,
        project_id: envelope.project_id,
        role: encrypted.descriptor.role,
        service_id: envelope.service_id,
    };
    let object_key = derive_object_key(occurrence_key, envelope.capture_id, &object_context)?;
    let object_context_digest = canonical::digest(&object_context)?;
    let chunk_count = u32::try_from(encrypted.chunks.len()).map_err(|_| upload_limit())?;
    let mut plaintext = Vec::new();
    for chunk in &encrypted.chunks {
        let stored = ciphertext
            .get(&chunk.cipher_digest)
            .ok_or_else(Error::object_digest_mismatch)?;
        let context = ChunkKeyContext {
            chunk_count,
            chunk_index: chunk.index,
            format: ChunkKeyContextFormat::V1,
            object_context_digest,
            plain_size: chunk
                .cipher_size
                .checked_sub(28)
                .ok_or_else(Error::schema_invalid)?,
        };
        let chunk_key = derive_chunk_key(&object_key, &context)?;
        plaintext.extend(decrypt_chunk(&chunk_key, stored, &context)?);
    }
    if u64::try_from(plaintext.len()).map_err(|_| upload_limit())?
        != encrypted.descriptor.plain_size
        || Digest::of(&plaintext) != encrypted.descriptor.plain_digest
    {
        return Err(Error::object_digest_mismatch());
    }
    Ok(plaintext)
}

fn validate_sealing_ids(request: &SealRequest<'_>) -> Result<(), Error> {
    let ids = std::iter::once(request.ids.capsule_object_id)
        .chain(std::iter::once(request.ids.manifest_object_id))
        .chain(request.ids.proof_object_ids)
        .collect::<BTreeSet<_>>();
    if ids.len() != 5
        || request
            .ids
            .proof_object_ids
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || ids
            .iter()
            .any(|id| request.input.objects.all().contains_key(id))
    {
        return Err(Error::schema_invalid());
    }
    Ok(())
}

fn upload_limit() -> Error {
    Error::new(
        ErrorCode::UploadLimitExceeded,
        "The capture batch exceeds an upload limit.",
    )
}

fn world_not_closed() -> Error {
    Error::new(
        ErrorCode::WorldNotClosed,
        "The object closure is incomplete.",
    )
}

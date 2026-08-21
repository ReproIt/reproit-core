use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    Error, canonical,
    crypto::{decode_base64url, verify_signed_value},
    error::ErrorCode,
    identity::{CaptureId, Digest, OrganizationId, ProjectId, ServiceId, Timestamp},
};

use super::{
    EncryptedObject, LogicalObject, LogicalObjectRole, ManifestUploadObject, ProcessingMode,
    Validate, validate_chunks,
};

const MAX_CANDIDATE_OBJECTS: usize = 32_767;
const MAX_CANDIDATE_PLAINTEXT_BYTES: u64 = 1_048_576;
const MAX_CANDIDATE_CIPHERTEXT_BYTES: u64 = 1_048_604;
const MAX_TOTAL_CANDIDATE_CIPHERTEXT_BYTES: u64 = 274_878_824_448;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum CandidateCipherSuite {
    #[serde(rename = "AES-256-GCM+HKDF-SHA-256")]
    Aes256GcmHkdfSha256,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum ManagedCandidateIdentityFormat {
    #[serde(rename = "reproit.managed-candidate-identity.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedCandidateIdentity {
    pub candidate_digest: Digest,
    pub capture_id: CaptureId,
    pub deployment_digest: Digest,
    pub format: ManagedCandidateIdentityFormat,
    pub objects: Vec<LogicalObject>,
    pub organization_id: OrganizationId,
    pub processing_mode: ProcessingMode,
    pub project_id: ProjectId,
    pub required_capabilities: Vec<String>,
    pub service_id: ServiceId,
    pub subject_digest: Digest,
    pub total_plaintext_bytes: u64,
}

impl Validate for ManagedCandidateIdentity {
    fn validate(&self) -> Result<(), Error> {
        if self.processing_mode != ProcessingMode::Managed
            || self.objects.len() < 5
            || self.objects.len() > MAX_CANDIDATE_OBJECTS
            || self.required_capabilities.len() > 64
            || !self
                .required_capabilities
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            || !self
                .objects
                .windows(2)
                .all(|pair| pair[0].object_id < pair[1].object_id)
        {
            return Err(Error::schema_invalid());
        }

        let mut roles = BTreeSet::new();
        let mut total_plaintext_bytes = 0_u64;
        for object in &self.objects {
            object.validate()?;
            roles.insert(object.role);
            total_plaintext_bytes = total_plaintext_bytes
                .checked_add(object.plain_size)
                .ok_or_else(Error::schema_invalid)?;
        }
        require_candidate_roles(&roles)?;
        let candidate = self.required_manifest(
            LogicalObjectRole::Candidate,
            "application/vnd.reproit.candidate.v1+json",
        )?;
        self.required_manifest(
            LogicalObjectRole::Failure,
            "application/vnd.reproit.failure.v1+json",
        )?;
        self.required_manifest(
            LogicalObjectRole::Trigger,
            "application/vnd.reproit.trigger.v1+json",
        )?;
        self.required_manifest(
            LogicalObjectRole::WorldManifest,
            "application/vnd.reproit.world-manifest.v1+json",
        )?;
        let subject = self.required_manifest(
            LogicalObjectRole::Subject,
            "application/vnd.reproit.subject-closure.v1+json",
        )?;
        if candidate.plain_digest != self.candidate_digest
            || candidate.plain_size > MAX_CANDIDATE_PLAINTEXT_BYTES
            || subject.plain_digest != self.subject_digest
            || total_plaintext_bytes != self.total_plaintext_bytes
            || total_plaintext_bytes > MAX_TOTAL_CANDIDATE_CIPHERTEXT_BYTES
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

impl ManagedCandidateIdentity {
    fn required_manifest(
        &self,
        role: LogicalObjectRole,
        media_type: &str,
    ) -> Result<&LogicalObject, Error> {
        let mut matches = self
            .objects
            .iter()
            .filter(|object| object.role == role && object.media_type == media_type);
        let object = matches.next().ok_or_else(Error::schema_invalid)?;
        if matches.next().is_some() {
            return Err(Error::schema_invalid());
        }
        Ok(object)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum ManagedCandidateManifestFormat {
    #[serde(rename = "reproit.managed-candidate-manifest.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedCandidateManifest {
    pub candidate_identity: ManagedCandidateIdentity,
    pub candidate_identity_digest: Digest,
    pub candidate_key_reference: String,
    pub cipher_suite: CandidateCipherSuite,
    pub format: ManagedCandidateManifestFormat,
}

impl Validate for ManagedCandidateManifest {
    fn validate(&self) -> Result<(), Error> {
        self.candidate_identity.validate()?;
        validate_opaque_reference(&self.candidate_key_reference)?;
        if canonical::digest(&self.candidate_identity)? != self.candidate_identity_digest {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum ManagedCandidateCiphertextIdentityFormat {
    #[serde(rename = "reproit.managed-candidate-ciphertext-identity.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedCandidateCiphertextIdentity {
    pub candidate_identity_digest: Digest,
    pub candidate_key_reference: String,
    pub capture_id: CaptureId,
    pub cipher_suite: CandidateCipherSuite,
    pub format: ManagedCandidateCiphertextIdentityFormat,
    pub manifest_object: ManifestUploadObject,
    pub objects: Vec<EncryptedObject>,
    pub organization_id: OrganizationId,
    pub processing_mode: ProcessingMode,
    pub project_id: ProjectId,
    pub required_capabilities: Vec<String>,
    pub service_id: ServiceId,
    pub total_ciphertext_bytes: u64,
}

impl Validate for ManagedCandidateCiphertextIdentity {
    fn validate(&self) -> Result<(), Error> {
        validate_opaque_reference(&self.candidate_key_reference)?;
        if self.processing_mode != ProcessingMode::Managed
            || self.objects.len() < 5
            || self.objects.len() > MAX_CANDIDATE_OBJECTS
            || self.required_capabilities.is_empty()
            || self.required_capabilities.len() > 64
            || !self
                .required_capabilities
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            || !self
                .objects
                .windows(2)
                .all(|pair| pair[0].descriptor.object_id < pair[1].descriptor.object_id)
        {
            return Err(Error::schema_invalid());
        }

        let mut roles = BTreeSet::new();
        let mut nonces = BTreeSet::new();
        let mut chunk_count = 1_usize;
        let mut total_ciphertext_bytes = self.manifest_object.cipher_size;
        self.manifest_object.validate()?;
        nonces.insert(self.manifest_object.nonce.clone());
        for object in &self.objects {
            object.descriptor.validate()?;
            validate_chunks(&object.chunks)?;
            roles.insert(object.descriptor.role);
            chunk_count = chunk_count
                .checked_add(object.chunks.len())
                .ok_or_else(Error::schema_invalid)?;
            for chunk in &object.chunks {
                decode_base64url::<12>(&chunk.nonce)?;
                if !nonces.insert(chunk.nonce.clone()) {
                    return Err(Error::schema_invalid());
                }
                total_ciphertext_bytes = total_ciphertext_bytes
                    .checked_add(chunk.cipher_size)
                    .ok_or_else(Error::schema_invalid)?;
            }
        }
        require_candidate_roles(&roles)?;
        let candidate_ciphertext_bytes = self
            .objects
            .iter()
            .filter(|object| {
                object.descriptor.role == LogicalObjectRole::Candidate
                    && object.descriptor.media_type == "application/vnd.reproit.candidate.v1+json"
            })
            .map(|object| &object.chunks)
            .collect::<Vec<_>>();
        if candidate_ciphertext_bytes.len() != 1 {
            return Err(Error::schema_invalid());
        }
        let candidate_ciphertext_bytes =
            candidate_ciphertext_bytes[0]
                .iter()
                .try_fold(0_u64, |total, chunk| {
                    total
                        .checked_add(chunk.cipher_size)
                        .ok_or_else(Error::schema_invalid)
                })?;
        if !has_one_manifest(
            &self.objects,
            LogicalObjectRole::Failure,
            "application/vnd.reproit.failure.v1+json",
        ) || !has_one_manifest(
            &self.objects,
            LogicalObjectRole::Subject,
            "application/vnd.reproit.subject-closure.v1+json",
        ) || !has_one_manifest(
            &self.objects,
            LogicalObjectRole::Trigger,
            "application/vnd.reproit.trigger.v1+json",
        ) || !has_one_manifest(
            &self.objects,
            LogicalObjectRole::WorldManifest,
            "application/vnd.reproit.world-manifest.v1+json",
        ) {
            return Err(Error::schema_invalid());
        }
        if chunk_count > 32_768
            || total_ciphertext_bytes != self.total_ciphertext_bytes
            || total_ciphertext_bytes > MAX_TOTAL_CANDIDATE_CIPHERTEXT_BYTES
            || candidate_ciphertext_bytes > MAX_CANDIDATE_CIPHERTEXT_BYTES
            || self
                .objects
                .iter()
                .any(|object| object.descriptor.object_id == self.manifest_object.object_id)
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

fn has_one_manifest(
    objects: &[EncryptedObject],
    role: LogicalObjectRole,
    media_type: &str,
) -> bool {
    objects
        .iter()
        .filter(|object| {
            object.descriptor.role == role && object.descriptor.media_type == media_type
        })
        .count()
        == 1
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum ManagedCandidateCaptureGrantFormat {
    #[serde(rename = "reproit.managed-candidate-capture-grant.v1")]
    V1,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum ManagedCandidateCaptureOperation {
    #[serde(rename = "encrypt-and-upload-candidate")]
    EncryptAndUploadCandidate,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedCandidateCaptureGrant {
    pub candidate_identity_digest: Digest,
    pub candidate_key_reference: String,
    pub capture_id: CaptureId,
    pub cipher_suite: CandidateCipherSuite,
    pub expires_at: Timestamp,
    pub format: ManagedCandidateCaptureGrantFormat,
    pub grant_id: String,
    pub not_before: Timestamp,
    pub operation: ManagedCandidateCaptureOperation,
    pub organization_id: OrganizationId,
    pub processing_mode: ProcessingMode,
    pub project_id: ProjectId,
    pub service_id: ServiceId,
    pub signature: String,
    pub signer_key_id: String,
}

impl Validate for ManagedCandidateCaptureGrant {
    fn validate(&self) -> Result<(), Error> {
        validate_opaque_reference(&self.candidate_key_reference)?;
        validate_opaque_reference(&self.grant_id)?;
        if self.processing_mode != ProcessingMode::Managed
            || self.signer_key_id.is_empty()
            || self.signer_key_id.len() > 256
            || self.signature.len() != 86
            || parse_time(&self.not_before)? >= parse_time(&self.expires_at)?
        {
            return Err(Error::schema_invalid());
        }
        decode_base64url::<64>(&self.signature)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ManagedCandidateCaptureGrantExpectation {
    pub candidate_identity_digest: Digest,
    pub candidate_key_reference: String,
    pub capture_id: CaptureId,
    pub organization_id: OrganizationId,
    pub project_id: ProjectId,
    pub service_id: ServiceId,
    pub signer_key_id: String,
}

pub fn verify_managed_candidate_capture_grant(
    grant: &ManagedCandidateCaptureGrant,
    expected: &ManagedCandidateCaptureGrantExpectation,
    now: &Timestamp,
    public_key: &[u8; 32],
) -> Result<(), Error> {
    grant.validate()?;
    let current_time = parse_time(now)?;
    if grant.candidate_identity_digest != expected.candidate_identity_digest
        || grant.candidate_key_reference != expected.candidate_key_reference
        || grant.capture_id != expected.capture_id
        || grant.organization_id != expected.organization_id
        || grant.project_id != expected.project_id
        || grant.service_id != expected.service_id
        || grant.signer_key_id != expected.signer_key_id
        || current_time < parse_time(&grant.not_before)?
        || current_time >= parse_time(&grant.expires_at)?
    {
        return Err(Error::new(
            ErrorCode::AttestationScope,
            "The managed candidate capture grant does not match this capture.",
        ));
    }
    verify_signed_value(
        &serde_json::to_value(grant).map_err(|_| Error::schema_invalid())?,
        public_key,
    )
}

fn require_candidate_roles(roles: &BTreeSet<LogicalObjectRole>) -> Result<(), Error> {
    for role in required_candidate_roles() {
        if !roles.contains(&role) {
            return Err(Error::schema_invalid());
        }
    }
    Ok(())
}

fn required_candidate_roles() -> [LogicalObjectRole; 5] {
    [
        LogicalObjectRole::Candidate,
        LogicalObjectRole::Failure,
        LogicalObjectRole::Subject,
        LogicalObjectRole::Trigger,
        LogicalObjectRole::WorldManifest,
    ]
}

fn validate_opaque_reference(value: &str) -> Result<(), Error> {
    if value.len() != 43 {
        return Err(Error::schema_invalid());
    }
    decode_base64url::<32>(value).map(|_| ())
}

fn parse_time(value: &Timestamp) -> Result<OffsetDateTime, Error> {
    OffsetDateTime::parse(value.as_str(), &Rfc3339).map_err(|_| Error::schema_invalid())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opaque_references_require_exact_random_key_shape() {
        assert!(validate_opaque_reference("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").is_ok());
        assert!(validate_opaque_reference("short").is_err());
    }
}

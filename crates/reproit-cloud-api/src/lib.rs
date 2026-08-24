#![forbid(unsafe_code)]

mod onboarding;

pub use onboarding::*;

pub use reproit_core::model::{
    CandidateDurability as CandidateStagingState, CandidateStagingReceipt,
};
use reproit_core::{
    Error,
    crypto::{decode_base64url, verify_signed_value},
    identity::{
        CaptureId, DeletionId, Digest, LeaseId, OccurrenceId, OrganizationId, ProjectId, ReproId,
        ServiceId, Timestamp, UploadId,
    },
    model::{
        CandidateCipherSuite, Deployment, ExecutionResult, FailureSummary, KeptReference,
        ManagedCandidateCaptureGrant, ManagedCandidateCiphertextIdentity, ProcessingMode,
        TriggerSummary, Validate, WrappedKey,
    },
};
use secrecy::ExposeSecret;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

pub struct CandidateKey(reproit_core::crypto::SecretKey);

impl CandidateKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(reproit_core::crypto::secret_key(bytes))
    }

    pub fn expose(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }
}

impl Clone for CandidateKey {
    fn clone(&self) -> Self {
        Self::new(*self.expose())
    }
}

impl PartialEq for CandidateKey {
    fn eq(&self, other: &Self) -> bool {
        self.expose() == other.expose()
    }
}

impl Eq for CandidateKey {}

impl Serialize for CandidateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&reproit_core::crypto::encode_base64url(self.expose()))
    }
}

impl<'de> Deserialize<'de> for CandidateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let bytes = reproit_core::crypto::decode_base64url::<32>(&encoded).map_err(|_| {
            de::Error::custom("The candidate key is not a 256-bit base64url value.")
        })?;
        Ok(Self::new(bytes))
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum LegalDeletionAuthority {
    #[serde(rename = "organization-administrator")]
    OrganizationAdministrator,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminRetention {
    pub audit_tombstone_days: u16,
    pub config_revision: u64,
    pub legal_deletion_authority: LegalDeletionAuthority,
    pub verified_occurrence_days: u16,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigConflict {
    pub current: AdminRetention,
    pub error: Error,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum LegalDeletionReason {
    #[serde(rename = "CONTRACT_TERMINATION")]
    ContractTermination,
    #[serde(rename = "CUSTOMER_REQUEST")]
    CustomerRequest,
    #[serde(rename = "LEGAL_REQUIREMENT")]
    LegalRequirement,
    #[serde(rename = "RETENTION_CORRECTION")]
    RetentionCorrection,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegalDeletion {
    pub idempotency_key: String,
    pub occurrence_id: Option<OccurrenceId>,
    pub reason_code: LegalDeletionReason,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum LegalDeletionState {
    #[serde(rename = "ACCEPTED")]
    Accepted,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegalDeletionAcceptance {
    pub deletion_id: DeletionId,
    pub state: LegalDeletionState,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadLimits {
    pub max_chunk_bytes: u64,
    pub max_chunks: u64,
    pub max_occurrence_ciphertext_bytes: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadSessionLimits {
    pub concurrent_object_uploads: u8,
    pub object_attempts: u8,
    pub open_uploads_per_organization: u8,
    pub open_uploads_per_service: u8,
    pub reserved_ciphertext_bytes_per_organization: u64,
    pub session_request_capacity: u8,
    pub session_requests_per_second: u8,
    pub url_lifetime_ms: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedQuota {
    pub organization_ciphertext_bytes: u64,
    pub organization_occurrences: u64,
    pub organization_repros: u64,
    pub service_logical_ciphertext_bytes: u64,
    pub service_occurrences: u64,
    pub service_repros: u64,
}

impl RetainedQuota {
    pub fn validate(&self) -> Result<(), Error> {
        if self.organization_ciphertext_bytes == 0
            || self.organization_occurrences == 0
            || self.organization_repros == 0
            || self.service_logical_ciphertext_bytes == 0
            || self.service_occurrences == 0
            || self.service_repros == 0
            || self.service_logical_ciphertext_bytes > self.organization_ciphertext_bytes
            || self.service_occurrences > self.organization_occurrences
            || self.service_repros > self.organization_repros
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DownloadGrantLimits {
    pub organization_open_grants: u16,
    pub user_open_grants: u8,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleLimits {
    pub concurrent_jobs: u8,
    pub concurrent_object_deletions: u8,
    pub database_timeout_ms: u64,
    pub lease_items: u8,
    pub lease_lifetime_ms: u64,
    pub object_attempts_per_lease: u8,
    pub object_timeout_ms: u64,
    pub organization_open_records: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleLease {
    pub expires_at: Timestamp,
    pub job_id: String,
    pub lease_id: String,
    pub object_identities: Vec<Digest>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateStagingLimits {
    pub claim_page_size: u8,
    pub lease_lifetime_ms: u64,
    pub max_candidate_bytes: u64,
    pub max_candidates_per_organization: u16,
    pub max_candidates_per_service: u16,
    pub max_retained_bytes_per_organization: u64,
    pub max_retained_bytes_per_service: u64,
    pub max_staging_lifetime_ms: u64,
}

impl CandidateStagingLimits {
    pub const V1: Self = Self {
        claim_page_size: 8,
        lease_lifetime_ms: 30_000,
        max_candidate_bytes: 1_048_604,
        max_candidates_per_organization: 1_024,
        max_candidates_per_service: 256,
        max_retained_bytes_per_organization: 1_073_741_824,
        max_retained_bytes_per_service: 268_435_456,
        max_staging_lifetime_ms: 3_600_000,
    };
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedCandidateLimits {
    pub max_candidate_bytes: u64,
    pub max_object_bytes: u64,
    pub max_objects: u32,
    pub max_total_ciphertext_bytes: u64,
    pub missing_page_size: u8,
    pub object_attempts: u8,
    pub upload_lifetime_ms: u64,
}

impl ManagedCandidateLimits {
    pub const V1: Self = Self {
        max_candidate_bytes: 1_048_576,
        max_object_bytes: 8_388_636,
        max_objects: 32_768,
        max_total_ciphertext_bytes: 274_878_824_448,
        missing_page_size: 100,
        object_attempts: 5,
        upload_lifetime_ms: 60_000,
    };
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedCandidateEncryptionGrantRequest {
    pub candidate_identity_digest: Digest,
    pub capture_id: CaptureId,
    pub cipher_suite: CandidateCipherSuite,
    pub deployment_digest: Digest,
    pub organization_id: OrganizationId,
    pub processing_mode: ProcessingMode,
    pub project_id: ProjectId,
    pub service_id: ServiceId,
    pub signature: String,
    pub signer_key_id: String,
}

impl ManagedCandidateEncryptionGrantRequest {
    pub fn validate(&self) -> Result<(), Error> {
        if self.processing_mode != ProcessingMode::Managed {
            return Err(Error::schema_invalid());
        }
        validate_managed_workload_key_id(&self.signer_key_id)?;
        decode_base64url::<64>(&self.signature)?;
        Ok(())
    }

    pub fn verify(&self, public_key: &[u8; 32]) -> Result<(), Error> {
        self.validate()?;
        if managed_workload_key_id(&reproit_core::crypto::encode_base64url(public_key))?
            != self.signer_key_id
        {
            return Err(workload_attestation_error());
        }
        let value = serde_json::to_value(self).map_err(|_| Error::schema_invalid())?;
        verify_signed_value(&value, public_key)
    }

    pub fn validate_for_registration(
        &self,
        registration: &WorkloadKeyRegistration,
    ) -> Result<(), Error> {
        registration.validate()?;
        if self.deployment_digest != registration.deployment_digest()?
            || self.organization_id != registration.deployment.organization_id
            || self.project_id != registration.deployment.project_id
            || self.service_id != registration.deployment.service_id
            || self.signer_key_id != registration.deployment.signer_key_id
        {
            return Err(workload_attestation_error());
        }
        let public_key = decode_base64url::<32>(&registration.public_key)?;
        self.verify(&public_key)
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedCandidateEncryptionResponse {
    pub candidate_key: CandidateKey,
    pub capture_grant: ManagedCandidateCaptureGrant,
}

impl ManagedCandidateEncryptionResponse {
    pub fn validate(&self) -> Result<(), Error> {
        self.capture_grant.validate()
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedCandidateUploadRequest {
    pub capture_grant: ManagedCandidateCaptureGrant,
    pub ciphertext_identity: ManagedCandidateCiphertextIdentity,
    pub encrypted_candidate_digest: Digest,
}

impl ManagedCandidateUploadRequest {
    pub fn validate(&self) -> Result<(), Error> {
        self.capture_grant.validate()?;
        self.ciphertext_identity.validate()?;
        if self.capture_grant.candidate_identity_digest
            != self.ciphertext_identity.candidate_identity_digest
            || self.capture_grant.candidate_key_reference
                != self.ciphertext_identity.candidate_key_reference
            || self.capture_grant.capture_id != self.ciphertext_identity.capture_id
            || self.capture_grant.organization_id != self.ciphertext_identity.organization_id
            || self.capture_grant.project_id != self.ciphertext_identity.project_id
            || self.capture_grant.service_id != self.ciphertext_identity.service_id
            || self.capture_grant.processing_mode != self.ciphertext_identity.processing_mode
            || self.capture_grant.cipher_suite != self.ciphertext_identity.cipher_suite
        {
            return Err(grant_scope_error());
        }
        if reproit_core::canonical::digest(&self.ciphertext_identity)?
            != self.encrypted_candidate_digest
        {
            return Err(Error::object_digest_mismatch());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ManagedCandidateUploadState {
    Cancelled,
    Committed,
    Committing,
    Expired,
    Open,
    Uploading,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedCandidateStart {
    pub expires_at: Timestamp,
    pub limits: ManagedCandidateLimits,
    pub missing_objects: Vec<MissingObject>,
    pub next_missing_cursor: Option<String>,
    pub state: ManagedCandidateUploadState,
    pub upload_id: UploadId,
    pub upload_token: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedCandidateCommit {
    pub candidate_identity_digest: Digest,
    pub candidate_key_reference: String,
    pub capture_id: CaptureId,
    pub encrypted_candidate_digest: Digest,
    pub state: CandidateStagingState,
    pub upload_id: UploadId,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedCandidateStatus {
    pub candidate_identity_digest: Digest,
    pub candidate_key_reference: String,
    pub capture_id: CaptureId,
    pub encrypted_candidate_digest: Digest,
    pub expires_at: Option<Timestamp>,
    pub missing_digests: Vec<Digest>,
    pub state: ManagedCandidateUploadState,
    pub upload_id: UploadId,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadKeyRegistration {
    pub algorithm: String,
    pub deployment: Deployment,
    pub public_key: String,
    pub service_id: ServiceId,
}

impl WorkloadKeyRegistration {
    pub fn validate(&self) -> Result<(), Error> {
        if self.algorithm != "Ed25519" || self.deployment.processing_mode != ProcessingMode::Managed
        {
            return Err(Error::schema_invalid());
        }
        self.deployment.validate()?;
        validate_managed_workload_key_id(&self.deployment.signer_key_id)?;
        if self.deployment.service_id != self.service_id {
            return Err(workload_attestation_error());
        }
        let public_key = decode_base64url::<32>(&self.public_key)?;
        if managed_workload_key_id(&self.public_key)? != self.deployment.signer_key_id {
            return Err(workload_attestation_error());
        }
        let value = serde_json::to_value(&self.deployment).map_err(|_| Error::schema_invalid())?;
        verify_signed_value(&value, &public_key)
    }

    pub fn deployment_digest(&self) -> Result<Digest, Error> {
        reproit_core::canonical::digest(&self.deployment)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadKeyRegistrationResult {
    pub deployment_digest: Digest,
    pub key_id: String,
    pub service_id: ServiceId,
}

impl WorkloadKeyRegistrationResult {
    pub fn validate(&self) -> Result<(), Error> {
        validate_managed_workload_key_id(&self.key_id)
    }

    pub fn validate_for_registration(
        &self,
        registration: &WorkloadKeyRegistration,
    ) -> Result<(), Error> {
        self.validate()?;
        registration.validate()?;
        if self.key_id != managed_workload_key_id(&registration.public_key)?
            || self.service_id != registration.service_id
            || self.deployment_digest != registration.deployment_digest()?
        {
            return Err(workload_attestation_error());
        }
        Ok(())
    }
}

/// Derives the stable managed workload key ID from one canonical Ed25519 public key.
pub fn managed_workload_key_id(public_key: &str) -> Result<String, Error> {
    decode_base64url::<32>(public_key)?;
    Ok(format!(
        "managed-workload-{}",
        Digest::of(public_key.as_bytes())
    ))
}

pub fn validate_managed_workload_key_id(key_id: &str) -> Result<(), Error> {
    const PREFIX: &str = "managed-workload-sha256:";
    let Some(digest) = key_id.strip_prefix(PREFIX) else {
        return Err(Error::schema_invalid());
    };
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(Error::schema_invalid());
    }
    Ok(())
}

fn workload_attestation_error() -> Error {
    Error::new(
        reproit_core::ErrorCode::AttestationScope,
        "The workload key, deployment, and signed request do not agree.",
    )
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ManagedOperation {
    Admission,
    Check,
    Debug,
    Keep,
    Replay,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum ManagedWorkerGrantFormat {
    #[serde(rename = "reproit.managed-worker-grant.v1")]
    V1,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedWorkerGrant {
    pub candidate_identity_digest: Digest,
    pub candidate_key_reference: String,
    pub capabilities: Vec<String>,
    pub capture_id: CaptureId,
    pub encrypted_candidate_digest: Digest,
    pub expires_at: Timestamp,
    pub format: ManagedWorkerGrantFormat,
    pub grant_id: String,
    pub lease_id: LeaseId,
    pub not_before: Timestamp,
    pub operation: ManagedOperation,
    pub organization_id: OrganizationId,
    pub processing_mode: ProcessingMode,
    pub project_id: ProjectId,
    pub service_id: ServiceId,
    pub signature: String,
    pub signer_key_id: String,
    pub worker_id: String,
    pub worker_release: Digest,
}

impl ManagedWorkerGrant {
    pub fn validate(&self) -> Result<(), Error> {
        validate_opaque_identity(&self.candidate_key_reference)?;
        validate_opaque_identity(&self.grant_id)?;
        validate_signed_grant(
            &self.capabilities,
            &self.not_before,
            &self.expires_at,
            self.processing_mode,
            &self.signature,
            &self.signer_key_id,
            &self.worker_id,
        )
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum ManagedKeyGrantFormat {
    #[serde(rename = "reproit.managed-key-grant.v1")]
    V1,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedKeyGrant {
    pub candidate_identity_digest: Digest,
    pub candidate_key_reference: String,
    pub capabilities: Vec<String>,
    pub capture_id: CaptureId,
    pub encrypted_candidate_digest: Digest,
    pub expires_at: Timestamp,
    pub format: ManagedKeyGrantFormat,
    pub grant_id: String,
    pub lease_id: LeaseId,
    pub not_before: Timestamp,
    pub operation: ManagedOperation,
    pub organization_id: OrganizationId,
    pub processing_mode: ProcessingMode,
    pub project_id: ProjectId,
    pub service_id: ServiceId,
    pub signature: String,
    pub signer_key_id: String,
    pub worker_id: String,
    pub worker_grant_digest: Digest,
    pub worker_release: Digest,
}

impl ManagedKeyGrant {
    pub fn validate(&self) -> Result<(), Error> {
        validate_opaque_identity(&self.candidate_key_reference)?;
        validate_opaque_identity(&self.grant_id)?;
        validate_signed_grant(
            &self.capabilities,
            &self.not_before,
            &self.expires_at,
            self.processing_mode,
            &self.signature,
            &self.signer_key_id,
            &self.worker_id,
        )
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedCandidateKeyResponse {
    pub candidate_key: CandidateKey,
    pub candidate_key_reference: String,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedCandidateKeyRequest {
    pub key_grant: ManagedKeyGrant,
    pub worker_grant: ManagedWorkerGrant,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedOccurrenceKeyWrapRequest {
    pub grants: ManagedCandidateKeyRequest,
    pub occurrence_key: CandidateKey,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedOccurrenceKeyWrapResponse {
    pub wrapped_key: reproit_core::model::WrappedKey,
}

impl ManagedOccurrenceKeyWrapRequest {
    pub fn validate(&self) -> Result<(), Error> {
        self.grants.worker_grant.validate()?;
        self.grants.key_grant.validate()
    }
}

impl ManagedOccurrenceKeyWrapResponse {
    pub fn validate(&self) -> Result<(), Error> {
        self.wrapped_key.validate()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedOccurrenceKeyOpenRequest {
    pub capture_id: CaptureId,
    pub grant: ManagedOciGrant,
    pub wrapped_key: WrappedKey,
}

impl ManagedOccurrenceKeyOpenRequest {
    pub fn validate(&self) -> Result<(), Error> {
        self.grant.validate()?;
        self.wrapped_key.validate()?;
        let organization_prefix = format!("managed-occurrence:{}:", self.grant.organization_id);
        if self.wrapped_key.algorithm != "AES-256-GCM+HKDF-SHA-256"
            || self.wrapped_key.context_version != 1
            || self.wrapped_key.provider_id != "reproit-managed-key-service"
            || !self
                .wrapped_key
                .key_reference
                .starts_with(&organization_prefix)
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedOccurrenceKeyOpenResponse {
    pub occurrence_key: CandidateKey,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedCandidateObjectRequest {
    pub worker_grant: ManagedWorkerGrant,
}

impl ManagedCandidateObjectRequest {
    pub fn validate(&self) -> Result<(), Error> {
        self.worker_grant.validate()
    }
}

impl ManagedCandidateKeyResponse {
    pub fn validate(&self) -> Result<(), Error> {
        validate_opaque_identity(&self.candidate_key_reference)
    }
}

pub fn verify_managed_worker_key_grants(
    worker: &ManagedWorkerGrant,
    key: &ManagedKeyGrant,
    now: &Timestamp,
    worker_public_key: &[u8; 32],
    key_public_key: &[u8; 32],
) -> Result<(), Error> {
    worker.validate()?;
    key.validate()?;
    if now < &worker.not_before
        || now >= &worker.expires_at
        || now < &key.not_before
        || now >= &key.expires_at
        || key.expires_at > worker.expires_at
        || key.candidate_identity_digest != worker.candidate_identity_digest
        || key.candidate_key_reference != worker.candidate_key_reference
        || key.capabilities != worker.capabilities
        || key.capture_id != worker.capture_id
        || key.encrypted_candidate_digest != worker.encrypted_candidate_digest
        || key.lease_id != worker.lease_id
        || key.operation != worker.operation
        || key.organization_id != worker.organization_id
        || key.processing_mode != worker.processing_mode
        || key.project_id != worker.project_id
        || key.service_id != worker.service_id
        || key.worker_grant_digest != reproit_core::canonical::digest(worker)?
        || key.worker_id != worker.worker_id
        || key.worker_release != worker.worker_release
    {
        return Err(grant_scope_error());
    }
    reproit_core::crypto::verify_signed_value(
        &serde_json::to_value(worker).map_err(|_| Error::schema_invalid())?,
        worker_public_key,
    )?;
    reproit_core::crypto::verify_signed_value(
        &serde_json::to_value(key).map_err(|_| Error::schema_invalid())?,
        key_public_key,
    )
}

fn validate_signed_grant(
    capabilities: &[String],
    not_before: &Timestamp,
    expires_at: &Timestamp,
    processing_mode: ProcessingMode,
    signature: &str,
    signer_key_id: &str,
    worker_id: &str,
) -> Result<(), Error> {
    if processing_mode != ProcessingMode::Managed
        || not_before >= expires_at
        || capabilities.len() > 64
        || !capabilities.windows(2).all(|pair| pair[0] < pair[1])
        || signer_key_id.is_empty()
        || signer_key_id.len() > 256
        || worker_id.is_empty()
        || worker_id.len() > 256
    {
        return Err(Error::schema_invalid());
    }
    reproit_core::crypto::decode_base64url::<64>(signature)?;
    Ok(())
}

fn validate_opaque_identity(value: &str) -> Result<(), Error> {
    reproit_core::crypto::decode_base64url::<32>(value).map(|_| ())
}

fn grant_scope_error() -> Error {
    Error::new(
        reproit_core::ErrorCode::AttestationScope,
        "The managed worker and key grants do not match the active lease.",
    )
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedOciGrant {
    pub capture_id: CaptureId,
    pub capture_batch_digest: Digest,
    pub capsule_digest: Digest,
    pub debugger_capability_digest: Digest,
    pub expires_at: Timestamp,
    pub grant_id: String,
    pub not_before: Timestamp,
    pub operation: ManagedOperation,
    pub organization_id: OrganizationId,
    pub processing_mode: ProcessingMode,
    pub project_id: ProjectId,
    pub repro_id: ReproId,
    pub requester_identity: String,
    pub service_id: ServiceId,
    pub signature: String,
    pub signer_key_id: String,
    pub worker_id: String,
    pub worker_release: Digest,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedOciGrantRequest {
    pub capture_batch_digest: Digest,
    pub debugger_capability_digest: Digest,
    pub operation: ManagedOperation,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedExecutionMaterialRequest {
    pub grant: ManagedOciGrant,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedExecutionMaterial {
    pub admission_key: reproit_core::model::AdmissionVerificationKey,
    pub ciphertext: std::collections::BTreeMap<Digest, String>,
    pub envelope: String,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedExecutionResultReport {
    pub grant: ManagedOciGrant,
    pub result: ExecutionResult,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedKeepRequest {
    pub grant: ManagedOciGrant,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedKeepResult {
    pub reference: KeptReference,
}

impl ManagedOciGrantRequest {
    pub fn validate(&self) -> Result<(), Error> {
        if self.operation == ManagedOperation::Admission
            || self.capture_batch_digest == Digest::of(&[])
            || self.debugger_capability_digest == Digest::of(&[])
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

impl ManagedExecutionMaterialRequest {
    pub fn validate(&self) -> Result<(), Error> {
        self.grant.validate()
    }
}

impl ManagedExecutionMaterial {
    pub fn validate(&self) -> Result<(), Error> {
        self.admission_key.validate()?;
        let envelope = reproit_core::crypto::decode_base64url_bytes(&self.envelope)?;
        if envelope.is_empty() || envelope.len() > 8 * 1_024 * 1_024 || self.ciphertext.is_empty() {
            return Err(Error::schema_invalid());
        }
        let mut total = 0_usize;
        for bytes in self.ciphertext.values() {
            let decoded = reproit_core::crypto::decode_base64url_bytes(bytes)?;
            total = total
                .checked_add(decoded.len())
                .filter(|value| *value <= 384 * 1_024 * 1_024)
                .ok_or_else(Error::schema_invalid)?;
        }
        Ok(())
    }
}

impl ManagedExecutionResultReport {
    pub fn validate(&self) -> Result<(), Error> {
        self.grant.validate()?;
        self.result.validate()?;
        if !self.result.cleanup_complete {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

impl ManagedKeepRequest {
    pub fn validate(&self) -> Result<(), Error> {
        self.grant.validate()?;
        if self.grant.operation != ManagedOperation::Keep {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

impl ManagedKeepResult {
    pub fn validate(&self) -> Result<(), Error> {
        self.reference.validate()
    }
}

impl ManagedOciGrant {
    pub fn validate(&self) -> Result<(), Error> {
        if self.processing_mode != ProcessingMode::Managed
            || self.operation == ManagedOperation::Admission
            || self.not_before >= self.expires_at
            || self.signer_key_id.is_empty()
            || self.signer_key_id.len() > 256
            || self.requester_identity.is_empty()
            || self.requester_identity.len() > 512
            || self.worker_id.is_empty()
            || self.worker_id.len() > 256
        {
            return Err(Error::schema_invalid());
        }
        validate_opaque_identity(&self.grant_id)?;
        reproit_core::crypto::decode_base64url::<64>(&self.signature).map(|_| ())
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OciLinkRequest {
    pub credential: String,
    pub destination: String,
    pub idempotency_key: String,
}

impl OciLinkRequest {
    pub fn validate(&self) -> Result<(), Error> {
        let repository = self
            .destination
            .strip_prefix("oci://")
            .ok_or_else(Error::schema_invalid)?;
        let Some((registry, path)) = repository.split_once('/') else {
            return Err(Error::schema_invalid());
        };
        if self.credential.is_empty()
            || self.credential.len() > 8_192
            || self.idempotency_key.len() < 16
            || self.idempotency_key.len() > 256
            || self.destination.len() > 2_048
            || registry.is_empty()
            || path.is_empty()
            || path.starts_with('/')
            || path.ends_with('/')
            || repository.contains('@')
            || repository.bytes().any(|byte| {
                byte.is_ascii_whitespace() || byte.is_ascii_control() || !byte.is_ascii()
            })
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OciLinkState {
    Active,
    Error,
    Exporting,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OciLinkStatus {
    pub config_revision: u64,
    pub current_export_count: u64,
    pub destination: String,
    pub failure_code: Option<String>,
    pub last_successful_export: Option<Timestamp>,
    pub state: OciLinkState,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateStagingGrantRequest {
    pub deployment_digest: Digest,
    pub expires_at: Timestamp,
    pub organization_id: OrganizationId,
    pub processing_mode: ProcessingMode,
    pub project_id: ProjectId,
    pub service_id: ServiceId,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateStagingGrant {
    pub bearer_token: String,
    pub expires_at: Timestamp,
    pub limits: CandidateStagingLimits,
    pub processing_mode: ProcessingMode,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateClaimRequest {
    pub limit: u8,
    pub organization_id: OrganizationId,
    pub project_id: ProjectId,
    pub service_id: ServiceId,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimedCandidate {
    pub envelope: reproit_core::model::CandidateStagingEnvelope,
    pub lease_expires_at: Timestamp,
    pub lease_id: String,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateClaimPage {
    pub candidates: Vec<ClaimedCandidate>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateLeaseRequest {
    pub lease_id: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CandidateTerminalOutcome {
    Admitted,
    Cancelled,
    Expired,
    Rejected,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateTerminalRequest {
    pub lease_id: String,
    pub outcome: CandidateTerminalOutcome,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MissingObject {
    pub cipher_digest: Digest,
    pub expires_at: Timestamp,
    pub upload_url: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DownloadLimits {
    pub max_concurrent_reads: u8,
    pub max_read_attempts_per_object: u8,
    pub max_served_closure_multiplier: u8,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadStart {
    pub expires_at: Timestamp,
    pub limits: UploadLimits,
    pub missing_objects: Vec<MissingObject>,
    pub next_missing_cursor: Option<String>,
    pub state: UploadState,
    pub upload_id: UploadId,
    pub upload_token: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadMissingQuery {
    pub cursor: Option<String>,
    pub limit: Option<u8>,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadMissingPage {
    pub missing_objects: Vec<MissingObject>,
    pub next_missing_cursor: Option<String>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum UploadState {
    #[serde(rename = "OPEN")]
    Open,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadCommit {
    pub capture_batch_digest: Digest,
    pub capture_id: CaptureId,
    pub occurrence_id: OccurrenceId,
    pub repro_id: ReproId,
    pub state: CommitState,
    pub upload_id: UploadId,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum CommitState {
    #[serde(rename = "COMMITTED")]
    Committed,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum CancelledState {
    #[serde(rename = "CANCELLED")]
    Cancelled,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadCancelled {
    pub capture_batch_digest: Digest,
    pub capture_id: CaptureId,
    pub state: CancelledState,
    pub upload_id: UploadId,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum ExpiredState {
    #[serde(rename = "EXPIRED")]
    Expired,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadExpired {
    pub capture_batch_digest: Digest,
    pub capture_id: CaptureId,
    pub state: ExpiredState,
    pub upload_id: UploadId,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum PendingState {
    #[serde(rename = "OPEN")]
    Open,
    #[serde(rename = "UPLOADING")]
    Uploading,
    #[serde(rename = "COMMITTING")]
    Committing,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadPending {
    pub capture_batch_digest: Digest,
    pub capture_id: CaptureId,
    pub expires_at: Timestamp,
    pub missing_digests: Vec<Digest>,
    pub state: PendingState,
    pub upload_id: UploadId,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum Workflow {
    #[serde(rename = "OPEN")]
    Open,
    #[serde(rename = "REGRESSED")]
    Regressed,
    #[serde(rename = "RESOLVED")]
    Resolved,
}

impl Workflow {
    pub const fn accepts_triage_next(self, next: Self) -> bool {
        match self {
            Self::Open => matches!(next, Self::Open | Self::Resolved),
            Self::Regressed => matches!(next, Self::Regressed | Self::Resolved),
            Self::Resolved => matches!(next, Self::Resolved | Self::Open),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum Priority {
    #[serde(rename = "UNSET")]
    Unset,
    #[serde(rename = "P0")]
    P0,
    #[serde(rename = "P1")]
    P1,
    #[serde(rename = "P2")]
    P2,
    #[serde(rename = "P3")]
    P3,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Triage {
    pub assignee_id: Option<String>,
    pub priority: Priority,
    pub triage_revision: u64,
    pub workflow: Workflow,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TriageConflict {
    pub current: Triage,
    pub error: Error,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReproSummary {
    pub assignee_id: Option<String>,
    pub failure_summary: FailureSummary,
    pub first_seen_at: Timestamp,
    pub latest_seen_at: Timestamp,
    pub occurrence_count: u64,
    pub priority: Priority,
    pub repro_id: ReproId,
    pub service_id: ServiceId,
    pub source_revision: String,
    pub triage_revision: u64,
    pub workflow: Workflow,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReproList {
    pub next_cursor: Option<String>,
    pub repros: Vec<ReproSummary>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ReproListQuery {
    pub assignee_id: Option<String>,
    pub cursor: Option<String>,
    pub limit: Option<u16>,
    pub priority: Option<Priority>,
    pub project_id: Option<ProjectId>,
    pub service_id: Option<ServiceId>,
    pub workflow: Option<Workflow>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReproDetail {
    pub capsule_digest: Digest,
    pub processing_mode: ProcessingMode,
    pub required_capabilities: Vec<String>,
    pub selected_occurrence_id: OccurrenceId,
    pub summary: ReproSummary,
    pub trigger_summary: TriggerSummary,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OccurrenceSummary {
    pub capsule_digest: Digest,
    pub capture_batch_digest: Digest,
    pub capture_id: CaptureId,
    pub captured_at: Timestamp,
    pub occurrence_id: OccurrenceId,
    pub processing_mode: ProcessingMode,
    pub required_capabilities: Vec<String>,
    pub source_revision: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OccurrenceList {
    pub next_cursor: Option<String>,
    pub occurrences: Vec<OccurrenceSummary>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct OccurrenceListQuery {
    pub cursor: Option<String>,
    pub limit: Option<u16>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DownloadRequest {
    pub occurrence_id: OccurrenceId,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DownloadGrant {
    pub bearer_token: String,
    pub capsule_digest: Digest,
    pub download_base_url: String,
    pub expires_at: Timestamp,
    pub limits: DownloadLimits,
    pub occurrence_id: OccurrenceId,
    pub processing_mode: ProcessingMode,
}

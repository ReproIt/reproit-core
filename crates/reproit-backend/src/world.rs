use std::collections::{BTreeMap, BTreeSet};

use reproit_core::{
    Error, ErrorCode,
    identity::{CaptureId, Digest, ExecutionId, LeaseId, ObjectId, OperationId, Timestamp},
    model::{ProviderResourceClaim, Validate},
};

const MAX_PROVIDER_ARTIFACTS: usize = 32_767;
const MAX_PROVIDER_CAPABILITIES: usize = 64;
const MAX_SCOPE_RULES: usize = 1_024;
const MAX_TRANSCRIPT_INTERACTIONS: usize = 1_024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CheckpointScope {
    Full,
    Scoped(BTreeSet<String>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoverablePoint {
    pub artifacts: BTreeMap<Digest, u64>,
    pub capabilities: BTreeSet<String>,
    pub configuration_digest: Digest,
    pub engine_identity: String,
    pub engine_version: String,
    pub generation: u64,
    pub point_digest: Digest,
    pub provider_id: String,
    pub published_at: Timestamp,
    pub recoverable_until: Timestamp,
    pub resource_claim: ProviderResourceClaim,
    pub scope: CheckpointScope,
}

impl RecoverablePoint {
    pub fn validate(&self, now: &Timestamp) -> Result<(), Error> {
        if !valid_component_id(&self.provider_id)
            || self.engine_identity.is_empty()
            || self.engine_identity.len() > 256
            || self.engine_version.is_empty()
            || self.engine_version.len() > 128
            || self.generation == 0
            || self.generation > 9_007_199_254_740_991
            || self.artifacts.len() > MAX_PROVIDER_ARTIFACTS
            || self.capabilities.len() > MAX_PROVIDER_CAPABILITIES
            || self
                .capabilities
                .iter()
                .any(|capability| !valid_component_id(capability))
        {
            return Err(Error::schema_invalid());
        }
        if self.published_at > self.recoverable_until || now > &self.recoverable_until {
            return Err(Error::new(
                ErrorCode::WorldPointExpired,
                "The selected World point is no longer recoverable.",
            ));
        }
        self.resource_claim.validate()?;
        let pinned_bytes = self
            .artifacts
            .values()
            .try_fold(0_u64, |total, size| total.checked_add(*size))
            .ok_or_else(Error::schema_invalid)?;
        if pinned_bytes > self.resource_claim.pinned_bytes
            || u64::try_from(self.artifacts.len()).map_err(|_| Error::schema_invalid())?
                > self.resource_claim.objects
        {
            return Err(Error::new(
                ErrorCode::RuntimeQuota,
                "The provider point exceeds its declared resource claim.",
            ));
        }
        match &self.scope {
            CheckpointScope::Scoped(rules)
                if rules.is_empty()
                    || rules.len() > MAX_SCOPE_RULES
                    || rules.iter().any(|rule| rule.is_empty() || rule.len() > 512) =>
            {
                return Err(Error::schema_invalid());
            }
            CheckpointScope::Full | CheckpointScope::Scoped(_) => {}
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderLease {
    pub capture_id: CaptureId,
    pub expires_at: Timestamp,
    pub lease_id: LeaseId,
    pub point_digest: Digest,
    pub provider_id: String,
    pub world_id: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderMaterialization {
    pub evidence_digest: Digest,
    pub execution_id: ExecutionId,
    pub lease_id: LeaseId,
    pub provider_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderVerification {
    pub evidence_digest: Digest,
    pub execution_id: ExecutionId,
    pub lease_id: LeaseId,
    pub provider_id: String,
}

pub trait StateProvider {
    fn pin(
        &self,
        point: &RecoverablePoint,
        capture_id: CaptureId,
        world_id: Digest,
    ) -> Result<ProviderLease, Error>;

    fn materialize(
        &self,
        lease: &ProviderLease,
        execution_id: ExecutionId,
        target_reference: &str,
    ) -> Result<ProviderMaterialization, Error>;

    fn verify(
        &self,
        lease: &ProviderLease,
        materialization: &ProviderMaterialization,
    ) -> Result<ProviderVerification, Error>;

    fn release(&self, lease: &ProviderLease) -> Result<(), Error>;
}

pub struct MaterializeRequest {
    pub capture_id: CaptureId,
    pub execution_capabilities: BTreeSet<String>,
    pub execution_id: ExecutionId,
    pub now: Timestamp,
    pub point: RecoverablePoint,
    pub target_reference: String,
    pub world_id: Digest,
}

pub fn with_verified_world<T>(
    provider: &impl StateProvider,
    request: &MaterializeRequest,
    execute: impl FnOnce(&ProviderVerification) -> Result<T, Error>,
) -> Result<T, Error> {
    request.point.validate(&request.now)?;
    if request.target_reference.is_empty() || request.target_reference.len() > 16_384 {
        return Err(Error::schema_invalid());
    }
    if !request
        .point
        .capabilities
        .is_subset(&request.execution_capabilities)
    {
        return Err(Error::new(
            ErrorCode::UnsupportedCapabilitySet,
            "The executor does not support the required capability set.",
        ));
    }
    let lease = provider.pin(&request.point, request.capture_id, request.world_id)?;
    let result = materialize_and_execute(provider, request, &lease, execute);
    let release = provider.release(&lease);
    match (result, release) {
        (_, Err(error)) => Err(error),
        (result, Ok(())) => result,
    }
}

fn materialize_and_execute<T>(
    provider: &impl StateProvider,
    request: &MaterializeRequest,
    lease: &ProviderLease,
    execute: impl FnOnce(&ProviderVerification) -> Result<T, Error>,
) -> Result<T, Error> {
    validate_lease(request, lease)?;
    let materialization =
        provider.materialize(lease, request.execution_id, &request.target_reference)?;
    validate_materialization(lease, request.execution_id, &materialization)?;
    let verification = provider.verify(lease, &materialization)?;
    validate_verification(lease, request.execution_id, &materialization, &verification)?;
    execute(&verification)
}

fn validate_lease(request: &MaterializeRequest, lease: &ProviderLease) -> Result<(), Error> {
    if lease.capture_id != request.capture_id
        || lease.point_digest != request.point.point_digest
        || lease.provider_id != request.point.provider_id
        || lease.world_id != request.world_id
        || lease.expires_at < request.now
    {
        return Err(Error::new(
            ErrorCode::WorldNotClosed,
            "The provider lease does not bind the selected World point.",
        ));
    }
    Ok(())
}

fn validate_materialization(
    lease: &ProviderLease,
    execution_id: ExecutionId,
    materialization: &ProviderMaterialization,
) -> Result<(), Error> {
    if materialization.execution_id != execution_id
        || materialization.lease_id != lease.lease_id
        || materialization.provider_id != lease.provider_id
    {
        return Err(Error::new(
            ErrorCode::WorldNotClosed,
            "The materialized World does not bind the provider lease.",
        ));
    }
    Ok(())
}

fn validate_verification(
    lease: &ProviderLease,
    execution_id: ExecutionId,
    materialization: &ProviderMaterialization,
    verification: &ProviderVerification,
) -> Result<(), Error> {
    if verification.execution_id != execution_id
        || verification.lease_id != lease.lease_id
        || verification.provider_id != lease.provider_id
        || verification.evidence_digest != materialization.evidence_digest
    {
        return Err(Error::new(
            ErrorCode::WorldNotClosed,
            "The provider verification does not bind the materialized World.",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TranscriptInteraction {
    pub causal_parent_id: Option<OperationId>,
    pub operation_id: OperationId,
    pub request_digest: Digest,
    pub request_object_id: ObjectId,
    pub response_digest: Digest,
    pub response_object_id: ObjectId,
    pub sequence: u16,
    pub session_position: u64,
}

pub fn verify_dependency_transcript(
    operation_id: OperationId,
    interactions: &[TranscriptInteraction],
    objects: &BTreeMap<ObjectId, Vec<u8>>,
) -> Result<(), Error> {
    if interactions.is_empty() || interactions.len() > MAX_TRANSCRIPT_INTERACTIONS {
        return Err(Error::schema_invalid());
    }
    for (index, interaction) in interactions.iter().enumerate() {
        let sequence = u16::try_from(index).map_err(|_| Error::schema_invalid())?;
        let session_position = u64::try_from(index).map_err(|_| Error::schema_invalid())?;
        let causal_match = interaction.operation_id == operation_id
            || interaction.causal_parent_id == Some(operation_id);
        let request = objects.get(&interaction.request_object_id);
        let response = objects.get(&interaction.response_object_id);
        if interaction.sequence != sequence
            || interaction.session_position != session_position
            || !causal_match
            || request.is_none_or(|bytes| Digest::of(bytes) != interaction.request_digest)
            || response.is_none_or(|bytes| Digest::of(bytes) != interaction.response_digest)
        {
            return Err(Error::new(
                ErrorCode::DependencyTranscriptMismatch,
                "The dependency transcript does not match the captured operation.",
            ));
        }
    }
    Ok(())
}

pub fn verify_subject_artifact(
    bytes: &[u8],
    expected_digest: Digest,
    maximum_bytes: usize,
) -> Result<(), Error> {
    if bytes.len() > maximum_bytes {
        return Err(Error::new(
            ErrorCode::UploadLimitExceeded,
            "The subject artifact exceeds the configured size limit.",
        ));
    }
    if Digest::of(bytes) != expected_digest {
        return Err(Error::new(
            ErrorCode::SubjectDigestMismatch,
            "The subject artifact does not match the captured deployment.",
        ));
    }
    Ok(())
}

fn valid_component_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_lowercase()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
}

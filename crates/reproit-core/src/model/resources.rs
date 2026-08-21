use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    Error, canonical,
    identity::{Digest, ServiceId, Timestamp},
    model::Validate,
};

use super::OperationKind;

const MAX_EXACT_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum FailureStormIdentityFormat {
    #[serde(rename = "reproit.failure-storm-identity.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailureStormIdentity {
    pub failure_identity_digest: Digest,
    pub format: FailureStormIdentityFormat,
    pub operation_kind: OperationKind,
    pub operation_name: String,
    pub service_id: ServiceId,
    pub source_revision: String,
    pub subject_artifact_digest: Digest,
}

impl FailureStormIdentity {
    pub fn key(&self) -> Result<Digest, Error> {
        self.validate()?;
        canonical::digest(self)
    }
}

impl Validate for FailureStormIdentity {
    fn validate(&self) -> Result<(), Error> {
        if self.operation_name.is_empty()
            || self.operation_name.len() > 128
            || self.source_revision.is_empty()
            || self.source_revision.len() > 256
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderResourceClaim {
    pub materialized_bytes: u64,
    pub objects: u64,
    pub pinned_bytes: u64,
    pub temporary_bytes: u64,
}

impl Validate for ProviderResourceClaim {
    fn validate(&self) -> Result<(), Error> {
        validate_exact([
            self.materialized_bytes,
            self.objects,
            self.pinned_bytes,
            self.temporary_bytes,
        ])
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyLimits {
    pub active_operations: u64,
    pub candidate_bytes: u64,
    pub concurrent_close_requests: u64,
    pub cursor_lifetime_ms: u64,
    pub durable_bytes: u64,
    pub interactions_per_operation: u64,
    pub memory_bytes: u64,
    pub object_bytes: u64,
    pub sessions: u64,
}

impl Validate for DependencyLimits {
    fn validate(&self) -> Result<(), Error> {
        validate_positive([
            self.active_operations,
            self.candidate_bytes,
            self.concurrent_close_requests,
            self.cursor_lifetime_ms,
            self.durable_bytes,
            self.interactions_per_operation,
            self.memory_bytes,
            self.object_bytes,
            self.sessions,
        ])?;
        if self.active_operations > 1_024
            || self.candidate_bytes > 8_388_608
            || self.concurrent_close_requests > 8
            || self.cursor_lifetime_ms > 60_000
            || self.durable_bytes > 1_073_741_824
            || self.interactions_per_operation > 1_024
            || self.memory_bytes > 67_108_864
            || self.object_bytes > 8_388_608
            || self.sessions > 256
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

impl DependencyLimits {
    pub const V1: Self = Self {
        active_operations: 1_024,
        candidate_bytes: 8_388_608,
        concurrent_close_requests: 8,
        cursor_lifetime_ms: 60_000,
        durable_bytes: 1_073_741_824,
        interactions_per_operation: 1_024,
        memory_bytes: 67_108_864,
        object_bytes: 8_388_608,
        sessions: 256,
    };
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldHistoryLimits {
    pub environment_bytes: u64,
    pub manifest_bytes: u64,
    pub minimum_retention_ms: u64,
    pub service_bytes: u64,
}

impl Validate for WorldHistoryLimits {
    fn validate(&self) -> Result<(), Error> {
        validate_positive([
            self.environment_bytes,
            self.manifest_bytes,
            self.minimum_retention_ms,
            self.service_bytes,
        ])?;
        if self.environment_bytes > 16_777_216
            || self.manifest_bytes > 262_144
            || self.minimum_retention_ms < 7_000
            || self.service_bytes > 2_097_152
            || self.service_bytes > self.environment_bytes
            || self.manifest_bytes > self.service_bytes
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

impl WorldHistoryLimits {
    pub const V1: Self = Self {
        environment_bytes: 16_777_216,
        manifest_bytes: 262_144,
        minimum_retention_ms: 7_000,
        service_bytes: 2_097_152,
    };
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourcePreparationPolicy {
    pub build_network_bytes: u64,
    pub build_timeout_ms: u64,
    pub concurrent_jobs: u64,
    pub filesystem_entries: u64,
    pub git_lfs_bytes: u64,
    pub git_lfs_object_bytes: u64,
    pub git_lfs_objects: u64,
    pub git_network_bytes: u64,
    pub source_bytes: u64,
    pub source_timeout_ms: u64,
    pub submodule_depth: u64,
    pub submodules: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OciOperationLimits {
    pub concurrent_object_transfers: u64,
    pub control_response_bytes: u64,
    pub object_attempts: u64,
    pub redirects_per_request: u64,
    pub response_header_bytes: u64,
    pub timeout_ms: u64,
}

impl Validate for OciOperationLimits {
    fn validate(&self) -> Result<(), Error> {
        validate_positive([
            self.concurrent_object_transfers,
            self.control_response_bytes,
            self.object_attempts,
            self.redirects_per_request,
            self.response_header_bytes,
            self.timeout_ms,
        ])?;
        if self.concurrent_object_transfers > 8
            || self.control_response_bytes > 8_388_608
            || self.object_attempts > 5
            || self.redirects_per_request > 3
            || self.response_header_bytes > 32_768
            || self.timeout_ms > 1_800_000
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

impl OciOperationLimits {
    pub const V1: Self = Self {
        concurrent_object_transfers: 8,
        control_response_bytes: 8_388_608,
        object_attempts: 5,
        redirects_per_request: 3,
        response_header_bytes: 32_768,
        timeout_ms: 1_800_000,
    };
}

impl Validate for SourcePreparationPolicy {
    fn validate(&self) -> Result<(), Error> {
        validate_positive([
            self.build_network_bytes,
            self.build_timeout_ms,
            self.concurrent_jobs,
            self.filesystem_entries,
            self.git_lfs_bytes,
            self.git_lfs_object_bytes,
            self.git_lfs_objects,
            self.git_network_bytes,
            self.source_bytes,
            self.source_timeout_ms,
            self.submodule_depth,
            self.submodules,
        ])?;
        if self.build_network_bytes > 21_474_836_480
            || self.build_timeout_ms > 1_800_000
            || self.concurrent_jobs > 2
            || self.filesystem_entries > 1_000_000
            || self.git_lfs_bytes > 21_474_836_480
            || self.git_lfs_object_bytes > 2_147_483_648
            || self.git_lfs_objects > 10_000
            || self.git_network_bytes > 21_474_836_480
            || self.source_bytes > 21_474_836_480
            || self.source_timeout_ms > 600_000
            || self.submodule_depth > 4
            || self.submodules > 64
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

impl SourcePreparationPolicy {
    pub const V1: Self = Self {
        build_network_bytes: 21_474_836_480,
        build_timeout_ms: 1_800_000,
        concurrent_jobs: 2,
        filesystem_entries: 1_000_000,
        git_lfs_bytes: 21_474_836_480,
        git_lfs_object_bytes: 2_147_483_648,
        git_lfs_objects: 10_000,
        git_network_bytes: 21_474_836_480,
        source_bytes: 21_474_836_480,
        source_timeout_ms: 600_000,
        submodule_depth: 4,
        submodules: 64,
    };
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyOperationLimits {
    pub environment_operations: u64,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub service_operations: u64,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum ExecutionPolicyFormat {
    #[serde(rename = "reproit.execution-policy.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPolicy {
    pub active_grants: u64,
    pub active_grants_per_identity: u64,
    pub combined_output_bytes: u64,
    pub cleanup_timeout_ms: u64,
    pub concurrent_jobs: u64,
    pub cpu_count: u64,
    pub filesystem_entries: u64,
    pub format: ExecutionPolicyFormat,
    pub grant_idle_timeout_ms: u64,
    pub grant_lifetime_ms: u64,
    pub memory_bytes: u64,
    pub process_count: u64,
    pub readiness_timeout_ms: u64,
    pub trigger_timeout_ms: u64,
    pub unmaterialized_grants: u64,
    pub workspace_bytes: u64,
}

impl Validate for ExecutionPolicy {
    fn validate(&self) -> Result<(), Error> {
        validate_positive([
            self.active_grants,
            self.active_grants_per_identity,
            self.combined_output_bytes,
            self.cleanup_timeout_ms,
            self.concurrent_jobs,
            self.cpu_count,
            self.filesystem_entries,
            self.grant_idle_timeout_ms,
            self.grant_lifetime_ms,
            self.memory_bytes,
            self.process_count,
            self.readiness_timeout_ms,
            self.trigger_timeout_ms,
            self.unmaterialized_grants,
            self.workspace_bytes,
        ])?;
        if self.active_grants > 2
            || self.active_grants_per_identity > 1
            || self.active_grants_per_identity > self.active_grants
            || self.cleanup_timeout_ms > 60_000
            || self.combined_output_bytes > 1_048_576
            || self.concurrent_jobs > 2
            || self.cpu_count > 4
            || self.filesystem_entries > 1_000_000
            || self.grant_idle_timeout_ms > 900_000
            || self.grant_lifetime_ms > 7_200_000
            || self.memory_bytes > 8_589_934_592
            || self.process_count > 256
            || self.readiness_timeout_ms > 120_000
            || self.trigger_timeout_ms > 60_000
            || self.unmaterialized_grants > 8
            || self.workspace_bytes > 107_374_182_400
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

impl ExecutionPolicy {
    pub const V1: Self = Self {
        active_grants: 2,
        active_grants_per_identity: 1,
        combined_output_bytes: 1_048_576,
        cleanup_timeout_ms: 60_000,
        concurrent_jobs: 2,
        cpu_count: 4,
        filesystem_entries: 1_000_000,
        format: ExecutionPolicyFormat::V1,
        grant_idle_timeout_ms: 900_000,
        grant_lifetime_ms: 7_200_000,
        memory_bytes: 8_589_934_592,
        process_count: 256,
        readiness_timeout_ms: 120_000,
        trigger_timeout_ms: 60_000,
        unmaterialized_grants: 8,
        workspace_bytes: 107_374_182_400,
    };
}

impl Validate for KeyOperationLimits {
    fn validate(&self) -> Result<(), Error> {
        validate_positive([
            self.environment_operations,
            self.request_bytes,
            self.response_bytes,
            self.service_operations,
            self.timeout_ms,
        ])?;
        if self.environment_operations > 8
            || self.request_bytes > 8_192
            || self.response_bytes > 16_384
            || self.service_operations > 2
            || self.service_operations > self.environment_operations
            || self.timeout_ms > 5_000
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

impl KeyOperationLimits {
    pub const V1: Self = Self {
        environment_operations: 8,
        request_bytes: 8_192,
        response_bytes: 16_384,
        service_operations: 2,
        timeout_ms: 5_000,
    };
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum WorldTokenFormat {
    #[serde(rename = "reproit.world-token.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldToken {
    pub expires_in_ms: u64,
    pub format: WorldTokenFormat,
    pub world_id: Digest,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactReference {
    pub digest: Digest,
    pub media_type: String,
    pub size: u64,
    pub uri: String,
}

impl Validate for ArtifactReference {
    fn validate(&self) -> Result<(), Error> {
        if self.media_type.is_empty()
            || self.media_type.len() > 256
            || self.uri.is_empty()
            || self.uri.len() > 2_048
            || self.size > 274_878_824_448
            || self
                .media_type
                .bytes()
                .chain(self.uri.bytes())
                .any(|byte| byte.is_ascii_control())
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeRule {
    pub boundary_schema_digest: Digest,
    pub end_inclusive: Option<String>,
    pub namespace: String,
    pub start_inclusive: Option<String>,
}

impl Validate for ScopeRule {
    fn validate(&self) -> Result<(), Error> {
        if self.namespace.is_empty()
            || self.namespace.len() > 512
            || !valid_optional_base64url(self.end_inclusive.as_deref())
            || !valid_optional_base64url(self.start_inclusive.as_deref())
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckpointScopeKind {
    Full,
    Scoped,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointScope {
    pub kind: CheckpointScopeKind,
    pub rules: Vec<ScopeRule>,
}

impl Validate for CheckpointScope {
    fn validate(&self) -> Result<(), Error> {
        if self.rules.len() > 1_024
            || matches!(self.kind, CheckpointScopeKind::Full) && !self.rules.is_empty()
            || matches!(self.kind, CheckpointScopeKind::Scoped) && self.rules.is_empty()
        {
            return Err(Error::schema_invalid());
        }
        self.rules.iter().try_for_each(Validate::validate)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum RecoverablePointFormat {
    #[serde(rename = "reproit.recoverable-point.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverablePoint {
    pub artifacts: Vec<ArtifactReference>,
    pub capabilities: Vec<String>,
    pub configuration_digest: Digest,
    pub engine_identity: String,
    pub engine_version: String,
    pub format: RecoverablePointFormat,
    pub generation: u64,
    pub point: String,
    pub provider_id: String,
    pub published_at: Timestamp,
    pub recoverable_until: Timestamp,
    pub resource_claim: ProviderResourceClaim,
    pub scope: CheckpointScope,
}

impl Validate for RecoverablePoint {
    fn validate(&self) -> Result<(), Error> {
        if self.artifacts.len() > 32_767
            || self.capabilities.len() > 64
            || self.engine_identity.is_empty()
            || self.engine_identity.len() > 256
            || self.engine_version.is_empty()
            || self.engine_version.len() > 128
            || self.generation == 0
            || self.generation > MAX_EXACT_INTEGER
            || self.point.is_empty()
            || self.point.len() > 16_384
            || !valid_base64url(&self.point)
            || !valid_component(&self.provider_id)
            || self.published_at > self.recoverable_until
        {
            return Err(Error::schema_invalid());
        }
        let mut capabilities = BTreeSet::new();
        if self
            .capabilities
            .iter()
            .any(|value| !valid_component(value) || !capabilities.insert(value))
        {
            return Err(Error::schema_invalid());
        }
        self.resource_claim.validate()?;
        self.scope.validate()?;
        self.artifacts.iter().try_for_each(Validate::validate)?;
        let bytes = self.artifacts.iter().try_fold(0_u64, |total, artifact| {
            total
                .checked_add(artifact.size)
                .ok_or_else(Error::schema_invalid)
        })?;
        if bytes > self.resource_claim.pinned_bytes
            || u64::try_from(self.artifacts.len()).map_err(|_| Error::schema_invalid())?
                > self.resource_claim.objects
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum WorldCheckpointFormat {
    #[serde(rename = "reproit.world-checkpoint.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldCheckpoint {
    pub created_at: Timestamp,
    pub format: WorldCheckpointFormat,
    pub points: Vec<RecoverablePoint>,
}

impl WorldCheckpoint {
    pub fn world_id(&self) -> Result<Digest, Error> {
        self.validate()?;
        canonical::digest(self)
    }
}

impl Validate for WorldCheckpoint {
    fn validate(&self) -> Result<(), Error> {
        if self.points.len() > 64 {
            return Err(Error::schema_invalid());
        }
        let mut providers = BTreeSet::new();
        for point in &self.points {
            point.validate()?;
            if point.published_at > self.created_at || !providers.insert(&point.provider_id) {
                return Err(Error::schema_invalid());
            }
        }
        let manifest_bytes = usize::try_from(WorldHistoryLimits::V1.manifest_bytes)
            .map_err(|_| Error::schema_invalid())?;
        if canonical::canonical_bytes(self)?.len() > manifest_bytes {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

impl Validate for WorldToken {
    fn validate(&self) -> Result<(), Error> {
        if self.expires_in_ms != 5_000 {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

fn validate_positive<const N: usize>(values: [u64; N]) -> Result<(), Error> {
    validate_exact(values)?;
    if values.contains(&0) {
        return Err(Error::schema_invalid());
    }
    Ok(())
}

fn validate_exact<const N: usize>(values: [u64; N]) -> Result<(), Error> {
    if values.into_iter().any(|value| value > MAX_EXACT_INTEGER) {
        return Err(Error::schema_invalid());
    }
    Ok(())
}

fn valid_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_lowercase()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
}

fn valid_base64url(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn valid_optional_base64url(value: Option<&str>) -> bool {
    value.is_none_or(|value| !value.is_empty() && valid_base64url(value))
}

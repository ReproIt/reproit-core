use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    Error,
    error::ErrorCode,
    identity::{
        CaptureId, Digest, ObjectId, OperationId, OrganizationId, ProjectId, ServiceId, Timestamp,
    },
};

mod capsule;
mod debugger;
mod environment;
mod execution;
mod executor;
mod key_provider;
mod managed_candidate;
mod observation_fence;
mod processor;
mod processor_capture;
mod profile;
mod resources;
mod semantic_observation;
mod staging;
mod subject;

pub use capsule::{
    DEPENDENCY_TRANSCRIPT_MEDIA_TYPE, FAILURE_MEDIA_TYPE, MAX_MANIFEST_OBJECT_BYTES,
    ResolvedDependencyTranscript, ResolvedInteraction, ResolvedReplayCapsule,
    ResolvedWorldArtifact, SUBJECT_CLOSURE_MEDIA_TYPE, TRIGGER_MEDIA_TYPE,
    WORLD_MANIFEST_MEDIA_TYPE, resolve_replay_capsule,
};
pub use debugger::{
    DebuggerContract, DebuggerContractFormat, DebuggerProtocol, DebuggerReadinessRule,
    DebuggerSourceMapping,
};
pub use environment::{
    EnvironmentKeepReference, EnvironmentPolicy, EnvironmentPolicyFormat, EnvironmentPolicyScope,
    EnvironmentReplayHost, ReplayHostOperation, environment_policy_verification_key,
    verify_environment_policy,
};
pub use execution::{ExecutionOutcome, ExecutionResult, ExecutionResultFormat};
pub use executor::{
    ExecutionGrant, ExecutionGrantExpectation, ExecutionGrantFormat, ExecutionGrantOperation,
    ExecutionWorkClass, ExecutorCapabilityEvidence, ExecutorCapabilityEvidenceFormat,
    ExecutorEvidenceScope, ExecutorEvidenceStatus, ExecutorLocality, debugger_protocol_capability,
    replay_capabilities_present, required_capabilities_present, verify_evidence_signature,
    verify_execution_grant, verify_executor_capability_evidence, verify_replay_capabilities,
};
pub use key_provider::{
    AdmissionVerificationKey, AdmissionVerificationKeyFormat, AdmissionVerificationKeyRequest,
    AdmissionVerificationKeyRequestFormat, validate_admission_verification_key,
};
pub use managed_candidate::{
    CandidateCipherSuite, ManagedCandidateCaptureGrant, ManagedCandidateCaptureGrantExpectation,
    ManagedCandidateCaptureGrantFormat, ManagedCandidateCaptureOperation,
    ManagedCandidateCiphertextIdentity, ManagedCandidateCiphertextIdentityFormat,
    ManagedCandidateIdentity, ManagedCandidateIdentityFormat, ManagedCandidateManifest,
    ManagedCandidateManifestFormat, verify_managed_candidate_capture_grant,
};
pub use observation_fence::{
    AutomaticObservationClass, AutomaticObservationPayload, AutomaticObservationPayloadFormat,
    NativeObservationFenceReceipt, NativeObservationFenceReceiptFormat, SemanticAdapterOwnership,
    verify_automatic_capture,
};
pub use processor::{
    ArmProcessorIdentity, ProcessorArchitecture, ProcessorIdentity, ProcessorObservation,
    ProcessorObservationFormat, ProcessorReductionDecision, ProcessorReductionReceipt,
    ProcessorReductionReceiptFormat, ProcessorReductionTerminalReason, ProcessorReductionTrial,
    ProcessorRequirement, ProcessorRequirementFormat, ProcessorTrialEvidenceKind,
    X86ProcessorIdentity, capsules_equal_except_processor_capabilities,
    processor_reduction_capability, processor_requirement_capabilities,
    validate_processor_reduction_capsule_binding,
};
pub use processor_capture::{
    PROCESSOR_FEATURE_PREFIX, PROCESSOR_IDENTITY_PREFIX, PROCESSOR_OS_STATE_PREFIX,
    ProcessorCapture, capability_suffix, capture_processor_capabilities, decode_identity_token,
    encode_identity_token, identity_token, parse_auxv_hwcap, processor_capture_abi,
    valid_captured_processor_capability,
};
pub use profile::{
    ComponentIdentity, ComponentKind, KeptReference, SupportBundle, SupportBundleFormat,
    SupportRegistry, SupportRegistryFormat, SupportedProfile, VerifiedSupportRegistry,
    verify_support_registry,
};
pub use resources::{
    ArtifactReference, CheckpointScope, CheckpointScopeKind, DependencyLimits, ExecutionPolicy,
    ExecutionPolicyFormat, FailureStormIdentity, FailureStormIdentityFormat, KeyOperationLimits,
    OciOperationLimits, ProviderResourceClaim, RecoverablePoint, RecoverablePointFormat, ScopeRule,
    SourcePreparationPolicy, WorldCheckpoint, WorldCheckpointFormat, WorldHistoryLimits,
    WorldToken, WorldTokenFormat,
};
pub use semantic_observation::{
    MAX_SEMANTIC_OBSERVATION_TARGET_BYTES, MAX_SEMANTIC_OBSERVATION_VALUE_BYTES,
    SemanticObservationErrorCode, SemanticObservationOperation, SemanticObservationOutcome,
    SemanticObservationRequest, SemanticObservationRequestFormat, SemanticObservationResponse,
    SemanticObservationResponseFormat, semantic_observation_value,
    validate_semantic_observation_pair,
};
pub use staging::{
    CANDIDATE_MAILBOX_MEDIA_TYPE, CandidateDurability, CandidateMailboxFormat,
    CandidateMailboxItem, CandidateMailboxObject, CandidateMailboxPayload,
    CandidateStagingEnvelope, CandidateStagingFormat, CandidateStagingIdentity,
    CandidateStagingIdentityFormat, CandidateStagingReceipt,
};
pub use subject::{
    DebugArtifactBinding, DebugArtifactKind, SubjectClosureFormat, SubjectClosureManifest,
    SubjectClosureObject, SubjectFile, SubjectLaunch, SubjectModule, SubjectObjectKind,
    SubjectRuntimeFamily,
};
pub trait Validate {
    fn validate(&self) -> Result<(), Error>;
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProcessingMode {
    Managed,
    Private,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum AuthenticationContextFormat {
    #[serde(rename = "reproit.authentication-context.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticationContext {
    pub audience: String,
    pub format: AuthenticationContextFormat,
    pub issuer: String,
    pub service_id: ServiceId,
    pub subject: String,
}

impl Validate for AuthenticationContext {
    fn validate(&self) -> Result<(), Error> {
        if self.audience != "reproit-runtime"
            || self.issuer.is_empty()
            || self.issuer.len() > 512
            || self.subject.is_empty()
            || self.subject.len() > 512
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum SubjectFormat {
    #[serde(rename = "reproit.subject.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Subject {
    pub architecture: String,
    pub arguments: Vec<String>,
    pub artifact_digest: Digest,
    pub artifact_media_type: String,
    pub artifact_uri: String,
    pub environment_names: Vec<String>,
    pub executable: String,
    pub format: SubjectFormat,
    pub operating_system: String,
    pub working_directory: String,
}

impl Validate for Subject {
    fn validate(&self) -> Result<(), Error> {
        if self.arguments.len() > 128
            || self.arguments.iter().any(|argument| argument.len() > 4_096)
            || self.environment_names.len() > 256
            || self.architecture.is_empty()
            || self.artifact_media_type.is_empty()
            || self.artifact_media_type.len() > 128
            || self.artifact_uri.is_empty()
            || self.artifact_uri.len() > 2_048
            || self.executable.is_empty()
            || self.executable.len() > 4_096
            || self.operating_system.is_empty()
            || self.working_directory.is_empty()
            || self.working_directory.len() > 4_096
        {
            return Err(Error::schema_invalid());
        }
        validate_capabilities(std::slice::from_ref(&self.architecture))?;
        validate_capabilities(std::slice::from_ref(&self.operating_system))?;
        require_strict_order(self.environment_names.iter().cloned())?;
        if self
            .environment_names
            .iter()
            .any(|name| !valid_environment_name(name))
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

pub(super) fn valid_environment_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && name
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'=')
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum DeploymentFormat {
    #[serde(rename = "reproit.deployment.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deployment {
    pub format: DeploymentFormat,
    pub organization_id: OrganizationId,
    pub processing_mode: ProcessingMode,
    pub project_id: ProjectId,
    pub repository_id: String,
    pub runtime_capabilities: Vec<String>,
    pub runtime_endpoint: String,
    pub service_id: ServiceId,
    pub service_path: String,
    pub signature: String,
    pub signed_at: Timestamp,
    pub signer_key_id: String,
    pub source_revision: String,
    pub subject: Subject,
}

impl Validate for Deployment {
    fn validate(&self) -> Result<(), Error> {
        if self.repository_id.is_empty()
            || self.repository_id.len() > 256
            || self.runtime_endpoint.is_empty()
            || self.runtime_endpoint.len() > 2_048
            || self.service_path.is_empty()
            || self.service_path.starts_with('/')
            || self.service_path.split('/').any(|part| part == "..")
            || self.signer_key_id.is_empty()
            || self.signer_key_id.len() > 256
            || self.source_revision.is_empty()
            || self.source_revision.len() > 256
        {
            return Err(Error::schema_invalid());
        }
        validate_capabilities(&self.runtime_capabilities)?;
        self.subject.validate()?;
        crate::crypto::decode_base64url::<64>(&self.signature)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum LogicalObjectRole {
    #[serde(rename = "admission-proof")]
    AdmissionProof,
    #[serde(rename = "candidate")]
    Candidate,
    #[serde(rename = "capture-batch-manifest")]
    CaptureBatchManifest,
    #[serde(rename = "debug-symbols")]
    DebugSymbols,
    #[serde(rename = "dependency-transcript")]
    DependencyTranscript,
    #[serde(rename = "failure")]
    Failure,
    #[serde(rename = "replay-capsule-manifest")]
    ReplayCapsuleManifest,
    #[serde(rename = "subject")]
    Subject,
    #[serde(rename = "trigger")]
    Trigger,
    #[serde(rename = "world-manifest")]
    WorldManifest,
    #[serde(rename = "world-state")]
    WorldState,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalObject {
    pub media_type: String,
    pub object_id: ObjectId,
    pub plain_digest: Digest,
    pub plain_size: u64,
    pub role: LogicalObjectRole,
}

impl Validate for LogicalObject {
    fn validate(&self) -> Result<(), Error> {
        if self.media_type.is_empty()
            || self.media_type.len() > 128
            || self.plain_size > 274_878_824_448
            || self.role == LogicalObjectRole::CaptureBatchManifest
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum ReplayCapsuleFormat {
    #[serde(rename = "reproit.replay-capsule.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayCapsule {
    pub closure_manifest_digest: Digest,
    pub failure_digest: Digest,
    pub format: ReplayCapsuleFormat,
    pub objects: Vec<LogicalObject>,
    pub perturbation_suite: String,
    pub processing_mode: ProcessingMode,
    pub profile: String,
    pub profile_format: u64,
    pub required_capabilities: Vec<String>,
    pub subject: Subject,
    pub subject_digest: Digest,
    pub support_bundle_digest: Digest,
    pub trigger_digest: Digest,
    pub world_digest: Digest,
}

impl Validate for ReplayCapsule {
    fn validate(&self) -> Result<(), Error> {
        if self.objects.is_empty()
            || self.objects.len() > 32_767
            || self.perturbation_suite != "reproit.controlled-perturbation.v1"
            || !valid_lower_identity(self.profile.as_bytes())
            || self.profile.len() > 128
            || !(1..=9_007_199_254_740_991).contains(&self.profile_format)
        {
            return Err(Error::schema_invalid());
        }
        for object in &self.objects {
            object.validate()?;
            // A sealed capsule holds only replayable payload objects. The
            // candidate record is dropped at closure, proofs and the capsule
            // manifest live in the capture batch, and debug artifacts travel
            // inside the subject closure.
            if matches!(
                object.role,
                LogicalObjectRole::AdmissionProof
                    | LogicalObjectRole::Candidate
                    | LogicalObjectRole::DebugSymbols
                    | LogicalObjectRole::ReplayCapsuleManifest
            ) {
                return Err(Error::schema_invalid());
            }
        }
        self.validate_closure_shape()?;
        self.subject.validate()?;
        if self.subject.artifact_digest != self.subject_digest
            || self.subject.artifact_media_type != SUBJECT_CLOSURE_MEDIA_TYPE
        {
            return Err(Error::new(
                ErrorCode::SubjectDigestMismatch,
                "The subject descriptor does not match the replay capsule.",
            ));
        }
        require_strict_order(
            self.objects
                .iter()
                .map(|object| object.object_id.to_string()),
        )?;
        validate_capabilities(&self.required_capabilities)
    }
}

impl ReplayCapsule {
    /// A sealed capsule is closure-shaped: exactly one subject-closure
    /// manifest bound to the capsule subject digest, exactly one Trigger
    /// descriptor bound to the trigger digest, exactly one Failure payload,
    /// exactly one World manifest, and at most one dependency-transcript
    /// manifest. The capsule resolver enforces the referential rules; this
    /// check pins the shape wherever a capsule document is validated.
    fn validate_closure_shape(&self) -> Result<(), Error> {
        let count = |select: &dyn Fn(&LogicalObject) -> bool| {
            self.objects.iter().filter(|object| select(object)).count()
        };
        let subject_manifests = count(&|object: &LogicalObject| {
            object.role == LogicalObjectRole::Subject
                && object.media_type == SUBJECT_CLOSURE_MEDIA_TYPE
                && object.plain_digest == self.subject_digest
        });
        let trigger_descriptors = count(&|object: &LogicalObject| {
            object.role == LogicalObjectRole::Trigger
                && object.media_type == TRIGGER_MEDIA_TYPE
                && object.plain_digest == self.trigger_digest
        });
        let failures = count(&|object: &LogicalObject| {
            object.role == LogicalObjectRole::Failure && object.media_type == FAILURE_MEDIA_TYPE
        });
        let world_manifests = count(&|object: &LogicalObject| {
            object.role == LogicalObjectRole::WorldManifest
                && object.media_type == WORLD_MANIFEST_MEDIA_TYPE
        });
        let transcript_manifests = count(&|object: &LogicalObject| {
            object.role == LogicalObjectRole::DependencyTranscript
                && object.media_type == DEPENDENCY_TRANSCRIPT_MEDIA_TYPE
        });
        if subject_manifests != 1
            || trigger_descriptors != 1
            || failures != 1
            || world_manifests != 1
            || transcript_manifests > 1
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum ProofFormat {
    #[serde(rename = "reproit.proof.v1")]
    V1,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum ExecutionResultKind {
    #[serde(rename = "TARGET_REPRODUCED")]
    TargetReproduced,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub capsule_digest: Digest,
    pub executor_capabilities_digest: Digest,
    pub failure_digest: Digest,
    pub format: ProofFormat,
    pub perturbation_digest: Digest,
    pub processing_mode: ProcessingMode,
    pub result: ExecutionResultKind,
    pub run_index: u8,
    pub subject_digest: Digest,
    pub trigger_digest: Digest,
    pub world_digest: Digest,
}

impl Validate for Proof {
    fn validate(&self) -> Result<(), Error> {
        if self.run_index > 2 {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum PerturbationFormat {
    #[serde(rename = "reproit.perturbation.v1")]
    V1,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum PerturbationCase {
    #[serde(rename = "baseline")]
    Baseline,
    #[serde(rename = "cold-ambient")]
    ColdAmbient,
    #[serde(rename = "timing-ambient")]
    TimingAmbient,
}

impl PerturbationCase {
    pub const fn run_index(self) -> u8 {
        match self {
            Self::Baseline => 0,
            Self::ColdAmbient => 1,
            Self::TimingAmbient => 2,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Perturbation {
    pub ambient_identity_digest: Digest,
    pub case: PerturbationCase,
    pub format: PerturbationFormat,
    pub run_index: u8,
    pub suite: String,
}

impl Validate for Perturbation {
    fn validate(&self) -> Result<(), Error> {
        if self.run_index != self.case.run_index()
            || self.suite != "reproit.controlled-perturbation.v1"
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClosureMechanism {
    Blocked,
    ExactTranscript,
    FixedExecutorCapability,
    ImmutableObject,
    VerifiedSimulator,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObservationClass {
    ClockRandomIdentity,
    Device,
    FilesystemEnvironment,
    NetworkIpcSignal,
    OperatingSystemHardware,
    OrderingConcurrency,
    StateService,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClosureRule {
    pub allowed_mechanisms: Vec<ClosureMechanism>,
    pub boundary_id: String,
    pub observation_class: ObservationClass,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClosureReceipt {
    pub boundary_id: String,
    pub evidence_digest: Digest,
    pub mechanism: ClosureMechanism,
    pub observation_class: ObservationClass,
    pub version: u64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum ClosurePolicyFormat {
    #[serde(rename = "reproit.closure-policy.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClosurePolicy {
    pub format: ClosurePolicyFormat,
    pub rules: Vec<ClosureRule>,
}

impl Validate for ClosurePolicy {
    fn validate(&self) -> Result<(), Error> {
        if self.rules.is_empty() || self.rules.len() > 256 {
            return Err(Error::schema_invalid());
        }
        require_strict_order(self.rules.iter().map(|rule| rule.boundary_id.clone()))?;
        for rule in &self.rules {
            if !valid_boundary_id(&rule.boundary_id)
                || rule.allowed_mechanisms.is_empty()
                || rule.allowed_mechanisms.len() > 5
            {
                return Err(Error::schema_invalid());
            }
            let unique = rule
                .allowed_mechanisms
                .iter()
                .copied()
                .collect::<BTreeSet<_>>();
            if unique.len() != rule.allowed_mechanisms.len() {
                return Err(Error::schema_invalid());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum WorldClosureFormat {
    #[serde(rename = "reproit.world-closure.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldClosure {
    pub format: WorldClosureFormat,
    pub policy_digest: Digest,
    pub receipts: Vec<ClosureReceipt>,
}

impl Validate for WorldClosure {
    fn validate(&self) -> Result<(), Error> {
        if self.receipts.is_empty() || self.receipts.len() > 256 {
            return Err(Error::schema_invalid());
        }
        require_strict_order(
            self.receipts
                .iter()
                .map(|receipt| receipt.boundary_id.clone()),
        )?;
        if self.receipts.iter().any(|receipt| {
            !valid_boundary_id(&receipt.boundary_id)
                || receipt.version == 0
                || receipt.version > 9_007_199_254_740_991
        }) {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

fn valid_boundary_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit() && index > 0
                || matches!(byte, b'.' | b'-') && index > 0
        })
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedChunk {
    pub cipher_digest: Digest,
    pub cipher_size: u64,
    pub index: u32,
    pub nonce: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedObject {
    pub chunks: Vec<EncryptedChunk>,
    pub descriptor: LogicalObject,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum CaptureBatchFormat {
    #[serde(rename = "reproit.capture-batch.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureBatchManifest {
    pub capture_id: CaptureId,
    pub encryption_context_version: u8,
    pub format: CaptureBatchFormat,
    pub objects: Vec<EncryptedObject>,
    pub organization_id: OrganizationId,
    pub processing_mode: ProcessingMode,
    pub profile: String,
    pub profile_format: u64,
    pub project_id: ProjectId,
    pub proof_digests: Vec<Digest>,
    pub replay_capsule_digest: Digest,
    pub replay_capsule_object_id: ObjectId,
    pub repository_id: String,
    pub required_capabilities: Vec<String>,
    pub service_id: ServiceId,
    pub service_path: String,
    pub source_revision: String,
}

impl Validate for CaptureBatchManifest {
    fn validate(&self) -> Result<(), Error> {
        if self.encryption_context_version != 1
            || !valid_lower_identity(self.profile.as_bytes())
            || self.profile.len() > 128
            || !(1..=9_007_199_254_740_991).contains(&self.profile_format)
            || self.objects.len() < 4
            || self.objects.len() > 32_768
            || self.proof_digests.len() != 3
            || self.proof_digests.iter().collect::<BTreeSet<_>>().len() != 3
        {
            return Err(Error::schema_invalid());
        }
        require_strict_order(
            self.objects
                .iter()
                .map(|object| object.descriptor.object_id.to_string()),
        )?;
        validate_capabilities(&self.required_capabilities)?;
        for object in &self.objects {
            object.descriptor.validate()?;
            validate_chunks(&object.chunks)?;
        }
        let chunk_count = self.objects.iter().try_fold(1_usize, |count, object| {
            count
                .checked_add(object.chunks.len())
                .ok_or_else(Error::schema_invalid)
        })?;
        if chunk_count > 32_768 || crate::canonical::canonical_bytes(self)?.len() > 8_388_608 {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum CaptureBatchIdentityFormat {
    #[serde(rename = "reproit.capture-batch-identity.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadObject {
    pub cipher_digest: Digest,
    pub cipher_size: u64,
    pub nonce: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestUploadObject {
    pub cipher_digest: Digest,
    pub cipher_size: u64,
    pub nonce: String,
    pub object_id: ObjectId,
}

impl Validate for ManifestUploadObject {
    fn validate(&self) -> Result<(), Error> {
        UploadObject {
            cipher_digest: self.cipher_digest,
            cipher_size: self.cipher_size,
            nonce: self.nonce.clone(),
        }
        .validate()
    }
}

impl Validate for UploadObject {
    fn validate(&self) -> Result<(), Error> {
        if !(28..=8_388_636).contains(&self.cipher_size)
            || self.nonce.len() != 16
            || !self
                .nonce
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureBatchIdentity {
    pub capture_id: CaptureId,
    pub cipher_suite: String,
    pub format: CaptureBatchIdentityFormat,
    pub manifest_object: ManifestUploadObject,
    pub objects: Vec<UploadObject>,
    pub processing_mode: ProcessingMode,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionAttestation {
    pub proof_digests: Vec<Digest>,
    pub run_count: u8,
    pub signer_key_id: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WrappedKey {
    pub algorithm: String,
    pub context_version: u8,
    pub key_reference: String,
    pub provider_id: String,
    pub wrapped_bytes: String,
}

impl Validate for WrappedKey {
    fn validate(&self) -> Result<(), Error> {
        if self.algorithm.is_empty()
            || self.algorithm.len() > 128
            || self.context_version != 1
            || self.key_reference.is_empty()
            || self.key_reference.len() > 2_048
            || self.provider_id.is_empty()
            || self.provider_id.len() > 256
            || self.wrapped_bytes.is_empty()
            || self.wrapped_bytes.len() > 16_384
        {
            return Err(Error::schema_invalid());
        }
        crate::crypto::decode_base64url_bytes(&self.wrapped_bytes)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum UploadEnvelopeFormat {
    #[serde(rename = "reproit.upload.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadEnvelope {
    pub admission: AdmissionAttestation,
    pub capture_batch_digest: Digest,
    pub capture_id: CaptureId,
    pub cipher_suite: String,
    pub failure_fingerprint: String,
    pub failure_summary: FailureSummary,
    pub format: UploadEnvelopeFormat,
    pub manifest_object: ManifestUploadObject,
    pub objects: Vec<UploadObject>,
    pub organization_id: OrganizationId,
    pub processing_mode: ProcessingMode,
    pub profile: String,
    pub profile_format: u64,
    pub project_id: ProjectId,
    pub replay_capsule_digest: Digest,
    pub required_capabilities: Vec<String>,
    pub service_id: ServiceId,
    pub signature: String,
    pub signed_at: Timestamp,
    pub source_revision: String,
    pub trigger_summary: TriggerSummary,
    pub wrapped_key: WrappedKey,
}

impl Validate for UploadEnvelope {
    fn validate(&self) -> Result<(), Error> {
        if self.admission.proof_digests.len() != 3
            || self
                .admission
                .proof_digests
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != 3
            || self.admission.run_count != 3
            || self.admission.signer_key_id.is_empty()
            || self.admission.signer_key_id.len() > 256
            || self.cipher_suite != "AES-256-GCM+HKDF-SHA-256"
            || !valid_failure_fingerprint(&self.failure_fingerprint)
            || !valid_lower_identity(self.profile.as_bytes())
            || self.profile.len() > 128
            || !(1..=9_007_199_254_740_991).contains(&self.profile_format)
            || self.source_revision.is_empty()
            || self.source_revision.len() > 256
        {
            return Err(Error::schema_invalid());
        }
        validate_capabilities(&self.required_capabilities)?;
        self.failure_summary
            .validate_for_mode(self.processing_mode)?;
        self.trigger_summary
            .validate_for_mode(self.processing_mode)?;
        crate::crypto::decode_base64url::<64>(&self.signature)?;
        self.wrapped_key.validate()?;
        let identity = CaptureBatchIdentity {
            capture_id: self.capture_id,
            cipher_suite: self.cipher_suite.clone(),
            format: CaptureBatchIdentityFormat::V1,
            manifest_object: self.manifest_object.clone(),
            objects: self.objects.clone(),
            processing_mode: self.processing_mode,
        };
        identity.validate()?;
        if crate::canonical::canonical_bytes(self)?.len() > 8_388_608 {
            return Err(Error::schema_invalid());
        }
        if crate::canonical::digest(&identity)? != self.capture_batch_digest {
            return Err(Error::object_digest_mismatch());
        }
        Ok(())
    }
}

impl UploadEnvelope {
    pub fn manifest_object_context(&self) -> ObjectKeyContext {
        ObjectKeyContext {
            capture_batch_format: "reproit.capture-batch.v1".to_owned(),
            capture_id: self.capture_id,
            format: ObjectKeyContextFormat::V1,
            object_id: self.manifest_object.object_id,
            organization_id: self.organization_id,
            processing_mode: self.processing_mode,
            project_id: self.project_id,
            role: LogicalObjectRole::CaptureBatchManifest,
            service_id: self.service_id,
        }
    }

    pub fn manifest_chunk_context(&self) -> Result<ChunkKeyContext, Error> {
        let object_context_digest = crate::canonical::digest(&self.manifest_object_context())?;
        Ok(ChunkKeyContext {
            chunk_count: 1,
            chunk_index: 0,
            format: ChunkKeyContextFormat::V1,
            object_context_digest,
            plain_size: self
                .manifest_object
                .cipher_size
                .checked_sub(28)
                .ok_or_else(Error::schema_invalid)?,
        })
    }
}

pub fn validate_manifest_binding(
    manifest: &CaptureBatchManifest,
    manifest_object: &ManifestUploadObject,
    replay_capsule_digest: Digest,
) -> Result<(), Error> {
    manifest.validate()?;
    manifest_object.validate()?;
    if manifest.replay_capsule_digest != replay_capsule_digest
        || manifest
            .objects
            .iter()
            .any(|object| object.descriptor.object_id == manifest_object.object_id)
    {
        return Err(Error::schema_invalid());
    }
    Ok(())
}

impl Validate for CaptureBatchIdentity {
    fn validate(&self) -> Result<(), Error> {
        if self.cipher_suite != "AES-256-GCM+HKDF-SHA-256"
            || self.objects.len() < 4
            || self.objects.len() > 32_767
        {
            return Err(Error::schema_invalid());
        }
        self.manifest_object.validate()?;
        let ciphertext_bytes = self
            .objects
            .iter()
            .try_fold(self.manifest_object.cipher_size, |total, object| {
                total.checked_add(object.cipher_size)
            });
        if ciphertext_bytes.is_none_or(|total| total > 274_878_824_448) {
            return Err(Error::schema_invalid());
        }
        let mut nonces = BTreeSet::from([self.manifest_object.nonce.as_str()]);
        let mut previous: Option<(Digest, &str)> = None;
        for object in &self.objects {
            object.validate()?;
            if !nonces.insert(object.nonce.as_str()) {
                return Err(crate::Error::new(
                    crate::ErrorCode::NonceReuse,
                    "An occurrence cannot reuse an encryption nonce.",
                ));
            }
            let current = (object.cipher_digest, object.nonce.as_str());
            if previous.is_some_and(|prior| prior >= current) {
                return Err(Error::schema_invalid());
            }
            previous = Some(current);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum ObjectKeyContextFormat {
    #[serde(rename = "reproit.object-key-context.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectKeyContext {
    pub capture_batch_format: String,
    pub capture_id: CaptureId,
    pub format: ObjectKeyContextFormat,
    pub object_id: ObjectId,
    pub organization_id: OrganizationId,
    pub processing_mode: ProcessingMode,
    pub project_id: ProjectId,
    pub role: LogicalObjectRole,
    pub service_id: ServiceId,
}

impl Validate for ObjectKeyContext {
    fn validate(&self) -> Result<(), Error> {
        if self.capture_batch_format != "reproit.capture-batch.v1" {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum ChunkKeyContextFormat {
    #[serde(rename = "reproit.chunk-key-context.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChunkKeyContext {
    pub chunk_count: u32,
    pub chunk_index: u32,
    pub format: ChunkKeyContextFormat,
    pub object_context_digest: Digest,
    pub plain_size: u64,
}

impl Validate for ChunkKeyContext {
    fn validate(&self) -> Result<(), Error> {
        if self.chunk_count == 0
            || self.chunk_count > 32_767
            || self.chunk_index >= self.chunk_count
            || self.plain_size > 8_388_608
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

include!("failure.rs");

pub(super) fn validate_capabilities(capabilities: &[String]) -> Result<(), Error> {
    if capabilities.len() > 64 {
        return Err(Error::schema_invalid());
    }
    require_strict_order(capabilities.iter().cloned())?;
    if capabilities.iter().any(|capability| {
        capability.is_empty()
            || capability.len() > 128
            || !valid_lower_identity(capability.as_bytes())
    }) {
        return Err(Error::schema_invalid());
    }
    Ok(())
}

pub(super) fn valid_lower_identity(bytes: &[u8]) -> bool {
    bytes.first().is_some_and(u8::is_ascii_lowercase)
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
}

fn valid_failure_fingerprint(value: &str) -> bool {
    value.strip_prefix("hmac-sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn validate_chunks(chunks: &[EncryptedChunk]) -> Result<(), Error> {
    if chunks.is_empty() || chunks.len() > 32_767 {
        return Err(Error::schema_invalid());
    }
    for (index, chunk) in chunks.iter().enumerate() {
        let expected_index = u32::try_from(index).map_err(|_| Error::schema_invalid())?;
        if chunk.index != expected_index
            || !(28..=8_388_636).contains(&chunk.cipher_size)
            || chunk.nonce.len() != 16
        {
            return Err(Error::schema_invalid());
        }
    }
    Ok(())
}

pub(super) fn require_strict_order<I>(values: I) -> Result<(), Error>
where
    I: IntoIterator<Item = String>,
{
    let mut previous: Option<String> = None;
    for value in values {
        if previous.as_ref().is_some_and(|prior| prior >= &value) {
            return Err(Error::schema_invalid());
        }
        previous = Some(value);
    }
    Ok(())
}

#[cfg(test)]
mod environment_name_tests {
    use super::valid_environment_name;

    #[test]
    fn exact_process_environment_names_allow_ascii_graphic_characters_except_equals() {
        assert!(valid_environment_name("CARGO_BIN_EXE_reproit-fixture"));
        assert!(valid_environment_name("1.RUNTIME-NAME"));
        assert!(!valid_environment_name("TOKEN=secret"));
        assert!(!valid_environment_name("LINE\nBREAK"));
        assert!(!valid_environment_name("NON_ASCII_é"));
    }
}

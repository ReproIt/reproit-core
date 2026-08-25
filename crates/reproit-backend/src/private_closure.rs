//! Private-mode candidate closure and capsule sealing.
//!
//! The private Runtime owns cross-record completeness and provider closure.
//! This module turns one accepted private candidate plus its provider-closed
//! byte sources into the one canonical closure-shaped sealed replay capsule.
//! Admission and debugging execute that sealed manifest and never rebuild it
//! from the candidate. Managed mode closes the same shape from SDK-shipped
//! objects in `closure::close_replay_capsule`, which this module also uses,
//! so both processing modes share one closure meaning.

use std::collections::BTreeMap;

use reproit_core::{
    Error, ErrorCode, canonical,
    identity::{Digest, ObjectId},
    model::{
        Candidate, DEPENDENCY_TRANSCRIPT_MEDIA_TYPE, DependencyCursorPayload, DependencyOutcome,
        DependencyTranscript, DependencyTranscriptFormat, DependencyTranscriptInteraction,
        EventKind, FAILURE_MEDIA_TYPE, FailurePayload, LogicalObject, LogicalObjectRole,
        OperationBeginPayload, OperationInputPayload, OperationKind, ReplayCapsule,
        SUBJECT_CLOSURE_MEDIA_TYPE, SubjectRuntimeFamily, TRIGGER_MEDIA_TYPE, Trigger,
        TriggerCompletion, TriggerFormat, TriggerInput, Validate as _, WORLD_MANIFEST_MEDIA_TYPE,
        WorldCheckpoint, WorldClosure, resolve_replay_capsule,
    },
};
use sha2::{Digest as _, Sha256};

use crate::{
    closure::{CandidateClosureRequest, close_replay_capsule},
    managed::{ManagedClosureEvidence, close_managed_world},
    processor::{
        bind_capsule_processor_requirement, initial_processor_requirement,
        observation_from_captured_capabilities,
    },
    subject::{SINGLE_FILE_DEBUG_MEDIA_TYPE, SINGLE_FILE_MEDIA_TYPE, verify_single_file_subject},
    support::{BackendSupportPackage, validate_backend_support_package},
};

/// Raw bytes for one transcript body object. Bounded by the candidate limits
/// because the SDK captured the exchange inside its operation budget.
const MAX_EXCHANGE_BYTES: usize = 1024 * 1024;
const MAX_WORLD_ARTIFACT_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const TRANSCRIPT_BODY_MEDIA_TYPE: &str = "application/octet-stream";

/// One dependency exchange resolved from a candidate cursor record by the
/// Runtime's transcript source.
pub struct ResolvedDependencyExchange {
    pub cursor: DependencyCursorPayload,
    pub request: Vec<u8>,
    pub response: Vec<u8>,
}

/// Deployment-fixed identities that close World boundaries the executor and
/// isolation mechanism own. The admission job revalidates the closure
/// against the installed policy before any run.
#[derive(Clone, Copy)]
pub struct PrivateClosureEvidence {
    pub executor_identity: Digest,
    pub isolation_identity: Digest,
}

pub struct PrivateClosureSources<'a> {
    pub candidate: &'a Candidate,
    pub debug_artifact: &'a [u8],
    pub dependencies: Vec<ResolvedDependencyExchange>,
    pub evidence: PrivateClosureEvidence,
    pub subject_binary: &'a [u8],
    pub support: &'a BackendSupportPackage,
    pub world: &'a WorldCheckpoint,
    /// One entry per World manifest artifact, in manifest order.
    pub world_artifacts: Vec<Vec<u8>>,
}

#[derive(Debug)]
pub struct SealedPrivateCapsule {
    pub capsule: ReplayCapsule,
    pub capsule_digest: Digest,
    pub closure: WorldClosure,
    pub failure: FailurePayload,
    pub objects: BTreeMap<ObjectId, Vec<u8>>,
}

/// Close one accepted private candidate into the sealed canonical capsule.
///
/// The construction is deterministic for one candidate and one byte source
/// set, so re-sealing after a Runtime restart reproduces the identical
/// capsule digest. The sealed result is verified through the one canonical
/// resolver before it is returned.
pub fn seal_private_candidate(
    sources: &PrivateClosureSources<'_>,
) -> Result<SealedPrivateCapsule, Error> {
    let candidate = sources.candidate;
    candidate.validate()?;
    validate_backend_support_package(sources.support)?;
    if candidate.world_id != sources.world.world_id()? {
        return Err(incomplete("the World manifest identity"));
    }
    let records = decode_candidate_records(candidate)?;
    let family = runtime_family(candidate)?;
    let subject_closure = verify_single_file_subject(
        &candidate.deployment.subject,
        sources.subject_binary,
        sources.debug_artifact,
        family,
    )?;
    let trigger = derive_trigger(candidate, &records)?;
    let dependency = derive_dependency_transcript(candidate, &records, &sources.dependencies)?;
    let (mut descriptors, objects) = assemble_object_set(
        sources,
        &records,
        &subject_closure,
        &trigger,
        dependency.as_ref(),
    )?;
    descriptors.push(candidate_descriptor(candidate)?);
    let closure = close_managed_world(
        &sources.support.closure_policy,
        ManagedClosureEvidence {
            dependency_identity: dependency_identity(&descriptors)?,
            executor_identity: sources.evidence.executor_identity,
            isolation_identity: sources.evidence.isolation_identity,
            subject_identity: candidate.deployment.subject.artifact_digest,
            world_identity: candidate.world_id,
        },
    )?;
    let mut capsule = close_replay_capsule(&CandidateClosureRequest {
        candidate,
        candidate_objects: &descriptors,
        closure: &closure,
        failure: &records.failure,
        support: sources.support,
        trigger: &trigger,
        world: sources.world,
    })?;
    bind_initial_processor_requirement(&mut capsule, candidate)?;
    capsule.validate()?;
    resolve_replay_capsule(&capsule, &mut |descriptor: &LogicalObject| {
        objects
            .get(&descriptor.object_id)
            .cloned()
            .ok_or_else(Error::object_digest_mismatch)
    })?;
    let capsule_digest = canonical::digest(&capsule)?;
    Ok(SealedPrivateCapsule {
        capsule,
        capsule_digest,
        closure,
        failure: records.failure,
        objects,
    })
}

/// The admitted capsule may narrow only the processor requirement relative
/// to the Runtime-sealed capsule. Every other field and object must be
/// byte-identical, so a job that rebuilt a different capsule fails closed.
pub fn capsules_equal_modulo_processor(
    sealed: &ReplayCapsule,
    admitted: &ReplayCapsule,
) -> Result<bool, Error> {
    reproit_core::model::capsules_equal_except_processor_capabilities(sealed, admitted)
}

/// Assemble the closure-shaped logical object set in canonical construction
/// order. The set carries every byte the sealed capsule references.
fn assemble_object_set(
    sources: &PrivateClosureSources<'_>,
    records: &DecodedRecords,
    subject_closure: &reproit_core::model::SubjectClosureManifest,
    trigger: &Trigger,
    dependency: Option<&DerivedDependency>,
) -> Result<ObjectSet, Error> {
    let world_artifact_entries = world_artifact_entries(sources)?;
    let mut builder = ObjectSetBuilder::new(sources.candidate);
    builder.push(
        LogicalObjectRole::Subject,
        SUBJECT_CLOSURE_MEDIA_TYPE.to_owned(),
        canonical::canonical_bytes(subject_closure)?,
        None,
    )?;
    builder.push(
        LogicalObjectRole::Subject,
        SINGLE_FILE_MEDIA_TYPE.to_owned(),
        sources.subject_binary.to_vec(),
        None,
    )?;
    builder.push(
        LogicalObjectRole::Subject,
        SINGLE_FILE_DEBUG_MEDIA_TYPE.to_owned(),
        sources.debug_artifact.to_vec(),
        None,
    )?;
    for (input, bytes) in &records.inputs {
        let trigger_input = trigger
            .inputs
            .get(usize::from(input.input_index))
            .ok_or_else(|| incomplete("one Trigger input"))?;
        builder.push(
            LogicalObjectRole::Trigger,
            input.content_type.clone(),
            bytes.clone(),
            Some(trigger_input.object_id),
        )?;
    }
    builder.push(
        LogicalObjectRole::Failure,
        FAILURE_MEDIA_TYPE.to_owned(),
        canonical::canonical_bytes(&records.failure)?,
        Some(records.failure.failure.object_id),
    )?;
    builder.push(
        LogicalObjectRole::Trigger,
        TRIGGER_MEDIA_TYPE.to_owned(),
        canonical::canonical_bytes(trigger)?,
        None,
    )?;
    builder.push(
        LogicalObjectRole::WorldManifest,
        WORLD_MANIFEST_MEDIA_TYPE.to_owned(),
        canonical::canonical_bytes(sources.world)?,
        None,
    )?;
    for (media_type, bytes) in world_artifact_entries {
        builder.push(LogicalObjectRole::WorldState, media_type, bytes, None)?;
    }
    if let Some(derived) = dependency {
        builder.push(
            LogicalObjectRole::DependencyTranscript,
            DEPENDENCY_TRANSCRIPT_MEDIA_TYPE.to_owned(),
            canonical::canonical_bytes(&derived.transcript)?,
            None,
        )?;
        for (object_id, bytes) in &derived.bodies {
            builder.push(
                LogicalObjectRole::DependencyTranscript,
                TRANSCRIPT_BODY_MEDIA_TYPE.to_owned(),
                bytes.clone(),
                Some(*object_id),
            )?;
        }
    }
    Ok(builder.finish())
}

struct DecodedRecords {
    begin: OperationBeginPayload,
    cursors: Vec<DependencyCursorPayload>,
    failure: FailurePayload,
    inputs: Vec<(OperationInputPayload, Vec<u8>)>,
}

fn decode_candidate_records(candidate: &Candidate) -> Result<DecodedRecords, Error> {
    let mut begin = None;
    let mut cursors = Vec::new();
    let mut failure = None;
    let mut inputs = Vec::new();
    for record in &candidate.records {
        let payload = reproit_core::crypto::decode_base64url_bytes(&record.payload)?;
        match record.kind {
            EventKind::Begin => {
                let decoded: OperationBeginPayload = canonical::parse_strict(&payload)?;
                if begin.replace(decoded).is_some() {
                    return Err(incomplete("one begin record"));
                }
            }
            EventKind::Input => {
                let decoded: OperationInputPayload = canonical::parse_strict(&payload)?;
                let bytes = reproit_core::crypto::decode_base64url_bytes(&decoded.value)?;
                if Digest::of(&bytes) != decoded.value_digest
                    || usize::from(decoded.input_index) != inputs.len()
                {
                    return Err(incomplete("one input record"));
                }
                inputs.push((decoded, bytes));
            }
            EventKind::Dependency => {
                let decoded: DependencyCursorPayload = canonical::parse_strict(&payload)?;
                decoded.validate()?;
                cursors.push(decoded);
            }
            EventKind::Failure => {
                let decoded: FailurePayload = canonical::parse_strict(&payload)?;
                decoded.validate()?;
                if failure.replace(decoded).is_some() {
                    return Err(incomplete("one Failure record"));
                }
            }
            EventKind::Terminal => {}
        }
    }
    let begin = begin.ok_or_else(|| incomplete("the begin record"))?;
    let failure = failure.ok_or_else(|| incomplete("the Failure record"))?;
    if failure.failure != candidate.failure
        || canonical::digest(&failure.identity)? != candidate.failure.identity
    {
        return Err(incomplete("the Failure binding"));
    }
    if inputs.is_empty() {
        return Err(incomplete("one semantic input"));
    }
    Ok(DecodedRecords {
        begin,
        cursors,
        failure,
        inputs,
    })
}

fn derive_trigger(candidate: &Candidate, records: &DecodedRecords) -> Result<Trigger, Error> {
    let inputs = records
        .inputs
        .iter()
        .map(|(input, bytes)| {
            Ok(TriggerInput {
                channel: input.channel,
                object_id: derive_object_id(
                    candidate,
                    "trigger-input",
                    Digest::of(bytes),
                    input.input_index.into(),
                )?,
                plain_digest: input.value_digest,
                sequence: input.input_index,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let trigger = Trigger {
        adapter_id: records.begin.adapter_id.clone(),
        adapter_version: records.begin.adapter_version.clone(),
        causal_parent_ids: records.begin.causal_parent_ids.clone(),
        // The candidate does not record how the operation would have
        // completed, so the completion derives canonically from the
        // operation kind. Delivered work uses the task-end completion
        // because acknowledgment-only capture is not part of Backend v1.0.
        completion: match records.begin.operation_kind {
            OperationKind::DeliveredWork => TriggerCompletion::TaskEnd,
            OperationKind::RequestResponse => TriggerCompletion::Return,
            OperationKind::Stream => TriggerCompletion::StreamEnd,
        },
        format: TriggerFormat::V1,
        inputs,
        operation_id: candidate.operation_id,
        operation_kind: records.begin.operation_kind,
        operation_name: records.begin.operation_name.clone(),
    };
    trigger.validate()?;
    Ok(trigger)
}

struct DerivedDependency {
    bodies: Vec<(ObjectId, Vec<u8>)>,
    transcript: DependencyTranscript,
}

fn derive_dependency_transcript(
    candidate: &Candidate,
    records: &DecodedRecords,
    resolved: &[ResolvedDependencyExchange],
) -> Result<Option<DerivedDependency>, Error> {
    if records.cursors.is_empty() {
        if resolved.is_empty() {
            return Ok(None);
        }
        return Err(incomplete("the dependency record set"));
    }
    if resolved.len() != records.cursors.len() {
        return Err(incomplete("one dependency exchange"));
    }
    // The canonical capsule carries at most one dependency-transcript
    // manifest, so every captured exchange must come from one adapter.
    let adapter_id = &records.cursors[0].adapter_id;
    let adapter_version = &records.cursors[0].adapter_version;
    let mut interactions = Vec::with_capacity(resolved.len());
    let mut bodies = Vec::with_capacity(resolved.len() * 2);
    for (index, exchange) in resolved.iter().enumerate() {
        let cursor = &records.cursors[index];
        if exchange.cursor != *cursor
            || cursor.adapter_id != *adapter_id
            || cursor.adapter_version != *adapter_version
        {
            return Err(incomplete("one dependency cursor binding"));
        }
        if exchange.request.is_empty()
            || exchange.request.len() > MAX_EXCHANGE_BYTES
            || exchange.response.is_empty()
            || exchange.response.len() > MAX_EXCHANGE_BYTES
        {
            return Err(incomplete("one bounded dependency exchange"));
        }
        let ordinal = u32::try_from(index).map_err(|_| Error::schema_invalid())?;
        let request_object_id = derive_object_id(
            candidate,
            "dependency-request",
            Digest::of(&exchange.request),
            ordinal,
        )?;
        let response_object_id = derive_object_id(
            candidate,
            "dependency-response",
            Digest::of(&exchange.response),
            ordinal,
        )?;
        interactions.push(DependencyTranscriptInteraction {
            causal_parent_id: cursor.causal_parent_id,
            operation_id: candidate.operation_id,
            outcome: DependencyOutcome::Response,
            request_digest: Digest::of(&exchange.request),
            request_object_id,
            response_digest: Digest::of(&exchange.response),
            response_object_id,
            sequence: u16::try_from(index).map_err(|_| Error::schema_invalid())?,
            session_position: u64::try_from(index).map_err(|_| Error::schema_invalid())?,
        });
        bodies.push((request_object_id, exchange.request.clone()));
        bodies.push((response_object_id, exchange.response.clone()));
    }
    let transcript = DependencyTranscript {
        adapter_id: adapter_id.clone(),
        adapter_version: adapter_version.clone(),
        format: DependencyTranscriptFormat::V1,
        interactions,
    };
    transcript.validate()?;
    Ok(Some(DerivedDependency { bodies, transcript }))
}

fn world_artifact_entries(
    sources: &PrivateClosureSources<'_>,
) -> Result<Vec<(String, Vec<u8>)>, Error> {
    let declared = sources
        .world
        .points
        .iter()
        .flat_map(|point| &point.artifacts)
        .collect::<Vec<_>>();
    if declared.len() != sources.world_artifacts.len() {
        return Err(incomplete("one World artifact"));
    }
    let mut entries = Vec::with_capacity(declared.len());
    for (artifact, bytes) in declared.iter().zip(&sources.world_artifacts) {
        if artifact.size > MAX_WORLD_ARTIFACT_BYTES
            || u64::try_from(bytes.len()).map_err(|_| Error::schema_invalid())? != artifact.size
            || Digest::of(bytes) != artifact.digest
        {
            return Err(Error::object_digest_mismatch());
        }
        entries.push((artifact.media_type.clone(), bytes.clone()));
    }
    Ok(entries)
}

/// The closure input requires exactly one candidate-role descriptor beside
/// the replay objects, mirroring the managed candidate identity shape.
fn candidate_descriptor(candidate: &Candidate) -> Result<LogicalObject, Error> {
    let bytes = canonical::canonical_bytes(candidate)?;
    Ok(LogicalObject {
        media_type: "application/vnd.reproit.candidate.v1+json".to_owned(),
        object_id: derive_object_id(candidate, "candidate", Digest::of(&bytes), 0)?,
        plain_digest: Digest::of(&bytes),
        plain_size: u64::try_from(bytes.len()).map_err(|_| Error::schema_invalid())?,
        role: LogicalObjectRole::Candidate,
    })
}

fn dependency_identity(descriptors: &[LogicalObject]) -> Result<Option<Digest>, Error> {
    let dependencies = descriptors
        .iter()
        .filter(|object| object.role == LogicalObjectRole::DependencyTranscript)
        .collect::<Vec<_>>();
    if dependencies.is_empty() {
        Ok(None)
    } else {
        canonical::digest(&dependencies).map(Some)
    }
}

/// Admission starts from the complete captured processor view, so the sealed
/// capsule binds the initial requirement derived from the candidate. The
/// admission reducer may only narrow it through bounded trials.
fn bind_initial_processor_requirement(
    capsule: &mut ReplayCapsule,
    candidate: &Candidate,
) -> Result<(), Error> {
    let observation = observation_from_captured_capabilities(
        crate::processor::captured_processor_architecture(
            &candidate.deployment.subject.architecture,
        )?,
        &candidate.deployment.runtime_capabilities,
    )?;
    let requirement = initial_processor_requirement(&observation)?;
    bind_capsule_processor_requirement(capsule, &requirement)
}

fn runtime_family(candidate: &Candidate) -> Result<SubjectRuntimeFamily, Error> {
    let mut family = None;
    for capability in &candidate.deployment.runtime_capabilities {
        let candidate_family = match capability.as_str() {
            "sdk.dotnet" => Some(SubjectRuntimeFamily::Dotnet),
            "sdk.go" => Some(SubjectRuntimeFamily::Go),
            "sdk.node" => Some(SubjectRuntimeFamily::Node),
            "sdk.python" => Some(SubjectRuntimeFamily::Python),
            "sdk.rust" => Some(SubjectRuntimeFamily::Rust),
            _ => None,
        };
        if let Some(candidate_family) = candidate_family
            && family.replace(candidate_family).is_some()
        {
            return Err(incomplete("one SDK capability"));
        }
    }
    family.ok_or_else(|| {
        Error::new(
            ErrorCode::UnsupportedCapabilitySet,
            "The candidate does not declare one supported SDK capability.",
        )
    })
}

type ObjectSet = (Vec<LogicalObject>, BTreeMap<ObjectId, Vec<u8>>);

struct ObjectSetBuilder<'a> {
    candidate: &'a Candidate,
    descriptors: Vec<LogicalObject>,
    objects: BTreeMap<ObjectId, Vec<u8>>,
    ordinal: u32,
}

impl<'a> ObjectSetBuilder<'a> {
    fn new(candidate: &'a Candidate) -> Self {
        Self {
            candidate,
            descriptors: Vec::new(),
            objects: BTreeMap::new(),
            ordinal: 0,
        }
    }

    fn push(
        &mut self,
        role: LogicalObjectRole,
        media_type: String,
        bytes: Vec<u8>,
        fixed_id: Option<ObjectId>,
    ) -> Result<(), Error> {
        let digest = Digest::of(&bytes);
        let object_id = if let Some(object_id) = fixed_id {
            object_id
        } else {
            let object_id = derive_object_id(self.candidate, role_tag(role), digest, self.ordinal)?;
            self.ordinal = self
                .ordinal
                .checked_add(1)
                .ok_or_else(Error::schema_invalid)?;
            object_id
        };
        if self.objects.contains_key(&object_id) {
            return Err(incomplete("one unique object identity"));
        }
        self.descriptors.push(LogicalObject {
            media_type,
            object_id,
            plain_digest: digest,
            plain_size: u64::try_from(bytes.len()).map_err(|_| Error::schema_invalid())?,
            role,
        });
        self.objects.insert(object_id, bytes);
        Ok(())
    }

    fn finish(self) -> ObjectSet {
        (self.descriptors, self.objects)
    }
}

const fn role_tag(role: LogicalObjectRole) -> &'static str {
    match role {
        LogicalObjectRole::AdmissionProof => "admission-proof",
        LogicalObjectRole::Candidate => "candidate",
        LogicalObjectRole::CaptureBatchManifest => "capture-batch-manifest",
        LogicalObjectRole::DebugSymbols => "debug-symbols",
        LogicalObjectRole::DependencyTranscript => "dependency",
        LogicalObjectRole::Failure => "failure",
        LogicalObjectRole::ReplayCapsuleManifest => "replay-capsule-manifest",
        LogicalObjectRole::Subject => "subject",
        LogicalObjectRole::Trigger => "trigger",
        LogicalObjectRole::WorldManifest => "world-manifest",
        LogicalObjectRole::WorldState => "world-state",
    }
}

/// Mint one deterministic version-7-shaped object identity from the capture
/// identity and the object content. Determinism makes re-sealing after a
/// Runtime restart idempotent, and the content binding keeps two different
/// objects from colliding on one identity.
fn derive_object_id(
    candidate: &Candidate,
    tag: &str,
    digest: Digest,
    ordinal: u32,
) -> Result<ObjectId, Error> {
    let mut hasher = Sha256::new();
    hasher.update(b"reproit.private-closure-object.v1\0");
    hasher.update(candidate.capture_id.uuid_bytes());
    hasher.update(tag.as_bytes());
    hasher.update([0]);
    hasher.update(digest.to_string().as_bytes());
    hasher.update(ordinal.to_be_bytes());
    let material = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&material[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let text = format!(
        "obj_{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    );
    text.parse()
}

fn incomplete(what: &'static str) -> Error {
    Error::new_owned(
        ErrorCode::IncompleteCandidate,
        format!("The private candidate closure is missing {what}."),
    )
}

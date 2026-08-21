//! Canonical sealed replay-capsule resolution.
//!
//! A sealed capsule stores one closure-shaped object set: one subject-closure
//! manifest plus its constituent objects (every one with the Subject role),
//! one Trigger descriptor plus one object per Trigger input, one Failure
//! payload, one World manifest plus one object per World artifact, and at
//! most one dependency-transcript manifest plus one object per recorded
//! request and response. Spec sections 1.6, 2.1, 4.6, and 4.9 define this
//! shape, and the managed candidate closure produces it.
//!
//! Every consumer of sealed capsule bytes (admission replay, debug, check,
//! Keep, CLI, MCP, and stored-byte replay) MUST resolve the capsule through
//! this module. A consumer-local interpretation of capsule objects creates a
//! second meaning for the same bytes and is forbidden.

use std::collections::BTreeMap;

use crate::{
    Error, ErrorCode, canonical,
    identity::{Digest, ObjectId},
};

use super::{
    ArtifactReference, DependencyTranscript, FailurePayload, LogicalObject, LogicalObjectRole,
    ReplayCapsule, SubjectClosureManifest, Trigger, Validate, WorldCheckpoint,
};

fn subject_binding_mismatch() -> Error {
    Error::new(
        ErrorCode::SubjectDigestMismatch,
        "The subject artifact does not match the sealed capsule.",
    )
}

pub const SUBJECT_CLOSURE_MEDIA_TYPE: &str = "application/vnd.reproit.subject-closure.v1+json";
pub const TRIGGER_MEDIA_TYPE: &str = "application/vnd.reproit.trigger.v1+json";
pub const FAILURE_MEDIA_TYPE: &str = "application/vnd.reproit.failure.v1+json";
pub const WORLD_MANIFEST_MEDIA_TYPE: &str = "application/vnd.reproit.world-manifest.v1+json";
pub const DEPENDENCY_TRANSCRIPT_MEDIA_TYPE: &str =
    "application/vnd.reproit.dependency-transcript.v1+json";

/// The manifest-class objects a resolver parses are small documents. Payload
/// objects (subject files, World state, Trigger inputs, transcript bodies)
/// are never read here, so this bound protects only manifest parsing.
pub const MAX_MANIFEST_OBJECT_BYTES: u64 = 1_048_576;

/// A sealed capsule resolved into its typed manifests with every payload
/// object bound to its descriptor. Payload bytes stay with the caller. The
/// caller MUST verify each payload object's digest and size when it
/// materializes the bytes.
#[derive(Debug, Clone)]
pub struct ResolvedReplayCapsule {
    pub dependency: Option<ResolvedDependencyTranscript>,
    pub failure: FailurePayload,
    pub failure_object: LogicalObject,
    pub subject_closure: SubjectClosureManifest,
    pub subject_manifest_object: LogicalObject,
    /// One descriptor per `subject_closure.objects` entry, in the same order.
    pub subject_objects: Vec<LogicalObject>,
    pub trigger: Trigger,
    /// One descriptor per `trigger.inputs` entry, in the same order.
    pub trigger_inputs: Vec<LogicalObject>,
    pub trigger_object: LogicalObject,
    pub world: WorldCheckpoint,
    pub world_artifacts: Vec<ResolvedWorldArtifact>,
    pub world_object: LogicalObject,
}

#[derive(Debug, Clone)]
pub struct ResolvedWorldArtifact {
    pub artifact: ArtifactReference,
    pub object: LogicalObject,
    /// Index into `world.points` for this artifact's recoverable point.
    pub point_index: usize,
}

#[derive(Debug, Clone)]
pub struct ResolvedDependencyTranscript {
    /// One entry per `transcript.interactions` entry, in the same order.
    pub interactions: Vec<ResolvedInteraction>,
    pub manifest_object: LogicalObject,
    pub transcript: DependencyTranscript,
}

#[derive(Debug, Clone)]
pub struct ResolvedInteraction {
    pub request: LogicalObject,
    pub response: LogicalObject,
}

/// Resolve a sealed replay capsule against a manifest reader.
///
/// The reader supplies plaintext bytes for one descriptor. The resolver calls
/// it only for the five manifest-class objects and verifies the returned
/// bytes against the descriptor digest and size before parsing. Every check
/// fails closed: a missing object, a duplicate candidate, a wrong role, a
/// wrong media type, a digest mismatch, or an object the capsule references
/// zero times rejects the whole capsule.
pub fn resolve_replay_capsule(
    capsule: &ReplayCapsule,
    read_manifest: &mut dyn FnMut(&LogicalObject) -> Result<Vec<u8>, Error>,
) -> Result<ResolvedReplayCapsule, Error> {
    capsule.validate()?;
    let mut consumption = ObjectConsumption::new(&capsule.objects)?;
    let (subject_manifest_object, subject_closure, subject_objects) =
        resolve_subject(capsule, read_manifest, &mut consumption)?;
    let (trigger_object, trigger, trigger_inputs) =
        resolve_trigger(capsule, read_manifest, &mut consumption)?;
    let (failure_object, failure) = resolve_failure(capsule, read_manifest, &mut consumption)?;
    let (world_object, world, world_artifacts) =
        resolve_world(capsule, read_manifest, &mut consumption)?;
    let dependency = resolve_dependency(capsule, read_manifest, &mut consumption)?;
    consumption.require_complete()?;
    Ok(ResolvedReplayCapsule {
        dependency,
        failure,
        failure_object,
        subject_closure,
        subject_manifest_object,
        subject_objects,
        trigger,
        trigger_inputs,
        trigger_object,
        world,
        world_artifacts,
        world_object,
    })
}

/// Track that every capsule object is referenced exactly once. Duplicate
/// consumption means two manifest references share one object. Unconsumed
/// objects are unreferenced extras. Both make the capsule invalid.
struct ObjectConsumption {
    consumed: BTreeMap<ObjectId, bool>,
}

impl ObjectConsumption {
    fn new(objects: &[LogicalObject]) -> Result<Self, Error> {
        let mut consumed = BTreeMap::new();
        for object in objects {
            // Sealing removes the candidate record, proofs and the capsule
            // manifest live in the capture batch, and no producer emits a
            // detached debug-symbols object: debug artifacts travel inside
            // the subject closure. Any of these roles in a sealed capsule is
            // invalid.
            match object.role {
                LogicalObjectRole::Subject
                | LogicalObjectRole::Trigger
                | LogicalObjectRole::Failure
                | LogicalObjectRole::WorldManifest
                | LogicalObjectRole::WorldState
                | LogicalObjectRole::DependencyTranscript => {}
                LogicalObjectRole::AdmissionProof
                | LogicalObjectRole::Candidate
                | LogicalObjectRole::CaptureBatchManifest
                | LogicalObjectRole::DebugSymbols
                | LogicalObjectRole::ReplayCapsuleManifest => {
                    return Err(Error::schema_invalid());
                }
            }
            if consumed.insert(object.object_id, false).is_some() {
                return Err(Error::schema_invalid());
            }
        }
        Ok(Self { consumed })
    }

    fn consume(&mut self, object: &LogicalObject) -> Result<(), Error> {
        match self.consumed.get_mut(&object.object_id) {
            Some(seen @ false) => {
                *seen = true;
                Ok(())
            }
            _ => Err(Error::schema_invalid()),
        }
    }

    fn require_complete(&self) -> Result<(), Error> {
        if self.consumed.values().all(|seen| *seen) {
            Ok(())
        } else {
            Err(Error::schema_invalid())
        }
    }
}

fn resolve_subject(
    capsule: &ReplayCapsule,
    read_manifest: &mut dyn FnMut(&LogicalObject) -> Result<Vec<u8>, Error>,
    consumption: &mut ObjectConsumption,
) -> Result<(LogicalObject, SubjectClosureManifest, Vec<LogicalObject>), Error> {
    if capsule.subject.artifact_media_type != SUBJECT_CLOSURE_MEDIA_TYPE {
        return Err(subject_binding_mismatch());
    }
    let manifest_object = one_object(&capsule.objects, |object| {
        object.role == LogicalObjectRole::Subject
            && object.media_type == SUBJECT_CLOSURE_MEDIA_TYPE
            && object.plain_digest == capsule.subject_digest
    })
    .map_err(|_| subject_binding_mismatch())?;
    consumption.consume(manifest_object)?;
    let manifest: SubjectClosureManifest =
        parse_manifest(manifest_object, read_manifest, capsule.subject_digest)?;
    // The capsule embeds the subject descriptor and the closure manifest owns
    // the launch record. Spec 1.6 rejects a capsule that binds a different
    // artifact or launch, so the two views must agree exactly.
    if manifest.architecture != capsule.subject.architecture
        || manifest.operating_system != capsule.subject.operating_system
        || manifest.launch.executable != capsule.subject.executable
        || manifest.launch.arguments != capsule.subject.arguments
        || manifest.launch.working_directory != capsule.subject.working_directory
        || manifest.launch.environment_names != capsule.subject.environment_names
    {
        return Err(subject_binding_mismatch());
    }
    let mut members = Vec::with_capacity(manifest.objects.len());
    for expected in &manifest.objects {
        // Spec error table: a sealed subject whose closure member no longer
        // binds is a changed subject digest, not a generic object mismatch.
        let member = one_object(&capsule.objects, |object| {
            object.role == LogicalObjectRole::Subject
                && object.media_type == expected.media_type
                && object.plain_digest == expected.digest
                && object.plain_size == expected.size
        })
        .map_err(|_| subject_binding_mismatch())?;
        consumption.consume(member)?;
        members.push(member.clone());
    }
    Ok((manifest_object.clone(), manifest, members))
}

fn resolve_trigger(
    capsule: &ReplayCapsule,
    read_manifest: &mut dyn FnMut(&LogicalObject) -> Result<Vec<u8>, Error>,
    consumption: &mut ObjectConsumption,
) -> Result<(LogicalObject, Trigger, Vec<LogicalObject>), Error> {
    let trigger_object = one_object(&capsule.objects, |object| {
        object.role == LogicalObjectRole::Trigger
            && object.media_type == TRIGGER_MEDIA_TYPE
            && object.plain_digest == capsule.trigger_digest
    })?;
    consumption.consume(trigger_object)?;
    let trigger: Trigger = parse_manifest(trigger_object, read_manifest, capsule.trigger_digest)?;
    let mut inputs = Vec::with_capacity(trigger.inputs.len());
    for input in &trigger.inputs {
        let object = one_object(&capsule.objects, |object| {
            object.object_id == input.object_id
                && object.role == LogicalObjectRole::Trigger
                && object.plain_digest == input.plain_digest
        })
        .map_err(|_| Error::object_digest_mismatch())?;
        consumption.consume(object)?;
        inputs.push(object.clone());
    }
    Ok((trigger_object.clone(), trigger, inputs))
}

fn resolve_failure(
    capsule: &ReplayCapsule,
    read_manifest: &mut dyn FnMut(&LogicalObject) -> Result<Vec<u8>, Error>,
    consumption: &mut ObjectConsumption,
) -> Result<(LogicalObject, FailurePayload), Error> {
    let failure_object = one_object(&capsule.objects, |object| {
        object.role == LogicalObjectRole::Failure && object.media_type == FAILURE_MEDIA_TYPE
    })?;
    consumption.consume(failure_object)?;
    let failure: FailurePayload =
        parse_manifest(failure_object, read_manifest, failure_object.plain_digest)?;
    // The payload names its own object and the capsule names the identity.
    // Both bindings must hold on the same object.
    if failure.failure.object_id != failure_object.object_id
        || canonical::digest(&failure.identity)? != capsule.failure_digest
    {
        return Err(Error::object_digest_mismatch());
    }
    Ok((failure_object.clone(), failure))
}

fn resolve_world(
    capsule: &ReplayCapsule,
    read_manifest: &mut dyn FnMut(&LogicalObject) -> Result<Vec<u8>, Error>,
    consumption: &mut ObjectConsumption,
) -> Result<(LogicalObject, WorldCheckpoint, Vec<ResolvedWorldArtifact>), Error> {
    let world_object = one_object(&capsule.objects, |object| {
        object.role == LogicalObjectRole::WorldManifest
            && object.media_type == WORLD_MANIFEST_MEDIA_TYPE
    })?;
    consumption.consume(world_object)?;
    let world: WorldCheckpoint =
        parse_manifest(world_object, read_manifest, world_object.plain_digest)?;
    if world.world_id()? != capsule.world_digest {
        return Err(Error::object_digest_mismatch());
    }
    let mut artifacts = Vec::new();
    for (point_index, point) in world.points.iter().enumerate() {
        for artifact in &point.artifacts {
            let object = one_object(&capsule.objects, |object| {
                object.role == LogicalObjectRole::WorldState
                    && object.media_type == artifact.media_type
                    && object.plain_digest == artifact.digest
                    && object.plain_size == artifact.size
            })
            .map_err(|_| Error::object_digest_mismatch())?;
            consumption.consume(object)?;
            artifacts.push(ResolvedWorldArtifact {
                artifact: artifact.clone(),
                object: object.clone(),
                point_index,
            });
        }
    }
    Ok((world_object.clone(), world, artifacts))
}

fn resolve_dependency(
    capsule: &ReplayCapsule,
    read_manifest: &mut dyn FnMut(&LogicalObject) -> Result<Vec<u8>, Error>,
    consumption: &mut ObjectConsumption,
) -> Result<Option<ResolvedDependencyTranscript>, Error> {
    let manifests = capsule
        .objects
        .iter()
        .filter(|object| {
            object.role == LogicalObjectRole::DependencyTranscript
                && object.media_type == DEPENDENCY_TRANSCRIPT_MEDIA_TYPE
        })
        .collect::<Vec<_>>();
    let manifest_object = match manifests.as_slice() {
        [] => return Ok(None),
        [manifest] => (*manifest).clone(),
        _ => return Err(Error::schema_invalid()),
    };
    consumption.consume(&manifest_object)?;
    let transcript: DependencyTranscript = parse_manifest(
        &manifest_object,
        read_manifest,
        manifest_object.plain_digest,
    )?;
    let mut interactions = Vec::with_capacity(transcript.interactions.len());
    for interaction in &transcript.interactions {
        let request = one_object(&capsule.objects, |object| {
            object.object_id == interaction.request_object_id
                && object.role == LogicalObjectRole::DependencyTranscript
                && object.plain_digest == interaction.request_digest
        })
        .map_err(|_| Error::object_digest_mismatch())?;
        consumption.consume(request)?;
        let response = one_object(&capsule.objects, |object| {
            object.object_id == interaction.response_object_id
                && object.role == LogicalObjectRole::DependencyTranscript
                && object.plain_digest == interaction.response_digest
        })
        .map_err(|_| Error::object_digest_mismatch())?;
        consumption.consume(response)?;
        interactions.push(ResolvedInteraction {
            request: request.clone(),
            response: response.clone(),
        });
    }
    Ok(Some(ResolvedDependencyTranscript {
        interactions,
        manifest_object,
        transcript,
    }))
}

/// Read and parse one manifest-class object. The returned bytes must match
/// the descriptor size and digest, the digest must match the expected
/// binding, and the parsed document must be strictly canonical and valid.
fn parse_manifest<T>(
    object: &LogicalObject,
    read_manifest: &mut dyn FnMut(&LogicalObject) -> Result<Vec<u8>, Error>,
    expected_digest: Digest,
) -> Result<T, Error>
where
    T: serde::de::DeserializeOwned + serde::Serialize + Validate,
{
    if object.plain_size > MAX_MANIFEST_OBJECT_BYTES || object.plain_digest != expected_digest {
        return Err(Error::object_digest_mismatch());
    }
    let bytes = read_manifest(object)?;
    if u64::try_from(bytes.len()).map_err(|_| Error::schema_invalid())? != object.plain_size
        || Digest::of(&bytes) != object.plain_digest
    {
        return Err(Error::object_digest_mismatch());
    }
    let value: T = canonical::parse_strict(&bytes)?;
    value.validate()?;
    // A non-canonical encoding of a valid document would pass the byte digest
    // but change the canonical identity. Reject it.
    if canonical::digest(&value)? != object.plain_digest {
        return Err(Error::object_digest_mismatch());
    }
    Ok(value)
}

fn one_object(
    objects: &[LogicalObject],
    select: impl Fn(&LogicalObject) -> bool,
) -> Result<&LogicalObject, Error> {
    let mut matches = objects.iter().filter(|object| select(object));
    let first = matches.next().ok_or_else(Error::schema_invalid)?;
    if matches.next().is_some() {
        return Err(Error::schema_invalid());
    }
    Ok(first)
}

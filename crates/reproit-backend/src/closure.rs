use std::collections::BTreeSet;

use reproit_core::{
    Error, ErrorCode, canonical,
    model::{
        Candidate, FailurePayload, LogicalObject, LogicalObjectRole, ReplayCapsule,
        ReplayCapsuleFormat, Trigger, Validate as _, WorldCheckpoint, WorldClosure,
    },
    proof,
};

use crate::support::{BackendSupportPackage, validate_backend_support_package};

const FAILURE_MEDIA_TYPE: &str = "application/vnd.reproit.failure.v1+json";
const SUBJECT_MEDIA_TYPE: &str = "application/vnd.reproit.subject-closure.v1+json";
const TRIGGER_MEDIA_TYPE: &str = "application/vnd.reproit.trigger.v1+json";
const WORLD_MEDIA_TYPE: &str = "application/vnd.reproit.world-manifest.v1+json";

pub struct CandidateClosureRequest<'a> {
    pub candidate: &'a Candidate,
    pub candidate_objects: &'a [LogicalObject],
    pub closure: &'a WorldClosure,
    pub failure: &'a FailurePayload,
    pub support: &'a BackendSupportPackage,
    pub trigger: &'a Trigger,
    pub world: &'a WorldCheckpoint,
}

pub fn close_replay_capsule(request: &CandidateClosureRequest<'_>) -> Result<ReplayCapsule, Error> {
    validate_inputs(request)?;
    let objects = replay_objects(request.candidate_objects)?;
    require_manifest(
        &objects,
        LogicalObjectRole::Failure,
        FAILURE_MEDIA_TYPE,
        canonical::digest(request.failure)?,
    )?;
    require_manifest(
        &objects,
        LogicalObjectRole::Subject,
        SUBJECT_MEDIA_TYPE,
        request.candidate.deployment.subject.artifact_digest,
    )?;
    let trigger_digest = canonical::digest(request.trigger)?;
    require_manifest(
        &objects,
        LogicalObjectRole::Trigger,
        TRIGGER_MEDIA_TYPE,
        trigger_digest,
    )?;
    require_manifest(
        &objects,
        LogicalObjectRole::WorldManifest,
        WORLD_MEDIA_TYPE,
        canonical::digest(request.world)?,
    )?;
    require_payload_closure(&objects, request)?;
    let capsule = ReplayCapsule {
        closure_manifest_digest: canonical::digest(request.closure)?,
        failure_digest: canonical::digest(&request.failure.identity)?,
        format: ReplayCapsuleFormat::V1,
        objects,
        perturbation_suite: "reproit.controlled-perturbation.v1".to_owned(),
        processing_mode: request.candidate.processing_mode,
        profile: "backend".to_owned(),
        profile_format: 1,
        required_capabilities: required_capabilities(request)?,
        subject: request.candidate.deployment.subject.clone(),
        subject_digest: request.candidate.deployment.subject.artifact_digest,
        support_bundle_digest: request.support.digest()?,
        trigger_digest,
        world_digest: request.candidate.world_id,
    };
    capsule.validate()?;
    Ok(capsule)
}

fn validate_inputs(request: &CandidateClosureRequest<'_>) -> Result<(), Error> {
    request.candidate.validate()?;
    request.failure.identity.validate()?;
    request.trigger.validate()?;
    request.world.validate()?;
    request.closure.validate()?;
    validate_backend_support_package(request.support)?;
    proof::validate_world_closure(&request.support.closure_policy, request.closure)?;
    let (failure_kind, failure_operation) = request.failure.identity.operation();
    // Private mode transfers the same closure shape, so both processing
    // modes close through this one function. The candidate validator has
    // already proved that the candidate and deployment modes agree.
    if request.candidate.failure != request.failure.failure
        || request.candidate.failure.identity != canonical::digest(&request.failure.identity)?
        || request.candidate.operation_id != request.trigger.operation_id
        || failure_kind != request.trigger.operation_kind
        || failure_operation != request.trigger.operation_name
        || request.world.world_id()? != request.candidate.world_id
    {
        return Err(incomplete_candidate());
    }
    Ok(())
}

fn replay_objects(candidate_objects: &[LogicalObject]) -> Result<Vec<LogicalObject>, Error> {
    if candidate_objects.is_empty() || candidate_objects.len() > 32_767 {
        return Err(incomplete_candidate());
    }
    let mut objects = candidate_objects
        .iter()
        .filter(|object| object.role != LogicalObjectRole::Candidate)
        .cloned()
        .collect::<Vec<_>>();
    objects.sort_by_key(|object| object.object_id);
    let ids = objects
        .iter()
        .map(|object| object.object_id)
        .collect::<BTreeSet<_>>();
    if ids.len() != objects.len() || objects.len() + 1 != candidate_objects.len() {
        return Err(incomplete_candidate());
    }
    Ok(objects)
}

fn require_manifest(
    objects: &[LogicalObject],
    role: LogicalObjectRole,
    media_type: &str,
    digest: reproit_core::identity::Digest,
) -> Result<(), Error> {
    let count = objects
        .iter()
        .filter(|object| {
            object.role == role && object.media_type == media_type && object.plain_digest == digest
        })
        .count();
    if count == 1 {
        Ok(())
    } else {
        Err(incomplete_candidate())
    }
}

fn require_payload_closure(
    objects: &[LogicalObject],
    request: &CandidateClosureRequest<'_>,
) -> Result<(), Error> {
    require_object(
        objects,
        request.failure.failure.object_id,
        LogicalObjectRole::Failure,
        canonical::digest(request.failure)?,
    )?;
    for input in &request.trigger.inputs {
        require_object(
            objects,
            input.object_id,
            LogicalObjectRole::Trigger,
            input.plain_digest,
        )?;
    }
    for artifact in request
        .world
        .points
        .iter()
        .flat_map(|point| &point.artifacts)
    {
        let count = objects
            .iter()
            .filter(|object| {
                object.role == LogicalObjectRole::WorldState
                    && object.media_type == artifact.media_type
                    && object.plain_digest == artifact.digest
                    && object.plain_size == artifact.size
            })
            .count();
        if count != 1 {
            return Err(incomplete_candidate());
        }
    }
    Ok(())
}

fn require_object(
    objects: &[LogicalObject],
    object_id: reproit_core::identity::ObjectId,
    role: LogicalObjectRole,
    digest: reproit_core::identity::Digest,
) -> Result<(), Error> {
    if objects.iter().any(|object| {
        object.object_id == object_id && object.role == role && object.plain_digest == digest
    }) {
        Ok(())
    } else {
        Err(incomplete_candidate())
    }
}

fn required_capabilities(request: &CandidateClosureRequest<'_>) -> Result<Vec<String>, Error> {
    replay_capability_union(
        &request.support.bundle,
        &request.candidate.deployment.runtime_capabilities,
    )
}

/// The canonical replay capability set of a sealed capsule: the union of the
/// support-bundle component capabilities and the deployment runtime
/// capabilities, sorted and bounded. Every capsule producer (managed closure
/// and the private promise harness) uses this one union so replay selection
/// sees the same contract in both processing modes.
pub fn replay_capability_union(
    bundle: &reproit_core::model::SupportBundle,
    runtime_capabilities: &[String],
) -> Result<Vec<String>, Error> {
    let mut capabilities = bundle
        .components
        .iter()
        .flat_map(|component| component.capabilities.iter().cloned())
        .chain(runtime_capabilities.iter().cloned())
        .collect::<Vec<_>>();
    capabilities.sort();
    capabilities.dedup();
    if capabilities.len() > 64 {
        return Err(Error::schema_invalid());
    }
    Ok(capabilities)
}

fn incomplete_candidate() -> Error {
    Error::new(
        ErrorCode::IncompleteCandidate,
        "The Runtime could not close the candidate into one replay capsule.",
    )
}

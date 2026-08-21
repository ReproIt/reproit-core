use std::str::FromStr as _;

use reproit_backend::{
    closure::{CandidateClosureRequest, close_replay_capsule},
    config::BackendSdk,
    support::build_backend_support_package,
};
use reproit_core::{
    canonical,
    identity::{Digest, ObjectId},
    model::{
        Candidate, ClosurePolicy, DebuggerContract, FailurePayload, LogicalObject,
        LogicalObjectRole, ProcessingMode, ProcessorArchitecture, SupportBundle, Trigger,
        Validate as _, WorldCheckpoint, WorldClosure,
    },
};
use serde::de::DeserializeOwned;
use serde_json::Value;

const CORE_VECTORS: &str = include_str!("../../../specs/v1/vectors.json");
const PROTOCOL_VECTORS: &str = include_str!("../../../specs/v1/protocol-vectors.json");

#[test]
fn managed_candidate_closes_with_the_exact_support_policy_and_payloads() {
    let core = parse(CORE_VECTORS);
    let protocol = parse(PROTOCOL_VECTORS);
    let closure_policy: ClosurePolicy = decode(&core["closure_policy"]["value"]);
    let support = build_backend_support_package(
        decode::<SupportBundle>(&core["support_bundle"]["value"]),
        closure_policy,
        BackendSdk::Rust,
        ProcessorArchitecture::X86_64,
        decode::<DebuggerContract>(&protocol["positive"]["debugger_contract"]["value"]),
        Digest::of(b"managed closure conformance"),
    )
    .unwrap();
    let mut candidate: Candidate = decode(&protocol["positive"]["candidate"]["value"]);
    let failure: FailurePayload = decode(&protocol["positive"]["failure_payload"]["value"]);
    let trigger: Trigger = decode(&protocol["positive"]["trigger"]["value"]);
    let world: WorldCheckpoint = decode(&protocol["positive"]["world_checkpoint"]["value"]);
    let closure: WorldClosure = decode(&core["world_closure"]["value"]);
    let subject_digest = Digest::of(b"complete managed Rust subject closure");
    candidate.processing_mode = ProcessingMode::Managed;
    candidate.deployment.processing_mode = ProcessingMode::Managed;
    candidate.deployment.subject.architecture = "architecture.x86-64".to_owned();
    candidate.deployment.subject.artifact_digest = subject_digest;
    candidate.deployment.subject.artifact_media_type =
        "application/vnd.reproit.subject-closure.v1+json".to_owned();
    candidate.deployment.runtime_capabilities = vec![
        "architecture.x86-64".to_owned(),
        "operating-system.linux".to_owned(),
        "runtime.rust-native".to_owned(),
        "sdk.rust".to_owned(),
    ];
    candidate.validate().unwrap();
    let objects = candidate_objects(&candidate, &failure, &trigger, &world, subject_digest);

    let capsule = close_replay_capsule(&CandidateClosureRequest {
        candidate: &candidate,
        candidate_objects: &objects,
        closure: &closure,
        failure: &failure,
        support: &support,
        trigger: &trigger,
        world: &world,
    })
    .unwrap();

    capsule.validate().unwrap();
    assert_eq!(capsule.support_bundle_digest, support.digest().unwrap());
    assert_eq!(capsule.trigger_digest, canonical::digest(&trigger).unwrap());
    assert_eq!(capsule.world_digest, world.world_id().unwrap());
    assert!(
        !capsule
            .objects
            .iter()
            .any(|object| object.role == LogicalObjectRole::Candidate)
    );

    let incomplete = objects
        .iter()
        .filter(|object| object.object_id != trigger.inputs[0].object_id)
        .cloned()
        .collect::<Vec<_>>();
    let error = close_replay_capsule(&CandidateClosureRequest {
        candidate: &candidate,
        candidate_objects: &incomplete,
        closure: &closure,
        failure: &failure,
        support: &support,
        trigger: &trigger,
        world: &world,
    })
    .expect_err("a missing Trigger input must keep the candidate local");
    assert_eq!(error.code, reproit_core::ErrorCode::IncompleteCandidate);
}

fn candidate_objects(
    candidate: &Candidate,
    failure: &FailurePayload,
    trigger: &Trigger,
    world: &WorldCheckpoint,
    subject_digest: Digest,
) -> Vec<LogicalObject> {
    let values = [
        (
            "obj_01890f3e-7b1c-7cc0-8a1b-123456789ab0",
            LogicalObjectRole::Candidate,
            "application/vnd.reproit.candidate.v1+json",
            canonical::digest(candidate).unwrap(),
        ),
        (
            "obj_01890f3e-7b1c-7cc0-8a1b-123456789ab1",
            LogicalObjectRole::Subject,
            "application/vnd.reproit.subject-closure.v1+json",
            subject_digest,
        ),
        (
            "obj_01890f3e-7b1c-7cc0-8a1b-123456789ab2",
            LogicalObjectRole::Trigger,
            "application/vnd.reproit.trigger.v1+json",
            canonical::digest(trigger).unwrap(),
        ),
        (
            "obj_01890f3e-7b1c-7cc0-8a1b-123456789ab7",
            LogicalObjectRole::Failure,
            "application/vnd.reproit.failure.v1+json",
            canonical::digest(failure).unwrap(),
        ),
        (
            "obj_01890f3e-7b1c-7cc0-8a1b-123456789ab4",
            LogicalObjectRole::WorldManifest,
            "application/vnd.reproit.world-manifest.v1+json",
            canonical::digest(world).unwrap(),
        ),
        (
            "obj_01890f3e-7b1c-7cc0-8a1b-123456789ab6",
            LogicalObjectRole::Trigger,
            "application/json",
            trigger.inputs[0].plain_digest,
        ),
        (
            "obj_01890f3e-7b1c-7cc0-8a1b-123456789ab8",
            LogicalObjectRole::WorldState,
            "application/vnd.reproit.sqlite-checkpoint.v1",
            world.points[0].artifacts[0].digest,
        ),
    ];
    values
        .into_iter()
        .map(
            |(object_id, role, media_type, plain_digest)| LogicalObject {
                media_type: media_type.to_owned(),
                object_id: ObjectId::from_str(object_id).unwrap(),
                plain_digest,
                plain_size: if role == LogicalObjectRole::WorldState {
                    world.points[0].artifacts[0].size
                } else {
                    1
                },
                role,
            },
        )
        .collect()
}

fn parse(text: &str) -> Value {
    serde_json::from_str(text).unwrap()
}

fn decode<T: DeserializeOwned>(value: &Value) -> T {
    serde_json::from_value(value.clone()).unwrap()
}

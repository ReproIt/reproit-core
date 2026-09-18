//! Canonical sealed-capsule resolution against the real managed producer.
//!
//! These tests seal a canonical closure-shaped capsule through
//! `close_replay_capsule` (the only production capsule producer) and prove
//! that `resolve_replay_capsule` accepts exactly that shape and rejects every
//! required mutation of it.

use std::collections::BTreeMap;
use std::str::FromStr as _;

use reproit_backend::{
    closure::{CandidateClosureRequest, close_replay_capsule},
    config::BackendSdk,
    support::build_backend_support_package,
};
use reproit_core::{
    ErrorCode, canonical,
    identity::{Digest, ObjectId},
    model::{
        Candidate, ClosurePolicy, DebuggerContract, DependencyOutcome, DependencyTranscript,
        DependencyTranscriptFormat, DependencyTranscriptInteraction, FailurePayload, LogicalObject,
        LogicalObjectRole, ProcessingMode, ProcessorArchitecture, ReplayCapsule,
        SubjectClosureManifest, SupportBundle, Trigger, Validate as _, WorldCheckpoint,
        WorldClosure, resolve_replay_capsule,
    },
};
use serde::de::DeserializeOwned;
use serde_json::Value;

const CORE_VECTORS: &str = include_str!("../../../specs/v1/vectors.json");
#[path = "capsule_resolution/automatic.rs"]
mod automatic;
const PROTOCOL_VECTORS: &str = include_str!("../../../specs/v1/protocol-vectors.json");

const SUBJECT_CLOSURE_MEDIA_TYPE: &str = "application/vnd.reproit.subject-closure.v1+json";
const TRIGGER_MEDIA_TYPE: &str = "application/vnd.reproit.trigger.v1+json";
const FAILURE_MEDIA_TYPE: &str = "application/vnd.reproit.failure.v1+json";
const WORLD_MANIFEST_MEDIA_TYPE: &str = "application/vnd.reproit.world-manifest.v1+json";
const DEPENDENCY_TRANSCRIPT_MEDIA_TYPE: &str =
    "application/vnd.reproit.dependency-transcript.v1+json";

struct SealedFixture {
    capsule: ReplayCapsule,
    manifest_bytes: BTreeMap<ObjectId, Vec<u8>>,
}

impl SealedFixture {
    fn resolve(&self) -> Result<reproit_core::model::ResolvedReplayCapsule, reproit_core::Error> {
        let manifest_bytes = self.manifest_bytes.clone();
        resolve_replay_capsule(&self.capsule, &mut |object: &LogicalObject| {
            manifest_bytes
                .get(&object.object_id)
                .cloned()
                .ok_or_else(reproit_core::Error::object_digest_mismatch)
        })
    }
}

fn object_id(suffix: u8) -> ObjectId {
    ObjectId::from_str(&format!(
        "obj_01890f3e-7b1c-7cc0-8a1b-1234567890{suffix:02x}"
    ))
    .unwrap()
}

#[allow(clippy::too_many_lines)]
fn sealed_fixture() -> SealedFixture {
    let core: Value = serde_json::from_str(CORE_VECTORS).unwrap();
    let protocol: Value = serde_json::from_str(PROTOCOL_VECTORS).unwrap();
    let closure_policy: ClosurePolicy = decode(&core["closure_policy"]["value"]);
    let support = build_backend_support_package(
        decode::<SupportBundle>(&core["support_bundle"]["value"]),
        closure_policy,
        BackendSdk::Rust,
        ProcessorArchitecture::X86_64,
        decode::<DebuggerContract>(&protocol["positive"]["debugger_contract"]["value"]),
        Digest::of(b"capsule resolution conformance"),
    )
    .unwrap();
    let subject_manifest: SubjectClosureManifest = decode(&core["subject_closure"]["value"]);
    let subject_manifest_bytes = canonical::canonical_bytes(&subject_manifest).unwrap();
    let subject_digest = Digest::of(&subject_manifest_bytes);

    let mut candidate: Candidate = decode(&protocol["positive"]["candidate"]["value"]);
    candidate.processing_mode = ProcessingMode::Managed;
    candidate.deployment.processing_mode = ProcessingMode::Managed;
    let subject = &mut candidate.deployment.subject;
    subject
        .architecture
        .clone_from(&subject_manifest.architecture);
    subject
        .operating_system
        .clone_from(&subject_manifest.operating_system);
    subject
        .executable
        .clone_from(&subject_manifest.launch.executable);
    subject
        .arguments
        .clone_from(&subject_manifest.launch.arguments);
    subject
        .working_directory
        .clone_from(&subject_manifest.launch.working_directory);
    subject
        .environment_names
        .clone_from(&subject_manifest.launch.environment_names);
    subject.artifact_digest = subject_digest;
    SUBJECT_CLOSURE_MEDIA_TYPE.clone_into(&mut subject.artifact_media_type);
    subject.artifact_uri = format!("reproit-managed://{subject_digest}");
    candidate.deployment.runtime_capabilities = vec![
        "architecture.x86-64".to_owned(),
        "operating-system.linux".to_owned(),
        "runtime.rust-native".to_owned(),
        "sdk.rust".to_owned(),
    ];
    candidate.validate().unwrap();

    let failure: FailurePayload = decode(&protocol["positive"]["failure_payload"]["value"]);
    let trigger: Trigger = decode(&protocol["positive"]["trigger"]["value"]);
    let world: WorldCheckpoint = decode(&protocol["positive"]["world_checkpoint"]["value"]);
    let closure: WorldClosure = decode(&core["world_closure"]["value"]);
    let failure_bytes = canonical::canonical_bytes(&failure).unwrap();
    let trigger_bytes = canonical::canonical_bytes(&trigger).unwrap();
    let world_bytes = canonical::canonical_bytes(&world).unwrap();

    let transcript = DependencyTranscript {
        adapter_id: "http-transcript".to_owned(),
        adapter_version: "1.0.0".to_owned(),
        format: DependencyTranscriptFormat::V1,
        interactions: vec![DependencyTranscriptInteraction {
            causal_parent_id: None,
            operation_id: trigger.operation_id,
            outcome: DependencyOutcome::Response,
            request_digest: Digest::of(b"GET /inventory"),
            request_object_id: object_id(0xd0),
            response_digest: Digest::of(b"inventory response"),
            response_object_id: object_id(0xd1),
            sequence: 0,
            session_position: 0,
        }],
    };
    let transcript_bytes = canonical::canonical_bytes(&transcript).unwrap();

    let mut objects = vec![
        descriptor(
            object_id(0xc0),
            LogicalObjectRole::Candidate,
            "application/vnd.reproit.candidate.v1+json",
            canonical::digest(&candidate).unwrap(),
            1,
        ),
        descriptor(
            object_id(0xa0),
            LogicalObjectRole::Subject,
            SUBJECT_CLOSURE_MEDIA_TYPE,
            subject_digest,
            subject_manifest_bytes.len() as u64,
        ),
        descriptor(
            object_id(0xb0),
            LogicalObjectRole::Trigger,
            TRIGGER_MEDIA_TYPE,
            canonical::digest(&trigger).unwrap(),
            trigger_bytes.len() as u64,
        ),
        descriptor(
            failure.failure.object_id,
            LogicalObjectRole::Failure,
            FAILURE_MEDIA_TYPE,
            canonical::digest(&failure).unwrap(),
            failure_bytes.len() as u64,
        ),
        descriptor(
            object_id(0xe0),
            LogicalObjectRole::WorldManifest,
            WORLD_MANIFEST_MEDIA_TYPE,
            canonical::digest(&world).unwrap(),
            world_bytes.len() as u64,
        ),
        descriptor(
            object_id(0xd2),
            LogicalObjectRole::DependencyTranscript,
            DEPENDENCY_TRANSCRIPT_MEDIA_TYPE,
            Digest::of(&transcript_bytes),
            transcript_bytes.len() as u64,
        ),
        descriptor(
            transcript.interactions[0].request_object_id,
            LogicalObjectRole::DependencyTranscript,
            "application/octet-stream",
            transcript.interactions[0].request_digest,
            14,
        ),
        descriptor(
            transcript.interactions[0].response_object_id,
            LogicalObjectRole::DependencyTranscript,
            "application/octet-stream",
            transcript.interactions[0].response_digest,
            18,
        ),
    ];
    for (index, member) in subject_manifest.objects.iter().enumerate() {
        objects.push(descriptor(
            object_id(0xa1 + u8::try_from(index).unwrap()),
            LogicalObjectRole::Subject,
            &member.media_type,
            member.digest,
            member.size,
        ));
    }
    for input in &trigger.inputs {
        objects.push(descriptor(
            input.object_id,
            LogicalObjectRole::Trigger,
            "application/json",
            input.plain_digest,
            13,
        ));
    }
    for point in &world.points {
        for (index, artifact) in point.artifacts.iter().enumerate() {
            objects.push(descriptor(
                object_id(0xe1 + u8::try_from(index).unwrap()),
                LogicalObjectRole::WorldState,
                &artifact.media_type,
                artifact.digest,
                artifact.size,
            ));
        }
    }

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

    let manifest_object_id = capsule
        .objects
        .iter()
        .find(|object| object.media_type == SUBJECT_CLOSURE_MEDIA_TYPE)
        .unwrap()
        .object_id;
    let mut manifest_bytes = BTreeMap::new();
    manifest_bytes.insert(manifest_object_id, subject_manifest_bytes);
    manifest_bytes.insert(object_id(0xb0), trigger_bytes);
    manifest_bytes.insert(failure.failure.object_id, failure_bytes);
    manifest_bytes.insert(object_id(0xe0), world_bytes);
    manifest_bytes.insert(object_id(0xd2), transcript_bytes);
    SealedFixture {
        capsule,
        manifest_bytes,
    }
}

fn descriptor(
    object_id: ObjectId,
    role: LogicalObjectRole,
    media_type: &str,
    plain_digest: Digest,
    plain_size: u64,
) -> LogicalObject {
    LogicalObject {
        media_type: media_type.to_owned(),
        object_id,
        plain_digest,
        plain_size,
        role,
    }
}

fn decode<T: DeserializeOwned>(value: &Value) -> T {
    serde_json::from_value(value.clone()).unwrap()
}

#[test]
fn the_sealed_canonical_capsule_resolves_completely() {
    let fixture = sealed_fixture();
    let resolved = fixture.resolve().unwrap();
    assert_eq!(
        resolved.subject_objects.len(),
        resolved.subject_closure.objects.len()
    );
    assert_eq!(resolved.trigger_inputs.len(), resolved.trigger.inputs.len());
    assert_eq!(resolved.world_artifacts.len(), 1);
    let dependency = resolved.dependency.unwrap();
    assert_eq!(dependency.interactions.len(), 1);
    assert_eq!(
        canonical::digest(&resolved.failure.identity).unwrap(),
        fixture.capsule.failure_digest
    );
}

fn expect_rejection(fixture: &SealedFixture, code: ErrorCode) {
    let error = fixture.resolve().expect_err("the mutation must reject");
    assert_eq!(error.code, code);
}

#[test]
fn a_missing_closure_object_is_rejected() {
    let mut fixture = sealed_fixture();
    let member = fixture
        .capsule
        .objects
        .iter()
        .position(|object| {
            object.role == LogicalObjectRole::Subject
                && object.media_type != SUBJECT_CLOSURE_MEDIA_TYPE
        })
        .unwrap();
    fixture.capsule.objects.remove(member);
    // Spec error table: a sealed subject whose closure member is absent is a
    // changed subject digest, not a generic object mismatch.
    expect_rejection(&fixture, ErrorCode::SubjectDigestMismatch);
}

#[test]
fn a_duplicate_manifest_identity_is_rejected() {
    let mut fixture = sealed_fixture();
    let mut duplicate = fixture
        .capsule
        .objects
        .iter()
        .find(|object| object.media_type == SUBJECT_CLOSURE_MEDIA_TYPE)
        .unwrap()
        .clone();
    duplicate.object_id = object_id(0xff);
    fixture.capsule.objects.push(duplicate);
    fixture
        .capsule
        .objects
        .sort_by_key(|object| object.object_id);
    expect_rejection(&fixture, ErrorCode::SchemaInvalid);
}

#[test]
fn a_wrong_object_role_is_rejected() {
    let mut fixture = sealed_fixture();
    for object in &mut fixture.capsule.objects {
        if object.role == LogicalObjectRole::Failure {
            object.role = LogicalObjectRole::Subject;
        }
    }
    expect_rejection(&fixture, ErrorCode::SchemaInvalid);
}

#[test]
fn a_wrong_media_type_is_rejected() {
    let mut fixture = sealed_fixture();
    for object in &mut fixture.capsule.objects {
        if object.media_type == SUBJECT_CLOSURE_MEDIA_TYPE {
            object.media_type = "application/vnd.reproit.subject-closure.v1".to_owned();
        }
    }
    expect_rejection(&fixture, ErrorCode::SchemaInvalid);
}

#[test]
fn a_wrong_manifest_digest_is_rejected() {
    let fixture = sealed_fixture();
    let trigger_id = object_id(0xb0);
    let mut corrupted = fixture.manifest_bytes.clone();
    corrupted.get_mut(&trigger_id).unwrap()[0] ^= 0x01;
    let mut fixture = fixture;
    fixture.manifest_bytes = corrupted;
    expect_rejection(&fixture, ErrorCode::ObjectDigestMismatch);
}

#[test]
fn an_unknown_manifest_field_is_rejected() {
    let mut fixture = sealed_fixture();
    let transcript_id = object_id(0xd2);
    let bytes = fixture.manifest_bytes.get(&transcript_id).unwrap();
    let mut document: serde_json::Map<String, Value> = serde_json::from_slice(bytes).unwrap();
    document.insert("unknown_field".to_owned(), Value::Bool(true));
    let mutated = serde_json::to_vec(&Value::Object(document)).unwrap();
    let digest = Digest::of(&mutated);
    let size = mutated.len() as u64;
    fixture.manifest_bytes.insert(transcript_id, mutated);
    for object in &mut fixture.capsule.objects {
        if object.object_id == transcript_id {
            object.plain_digest = digest;
            object.plain_size = size;
        }
    }
    expect_rejection(&fixture, ErrorCode::SchemaInvalid);
}

#[test]
fn an_extra_unreferenced_object_is_rejected() {
    let mut fixture = sealed_fixture();
    fixture.capsule.objects.push(descriptor(
        object_id(0xfe),
        LogicalObjectRole::Subject,
        "application/vnd.reproit.subject-file.v1",
        Digest::of(b"unreferenced bytes"),
        18,
    ));
    fixture
        .capsule
        .objects
        .sort_by_key(|object| object.object_id);
    expect_rejection(&fixture, ErrorCode::SchemaInvalid);
}

#[test]
fn a_subject_closure_mismatch_is_rejected() {
    let mut fixture = sealed_fixture();
    fixture.capsule.subject.executable = "/reproit/subject/bin/other".to_owned();
    expect_rejection(&fixture, ErrorCode::SubjectDigestMismatch);
}

#[test]
fn a_trigger_mismatch_is_rejected() {
    let mut fixture = sealed_fixture();
    fixture.capsule.trigger_digest = Digest::of(b"a different trigger");
    expect_rejection(&fixture, ErrorCode::SchemaInvalid);
}

#[test]
fn a_world_manifest_mismatch_is_rejected() {
    let mut fixture = sealed_fixture();
    fixture.capsule.world_digest = Digest::of(b"a different world");
    expect_rejection(&fixture, ErrorCode::ObjectDigestMismatch);
}

#[test]
fn a_failure_mismatch_is_rejected() {
    let mut fixture = sealed_fixture();
    fixture.capsule.failure_digest = Digest::of(b"a different failure");
    expect_rejection(&fixture, ErrorCode::ObjectDigestMismatch);
}

#[test]
fn a_dependency_transcript_mismatch_is_rejected() {
    let mut fixture = sealed_fixture();
    let transcript_id = object_id(0xd2);
    let bytes = fixture.manifest_bytes.get(&transcript_id).unwrap();
    let mut transcript: DependencyTranscript = canonical::parse_strict(bytes).unwrap();
    transcript.interactions[0].request_digest = Digest::of(b"a replayed different request");
    let mutated = canonical::canonical_bytes(&transcript).unwrap();
    let digest = Digest::of(&mutated);
    let size = mutated.len() as u64;
    fixture.manifest_bytes.insert(transcript_id, mutated);
    for object in &mut fixture.capsule.objects {
        if object.object_id == transcript_id {
            object.plain_digest = digest;
            object.plain_size = size;
        }
    }
    expect_rejection(&fixture, ErrorCode::ObjectDigestMismatch);
}

#[test]
fn a_cross_capture_object_substitution_is_rejected() {
    // A substituted payload from another capture cannot satisfy the digest
    // binding that the capsule manifest pins for the object identity.
    let fixture = sealed_fixture();
    let failure_id = fixture
        .capsule
        .objects
        .iter()
        .find(|object| object.role == LogicalObjectRole::Failure)
        .unwrap()
        .object_id;
    let mut substituted = fixture.manifest_bytes.clone();
    let foreign: Vec<u8> = substituted
        .get(&failure_id)
        .unwrap()
        .iter()
        .rev()
        .copied()
        .collect();
    substituted.insert(failure_id, foreign);
    let mut fixture = fixture;
    fixture.manifest_bytes = substituted;
    expect_rejection(&fixture, ErrorCode::ObjectDigestMismatch);
}

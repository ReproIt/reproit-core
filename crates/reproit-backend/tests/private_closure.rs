//! Private-mode candidate sealing tests.
//!
//! The private Runtime seals the canonical closure-shaped capsule before
//! admission dispatch. These tests prove the construction is deterministic
//! and idempotent (restart re-sealing reproduces the identical digest),
//! fails closed on every missing or divergent provider source, and yields a
//! capsule the one canonical resolver accepts.

mod support;

use reproit_backend::private_closure::{
    PrivateClosureEvidence, PrivateClosureSources, ResolvedDependencyExchange,
    SealedPrivateCapsule, capsules_equal_modulo_processor, seal_private_candidate,
};
use reproit_backend::processor::bind_capsule_processor_requirement;
use reproit_backend::subject::{SINGLE_FILE_EXECUTABLE_PATH, single_file_subject_closure};
use reproit_backend::support::{BackendSupportPackage, build_backend_support_package};
use reproit_core::{
    ErrorCode, canonical,
    identity::Digest,
    model::{
        Candidate, EventKind, EventRecord, LogicalObject, LogicalObjectRole, ProcessingMode,
        ProcessorArchitecture, ProcessorRequirement, ProcessorRequirementFormat,
        SubjectRuntimeFamily, Validate as _, WorldCheckpoint, resolve_replay_capsule,
    },
};
use serde_json::Value;

const CORE_VECTORS: &str = include_str!("../../../specs/v1/vectors.json");
const PROTOCOL_VECTORS: &str = include_str!("../../../specs/v1/protocol-vectors.json");

const SUBJECT_BINARY: &[u8] = b"private fixture subject binary";
const DEBUG_ARTIFACT: &[u8] = b"private fixture debug artifact";
const CHECKPOINT: &[u8] = b"private fixture sqlite checkpoint";

struct PrivateFixture {
    candidate: Candidate,
    cursor: reproit_core::model::DependencyCursorPayload,
    support: BackendSupportPackage,
    world: WorldCheckpoint,
}

fn decode<T: serde::de::DeserializeOwned>(value: &Value) -> T {
    serde_json::from_value(value.clone()).expect("conformance vector")
}

fn support_package() -> BackendSupportPackage {
    let core: Value = serde_json::from_str(CORE_VECTORS).expect("core vectors");
    let protocol: Value = serde_json::from_str(PROTOCOL_VECTORS).expect("protocol vectors");
    build_backend_support_package(
        decode(&core["support_bundle"]["value"]),
        decode(&core["closure_policy"]["value"]),
        reproit_backend::config::BackendSdk::Rust,
        ProcessorArchitecture::X86_64,
        decode(&protocol["positive"]["debugger_contract"]["value"]),
        Digest::of(b"private-closure-test-conformance"),
    )
    .expect("support package")
}

fn fixture_world() -> WorldCheckpoint {
    let protocol: Value = serde_json::from_str(PROTOCOL_VECTORS).expect("protocol vectors");
    let mut world: WorldCheckpoint = decode(&protocol["positive"]["world_checkpoint"]["value"]);
    let point = world.points.first_mut().expect("one recoverable point");
    point.recoverable_until = "2099-01-01T00:00:00.000Z".parse().expect("timestamp");
    let artifact = point.artifacts.first_mut().expect("one artifact");
    artifact.digest = Digest::of(CHECKPOINT);
    artifact.size = u64::try_from(CHECKPOINT.len()).expect("bounded checkpoint");
    artifact.uri = format!("oci://customer.example/state/orders@{}", artifact.digest);
    world.world_id().expect("world identity");
    world
}

fn fixture() -> PrivateFixture {
    let mut candidate = support::candidate();
    candidate.processing_mode = ProcessingMode::Private;
    candidate.deployment.processing_mode = ProcessingMode::Private;
    let world = fixture_world();
    candidate.world_id = world.world_id().expect("world identity");
    let subject = &mut candidate.deployment.subject;
    "architecture.x86-64".clone_into(&mut subject.architecture);
    SINGLE_FILE_EXECUTABLE_PATH.clone_into(&mut subject.executable);
    subject.arguments.clear();
    let manifest = single_file_subject_closure(
        subject,
        SUBJECT_BINARY,
        DEBUG_ARTIFACT,
        SubjectRuntimeFamily::Rust,
    )
    .expect("subject closure manifest");
    candidate.deployment.subject.artifact_digest =
        canonical::digest(&manifest).expect("manifest digest");
    // The Backend closure policy requires exact-transcript evidence for the
    // network boundary, so the canonical private capture always records its
    // dependency exchange.
    let cursor = push_dependency_record(&mut candidate);
    candidate.validate().expect("valid private candidate");
    PrivateFixture {
        candidate,
        cursor,
        support: support_package(),
        world,
    }
}

fn exchange(fixture: &PrivateFixture) -> ResolvedDependencyExchange {
    ResolvedDependencyExchange {
        cursor: fixture.cursor.clone(),
        request: b"GET /permit HTTP/1.1".to_vec(),
        response: b"HTTP/1.1 200 OK".to_vec(),
    }
}

fn seal(fixture: &PrivateFixture) -> SealedPrivateCapsule {
    try_seal(fixture, SUBJECT_BINARY, vec![exchange(fixture)]).expect("sealed private capsule")
}

fn try_seal(
    fixture: &PrivateFixture,
    subject_binary: &[u8],
    dependencies: Vec<ResolvedDependencyExchange>,
) -> Result<SealedPrivateCapsule, reproit_core::Error> {
    seal_private_candidate(&PrivateClosureSources {
        candidate: &fixture.candidate,
        debug_artifact: DEBUG_ARTIFACT,
        dependencies,
        evidence: PrivateClosureEvidence {
            executor_identity: Digest::of(b"private-closure-test-executor"),
            isolation_identity: Digest::of(b"private-closure-test-isolation"),
        },
        subject_binary,
        support: &fixture.support,
        world: &fixture.world,
        world_artifacts: vec![CHECKPOINT.to_vec()],
    })
}

#[test]
fn sealing_is_deterministic_and_idempotent_across_restart() {
    let fixture = fixture();
    let first = seal(&fixture);
    let second = seal(&fixture);
    assert_eq!(first.capsule_digest, second.capsule_digest);
    assert_eq!(first.capsule, second.capsule);
    assert_eq!(first.objects, second.objects);
    assert_eq!(
        canonical::digest(&first.capsule).expect("capsule digest"),
        first.capsule_digest
    );
}

#[test]
fn the_sealed_capsule_resolves_through_the_canonical_resolver() {
    let fixture = fixture();
    let sealed = seal(&fixture);
    let resolved = resolve_replay_capsule(&sealed.capsule, &mut |descriptor: &LogicalObject| {
        sealed
            .objects
            .get(&descriptor.object_id)
            .cloned()
            .ok_or_else(reproit_core::Error::object_digest_mismatch)
    })
    .expect("canonical resolution");
    assert_eq!(resolved.failure.identity, sealed.failure.identity);
    assert_eq!(
        resolved
            .dependency
            .as_ref()
            .map(|dependency| dependency.interactions.len()),
        Some(1)
    );
    assert_eq!(sealed.capsule.processing_mode, ProcessingMode::Private);
    // The sealed capsule binds the initial captured processor requirement.
    assert!(
        sealed
            .capsule
            .required_capabilities
            .iter()
            .any(|capability| capability.starts_with("processor.requirement."))
    );
}

#[test]
fn a_divergent_subject_artifact_is_rejected_before_sealing() {
    let fixture = fixture();
    let mut tampered = SUBJECT_BINARY.to_vec();
    tampered[0] ^= 1;
    let error =
        try_seal(&fixture, &tampered, vec![exchange(&fixture)]).expect_err("tampered subject");
    assert_eq!(error.code, ErrorCode::SubjectDigestMismatch);
}

#[test]
fn a_divergent_world_artifact_is_rejected_before_sealing() {
    let fixture = fixture();
    let dependency_error = seal_private_candidate(&PrivateClosureSources {
        candidate: &fixture.candidate,
        debug_artifact: DEBUG_ARTIFACT,
        dependencies: vec![exchange(&fixture)],
        evidence: PrivateClosureEvidence {
            executor_identity: Digest::of(b"private-closure-test-executor"),
            isolation_identity: Digest::of(b"private-closure-test-isolation"),
        },
        subject_binary: SUBJECT_BINARY,
        world: &fixture.world,
        support: &fixture.support,
        world_artifacts: vec![b"different checkpoint bytes".to_vec()],
    })
    .expect_err("divergent world artifact with dependency");
    assert_eq!(dependency_error.code, ErrorCode::ObjectDigestMismatch);
}

#[test]
fn an_unresolved_dependency_record_is_rejected() {
    let fixture = fixture();
    let error = try_seal(&fixture, SUBJECT_BINARY, Vec::new()).expect_err("missing exchange");
    assert_eq!(error.code, ErrorCode::IncompleteCandidate);
}

#[test]
fn a_recorded_dependency_seals_one_transcript_manifest_with_its_bodies() {
    let fixture = fixture();
    let sealed = try_seal(&fixture, SUBJECT_BINARY, vec![exchange(&fixture)])
        .expect("sealed capsule with dependency");
    let transcripts = sealed
        .capsule
        .objects
        .iter()
        .filter(|object| object.role == LogicalObjectRole::DependencyTranscript)
        .count();
    assert_eq!(transcripts, 3);
    let resolved = resolve_replay_capsule(&sealed.capsule, &mut |descriptor: &LogicalObject| {
        sealed
            .objects
            .get(&descriptor.object_id)
            .cloned()
            .ok_or_else(reproit_core::Error::object_digest_mismatch)
    })
    .expect("canonical resolution");
    assert_eq!(
        resolved
            .dependency
            .as_ref()
            .map(|dependency| dependency.interactions.len()),
        Some(1)
    );
}

#[test]
fn the_admitted_capsule_may_differ_only_in_its_processor_requirement() {
    let fixture = fixture();
    let sealed = seal(&fixture);
    let mut narrowed = sealed.capsule.clone();
    let requirement = ProcessorRequirement {
        abi: "sysv-x86-64".to_owned(),
        architecture: ProcessorArchitecture::X86_64,
        format: ProcessorRequirementFormat::V1,
        identity: None,
        instruction_features: Vec::new(),
        os_enabled_states: Vec::new(),
    };
    bind_capsule_processor_requirement(&mut narrowed, &requirement).expect("narrowed binding");
    assert!(
        capsules_equal_modulo_processor(&sealed.capsule, &narrowed)
            .expect("processor-only comparison")
    );
    let mut different_subject = sealed.capsule.clone();
    different_subject.subject_digest = Digest::of(b"another subject");
    different_subject.subject.artifact_digest = different_subject.subject_digest;
    assert!(
        !capsules_equal_modulo_processor(&sealed.capsule, &different_subject)
            .expect("subject divergence comparison")
    );
}

/// Append one dependency cursor record before the Failure record and repair
/// the sequence numbers and terminal payload, mirroring the SDK's record
/// order contract.
fn push_dependency_record(
    candidate: &mut Candidate,
) -> reproit_core::model::DependencyCursorPayload {
    let cursor_bytes = *Digest::of(b"private-closure-test-cursor").as_bytes();
    let cursor = reproit_core::model::DependencyCursorPayload {
        adapter_id: "http-transcript".to_owned(),
        adapter_version: "1.0.0".to_owned(),
        causal_parent_id: None,
        cursor: reproit_core::crypto::encode_base64url(&cursor_bytes),
        cursor_digest: Digest::of(&cursor_bytes),
        format: reproit_core::model::DependencyCursorFormat::V1,
    };
    let payload = reproit_core::crypto::encode_base64url(
        &canonical::canonical_bytes(&cursor).expect("cursor bytes"),
    );
    let failure_index = candidate
        .records
        .iter()
        .position(|record| record.kind == EventKind::Failure)
        .expect("one Failure record");
    candidate.records.insert(
        failure_index,
        EventRecord {
            kind: EventKind::Dependency,
            payload,
            sequence: 0,
        },
    );
    for (index, record) in candidate.records.iter_mut().enumerate() {
        record.sequence = u16::try_from(index).expect("bounded sequence");
    }
    let event_count = candidate.records.len() - 1;
    let terminal_payload = serde_json::json!({
        "complete": true,
        "event_count": event_count,
        "format": "reproit.terminal.v1",
    });
    let terminal = candidate.records.last_mut().expect("terminal record");
    terminal.payload = reproit_core::crypto::encode_base64url(
        &serde_json::to_vec(&terminal_payload).expect("terminal payload"),
    );
    candidate
        .validate()
        .expect("valid candidate with dependency");
    cursor
}

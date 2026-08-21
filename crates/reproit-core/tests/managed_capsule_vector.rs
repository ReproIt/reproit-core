//! Conformance over one real managed sealed capsule.
//!
//! The vector holds the exact canonical documents of a capsule that a real
//! managed acceptance admitted with three matching runs on a Kata replay
//! host. Payload bytes (subject files, World state) are not stored; their
//! digests are pinned inside the manifests, and the resolver reads only the
//! manifest-class documents.

use std::collections::BTreeMap;

use reproit_core::{
    ErrorCode, canonical,
    identity::{Digest, ObjectId},
    model::{
        LogicalObject, LogicalObjectRole, ReplayCapsule, Validate as _, resolve_replay_capsule,
    },
};
use serde_json::Value;

const VECTOR: &str = include_str!("../../../specs/v1/managed-capsule-vector.json");

const MANIFEST_DOCUMENTS: [&str; 5] = [
    "subject_closure",
    "trigger",
    "failure_payload",
    "world_checkpoint",
    "dependency_transcript",
];

fn vector() -> Value {
    serde_json::from_str(VECTOR).expect("the managed capsule vector must parse")
}

fn canonical_bytes(value: &Value) -> Vec<u8> {
    canonical::canonical_bytes(value).expect("the vector document must canonicalize")
}

fn capsule() -> ReplayCapsule {
    let vector = vector();
    canonical::parse_strict(&canonical_bytes(&vector["capsule"]["value"]))
        .expect("the real capsule must parse strictly")
}

/// Map each manifest document to its capsule object by plaintext digest.
fn manifest_bytes(vector: &Value, capsule: &ReplayCapsule) -> BTreeMap<ObjectId, Vec<u8>> {
    let mut bytes = BTreeMap::new();
    for name in MANIFEST_DOCUMENTS {
        let document = canonical_bytes(&vector[name]["value"]);
        let digest = Digest::of(&document);
        let object = capsule
            .objects
            .iter()
            .find(|object| object.plain_digest == digest)
            .unwrap_or_else(|| panic!("the {name} document must be a capsule object"));
        bytes.insert(object.object_id, document);
    }
    bytes
}

fn resolve(
    capsule: &ReplayCapsule,
    bytes: &BTreeMap<ObjectId, Vec<u8>>,
) -> Result<reproit_core::model::ResolvedReplayCapsule, reproit_core::Error> {
    let bytes = bytes.clone();
    resolve_replay_capsule(capsule, &mut |object: &LogicalObject| {
        bytes
            .get(&object.object_id)
            .cloned()
            .ok_or_else(reproit_core::Error::object_digest_mismatch)
    })
}

#[test]
fn every_real_document_matches_its_published_canonical_digest() {
    let vector = vector();
    for name in MANIFEST_DOCUMENTS.iter().chain(["capsule"].iter()) {
        let expected = vector[*name]["canonical_sha256"]
            .as_str()
            .expect("the canonical digest must be present");
        let actual = format!(
            "sha256:{}",
            hex_digest(&canonical_bytes(&vector[*name]["value"]))
        );
        assert_eq!(actual, expected, "the {name} digest must match");
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    Digest::of(bytes).to_string().replace("sha256:", "")
}

#[test]
fn the_real_managed_capsule_resolves_completely() {
    let vector = vector();
    let capsule = capsule();
    capsule.validate().expect("the real capsule must validate");
    let bytes = manifest_bytes(&vector, &capsule);
    let resolved = resolve(&capsule, &bytes).expect("the real capsule must resolve");
    assert_eq!(
        resolved.subject_objects.len(),
        resolved.subject_closure.objects.len()
    );
    assert_eq!(resolved.trigger_inputs.len(), resolved.trigger.inputs.len());
    assert!(!resolved.world_artifacts.is_empty());
    let dependency = resolved
        .dependency
        .expect("the real capsule records a dependency transcript");
    assert_eq!(
        dependency.interactions.len(),
        dependency.transcript.interactions.len()
    );
    assert_eq!(
        canonical::digest(&resolved.failure.identity).unwrap(),
        capsule.failure_digest
    );
}

#[test]
fn the_real_capsule_rejects_a_missing_failure_object() {
    let vector = vector();
    let mut capsule = capsule();
    let bytes = manifest_bytes(&vector, &capsule);
    capsule
        .objects
        .retain(|object| object.role != LogicalObjectRole::Failure);
    let error = resolve(&capsule, &bytes).expect_err("a missing Failure object must reject");
    assert_eq!(error.code, ErrorCode::SchemaInvalid);
}

#[test]
fn the_real_capsule_rejects_a_changed_manifest_digest() {
    let vector = vector();
    let capsule = capsule();
    let mut bytes = manifest_bytes(&vector, &capsule);
    let trigger_id = capsule
        .objects
        .iter()
        .find(|object| {
            object.media_type == "application/vnd.reproit.trigger.v1+json"
                && object.role == LogicalObjectRole::Trigger
        })
        .unwrap()
        .object_id;
    bytes.get_mut(&trigger_id).unwrap()[0] ^= 0x01;
    let error = resolve(&capsule, &bytes).expect_err("a changed manifest must reject");
    assert_eq!(error.code, ErrorCode::ObjectDigestMismatch);
}

#[test]
fn the_real_capsule_rejects_a_swapped_object_role() {
    let vector = vector();
    let mut capsule = capsule();
    for object in &mut capsule.objects {
        if object.role == LogicalObjectRole::WorldState {
            object.role = LogicalObjectRole::Trigger;
        }
    }
    let bytes = manifest_bytes(&vector, &capsule);
    let error = resolve(&capsule, &bytes).expect_err("a swapped role must reject");
    // The World artifact can no longer bind to a WorldState object, so the
    // reference resolution reports the digest-binding failure.
    assert_eq!(error.code, ErrorCode::ObjectDigestMismatch);
}

use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};

mod support;

use reproit_backend::{
    AdmissionExecutor, ExecutionObservation, ExecutionRequest, ObjectClosure, admit, admit_run,
    complete_admission,
    keep::KeptCapture,
    seal::{open_capture_object, open_manifest},
    validate_candidate_binding,
};
use reproit_core::{
    Error, ErrorCode, canonical,
    crypto::{decode_base64url, secret_key},
    identity::Digest,
    model::{CaptureBatchManifest, FailureIdentity, ReplayCapsule, UploadEnvelope},
};
use serde_json::Value;
use support::{input, seal_fixture};

const CRYPTO_VECTORS: &str = include_str!("../../../specs/v1/crypto-vectors.json");

struct Executor {
    capsule_bytes: Mutex<Vec<Vec<u8>>>,
    expected: FailureIdentity,
    runs: AtomicUsize,
}

impl Executor {
    fn new(expected: FailureIdentity) -> Self {
        Self {
            capsule_bytes: Mutex::new(Vec::new()),
            expected,
            runs: AtomicUsize::new(0),
        }
    }
}

struct SubjectExecutor {
    defect_subject: Digest,
    expected: FailureIdentity,
}

impl AdmissionExecutor for SubjectExecutor {
    fn execute(&self, request: ExecutionRequest<'_>) -> Result<ExecutionObservation, Error> {
        Ok(ExecutionObservation {
            cleanup_complete: true,
            executor_capabilities_digest: request.capsule.support_bundle_digest,
            failure: (request.capsule.subject_digest == self.defect_subject)
                .then(|| self.expected.clone()),
        })
    }
}

impl AdmissionExecutor for Executor {
    fn execute(
        &self,
        request: ExecutionRequest<'_>,
    ) -> Result<ExecutionObservation, reproit_core::Error> {
        assert!(
            request
                .objects
                .get(request.capsule.objects[0].object_id)
                .is_some()
        );
        self.capsule_bytes
            .lock()
            .expect("capsule byte records")
            .push(canonical::canonical_bytes(request.capsule)?);
        self.runs.fetch_add(1, Ordering::SeqCst);
        Ok(ExecutionObservation {
            cleanup_complete: true,
            executor_capabilities_digest: request.capsule.support_bundle_digest,
            failure: Some(self.expected.clone()),
        })
    }
}

#[test]
fn admission_uses_three_clean_matching_runs() {
    let input = input();
    let sealed_capsule_bytes = canonical::canonical_bytes(&input.capsule).unwrap();
    let executor = Executor::new(input.expected_failure.clone());
    let admitted = admit(&input, &executor).expect("admission must pass");
    assert_eq!(executor.runs.load(Ordering::SeqCst), 3);
    assert_eq!(
        *executor.capsule_bytes.lock().expect("capsule byte records"),
        vec![sealed_capsule_bytes; 3]
    );
    assert_eq!(admitted.proofs.map(|proof| proof.run_index), [0, 1, 2]);
    assert_eq!(
        admitted.capsule_digest,
        canonical::digest(&input.capsule).unwrap()
    );
}

#[test]
fn distributed_runs_complete_with_the_same_proof_contract() {
    let input = input();
    let executor = Executor::new(input.expected_failure.clone());
    let proofs = [
        admit_run(&input, &executor, 0).unwrap(),
        admit_run(&input, &executor, 1).unwrap(),
        admit_run(&input, &executor, 2).unwrap(),
    ];
    let admitted = complete_admission(&input, proofs).unwrap();
    assert_eq!(executor.runs.load(Ordering::SeqCst), 3);
    assert_eq!(admitted.proofs.map(|proof| proof.run_index), [0, 1, 2]);

    assert_eq!(
        admit_run(&input, &executor, 3).unwrap_err().code,
        ErrorCode::AdmissionProofBinding
    );
}

#[test]
fn changed_failure_stops_before_an_admitted_result() {
    let input = input();
    let mut changed = input.expected_failure.clone();
    if let FailureIdentity::Exception(identity) = &mut changed {
        identity.type_name = "OtherFailure".to_owned();
    }
    let executor = Executor::new(changed);
    let error = admit(&input, &executor).expect_err("a different Failure must fail");
    assert_eq!(error.code, ErrorCode::DifferentFailure);
    assert_eq!(executor.runs.load(Ordering::SeqCst), 1);
}

#[test]
fn unknown_profile_stops_before_executor_work() {
    let mut input = input();
    input.capsule.profile = "unknown".to_owned();
    let executor = Executor::new(input.expected_failure.clone());
    let error = admit(&input, &executor).expect_err("an unknown profile must fail closed");
    assert_eq!(error.code, ErrorCode::UnsupportedCapabilitySet);
    assert_eq!(executor.runs.load(Ordering::SeqCst), 0);
}

#[test]
fn closed_candidate_binds_runtime_capture_identities() {
    let candidate = support::candidate();
    let input = input();
    validate_candidate_binding(&candidate, &input).unwrap();

    let mut changed = candidate;
    changed.world_id = Digest::of(b"another World checkpoint");
    let error = validate_candidate_binding(&changed, &input).unwrap_err();
    assert_eq!(error.code, ErrorCode::IncompleteCandidate);
}

#[test]
fn backend_opens_the_clean_download_manifest() {
    let crypto: Value = serde_json::from_str(CRYPTO_VECTORS).unwrap();
    let vector = &crypto["clean_download_manifest"];
    let envelope: UploadEnvelope = decode(&vector["signed_envelope"]);
    let verification_key = decode_base64url::<32>(vector["verification_key"].as_str().unwrap())
        .expect("the verification key must decode");
    let occurrence_key = secret_key(
        hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let stored = hex::decode(vector["downloaded_manifest_ciphertext"].as_str().unwrap()).unwrap();
    let manifest: CaptureBatchManifest =
        open_manifest(&envelope, &verification_key, &occurrence_key, &stored)
            .expect("the Backend must open the clean download");
    assert_eq!(
        canonical::digest(&manifest).unwrap().to_string(),
        vector["expected_manifest_canonical_sha256"]
            .as_str()
            .unwrap()
    );
}

#[test]
fn sealed_capture_debugs_and_kept_capture_checks_without_cloud() {
    let input = input();
    let executor = Executor::new(input.expected_failure.clone());
    let admitted = admit(&input, &executor).unwrap();
    let (sealed, occurrence_key, verification_key) = seal_fixture(&input, &admitted);

    let opened = reproit_backend::seal::open_capture(
        &sealed.envelope,
        &verification_key,
        &occurrence_key,
        &sealed.ciphertext,
    )
    .expect("local debug must open the sealed capture");
    let capsule: ReplayCapsule =
        canonical::parse_strict(&opened.objects[&opened.manifest.replay_capsule_object_id])
            .unwrap();
    assert_eq!(
        canonical::digest(&capsule).unwrap(),
        admitted.capsule_digest
    );
    let replay_objects = ObjectClosure::new(
        &capsule.objects,
        capsule
            .objects
            .iter()
            .map(|object| (object.object_id, opened.objects[&object.object_id].clone()))
            .collect(),
    )
    .unwrap();
    let subject_executor = SubjectExecutor {
        defect_subject: capsule.subject_digest,
        expected: input.expected_failure.clone(),
    };
    let debug = subject_executor
        .execute(ExecutionRequest {
            capsule: &capsule,
            objects: &replay_objects,
            perturbation: &input.perturbations[0],
        })
        .unwrap();
    assert!(
        input
            .expected_failure
            .matches(debug.failure.as_ref().unwrap())
    );

    let envelope_bytes = canonical::canonical_bytes(&sealed.envelope).unwrap();
    let kept = KeptCapture::copy_verified(
        &envelope_bytes,
        &sealed.ciphertext,
        &verification_key,
        &occurrence_key,
    )
    .expect("Keep must copy a complete verified closure");
    drop(sealed);
    let kept_opened = kept
        .open(&verification_key, &occurrence_key)
        .expect("the kept capture must open without Cloud");
    assert_eq!(kept_opened.manifest, opened.manifest);

    let mut fixed_capsule = capsule;
    fixed_capsule.subject_digest = Digest::of(b"fixed subject stores 15");
    fixed_capsule.subject.artifact_digest = fixed_capsule.subject_digest;
    let check = subject_executor
        .execute(ExecutionRequest {
            capsule: &fixed_capsule,
            objects: &replay_objects,
            perturbation: &input.perturbations[0],
        })
        .unwrap();
    assert!(
        check.failure.is_none(),
        "the kept changed-subject check must pass"
    );
    let regression = subject_executor
        .execute(ExecutionRequest {
            capsule: &canonical::parse_strict(
                &kept_opened.objects[&kept_opened.manifest.replay_capsule_object_id],
            )
            .unwrap(),
            objects: &replay_objects,
            perturbation: &input.perturbations[0],
        })
        .unwrap();
    assert!(
        regression.failure.is_some(),
        "reintroducing the defect must fail the kept check"
    );
}

#[test]
fn planning_opens_only_the_selected_replay_capsule() {
    let input = input();
    let executor = Executor::new(input.expected_failure.clone());
    let admitted = admit(&input, &executor).unwrap();
    let (sealed, occurrence_key, _) = seal_fixture(&input, &admitted);
    let encrypted_capsule = sealed
        .manifest
        .objects
        .iter()
        .find(|object| object.descriptor.object_id == sealed.manifest.replay_capsule_object_id)
        .unwrap();
    let selected_ciphertext: std::collections::BTreeMap<_, _> = encrypted_capsule
        .chunks
        .iter()
        .map(|chunk| {
            (
                chunk.cipher_digest,
                sealed.ciphertext[&chunk.cipher_digest].clone(),
            )
        })
        .collect();
    let selected_capsule = open_capture_object(
        &sealed.envelope,
        &occurrence_key,
        &sealed.manifest,
        sealed.manifest.replay_capsule_object_id,
        &selected_ciphertext,
    )
    .unwrap();
    assert_eq!(
        Digest::of(&selected_capsule),
        sealed.manifest.replay_capsule_digest
    );

    let mut extra_ciphertext = selected_ciphertext;
    extra_ciphertext.insert(
        Digest::of(b"unselected object"),
        b"unselected object".to_vec(),
    );
    assert_eq!(
        open_capture_object(
            &sealed.envelope,
            &occurrence_key,
            &sealed.manifest,
            sealed.manifest.replay_capsule_object_id,
            &extra_ciphertext,
        )
        .unwrap_err()
        .code,
        ErrorCode::ObjectDigestMismatch
    );
}

fn decode<T>(value: &Value) -> T
where
    T: for<'de> serde::Deserialize<'de>,
{
    canonical::parse_strict(&serde_json::to_vec(value).unwrap()).unwrap()
}

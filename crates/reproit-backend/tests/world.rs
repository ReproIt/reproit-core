use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
};

use reproit_backend::world::{
    CheckpointScope, MaterializeRequest, ProviderLease, ProviderMaterialization,
    ProviderVerification, RecoverablePoint, StateProvider, TranscriptInteraction,
    verify_dependency_transcript, verify_subject_artifact, with_verified_world,
};
use reproit_core::{
    Error, ErrorCode,
    identity::{CaptureId, Digest, ExecutionId, Timestamp},
    model::ProviderResourceClaim,
};

struct FixtureProvider {
    fail_materialize: bool,
    pinned: Mutex<Option<RecoverablePoint>>,
    releases: AtomicUsize,
    snapshot: BTreeMap<String, Vec<u8>>,
}

impl FixtureProvider {
    fn new(snapshot: BTreeMap<String, Vec<u8>>) -> Self {
        Self {
            fail_materialize: false,
            pinned: Mutex::new(None),
            releases: AtomicUsize::new(0),
            snapshot,
        }
    }

    fn materialized_digest(&self, target_reference: &str) -> Result<Digest, Error> {
        let pinned = self.pinned.lock().unwrap_or_else(PoisonError::into_inner);
        let point = pinned.as_ref().ok_or_else(|| {
            Error::new(
                ErrorCode::WorldProviderMissing,
                "The provider has no pinned World point.",
            )
        })?;
        if let CheckpointScope::Scoped(rules) = &point.scope
            && !rules.contains(target_reference)
        {
            return Err(Error::new(
                ErrorCode::StateScopeViolation,
                "The restore target is outside the declared checkpoint scope.",
            ));
        }
        let bytes = self.snapshot.get(target_reference).ok_or_else(|| {
            Error::new(
                ErrorCode::ArtifactNotFound,
                "The provider could not resolve the checkpoint artifact.",
            )
        })?;
        Ok(Digest::of(bytes))
    }
}

impl StateProvider for FixtureProvider {
    fn pin(
        &self,
        point: &RecoverablePoint,
        capture_id: CaptureId,
        world_id: Digest,
    ) -> Result<ProviderLease, Error> {
        self.pinned
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .replace(point.clone());
        Ok(ProviderLease {
            capture_id,
            expires_at: timestamp("2026-01-01T00:02:00.000Z"),
            lease_id: id("lse_01890f3e-7b1c-7cc0-8a1b-123456789ab3"),
            point_digest: point.point_digest,
            provider_id: point.provider_id.clone(),
            world_id,
        })
    }

    fn materialize(
        &self,
        lease: &ProviderLease,
        execution_id: ExecutionId,
        target_reference: &str,
    ) -> Result<ProviderMaterialization, Error> {
        if self.fail_materialize {
            return Err(Error::new(
                ErrorCode::ArtifactNotFound,
                "The provider could not materialize the checkpoint artifact.",
            ));
        }
        Ok(ProviderMaterialization {
            evidence_digest: self.materialized_digest(target_reference)?,
            execution_id,
            lease_id: lease.lease_id,
            provider_id: lease.provider_id.clone(),
        })
    }

    fn verify(
        &self,
        lease: &ProviderLease,
        materialization: &ProviderMaterialization,
    ) -> Result<ProviderVerification, Error> {
        Ok(ProviderVerification {
            evidence_digest: materialization.evidence_digest,
            execution_id: materialization.execution_id,
            lease_id: lease.lease_id,
            provider_id: lease.provider_id.clone(),
        })
    }

    fn release(&self, _lease: &ProviderLease) -> Result<(), Error> {
        self.pinned
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        self.releases.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[test]
fn full_and_scoped_points_restore_repeatably_and_release() {
    let snapshot = BTreeMap::from([
        ("counter".to_owned(), b"5".to_vec()),
        ("ordered-jobs".to_owned(), b"a,b,c".to_vec()),
    ]);
    let provider = FixtureProvider::new(snapshot);
    let capabilities = BTreeSet::from(["world.fixture".to_owned()]);

    let first = with_verified_world(
        &provider,
        &request(point(CheckpointScope::Full), &capabilities, "counter"),
        |verification| Ok(verification.evidence_digest),
    )
    .unwrap();
    let second = with_verified_world(
        &provider,
        &request(
            point(CheckpointScope::Scoped(BTreeSet::from([
                "counter".to_owned()
            ]))),
            &capabilities,
            "counter",
        ),
        |verification| Ok(verification.evidence_digest),
    )
    .unwrap();

    assert_eq!(first, Digest::of(b"5"));
    assert_eq!(first, second);
    assert_eq!(provider.releases.load(Ordering::SeqCst), 2);
    assert!(provider.pinned.lock().unwrap().is_none());
}

#[test]
fn scoped_access_and_every_post_pin_failure_release_the_lease() {
    let provider = FixtureProvider::new(BTreeMap::from([
        ("counter".to_owned(), b"5".to_vec()),
        ("secret".to_owned(), b"hidden".to_vec()),
    ]));
    let capabilities = BTreeSet::from(["world.fixture".to_owned()]);
    let scoped = point(CheckpointScope::Scoped(BTreeSet::from([
        "counter".to_owned()
    ])));

    let error = with_verified_world(
        &provider,
        &request(scoped.clone(), &capabilities, "secret"),
        |_| Ok(()),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::StateScopeViolation);

    let error = with_verified_world(
        &provider,
        &request(scoped, &capabilities, "counter"),
        |_| {
            Err::<(), _>(Error::new(
                ErrorCode::EvaluationError,
                "The isolated subject was cancelled.",
            ))
        },
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::EvaluationError);
    assert_eq!(provider.releases.load(Ordering::SeqCst), 2);
    assert!(provider.pinned.lock().unwrap().is_none());
}

#[test]
fn unsupported_and_expired_points_stop_before_pin() {
    let provider = FixtureProvider::new(BTreeMap::new());
    let no_capabilities = BTreeSet::new();
    let error = with_verified_world(
        &provider,
        &request(point(CheckpointScope::Full), &no_capabilities, "counter"),
        |_| Ok(()),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::UnsupportedCapabilitySet);

    let capabilities = BTreeSet::from(["world.fixture".to_owned()]);
    let mut expired = point(CheckpointScope::Full);
    expired.recoverable_until = timestamp("2025-12-31T23:59:59.999Z");
    let error = with_verified_world(
        &provider,
        &request(expired, &capabilities, "counter"),
        |_| Ok(()),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::WorldPointExpired);
    assert_eq!(provider.releases.load(Ordering::SeqCst), 0);
}

#[test]
fn dependency_and_subject_closure_fail_on_missing_or_changed_bytes() {
    let operation_id = id("op_01890f3e-7b1c-7cc0-8a1b-123456789ab1");
    let request_id = id("obj_01890f3e-7b1c-7cc0-8a1b-123456789ab4");
    let response_id = id("obj_01890f3e-7b1c-7cc0-8a1b-123456789ab5");
    let request_bytes = b"request".to_vec();
    let response_bytes = b"response".to_vec();
    let interaction = TranscriptInteraction {
        causal_parent_id: None,
        operation_id,
        request_digest: Digest::of(&request_bytes),
        request_object_id: request_id,
        response_digest: Digest::of(&response_bytes),
        response_object_id: response_id,
        sequence: 0,
        session_position: 0,
    };
    let mut objects = BTreeMap::from([(request_id, request_bytes), (response_id, response_bytes)]);
    verify_dependency_transcript(operation_id, std::slice::from_ref(&interaction), &objects)
        .unwrap();
    objects.insert(response_id, b"changed".to_vec());
    let error = verify_dependency_transcript(operation_id, &[interaction], &objects).unwrap_err();
    assert_eq!(error.code, ErrorCode::DependencyTranscriptMismatch);

    let subject = b"immutable subject";
    verify_subject_artifact(subject, Digest::of(subject), subject.len()).unwrap();
    assert_eq!(
        verify_subject_artifact(subject, Digest::of(b"other"), subject.len())
            .unwrap_err()
            .code,
        ErrorCode::SubjectDigestMismatch
    );
    assert_eq!(
        verify_subject_artifact(subject, Digest::of(subject), subject.len() - 1)
            .unwrap_err()
            .code,
        ErrorCode::UploadLimitExceeded
    );
}

fn point(scope: CheckpointScope) -> RecoverablePoint {
    RecoverablePoint {
        artifacts: BTreeMap::from([(Digest::of(b"checkpoint"), 10)]),
        capabilities: BTreeSet::from(["world.fixture".to_owned()]),
        configuration_digest: Digest::of(b"configuration"),
        engine_identity: "fixture-state".to_owned(),
        engine_version: "1.0.0".to_owned(),
        generation: 1,
        point_digest: Digest::of(b"point"),
        provider_id: "fixture-state".to_owned(),
        published_at: timestamp("2026-01-01T00:00:00.000Z"),
        recoverable_until: timestamp("2026-01-01T00:01:00.000Z"),
        resource_claim: ProviderResourceClaim {
            materialized_bytes: 10,
            objects: 1,
            pinned_bytes: 10,
            temporary_bytes: 10,
        },
        scope,
    }
}

fn request(
    point: RecoverablePoint,
    capabilities: &BTreeSet<String>,
    target_reference: &str,
) -> MaterializeRequest {
    MaterializeRequest {
        capture_id: id("cap_01890f3e-7b1c-7cc0-8a1b-123456789abc"),
        execution_capabilities: capabilities.clone(),
        execution_id: id("exe_01890f3e-7b1c-7cc0-8a1b-123456789ab2"),
        now: timestamp("2026-01-01T00:00:30.000Z"),
        point,
        target_reference: target_reference.to_owned(),
        world_id: Digest::of(b"world"),
    }
}

fn timestamp(value: &str) -> Timestamp {
    Timestamp::from_str(value).unwrap()
}

fn id<T: FromStr>(value: &str) -> T
where
    T::Err: std::fmt::Debug,
{
    value.parse().unwrap()
}

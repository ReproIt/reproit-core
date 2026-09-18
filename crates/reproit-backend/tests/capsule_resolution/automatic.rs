use super::*;
use reproit_backend::automatic_replay::{AutomaticReplay, resolve_automatic_replay};
use reproit_core::{
    Error,
    crypto::encode_base64url,
    model::{ArtifactReference, AutomaticObservationClass as Class},
};

fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../../../specs/v1/automatic-replay-vectors.json"
    ))
    .unwrap()
}

fn add_payload(
    fixture: &mut SealedFixture,
    role: LogicalObjectRole,
    bytes: Vec<u8>,
) -> LogicalObject {
    let id = object_id(u8::try_from(0x20 + fixture.manifest_bytes.len()).unwrap());
    let object = descriptor(
        id,
        role,
        "application/octet-stream",
        Digest::of(&bytes),
        bytes.len() as u64,
    );
    fixture.capsule.objects.push(object.clone());
    fixture.manifest_bytes.insert(id, bytes);
    object
}

fn replace_manifest<T: serde::Serialize>(
    fixture: &mut SealedFixture,
    media_type: &str,
    manifest: &T,
) {
    let bytes = canonical::canonical_bytes(manifest).unwrap();
    let object = fixture
        .capsule
        .objects
        .iter_mut()
        .find(|object| object.media_type == media_type)
        .unwrap();
    object.plain_digest = Digest::of(&bytes);
    object.plain_size = bytes.len() as u64;
    fixture.manifest_bytes.insert(object.object_id, bytes);
}

fn add_state(
    fixture: &mut SealedFixture,
    world: &mut WorldCheckpoint,
    class: Class,
    position: u64,
    request: &[u8],
    response: Vec<u8>,
) {
    let object = add_payload(fixture, LogicalObjectRole::WorldState, response);
    world.points[0].artifacts.push(ArtifactReference {
        digest: object.plain_digest,
        media_type: object.media_type,
        size: object.plain_size,
        uri: format!(
            "reproit-managed://automatic-world/{}/{}/{position}/response",
            class.boundary_id(),
            Digest::of(request)
        ),
    });
}

fn add_dependency(
    fixture: &mut SealedFixture,
    transcript: &mut DependencyTranscript,
    operation_id: reproit_core::identity::OperationId,
    position: u64,
    request: Vec<u8>,
    response: Vec<u8>,
) {
    let request = add_payload(fixture, LogicalObjectRole::DependencyTranscript, request);
    let response = add_payload(fixture, LogicalObjectRole::DependencyTranscript, response);
    transcript
        .interactions
        .push(DependencyTranscriptInteraction {
            causal_parent_id: None,
            operation_id,
            outcome: DependencyOutcome::Response,
            request_digest: request.plain_digest,
            request_object_id: request.object_id,
            response_digest: response.plain_digest,
            response_object_id: response.object_id,
            sequence: u16::try_from(transcript.interactions.len()).unwrap(),
            session_position: position,
        });
}

fn automatic_fixture(vectors: &Value) -> SealedFixture {
    let mut fixture = sealed_fixture();
    let resolved = fixture.resolve().unwrap();
    let mut world = resolved.world;
    let point = &mut world.points[0];
    "automatic-world".clone_into(&mut point.provider_id);
    "reproit-native".clone_into(&mut point.engine_identity);
    "1.0.0".clone_into(&mut point.engine_version);
    point.capabilities = vec!["capture.automatic-world.v1".to_owned()];
    point.artifacts.clear();
    point.resource_claim.pinned_bytes = 2_097_152;
    point.resource_claim.objects = 1_024;
    fixture.capsule.objects.retain(|object| {
        object.role != LogicalObjectRole::WorldState
            && (object.role != LogicalObjectRole::DependencyTranscript
                || object.media_type == DEPENDENCY_TRANSCRIPT_MEDIA_TYPE)
    });
    let mut transcript = resolved.dependency.unwrap().transcript;
    "reproit-native".clone_into(&mut transcript.adapter_id);
    transcript.interactions.clear();
    add_state(
        &mut fixture,
        &mut world,
        Class::Environment,
        0,
        b"process-environment",
        canonical::canonical_bytes(&vectors["environment"]).unwrap(),
    );
    add_dependency(
        &mut fixture,
        &mut transcript,
        resolved.trigger.operation_id,
        0,
        b"wall-clock".to_vec(),
        vectors["boundary_clock"]
            .as_str()
            .unwrap()
            .as_bytes()
            .to_vec(),
    );
    for record in vectors["observations"].as_array().unwrap() {
        let class: Class = decode(&record["observation_class"]);
        let position = record["position"].as_u64().unwrap();
        let request = canonical::canonical_bytes(&record["request"]).unwrap();
        let response = canonical::canonical_bytes(&record["response"]).unwrap();
        if matches!(class, Class::Environment | Class::Filesystem) {
            add_state(
                &mut fixture,
                &mut world,
                class,
                position,
                &request,
                response,
            );
        } else {
            add_dependency(
                &mut fixture,
                &mut transcript,
                resolved.trigger.operation_id,
                position,
                request,
                response,
            );
        }
    }
    fixture.capsule.world_digest = world.world_id().unwrap();
    replace_manifest(&mut fixture, WORLD_MANIFEST_MEDIA_TYPE, &world);
    replace_manifest(&mut fixture, DEPENDENCY_TRANSCRIPT_MEDIA_TYPE, &transcript);
    fixture
        .capsule
        .objects
        .sort_by_key(|object| object.object_id);
    fixture
}

fn replay(fixture: &SealedFixture) -> Result<AutomaticReplay, Error> {
    resolve_automatic_replay(&fixture.resolve()?, &mut |object| {
        fixture
            .manifest_bytes
            .get(&object.object_id)
            .cloned()
            .ok_or_else(Error::object_digest_mismatch)
    })
}

#[test]
fn automatic_capsule_replays_all_seven_classes_and_requires_exact_consumption() {
    let vectors = vectors();
    let fixture = automatic_fixture(&vectors);
    let mut replay = replay(&fixture).unwrap();
    assert_eq!(
        replay.environment().get(b"REGION".as_slice()).unwrap(),
        b"west"
    );
    assert_eq!(
        replay.boundary_clock().as_str(),
        vectors["boundary_clock"].as_str().unwrap()
    );
    assert!(replay.require_complete().is_err());
    for record in vectors["observations"].as_array().unwrap() {
        let class: Class = decode(&record["observation_class"]);
        let position = record["position"].as_u64().unwrap();
        let request = canonical::canonical_bytes(&record["request"]).unwrap();
        assert!(
            replay
                .take_response(class, position, b"changed request")
                .is_err()
        );
        assert!(replay.take_response(class, position + 1, &request).is_err());
        let response = replay.take_response(class, position, &request).unwrap();
        assert_eq!(
            response.response,
            canonical::canonical_bytes(&record["response"]).unwrap()
        );
        assert_eq!(response.outcome, DependencyOutcome::Response);
        assert!(replay.take_response(class, position, &request).is_err());
    }
    replay.require_complete().unwrap();
}

#[test]
fn automatic_capsule_rejects_invalid_environment_and_position_gaps() {
    for (name, value) in [
        (b"".as_slice(), b"value".as_slice()),
        (b"A=B", b"value"),
        (b"A\0", b"value"),
        (b"A", b"v\0"),
    ] {
        let mut vector = vectors();
        vector["environment"] =
            serde_json::json!({encode_base64url(name): encode_base64url(value)});
        assert!(replay(&automatic_fixture(&vector)).is_err());
    }
    let mut vector = vectors();
    vector["observations"][0]["position"] = 2.into();
    assert!(replay(&automatic_fixture(&vector)).is_err());
    let mut vector = vectors();
    let duplicate = vector["observations"][0].clone();
    vector["observations"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    assert!(replay(&automatic_fixture(&vector)).is_err());
}

#[test]
fn automatic_capsule_rejects_damaged_payloads_and_wrong_semantic_bindings() {
    let mut fixture = automatic_fixture(&vectors());
    let state = fixture
        .capsule
        .objects
        .iter()
        .find(|object| object.role == LogicalObjectRole::WorldState)
        .unwrap();
    fixture
        .manifest_bytes
        .get_mut(&state.object_id)
        .unwrap()
        .push(b' ');
    assert!(
        matches!(replay(&fixture), Err(error) if error.code == ErrorCode::ObjectDigestMismatch)
    );
    let mut vector = vectors();
    vector["observations"][0]["response"]["request_digest"] =
        Digest::of(b"wrong request").to_string().into();
    assert!(replay(&automatic_fixture(&vector)).is_err());
    let mut vector = vectors();
    vector["observations"][1]["response"]["operation"] = "filesystem-read".into();
    assert!(replay(&automatic_fixture(&vector)).is_err());
}

#[test]
fn automatic_capsule_checks_bounds_before_reading_payloads() {
    let fixture = automatic_fixture(&vectors());
    let mut resolved = fixture.resolve().unwrap();
    resolved.world_artifacts[0].object.plain_size = 1_048_577;
    assert!(
        resolve_automatic_replay(&resolved, &mut |_| panic!(
            "oversized object must not be read"
        ))
        .is_err()
    );
    resolved = fixture.resolve().unwrap();
    resolved.world.points[0].engine_version = "2.0.0".to_owned();
    assert!(
        matches!(resolve_automatic_replay(&resolved, &mut |_| panic!("unsupported provider must not be read")), Err(error) if error.code == ErrorCode::UnsupportedCapabilitySet)
    );
}

#[test]
fn automatic_environment_accepts_exact_limits_and_rejects_excess() {
    let mut vector = vectors();
    vector["environment"] =
        serde_json::json!({encode_base64url(b"A"): encode_base64url(&vec![b'x'; 524_287])});
    replay(&automatic_fixture(&vector)).unwrap();
    vector["environment"] =
        serde_json::json!({encode_base64url(b"A"): encode_base64url(&vec![b'x'; 524_288])});
    assert!(replay(&automatic_fixture(&vector)).is_err());
    let mut environment = BTreeMap::new();
    for index in 0..4_096 {
        environment.insert(
            encode_base64url(index.to_string().as_bytes()),
            String::new(),
        );
    }
    vector["environment"] = serde_json::to_value(&environment).unwrap();
    replay(&automatic_fixture(&vector)).unwrap();
    environment.insert(encode_base64url(b"extra"), String::new());
    vector["environment"] = serde_json::to_value(&environment).unwrap();
    assert!(replay(&automatic_fixture(&vector)).is_err());
}

#[test]
fn automatic_capsule_requires_both_baselines_and_the_captured_operation() {
    let fixture = automatic_fixture(&vectors());
    let resolved = fixture.resolve().unwrap();
    let mut missing_clock = resolved.clone();
    let dependency = missing_clock.dependency.as_mut().unwrap();
    dependency.interactions.remove(0);
    dependency.transcript.interactions.remove(0);
    for (index, interaction) in dependency.transcript.interactions.iter_mut().enumerate() {
        interaction.sequence = u16::try_from(index).unwrap();
    }
    let mut missing_environment = resolved.clone();
    missing_environment.world_artifacts.remove(0);
    missing_environment.world.points[0].artifacts.remove(0);
    let mut wrong_operation = resolved;
    wrong_operation
        .dependency
        .as_mut()
        .unwrap()
        .transcript
        .interactions[0]
        .operation_id = "op_01890f3e-7b1c-7cc0-8a1b-123456789099".parse().unwrap();
    for invalid in [missing_clock, missing_environment, wrong_operation] {
        assert!(
            resolve_automatic_replay(&invalid, &mut |object| {
                Ok(fixture.manifest_bytes[&object.object_id].clone())
            })
            .is_err()
        );
    }
}

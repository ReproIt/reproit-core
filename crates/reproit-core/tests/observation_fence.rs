use reproit_core::{
    ErrorCode, canonical,
    crypto::{decode_base64url, encode_base64url},
    model::{
        AutomaticObservationPayload, Candidate, ClosurePolicy, EventKind, EventRecord,
        NativeObservationFenceReceipt, TerminalFormat, TerminalPayload, verify_automatic_capture,
    },
};
use serde::Serialize;
use serde_json::Value;

const CORE_SCHEMA: &str = include_str!("../../../specs/v1/schemas.json");
const FENCE_VECTORS: &str = include_str!("../../../specs/v1/observation-fence-vector.json");
const PROTOCOL_VECTORS: &str = include_str!("../../../specs/v1/protocol-vectors.json");

#[test]
fn observation_fence_positive_vectors_match_schema_and_signature() {
    let vectors = parse(FENCE_VECTORS);
    let schema = parse(CORE_SCHEMA);
    assert!(schema_is_valid(
        &schema,
        "closure_policy",
        &vectors["positive"]["closure_policy"]
    ));
    for observation in array(&vectors["positive"]["observations"]) {
        assert!(schema_is_valid(
            &schema,
            "automatic_observation_payload",
            observation
        ));
    }
    for ownership in array(&vectors["positive"]["receipt"]["adapter_ownership"]) {
        assert!(schema_is_valid(
            &schema,
            "semantic_adapter_ownership",
            ownership
        ));
    }
    assert!(schema_is_valid(
        &schema,
        "native_observation_fence_receipt",
        &vectors["positive"]["receipt"]
    ));
    assert_digest(
        &vectors["positive"]["observations"][0],
        &vectors["canonical_sha256"]["automatic_observation_payload"],
    );
    assert_digest(
        &vectors["positive"]["receipt"]["adapter_ownership"][0],
        &vectors["canonical_sha256"]["semantic_adapter_ownership"],
    );
    assert_digest(
        &vectors["positive"]["receipt"],
        &vectors["canonical_sha256"]["native_observation_fence_receipt"],
    );

    let fixture = Fixture::from_vectors(&vectors);
    fixture
        .verify()
        .expect("the authenticated automatic capture must close");
}

#[test]
fn observation_fence_negative_vectors_fail_closed() {
    let vectors = parse(FENCE_VECTORS);
    for vector in array(&vectors["negative"]) {
        let name = string(&vector["name"]);
        let expected = error_code(string(&vector["expected"]));
        let error = negative_fixture(name, &vectors)
            .expect_err("the negative observation-fence vector must fail");
        assert_eq!(error.code, expected, "{name}");
    }
}

fn negative_fixture(name: &str, vectors: &Value) -> Result<(), reproit_core::Error> {
    if name == "missing-fence" {
        let protocol = parse(PROTOCOL_VECTORS);
        let candidate: Candidate = decode(&protocol["positive"]["candidate"]["value"]);
        let fixture = Fixture::from_candidate(vectors, candidate);
        return fixture.verify();
    }

    let mut observations = observations(vectors);
    let mut fence = fence(vectors);
    match name {
        "unowned-observation" => {
            observations[0].owner_adapter_id = None;
            fence.unowned_observation_count = 1;
        }
        "observation-sequence-gap" => observations[1].observation_sequence = 7,
        "dropped-observation" => fence.dropped_observation_count = 1,
        "observation-overflow" => fence.overflowed = true,
        "unknown-owner" => observations[0].owner_adapter_id = Some("unknown-adapter".to_owned()),
        "operation-scope-mismatch" => {
            observations[0].operation_id =
                "op_01890f3e-7b1c-7cc0-8a1b-123456789ab2".parse().unwrap();
        }
        "causal-parent-scope-mismatch" => {
            observations[0].causal_parent_id =
                Some("op_01890f3e-7b1c-7cc0-8a1b-123456789ab2".parse().unwrap());
        }
        "subject-mismatch" => {
            fence.subject_digest =
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .parse()
                    .unwrap();
        }
        "deployment-mismatch" => {
            fence.deployment_digest =
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .parse()
                    .unwrap();
        }
        "invalid-fence-signature" => {
            fence.signature.replace_range(..1, "A");
            return Fixture::from_parts(vectors, &observations, &fence).verify();
        }
        _ => panic!("unknown negative vector {name}"),
    }
    fence.observation_count = u16::try_from(observations.len()).unwrap();
    fence.observations_digest = canonical::digest(&observations).unwrap();
    Fixture::from_parts(vectors, &observations, &fence).verify()
}

struct Fixture {
    candidate: Candidate,
    policy: ClosurePolicy,
    public_key: [u8; 32],
}

impl Fixture {
    fn from_vectors(vectors: &Value) -> Self {
        let observations = observations(vectors);
        let fence = fence(vectors);
        Self::from_parts(vectors, &observations, &fence)
    }

    fn from_parts(
        vectors: &Value,
        observations: &[AutomaticObservationPayload],
        fence: &NativeObservationFenceReceipt,
    ) -> Self {
        let protocol = parse(PROTOCOL_VECTORS);
        let candidate: Candidate = decode(&protocol["positive"]["candidate"]["value"]);
        let candidate = automatic_candidate(candidate, observations, fence);
        Self::from_candidate(vectors, candidate)
    }

    fn from_candidate(vectors: &Value, candidate: Candidate) -> Self {
        Self {
            candidate,
            policy: decode(&vectors["positive"]["closure_policy"]),
            public_key: decode_base64url(string(&vectors["public_key"])).unwrap(),
        }
    }

    fn verify(&self) -> Result<(), reproit_core::Error> {
        verify_automatic_capture(
            &self.candidate,
            &self.policy,
            "native-observation-fence-test",
            &self.public_key,
        )
    }
}

fn automatic_candidate(
    mut candidate: Candidate,
    observations: &[AutomaticObservationPayload],
    fence: &NativeObservationFenceReceipt,
) -> Candidate {
    let begin = candidate.records[0].clone();
    let input = candidate
        .records
        .iter()
        .find(|record| record.kind == EventKind::Input)
        .cloned();
    let failure = candidate
        .records
        .iter()
        .find(|record| record.kind == EventKind::Failure)
        .cloned()
        .unwrap();
    let mut records = vec![begin];
    records.extend(input);
    records.extend(
        observations
            .iter()
            .map(|observation| event(EventKind::Observation, observation)),
    );
    records.push(event(EventKind::ObservationFence, fence));
    records.push(failure);
    let terminal = TerminalPayload {
        complete: true,
        event_count: u16::try_from(records.len()).unwrap(),
        format: TerminalFormat::V1,
    };
    records.push(event(EventKind::Terminal, &terminal));
    for (sequence, record) in records.iter_mut().enumerate() {
        record.sequence = u16::try_from(sequence).unwrap();
    }
    candidate.records = records;
    candidate
}

fn event(kind: EventKind, payload: &impl Serialize) -> EventRecord {
    EventRecord {
        kind,
        payload: encode_base64url(&canonical::canonical_bytes(payload).unwrap()),
        sequence: 0,
    }
}

fn observations(vectors: &Value) -> Vec<AutomaticObservationPayload> {
    array(&vectors["positive"]["observations"])
        .iter()
        .map(decode)
        .collect()
}

fn fence(vectors: &Value) -> NativeObservationFenceReceipt {
    decode(&vectors["positive"]["receipt"])
}

fn schema_is_valid(schema: &Value, definition: &str, value: &Value) -> bool {
    let reference = serde_json::json!({
        "$ref": format!("https://reproit.dev/spec/v1/schemas.json#/$defs/{definition}")
    });
    let registry = jsonschema::Registry::new()
        .add("https://reproit.dev/spec/v1/schemas.json", schema)
        .unwrap()
        .prepare()
        .unwrap();
    jsonschema::options()
        .with_registry(&registry)
        .build(&reference)
        .unwrap()
        .is_valid(value)
}

fn error_code(value: &str) -> ErrorCode {
    serde_json::from_value(Value::String(value.to_owned())).unwrap()
}

fn assert_digest(value: &Value, expected: &Value) {
    assert_eq!(
        canonical::digest_value(value).unwrap().to_string(),
        string(expected)
    );
}

fn decode<T>(value: &Value) -> T
where
    T: for<'de> serde::Deserialize<'de>,
{
    canonical::parse_strict(&serde_json::to_vec(value).unwrap()).unwrap()
}

fn parse(value: &str) -> Value {
    serde_json::from_str(value).unwrap()
}

fn array(value: &Value) -> &[Value] {
    value.as_array().unwrap()
}

fn string(value: &Value) -> &str {
    value.as_str().unwrap()
}

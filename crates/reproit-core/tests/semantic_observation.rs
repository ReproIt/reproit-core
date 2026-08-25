use reproit_core::{
    canonical,
    model::{
        SemanticObservationRequest, SemanticObservationResponse, Validate,
        validate_semantic_observation_pair,
    },
};
use serde_json::Value;

const CORE_SCHEMA: &str = include_str!("../../../specs/v1/schemas.json");
const VECTORS: &str = include_str!("../../../specs/v1/semantic-observation-vector.json");

#[test]
fn positive_vectors_match_the_shared_schema_and_pair_contract() {
    let schema = parse(CORE_SCHEMA);
    let vectors = parse(VECTORS);
    for vector in array(&vectors["positive"]) {
        let request: SemanticObservationRequest = decode(&vector["request"]);
        let response: SemanticObservationResponse = decode(&vector["response"]);
        assert!(schema_is_valid(
            &schema,
            "semantic_observation_request",
            &vector["request"]
        ));
        assert!(schema_is_valid(
            &schema,
            "semantic_observation_response",
            &vector["response"]
        ));
        request.validate().unwrap();
        response.validate().unwrap();
        validate_semantic_observation_pair(&request, &response).unwrap();
        assert_eq!(
            response.request_digest,
            canonical::digest(&request).unwrap(),
            "{}",
            string(&vector["name"])
        );
    }
}

#[test]
fn negative_vectors_fail_the_request_or_pair_contract() {
    let vectors = parse(VECTORS);
    for vector in array(&vectors["negative"]) {
        let request: SemanticObservationRequest = decode(&vector["request"]);
        let rejected = if vector["response"].is_null() {
            request.validate().is_err()
        } else {
            let response: SemanticObservationResponse = decode(&vector["response"]);
            validate_semantic_observation_pair(&request, &response).is_err()
        };
        assert!(rejected, "{}", string(&vector["name"]));
    }
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

fn parse(value: &str) -> Value {
    serde_json::from_str(value).unwrap()
}

fn array(value: &Value) -> &[Value] {
    value.as_array().unwrap()
}

fn string(value: &Value) -> &str {
    value.as_str().unwrap()
}

fn decode<T>(value: &Value) -> T
where
    T: for<'de> serde::Deserialize<'de>,
{
    serde_json::from_value(value.clone()).unwrap()
}

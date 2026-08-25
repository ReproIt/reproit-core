use std::{
    io::Write as _,
    process::{Command, Stdio},
};

use reproit_core::canonical;
use serde_json::Value;

const CORE_VECTORS: &str = include_str!("../../../specs/v1/vectors.json");
const PROTOCOL_VECTORS: &str = include_str!("../../../specs/v1/protocol-vectors.json");

#[test]
fn canonical_bytes_match_two_independent_implementations() {
    let core = parse(CORE_VECTORS);
    let protocol = parse(PROTOCOL_VECTORS);
    let values = [
        &core["closure_policy"]["value"],
        &core["capture_batch_manifest"]["value"],
        &core["replay_capsule"]["value"],
        &protocol["positive"]["failure_payload"]["value"],
        &protocol["positive"]["dependency_transcript"]["value"],
        &protocol["positive"]["semantic_dependency_request_database"]["value"],
        &protocol["positive"]["semantic_dependency_response_database"]["value"],
        &protocol["positive"]["semantic_dependency_request_outbound_http"]["value"],
        &protocol["positive"]["semantic_dependency_response_outbound_http"]["value"],
        &protocol["positive"]["semantic_dependency_response_outbound_http_error"]["value"],
        &protocol["positive"]["semantic_dependency_request_queue"]["value"],
        &protocol["positive"]["semantic_dependency_response_queue"]["value"],
    ];

    for value in values {
        let input = serde_json::to_vec(value).expect("the vector must serialize");
        let expected = canonical::canonical_bytes(value).expect("the vector must canonicalize");
        assert_eq!(run_jq(&input), expected);
        assert_eq!(run_node(&input), expected);
    }
}

#[test]
fn rfc_8785_reference_value_matches() {
    let value = serde_json::json!({
        "string": "€$\u{000f}\nA'B\"\\\"/",
        "literals": [null, true, false]
    });
    assert_eq!(
        canonical::canonical_bytes(&value).unwrap(),
        r#"{"literals":[null,true,false],"string":"€$\u000f\nA'B\"\\\"/"}"#.as_bytes()
    );
}

fn run_jq(input: &[u8]) -> Vec<u8> {
    let mut output = run("jq", &["-cS", "."], input);
    assert_eq!(output.pop(), Some(b'\n'));
    output
}

fn run_node(input: &[u8]) -> Vec<u8> {
    let source = r"
const fs = require('fs');
const sort = value => {
  if (Array.isArray(value)) return value.map(sort);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, sort(value[key])]));
  }
  return value;
};
process.stdout.write(JSON.stringify(sort(JSON.parse(fs.readFileSync(0, 'utf8')))));
";
    run("node", &["-e", source], input)
}

fn run(program: &str, arguments: &[&str], input: &[u8]) -> Vec<u8> {
    let mut child = Command::new(program)
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("{program} must start: {error}"));
    child
        .stdin
        .take()
        .expect("the child input must exist")
        .write_all(input)
        .expect("the child input must write");
    let output = child.wait_with_output().expect("the child must finish");
    assert!(
        output.status.success(),
        "{program} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

fn parse(input: &str) -> Value {
    serde_json::from_str(input).expect("the checked-in vector must parse")
}

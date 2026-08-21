use reproit_core::limits::{MAX_KEPT_PREPARATIONS, MAX_KEPT_REFERENCES};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeptSetLimits {
    format: String,
    max_concurrent_preparations: usize,
    max_references: usize,
}

#[test]
fn generated_limits_match_the_canonical_machine_contract() {
    let contract: KeptSetLimits =
        serde_json::from_str(include_str!("../../../specs/v1/kept-set-limits.json"))
            .expect("The kept-set limits contract must be valid JSON.");
    assert_eq!(contract.format, "reproit.kept-set-limits.v1");
    assert_eq!(MAX_KEPT_REFERENCES, contract.max_references);
    assert_eq!(MAX_KEPT_PREPARATIONS, contract.max_concurrent_preparations);
}

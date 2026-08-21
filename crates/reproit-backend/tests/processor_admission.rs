use std::sync::atomic::{AtomicUsize, Ordering};

mod support;

use reproit_backend::{
    AdmissionExecutor, ExecutionObservation, ExecutionRequest,
    processor::{
        ProcessorConstraint, ProcessorReductionPolicy, ProcessorTrialExecutor,
        ProcessorTrialLimits, ProcessorTrialResult, bind_processor_requirement, reduce_and_admit,
    },
};
use reproit_core::{
    Error, canonical,
    model::{
        ExecutionOutcome, ProcessorObservation, ProcessorRequirement, ProcessorTrialEvidenceKind,
    },
};
use serde_json::Value;
use support::{input, seal_fixture};

const VECTORS: &str = include_str!("../../../specs/v1/protocol-vectors.json");

struct Trials;

impl ProcessorTrialExecutor for Trials {
    fn can_control(&self, _constraint: &ProcessorConstraint) -> bool {
        true
    }

    fn execute_trial(
        &self,
        requirement: &ProcessorRequirement,
        _limits: ProcessorTrialLimits,
    ) -> Result<ProcessorTrialResult, Error> {
        Ok(ProcessorTrialResult {
            cpu_milliseconds: 1,
            elapsed_milliseconds: 1,
            execution_result: if requirement
                .instruction_features
                .iter()
                .any(|feature| feature == "AVX512F")
            {
                ExecutionOutcome::TargetReproduced
            } else {
                ExecutionOutcome::TargetAbsent
            },
            output_bytes: 1,
            timed_out: false,
            unstable: false,
        })
    }
}

struct Admission {
    expected_requirement: String,
    runs: AtomicUsize,
}

impl AdmissionExecutor for Admission {
    fn execute(&self, request: ExecutionRequest<'_>) -> Result<ExecutionObservation, Error> {
        assert!(
            request
                .capsule
                .required_capabilities
                .iter()
                .any(|value| value == &self.expected_requirement)
        );
        self.runs.fetch_add(1, Ordering::SeqCst);
        Ok(ExecutionObservation {
            cleanup_complete: true,
            executor_capabilities_digest: request.capsule.support_bundle_digest,
            failure: Some(input().expected_failure),
        })
    }
}

#[test]
fn production_admission_uses_and_binds_the_reduced_requirement() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let observation: ProcessorObservation =
        serde_json::from_value(vectors["positive"]["processor_observation_x86"]["value"].clone())
            .unwrap();
    let mut requirement: ProcessorRequirement =
        serde_json::from_value(vectors["positive"]["processor_requirement_x86"]["value"].clone())
            .unwrap();
    requirement
        .instruction_features
        .insert(1, "AVX512BW".to_owned());
    let mut admission_input = input();
    bind_processor_requirement(&mut admission_input, &requirement).unwrap();
    let original_digest = canonical::digest(&admission_input.capsule).unwrap();
    let expected_reduced = ProcessorRequirement {
        instruction_features: vec!["AVX512F".to_owned()],
        identity: None,
        os_enabled_states: Vec::new(),
        ..requirement.clone()
    };
    let expected_requirement = format!(
        "processor.requirement.{}",
        canonical::digest(&expected_reduced)
            .unwrap()
            .to_string()
            .trim_start_matches("sha256:")
    );
    let admission = Admission {
        expected_requirement: expected_requirement.clone(),
        runs: AtomicUsize::new(0),
    };
    let (reduction, admitted) = reduce_and_admit(
        &mut admission_input,
        &observation,
        &requirement,
        ProcessorReductionPolicy::PRODUCTION,
        &Trials,
        &admission,
    )
    .unwrap();
    assert_eq!(reduction.requirement, expected_reduced);
    assert_eq!(admission.runs.load(Ordering::SeqCst), 3);
    assert_ne!(admitted.capsule_digest, original_digest);
    assert_eq!(
        admitted.capsule_digest,
        canonical::digest(&admission_input.capsule).unwrap()
    );
    assert!(
        admission_input
            .capsule
            .required_capabilities
            .contains(&expected_requirement)
    );
    assert!(
        reduction
            .receipt
            .trials
            .iter()
            .all(|trial| { trial.evidence_kind == ProcessorTrialEvidenceKind::ExactNative })
    );
    let (sealed, _, _) = seal_fixture(&admission_input, &admitted);
    assert_eq!(
        sealed.envelope.replay_capsule_digest,
        admitted.capsule_digest
    );
}

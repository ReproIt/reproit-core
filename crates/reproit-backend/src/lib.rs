#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use reproit_core::{
    Error, ErrorCode, canonical,
    identity::{Digest, ObjectId},
    model::{
        Candidate, ClosurePolicy, FailureIdentity, LogicalObject, Perturbation, Proof, ProofFormat,
        ReplayCapsule, Validate, WorldClosure,
    },
    proof,
};

pub mod checkpoint;
pub mod closure;
pub mod config;
pub mod dependency;
#[cfg(feature = "acceptance-fixture")]
pub mod fixture;
pub mod host_processor;
pub mod keep;
pub mod managed;
pub mod processor;
pub mod production_support;
pub mod seal;
pub mod subject;
pub mod support;
pub mod world;

pub struct ObjectClosure {
    objects: BTreeMap<ObjectId, Vec<u8>>,
}

impl ObjectClosure {
    pub fn new(
        descriptors: &[LogicalObject],
        objects: BTreeMap<ObjectId, Vec<u8>>,
    ) -> Result<Self, Error> {
        let descriptor_ids = descriptors
            .iter()
            .map(|descriptor| descriptor.object_id)
            .collect::<BTreeSet<_>>();
        if descriptor_ids.len() != descriptors.len()
            || descriptor_ids.len() != objects.len()
            || descriptor_ids != objects.keys().copied().collect()
        {
            return Err(Error::new(
                ErrorCode::WorldNotClosed,
                "The object closure is incomplete.",
            ));
        }
        for descriptor in descriptors {
            descriptor.validate()?;
            let bytes = &objects[&descriptor.object_id];
            if descriptor.plain_digest != Digest::of(bytes)
                || descriptor.plain_size != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
            {
                return Err(Error::object_digest_mismatch());
            }
        }
        Ok(Self { objects })
    }

    pub fn get(&self, object_id: ObjectId) -> Option<&[u8]> {
        self.objects.get(&object_id).map(Vec::as_slice)
    }

    pub fn all(&self) -> &BTreeMap<ObjectId, Vec<u8>> {
        &self.objects
    }
}

pub struct AdmissionInput {
    pub capsule: ReplayCapsule,
    pub closure: WorldClosure,
    pub closure_policy: ClosurePolicy,
    pub expected_failure: FailureIdentity,
    pub objects: ObjectClosure,
    pub perturbations: [Perturbation; 3],
}

pub struct ExecutionRequest<'a> {
    pub capsule: &'a ReplayCapsule,
    pub objects: &'a ObjectClosure,
    pub perturbation: &'a Perturbation,
}

pub struct ExecutionObservation {
    pub cleanup_complete: bool,
    pub executor_capabilities_digest: Digest,
    pub failure: Option<FailureIdentity>,
}

pub trait AdmissionExecutor {
    fn execute(&self, request: ExecutionRequest<'_>) -> Result<ExecutionObservation, Error>;
}

pub fn validate_candidate_binding(
    candidate: &Candidate,
    input: &AdmissionInput,
) -> Result<(), Error> {
    candidate.validate()?;
    input.expected_failure.validate()?;
    input.capsule.validate()?;
    if canonical::digest(&input.expected_failure)? != candidate.failure.identity
        || input.capsule.failure_digest != candidate.failure.identity
        || input.capsule.subject_digest != candidate.deployment.subject.artifact_digest
        || input.capsule.world_digest != candidate.world_id
    {
        return Err(Error::new(
            ErrorCode::IncompleteCandidate,
            "The closed candidate does not bind the captured operation.",
        ));
    }
    Ok(())
}

#[derive(Debug)]
pub struct AdmittedCandidate {
    pub capsule_digest: Digest,
    pub proofs: [Proof; 3],
}

pub fn admit(
    input: &AdmissionInput,
    executor: &impl AdmissionExecutor,
) -> Result<AdmittedCandidate, Error> {
    validate_admission_input(input)?;
    let proofs = [
        admit_run(input, executor, 0)?,
        admit_run(input, executor, 1)?,
        admit_run(input, executor, 2)?,
    ];
    complete_admission(input, proofs)
}

pub fn admit_run(
    input: &AdmissionInput,
    executor: &impl AdmissionExecutor,
    run_index: usize,
) -> Result<Proof, Error> {
    validate_admission_input(input)?;
    let perturbation = input
        .perturbations
        .get(run_index)
        .ok_or_else(proof_binding)?;
    perturbation.validate()?;
    if usize::from(perturbation.run_index) != run_index {
        return Err(proof_binding());
    }
    let observation = executor.execute(ExecutionRequest {
        capsule: &input.capsule,
        objects: &input.objects,
        perturbation,
    })?;
    if !observation.cleanup_complete {
        return Err(Error::new(
            ErrorCode::EvaluationError,
            "The admission executor did not complete cleanup.",
        ));
    }
    let Some(observed_failure) = observation.failure else {
        return Err(Error::new(
            ErrorCode::DifferentFailure,
            "The target Failure did not reproduce.",
        ));
    };
    if !input.expected_failure.matches(&observed_failure) {
        return Err(Error::new(
            ErrorCode::DifferentFailure,
            "A different Failure occurred during admission.",
        ));
    }
    Ok(Proof {
        capsule_digest: canonical::digest(&input.capsule)?,
        executor_capabilities_digest: observation.executor_capabilities_digest,
        failure_digest: input.capsule.failure_digest,
        format: ProofFormat::V1,
        perturbation_digest: canonical::digest(perturbation)?,
        processing_mode: input.capsule.processing_mode,
        result: reproit_core::model::ExecutionResultKind::TargetReproduced,
        run_index: perturbation.run_index,
        subject_digest: input.capsule.subject_digest,
        trigger_digest: input.capsule.trigger_digest,
        world_digest: input.capsule.world_digest,
    })
}

pub fn complete_admission(
    input: &AdmissionInput,
    proofs: [Proof; 3],
) -> Result<AdmittedCandidate, Error> {
    validate_admission_input(input)?;
    let capsule_digest = canonical::digest(&input.capsule)?;
    proof::validate_proof_set(&input.capsule, &proofs, &input.perturbations)?;
    Ok(AdmittedCandidate {
        capsule_digest,
        proofs,
    })
}

fn validate_admission_input(input: &AdmissionInput) -> Result<(), Error> {
    input.capsule.validate()?;
    if input.capsule.profile != "backend" || input.capsule.profile_format != 1 {
        return Err(Error::new(
            ErrorCode::UnsupportedCapabilitySet,
            "The Backend release does not support this profile.",
        ));
    }
    input.expected_failure.validate()?;
    proof::validate_world_closure(&input.closure_policy, &input.closure)?;
    if canonical::digest(&input.closure)? != input.capsule.closure_manifest_digest {
        return Err(Error::new(
            ErrorCode::WorldNotClosed,
            "The capsule does not bind the closed World.",
        ));
    }
    for (run_index, perturbation) in input.perturbations.iter().enumerate() {
        perturbation.validate()?;
        if usize::from(perturbation.run_index) != run_index {
            return Err(proof_binding());
        }
    }
    Ok(())
}

fn proof_binding() -> Error {
    Error::new(
        ErrorCode::AdmissionProofBinding,
        "The admission proof does not bind the sealed capsule.",
    )
}

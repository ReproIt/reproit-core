use std::collections::BTreeSet;

use crate::{
    Error, canonical,
    error::ErrorCode,
    identity::Digest,
    model::{
        CaptureBatchManifest, ClosurePolicy, LogicalObjectRole, Perturbation, Proof, ReplayCapsule,
        Validate, WorldClosure,
    },
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Admission {
    capsule_digest: Digest,
}

impl Admission {
    pub const fn capsule_digest(self) -> Digest {
        self.capsule_digest
    }
}

pub fn validate_world_closure(policy: &ClosurePolicy, closure: &WorldClosure) -> Result<(), Error> {
    policy.validate()?;
    closure.validate()?;
    let policy_digest = canonical::digest(policy)?;
    if closure.policy_digest != policy_digest || closure.receipts.len() != policy.rules.len() {
        return Err(world_not_closed());
    }
    for (rule, receipt) in policy.rules.iter().zip(&closure.receipts) {
        if rule.boundary_id != receipt.boundary_id
            || rule.observation_class != receipt.observation_class
            || !rule.allowed_mechanisms.contains(&receipt.mechanism)
        {
            return Err(world_not_closed());
        }
    }
    Ok(())
}

pub fn validate_proof_set(
    capsule: &ReplayCapsule,
    proofs: &[Proof],
    perturbations: &[Perturbation],
) -> Result<Digest, Error> {
    capsule.validate()?;
    if proofs.len() != 3 {
        return Err(Error::new(
            ErrorCode::AdmissionProofCount,
            "Admission requires exactly three proof records.",
        ));
    }
    if perturbations.len() != 3 {
        return Err(proof_binding());
    }
    let capsule_digest = canonical::digest(capsule)?;
    let mut proof_digests = BTreeSet::new();
    for run_index in 0_u8..3 {
        let proof = &proofs[usize::from(run_index)];
        let perturbation = &perturbations[usize::from(run_index)];
        proof.validate()?;
        perturbation.validate()?;
        validate_run_binding(capsule, capsule_digest, proof, perturbation, run_index)?;
        if !proof_digests.insert(canonical::digest(proof)?) {
            return Err(proof_binding());
        }
    }
    Ok(capsule_digest)
}

pub fn validate_capture_manifest(
    manifest: &CaptureBatchManifest,
    capsule_digest: Digest,
    proofs: &[Proof],
) -> Result<(), Error> {
    manifest.validate()?;
    if manifest.replay_capsule_digest != capsule_digest
        || proofs.len() != 3
        || proofs
            .iter()
            .any(|proof| proof.processing_mode != manifest.processing_mode)
    {
        return Err(proof_binding());
    }
    let capsule_objects = manifest
        .objects
        .iter()
        .filter(|object| object.descriptor.role == LogicalObjectRole::ReplayCapsuleManifest)
        .collect::<Vec<_>>();
    if capsule_objects.len() != 1
        || capsule_objects[0].descriptor.object_id != manifest.replay_capsule_object_id
        || capsule_objects[0].descriptor.plain_digest != capsule_digest
    {
        return Err(proof_binding());
    }
    let proof_objects = manifest
        .objects
        .iter()
        .filter(|object| object.descriptor.role == LogicalObjectRole::AdmissionProof)
        .collect::<Vec<_>>();
    if proof_objects.len() != 3 {
        return Err(Error::new(
            ErrorCode::AdmissionProofCount,
            "The capture batch needs three proof objects.",
        ));
    }
    for run_index in 0..3 {
        let digest = canonical::digest(&proofs[run_index])?;
        if manifest.proof_digests[run_index] != digest
            || proof_objects[run_index].descriptor.plain_digest != digest
        {
            return Err(proof_binding());
        }
    }
    Ok(())
}

pub fn admit(
    capsule: &ReplayCapsule,
    policy: &ClosurePolicy,
    closure: &WorldClosure,
    proofs: &[Proof],
    perturbations: &[Perturbation],
    manifest: &CaptureBatchManifest,
) -> Result<Admission, Error> {
    validate_world_closure(policy, closure)?;
    let closure_digest = canonical::digest(closure)?;
    if capsule.closure_manifest_digest != closure_digest
        || capsule.processing_mode != manifest.processing_mode
    {
        return Err(world_not_closed());
    }
    let capsule_digest = validate_proof_set(capsule, proofs, perturbations)?;
    validate_capture_manifest(manifest, capsule_digest, proofs)?;
    Ok(Admission { capsule_digest })
}

fn validate_run_binding(
    capsule: &ReplayCapsule,
    capsule_digest: Digest,
    proof: &Proof,
    perturbation: &Perturbation,
    run_index: u8,
) -> Result<(), Error> {
    if proof.run_index != run_index
        || perturbation.run_index != run_index
        || proof.perturbation_digest != canonical::digest(perturbation)?
        || proof.capsule_digest != capsule_digest
        || proof.processing_mode != capsule.processing_mode
        || proof.world_digest != capsule.world_digest
        || proof.trigger_digest != capsule.trigger_digest
        || proof.subject_digest != capsule.subject_digest
        || proof.failure_digest != capsule.failure_digest
        || proof.executor_capabilities_digest != capsule.support_bundle_digest
    {
        return Err(proof_binding());
    }
    Ok(())
}

fn proof_binding() -> Error {
    Error::new(
        ErrorCode::AdmissionProofBinding,
        "An admission proof does not bind the sealed capsule.",
    )
}

fn world_not_closed() -> Error {
    Error::new(
        ErrorCode::WorldNotClosed,
        "The World closure does not match its policy.",
    )
}

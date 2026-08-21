use reproit_core::{
    Error, ErrorCode, canonical,
    identity::Digest,
    model::{
        ClosureMechanism, ClosurePolicy, ClosureReceipt, ObservationClass, Perturbation,
        PerturbationCase, PerturbationFormat, Validate as _, WorldClosure, WorldClosureFormat,
    },
};
use serde::Serialize;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ManagedClosureEvidence {
    pub dependency_identity: Option<Digest>,
    pub executor_identity: Digest,
    pub isolation_identity: Digest,
    pub subject_identity: Digest,
    pub world_identity: Digest,
}

#[derive(Serialize)]
struct ClosureEvidenceBinding<'a> {
    boundary_id: &'a str,
    evidence_identity: Digest,
    mechanism: ClosureMechanism,
    observation_class: ObservationClass,
}

#[derive(Serialize)]
struct AmbientIdentity {
    case: PerturbationCase,
    executor_identity: Digest,
    suite: &'static str,
}

pub fn close_managed_world(
    policy: &ClosurePolicy,
    evidence: ManagedClosureEvidence,
) -> Result<WorldClosure, Error> {
    policy.validate()?;
    let mut receipts = Vec::with_capacity(policy.rules.len());
    for rule in &policy.rules {
        let (mechanism, evidence_identity) =
            select_evidence(&rule.allowed_mechanisms, rule.observation_class, evidence)?;
        let evidence_digest = canonical::digest(&ClosureEvidenceBinding {
            boundary_id: &rule.boundary_id,
            evidence_identity,
            mechanism,
            observation_class: rule.observation_class,
        })?;
        receipts.push(ClosureReceipt {
            boundary_id: rule.boundary_id.clone(),
            evidence_digest,
            mechanism,
            observation_class: rule.observation_class,
            version: 1,
        });
    }
    let closure = WorldClosure {
        format: WorldClosureFormat::V1,
        policy_digest: canonical::digest(policy)?,
        receipts,
    };
    reproit_core::proof::validate_world_closure(policy, &closure)?;
    Ok(closure)
}

pub fn managed_perturbations(executor_identity: Digest) -> Result<[Perturbation; 3], Error> {
    let cases = [
        PerturbationCase::Baseline,
        PerturbationCase::ColdAmbient,
        PerturbationCase::TimingAmbient,
    ];
    let perturbations = cases.map(|case| {
        Ok(Perturbation {
            ambient_identity_digest: canonical::digest(&AmbientIdentity {
                case,
                executor_identity,
                suite: "reproit.controlled-perturbation.v1",
            })?,
            case,
            format: PerturbationFormat::V1,
            run_index: case.run_index(),
            suite: "reproit.controlled-perturbation.v1".to_owned(),
        })
    });
    let perturbations: [Perturbation; 3] = perturbations
        .into_iter()
        .collect::<Result<Vec<_>, Error>>()?
        .try_into()
        .map_err(|_| Error::schema_invalid())?;
    for perturbation in &perturbations {
        perturbation.validate()?;
    }
    Ok(perturbations)
}

fn select_evidence(
    allowed: &[ClosureMechanism],
    observation_class: ObservationClass,
    evidence: ManagedClosureEvidence,
) -> Result<(ClosureMechanism, Digest), Error> {
    for mechanism in allowed {
        let identity = match mechanism {
            ClosureMechanism::Blocked => Some(evidence.isolation_identity),
            ClosureMechanism::ExactTranscript => evidence.dependency_identity,
            ClosureMechanism::FixedExecutorCapability => Some(evidence.executor_identity),
            ClosureMechanism::ImmutableObject => match observation_class {
                ObservationClass::FilesystemEnvironment => Some(evidence.subject_identity),
                ObservationClass::StateService => Some(evidence.world_identity),
                _ => None,
            },
            ClosureMechanism::VerifiedSimulator => None,
        };
        if let Some(identity) = identity {
            return Ok((*mechanism, identity));
        }
    }
    Err(Error::new(
        ErrorCode::WorldNotClosed,
        "The managed worker has no verified evidence for one World boundary.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use reproit_core::model::{ClosurePolicyFormat, ClosureRule};

    fn policy(mechanism: ClosureMechanism, class: ObservationClass) -> ClosurePolicy {
        ClosurePolicy {
            format: ClosurePolicyFormat::V1,
            rules: vec![ClosureRule {
                allowed_mechanisms: vec![mechanism],
                boundary_id: "boundary".to_owned(),
                observation_class: class,
            }],
        }
    }

    fn evidence() -> ManagedClosureEvidence {
        ManagedClosureEvidence {
            dependency_identity: Some(Digest::of(b"dependency")),
            executor_identity: Digest::of(b"executor"),
            isolation_identity: Digest::of(b"isolation"),
            subject_identity: Digest::of(b"subject"),
            world_identity: Digest::of(b"world"),
        }
    }

    #[test]
    fn managed_closure_binds_each_supported_evidence_kind() {
        for (mechanism, class) in [
            (
                ClosureMechanism::Blocked,
                ObservationClass::NetworkIpcSignal,
            ),
            (
                ClosureMechanism::ExactTranscript,
                ObservationClass::NetworkIpcSignal,
            ),
            (
                ClosureMechanism::FixedExecutorCapability,
                ObservationClass::OperatingSystemHardware,
            ),
            (
                ClosureMechanism::ImmutableObject,
                ObservationClass::FilesystemEnvironment,
            ),
            (
                ClosureMechanism::ImmutableObject,
                ObservationClass::StateService,
            ),
        ] {
            let policy = policy(mechanism, class);
            let closure = close_managed_world(&policy, evidence()).unwrap();
            assert_eq!(closure.receipts[0].mechanism, mechanism);
            assert_eq!(closure.receipts[0].observation_class, class);
        }
    }

    #[test]
    fn managed_closure_rejects_absent_transcript_and_unproved_simulator() {
        let mut without_transcript = evidence();
        without_transcript.dependency_identity = None;
        assert!(
            close_managed_world(
                &policy(
                    ClosureMechanism::ExactTranscript,
                    ObservationClass::NetworkIpcSignal,
                ),
                without_transcript,
            )
            .is_err()
        );
        assert!(
            close_managed_world(
                &policy(
                    ClosureMechanism::VerifiedSimulator,
                    ObservationClass::Device,
                ),
                evidence(),
            )
            .is_err()
        );
    }

    #[test]
    fn managed_perturbations_are_exact_ordered_and_executor_bound() {
        let first = managed_perturbations(Digest::of(b"worker-a")).unwrap();
        let second = managed_perturbations(Digest::of(b"worker-b")).unwrap();
        assert_eq!(first.each_ref().map(|value| value.run_index), [0, 1, 2]);
        assert_ne!(
            first.each_ref().map(|value| value.ambient_identity_digest),
            second.each_ref().map(|value| value.ambient_identity_digest)
        );
    }
}

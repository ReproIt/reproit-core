use std::collections::BTreeMap;

use crate::{
    Error, ErrorCode, canonical,
    model::{ClosurePolicy, ClosureReceipt, Validate as _, WorldClosure, WorldClosureFormat},
    proof::validate_world_closure,
};

pub struct CaptureCoverage {
    policy: ClosurePolicy,
    receipts: BTreeMap<String, ClosureReceipt>,
    coverage_invalid: bool,
}

impl CaptureCoverage {
    pub fn new(policy: ClosurePolicy) -> Result<Self, Error> {
        policy.validate()?;
        Ok(Self {
            policy,
            receipts: BTreeMap::new(),
            coverage_invalid: false,
        })
    }

    pub fn record(&mut self, receipt: ClosureReceipt) -> Result<(), Error> {
        let Some(rule) = self
            .policy
            .rules
            .iter()
            .find(|rule| rule.boundary_id == receipt.boundary_id)
        else {
            self.coverage_invalid = true;
            return Err(world_not_closed());
        };
        if rule.observation_class != receipt.observation_class
            || !rule.allowed_mechanisms.contains(&receipt.mechanism)
            || self.receipts.contains_key(&receipt.boundary_id)
        {
            self.coverage_invalid = true;
            return Err(world_not_closed());
        }
        self.receipts.insert(receipt.boundary_id.clone(), receipt);
        Ok(())
    }

    pub const fn mark_unowned(&mut self) {
        self.coverage_invalid = true;
    }

    pub fn close(self) -> Result<WorldClosure, Error> {
        if self.coverage_invalid || self.receipts.len() != self.policy.rules.len() {
            return Err(world_not_closed());
        }
        let closure = WorldClosure {
            format: WorldClosureFormat::V1,
            policy_digest: canonical::digest(&self.policy)?,
            receipts: self.receipts.into_values().collect(),
        };
        validate_world_closure(&self.policy, &closure)?;
        Ok(closure)
    }
}

fn world_not_closed() -> Error {
    Error::new(
        ErrorCode::WorldNotClosed,
        "Repro It could not capture every required application observation.",
    )
}

#[cfg(test)]
mod tests {
    use crate::{
        ErrorCode,
        identity::Digest,
        model::{
            ClosureMechanism, ClosurePolicy, ClosurePolicyFormat, ClosureReceipt, ClosureRule,
            ObservationClass,
        },
    };

    use super::CaptureCoverage;

    #[test]
    fn complete_coverage_closes() {
        let mut coverage = CaptureCoverage::new(policy()).unwrap();
        coverage.record(receipt("clock")).unwrap();
        coverage.record(receipt("filesystem")).unwrap();
        assert_eq!(coverage.close().unwrap().receipts.len(), 2);
    }

    #[test]
    fn missing_coverage_stays_local() {
        let mut coverage = CaptureCoverage::new(policy()).unwrap();
        coverage.record(receipt("clock")).unwrap();
        assert_eq!(
            coverage.close().unwrap_err().code,
            ErrorCode::WorldNotClosed
        );
    }

    #[test]
    fn an_unowned_observation_stays_local() {
        let mut coverage = CaptureCoverage::new(policy()).unwrap();
        coverage.record(receipt("clock")).unwrap();
        coverage.record(receipt("filesystem")).unwrap();
        coverage.mark_unowned();
        assert_eq!(
            coverage.close().unwrap_err().code,
            ErrorCode::WorldNotClosed
        );
    }

    #[test]
    fn duplicate_coverage_is_rejected() {
        let mut coverage = CaptureCoverage::new(policy()).unwrap();
        coverage.record(receipt("clock")).unwrap();
        assert_eq!(
            coverage.record(receipt("clock")).unwrap_err().code,
            ErrorCode::WorldNotClosed
        );
        coverage.record(receipt("filesystem")).unwrap();
        assert_eq!(
            coverage.close().unwrap_err().code,
            ErrorCode::WorldNotClosed
        );
    }

    #[test]
    fn mismatched_coverage_poisons_the_capture() {
        let mut coverage = CaptureCoverage::new(policy()).unwrap();
        let mut wrong = receipt("clock");
        wrong.observation_class = ObservationClass::FilesystemEnvironment;
        assert_eq!(
            coverage.record(wrong).unwrap_err().code,
            ErrorCode::WorldNotClosed
        );
        coverage.record(receipt("clock")).unwrap();
        coverage.record(receipt("filesystem")).unwrap();
        assert_eq!(
            coverage.close().unwrap_err().code,
            ErrorCode::WorldNotClosed
        );
    }

    fn policy() -> ClosurePolicy {
        ClosurePolicy {
            format: ClosurePolicyFormat::V1,
            rules: vec![
                ClosureRule {
                    allowed_mechanisms: vec![ClosureMechanism::ExactTranscript],
                    boundary_id: "clock".to_owned(),
                    observation_class: ObservationClass::ClockRandomIdentity,
                },
                ClosureRule {
                    allowed_mechanisms: vec![ClosureMechanism::ExactTranscript],
                    boundary_id: "filesystem".to_owned(),
                    observation_class: ObservationClass::FilesystemEnvironment,
                },
            ],
        }
    }

    fn receipt(boundary_id: &str) -> ClosureReceipt {
        ClosureReceipt {
            boundary_id: boundary_id.to_owned(),
            evidence_digest: Digest::of(boundary_id.as_bytes()),
            mechanism: ClosureMechanism::ExactTranscript,
            observation_class: match boundary_id {
                "clock" => ObservationClass::ClockRandomIdentity,
                _ => ObservationClass::FilesystemEnvironment,
            },
            version: 1,
        }
    }
}

use serde::{Deserialize, Serialize};

use std::collections::BTreeSet;

use super::{ExecutionOutcome, ReplayCapsule, Validate, require_strict_order};
use crate::{Error, canonical, identity::Digest};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum ProcessorArchitecture {
    #[serde(rename = "architecture.arm64")]
    Arm64,
    #[serde(rename = "architecture.x86-64")]
    X86_64,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ProcessorIdentity {
    Arm(ArmProcessorIdentity),
    X86(X86ProcessorIdentity),
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArmProcessorIdentity {
    pub implementer: String,
    pub part: String,
    pub revision: String,
    pub variant: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct X86ProcessorIdentity {
    pub family: u32,
    pub microcode: String,
    pub model: u32,
    pub stepping: u32,
    pub vendor: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum ProcessorObservationFormat {
    #[serde(rename = "reproit.processor-observation.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessorObservation {
    pub abi: String,
    pub architecture: ProcessorArchitecture,
    pub format: ProcessorObservationFormat,
    pub identity: Option<ProcessorIdentity>,
    pub instruction_features: Vec<String>,
    pub os_enabled_states: Vec<String>,
}

impl Validate for ProcessorObservation {
    fn validate(&self) -> Result<(), Error> {
        validate_processor_view(
            &self.abi,
            self.architecture,
            self.identity.as_ref(),
            &self.instruction_features,
            &self.os_enabled_states,
        )
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum ProcessorRequirementFormat {
    #[serde(rename = "reproit.processor-requirement.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessorRequirement {
    pub abi: String,
    pub architecture: ProcessorArchitecture,
    pub format: ProcessorRequirementFormat,
    pub identity: Option<ProcessorIdentity>,
    pub instruction_features: Vec<String>,
    pub os_enabled_states: Vec<String>,
}

impl Validate for ProcessorRequirement {
    fn validate(&self) -> Result<(), Error> {
        validate_processor_view(
            &self.abi,
            self.architecture,
            self.identity.as_ref(),
            &self.instruction_features,
            &self.os_enabled_states,
        )
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProcessorReductionDecision {
    Removed,
    Retained,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum ProcessorTrialEvidenceKind {
    #[serde(rename = "exact-native")]
    ExactNative,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessorReductionTrial {
    pub candidate_requirement_digest: Digest,
    pub decision: ProcessorReductionDecision,
    pub evidence_kind: ProcessorTrialEvidenceKind,
    pub execution_result: ExecutionOutcome,
    pub tested_constraint: String,
    pub trial_index: u8,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProcessorReductionTerminalReason {
    Complete,
    CpuLimit,
    ElapsedLimit,
    OutputLimit,
    Timeout,
    TrialLimit,
    Uncontrollable,
    Unstable,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum ProcessorReductionReceiptFormat {
    #[serde(rename = "reproit.processor-reduction-receipt.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessorReductionReceipt {
    pub final_requirement_digest: Digest,
    pub format: ProcessorReductionReceiptFormat,
    pub observation_digest: Digest,
    pub terminal_reason: ProcessorReductionTerminalReason,
    pub trials: Vec<ProcessorReductionTrial>,
}

impl Validate for ProcessorReductionReceipt {
    fn validate(&self) -> Result<(), Error> {
        if self.trials.len() > 16 {
            return Err(Error::schema_invalid());
        }
        let mut tested_constraints = BTreeSet::new();
        for (index, trial) in self.trials.iter().enumerate() {
            if usize::from(trial.trial_index) != index
                || !valid_tested_constraint(&trial.tested_constraint)
                || !tested_constraints.insert(&trial.tested_constraint)
                || trial.decision == ProcessorReductionDecision::Removed
                    && trial.execution_result != ExecutionOutcome::TargetReproduced
            {
                return Err(Error::schema_invalid());
            }
        }
        Ok(())
    }
}

/// Return the canonical capsule capabilities for one processor requirement.
/// The requirement digest and identity digest are capsule bindings. Features
/// and operating-system states remain replay-host requirements.
pub fn processor_requirement_capabilities(
    requirement: &ProcessorRequirement,
) -> Result<Vec<String>, Error> {
    requirement.validate()?;
    let mut capabilities = vec![match requirement.architecture {
        ProcessorArchitecture::Arm64 => "architecture.arm64".to_owned(),
        ProcessorArchitecture::X86_64 => "architecture.x86-64".to_owned(),
    }];
    capabilities.push(format!(
        "processor.requirement.{}",
        digest_suffix(canonical::digest(requirement)?)
    ));
    for feature in &requirement.instruction_features {
        capabilities.push(format!(
            "processor.feature.{}",
            normalize_processor_name(feature)?
        ));
    }
    for state in &requirement.os_enabled_states {
        capabilities.push(format!(
            "processor.os-state.{}",
            normalize_processor_name(state)?
        ));
    }
    if let Some(identity) = &requirement.identity {
        // Capture names an identity with its structured token
        // (specs/v1/processor-capture.json). The reduction contract compares a
        // retained identity against the sealed captured set, so both sides must
        // use that one encoding.
        capabilities.push(format!(
            "processor.identity.{}",
            super::encode_identity_token(identity)
        ));
    }
    capabilities.sort();
    capabilities.dedup();
    Ok(capabilities)
}

/// Return the capsule binding for one complete processor reduction receipt.
pub fn processor_reduction_capability(
    receipt: &ProcessorReductionReceipt,
) -> Result<String, Error> {
    receipt.validate()?;
    Ok(format!(
        "processor.reduction.{}",
        digest_suffix(canonical::digest(receipt)?)
    ))
}

/// Verify the only post-seal capsule transition permitted by admission.
/// Every non-processor byte stays identical. The final processor capabilities
/// must exactly encode the supplied requirement and receipt. Host-declarable
/// processor requirements may only narrow from the Runtime-sealed set.
pub fn validate_processor_reduction_capsule_binding(
    sealed: &ReplayCapsule,
    admitted: &ReplayCapsule,
    requirement: &ProcessorRequirement,
    receipt: &ProcessorReductionReceipt,
) -> Result<(), Error> {
    sealed.validate()?;
    admitted.validate()?;
    requirement.validate()?;
    receipt.validate()?;
    if receipt.final_requirement_digest != canonical::digest(requirement)?
        || !capsules_equal_except_processor_capabilities(sealed, admitted)?
    {
        return Err(Error::schema_invalid());
    }
    let mut expected = processor_requirement_capabilities(requirement)?;
    expected.push(processor_reduction_capability(receipt)?);
    expected.sort();
    let actual = admitted
        .required_capabilities
        .iter()
        .filter(|capability| {
            capability.starts_with("architecture.") || capability.starts_with("processor.")
        })
        .cloned()
        .collect::<Vec<_>>();
    if actual != expected {
        return Err(Error::schema_invalid());
    }
    let sealed_host_requirements = sealed
        .required_capabilities
        .iter()
        .filter(|capability| host_processor_requirement(capability))
        .collect::<BTreeSet<_>>();
    if expected
        .iter()
        .filter(|capability| host_processor_requirement(capability))
        .any(|capability| !sealed_host_requirements.contains(capability))
    {
        return Err(Error::schema_invalid());
    }
    let admitted_set = expected.iter().collect::<BTreeSet<_>>();
    let removed_constraints = receipt
        .trials
        .iter()
        .filter(|trial| trial.decision == ProcessorReductionDecision::Removed)
        .map(|trial| trial.tested_constraint.as_str())
        .collect::<BTreeSet<_>>();
    for capability in &sealed_host_requirements {
        if admitted_set.contains(*capability) {
            continue;
        }
        let Some(constraint) = removed_constraint_for_capability(capability) else {
            return Err(Error::schema_invalid());
        };
        let removed_with_feature = match constraint.as_str() {
            "os-enabled-state.xcr0.avx" => removed_constraints.contains("instruction-feature.AVX"),
            "os-enabled-state.xcr0.avx512" => {
                removed_constraints.contains("instruction-feature.AVX512F")
            }
            _ => false,
        };
        if !removed_constraints.contains(constraint.as_str()) && !removed_with_feature {
            return Err(Error::schema_invalid());
        }
    }
    for trial in &receipt.trials {
        let present = constraint_present(&trial.tested_constraint, &admitted_set)?;
        if trial.decision == ProcessorReductionDecision::Removed && present
            || trial.decision == ProcessorReductionDecision::Retained && !present
        {
            return Err(Error::schema_invalid());
        }
    }
    Ok(())
}

/// Compare two capsules after removing only admission-owned processor
/// capabilities. The Runtime uses this before it accepts a reduced capsule.
pub fn capsules_equal_except_processor_capabilities(
    sealed: &ReplayCapsule,
    admitted: &ReplayCapsule,
) -> Result<bool, Error> {
    let strip = |capsule: &ReplayCapsule| -> Result<Digest, Error> {
        let mut stripped = capsule.clone();
        stripped
            .required_capabilities
            .retain(|capability| !capability.starts_with("processor."));
        canonical::digest(&stripped)
    };
    Ok(strip(sealed)? == strip(admitted)?)
}

fn host_processor_requirement(capability: &str) -> bool {
    capability.starts_with("architecture.")
        || capability.starts_with("processor.feature.")
        || capability.starts_with("processor.os-state.")
        || capability.starts_with("processor.identity.")
}

fn removed_constraint_for_capability(capability: &str) -> Option<String> {
    if let Some(feature) = capability.strip_prefix("processor.feature.") {
        return Some(format!(
            "instruction-feature.{}",
            feature
                .chars()
                .map(|character| match character {
                    'a'..='z' => character.to_ascii_uppercase(),
                    '-' => '_',
                    other => other,
                })
                .collect::<String>()
        ));
    }
    capability
        .strip_prefix("processor.os-state.")
        .map(|state| format!("os-enabled-state.{state}"))
        .or_else(|| {
            capability
                .starts_with("processor.identity.")
                .then(|| "processor-identity".to_owned())
        })
}

fn constraint_present(constraint: &str, capabilities: &BTreeSet<&String>) -> Result<bool, Error> {
    if let Some(feature) = constraint.strip_prefix("instruction-feature.") {
        let normalized = normalize_processor_name(feature)?;
        return Ok(capabilities
            .iter()
            .any(|value| value.as_str() == format!("processor.feature.{normalized}")));
    }
    if let Some(state) = constraint.strip_prefix("os-enabled-state.") {
        return Ok(capabilities
            .iter()
            .any(|value| value.as_str() == format!("processor.os-state.{state}")));
    }
    if constraint == "processor-identity" {
        return Ok(capabilities
            .iter()
            .any(|value| value.starts_with("processor.identity.")));
    }
    Err(Error::schema_invalid())
}

fn digest_suffix(digest: Digest) -> String {
    digest.to_string().trim_start_matches("sha256:").to_owned()
}

fn normalize_processor_name(value: &str) -> Result<String, Error> {
    let normalized = value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' => byte.to_ascii_lowercase(),
            b'_' => b'-',
            other => other,
        })
        .collect::<Vec<_>>();
    let normalized = String::from_utf8(normalized).map_err(|_| Error::schema_invalid())?;
    if normalized.is_empty()
        || normalized.len() > 96
        || !normalized.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
    {
        return Err(Error::schema_invalid());
    }
    Ok(normalized)
}

fn valid_tested_constraint(value: &str) -> bool {
    if value.len() > 128 {
        return false;
    }
    if value == "processor-identity" {
        return true;
    }
    if let Some(feature) = value.strip_prefix("instruction-feature.") {
        return !feature.is_empty()
            && feature.bytes().all(|byte| {
                byte.is_ascii_uppercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            });
    }
    value
        .strip_prefix("os-enabled-state.")
        .is_some_and(valid_lower_identity)
}

fn validate_processor_view(
    abi: &str,
    architecture: ProcessorArchitecture,
    identity: Option<&ProcessorIdentity>,
    instruction_features: &[String],
    os_enabled_states: &[String],
) -> Result<(), Error> {
    if abi.is_empty()
        || abi.len() > 128
        || instruction_features.len() > 256
        || os_enabled_states.len() > 64
        || instruction_features.iter().any(|feature| {
            feature.is_empty()
                || feature.len() > 128
                || !feature.bytes().all(|byte| {
                    byte.is_ascii_uppercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'_' | b'-')
                })
        })
        || os_enabled_states
            .iter()
            .any(|state| !valid_lower_identity(state))
    {
        return Err(Error::schema_invalid());
    }
    require_strict_order(instruction_features.iter().cloned())?;
    require_strict_order(os_enabled_states.iter().cloned())?;
    match (architecture, identity) {
        (ProcessorArchitecture::Arm64, Some(ProcessorIdentity::Arm(value))) => validate_arm(value),
        (ProcessorArchitecture::X86_64, Some(ProcessorIdentity::X86(value))) => validate_x86(value),
        (_, None) => Ok(()),
        _ => Err(Error::schema_invalid()),
    }
}

fn validate_arm(identity: &ArmProcessorIdentity) -> Result<(), Error> {
    [
        &identity.implementer,
        &identity.part,
        &identity.revision,
        &identity.variant,
    ]
    .into_iter()
    .all(|value| valid_processor_identity_value(value))
    .then_some(())
    .ok_or_else(Error::schema_invalid)
}

fn validate_x86(identity: &X86ProcessorIdentity) -> Result<(), Error> {
    if !valid_processor_identity_value(&identity.vendor)
        || !valid_processor_identity_value(&identity.microcode)
    {
        return Err(Error::schema_invalid());
    }
    Ok(())
}

fn valid_processor_identity_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_lower_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || (byte.is_ascii_digit() && index > 0)
                || (matches!(byte, b'.' | b'_' | b'-') && index > 0)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt() -> ProcessorReductionReceipt {
        serde_json::from_value(
            serde_json::from_str::<serde_json::Value>(include_str!(
                "../../../../specs/v1/protocol-vectors.json"
            ))
            .unwrap()["positive"]["processor_reduction_receipt"]["value"]
                .clone(),
        )
        .unwrap()
    }

    #[test]
    fn reduction_receipt_accepts_dependency_order_and_rejects_duplicate_constraints() {
        let mut receipt = receipt();
        receipt.trials[0].tested_constraint = "instruction-feature.AVX512BW".to_owned();
        receipt.trials[1].tested_constraint = "instruction-feature.AVX2".to_owned();
        assert!(receipt.validate().is_ok());

        receipt.trials[1].tested_constraint = receipt.trials[0].tested_constraint.clone();
        assert!(receipt.validate().is_err());
    }

    #[test]
    fn reduction_receipt_rejects_invalid_and_one_byte_over_constraint_labels() {
        let mut receipt = receipt();
        for invalid in [
            "feature.avx2".to_owned(),
            "instruction-feature.avx2".to_owned(),
            format!("instruction-feature.{}", "A".repeat(109)),
        ] {
            receipt.trials[0].tested_constraint = invalid;
            assert!(receipt.validate().is_err());
        }
    }

    #[test]
    fn processor_identity_requires_the_canonical_lowercase_form() {
        let mut requirement = ProcessorRequirement {
            abi: "sysv-x86-64".to_owned(),
            architecture: ProcessorArchitecture::X86_64,
            format: ProcessorRequirementFormat::V1,
            identity: Some(ProcessorIdentity::X86(X86ProcessorIdentity {
                family: 6,
                microcode: "0x2b000643".to_owned(),
                model: 143,
                stepping: 8,
                vendor: "genuineintel".to_owned(),
            })),
            instruction_features: vec!["AVX2".to_owned()],
            os_enabled_states: vec!["osxsave".to_owned()],
        };
        requirement
            .validate()
            .expect("canonical processor identity");

        let Some(ProcessorIdentity::X86(identity)) = &mut requirement.identity else {
            panic!("the test requirement must contain one x86 identity");
        };
        identity.vendor = "GenuineIntel".to_owned();
        assert!(requirement.validate().is_err());
    }
}

use reproit_core::{
    Error, canonical,
    model::{
        ExecutionOutcome, ProcessorArchitecture, ProcessorIdentity, ProcessorObservation,
        ProcessorObservationFormat, ProcessorReductionDecision, ProcessorReductionReceipt,
        ProcessorReductionReceiptFormat, ProcessorReductionTerminalReason, ProcessorReductionTrial,
        ProcessorRequirement, ProcessorRequirementFormat, ProcessorTrialEvidenceKind, Validate,
    },
};

use crate::{AdmissionExecutor, AdmissionInput, AdmittedCandidate, admit};

pub use reproit_core::model::processor_requirement_capabilities;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ProcessorTrialLimits {
    pub cpu_milliseconds: u32,
    pub elapsed_milliseconds: u32,
    pub memory_bytes: u64,
    pub output_bytes: u32,
}

impl ProcessorTrialLimits {
    // One managed trial boots a fresh separate-kernel guest, so the elapsed
    // budget covers guest boot plus World restore plus the Trigger. The
    // mechanism observes wall clock only and charges it against the CPU
    // budget, so the CPU bound equals the elapsed bound and stays a
    // conservative overcount.
    pub const PRODUCTION: Self = Self {
        cpu_milliseconds: 30_000,
        elapsed_milliseconds: 30_000,
        memory_bytes: 134_217_728,
        output_bytes: 65_536,
    };

    fn validate(self) -> Result<(), Error> {
        if self.cpu_milliseconds == 0
            || self.cpu_milliseconds > 60_000
            || self.elapsed_milliseconds < self.cpu_milliseconds
            || self.elapsed_milliseconds > 120_000
            || self.memory_bytes == 0
            || self.memory_bytes > 1_073_741_824
            || self.output_bytes == 0
            || self.output_bytes > 1_048_576
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ProcessorReductionPolicy {
    pub maximum_trials: u8,
    pub total_cpu_milliseconds: u64,
    pub total_elapsed_milliseconds: u64,
    pub total_output_bytes: u64,
    pub trial_limits: ProcessorTrialLimits,
}

impl ProcessorReductionPolicy {
    pub const PRODUCTION: Self = Self {
        maximum_trials: 16,
        total_cpu_milliseconds: 7_200_000,
        total_elapsed_milliseconds: 1_800_000,
        total_output_bytes: 16 * 1024 * 1024,
        trial_limits: ProcessorTrialLimits::PRODUCTION,
    };

    fn validate(self) -> Result<(), Error> {
        if self.maximum_trials == 0
            || self.maximum_trials > 16
            || self.total_cpu_milliseconds == 0
            || self.total_cpu_milliseconds > 7_200_000
            || self.total_elapsed_milliseconds == 0
            || self.total_elapsed_milliseconds > 1_800_000
            || self.total_output_bytes == 0
            || self.total_output_bytes > 16 * 1024 * 1024
        {
            return Err(Error::schema_invalid());
        }
        self.trial_limits.validate()
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ProcessorConstraint {
    InstructionFeature(String),
    OsEnabledState(String),
    ProcessorIdentity,
}

/// Conservative curated-group prerequisites as (dependent, prerequisite).
/// A subject that requires the dependent group also requires the
/// prerequisite, and no supported mechanism can hide the prerequisite while
/// the dependent stays application visible, so the reducer must not trial a
/// prerequisite while one of its dependents remains required.
const FEATURE_PREREQUISITES: &[(&str, &str)] = &[
    ("AVX2", "AVX"),
    ("AVX512BW", "AVX512F"),
    ("AVX512DQ", "AVX512F"),
    ("AVX512F", "AVX"),
    ("AVX512VL", "AVX512F"),
    ("FMA", "AVX"),
    ("SSE4_2", "SSE4_1"),
];

/// Operating-system enabled states that exist only while their feature
/// group is exposed. Removing the feature removes the state in the same
/// trial, because the guest kernel derives the state from the feature.
const OS_STATE_REQUIRED_FEATURE: &[(&str, &str)] =
    &[("xcr0.avx", "AVX"), ("xcr0.avx512", "AVX512F")];

/// True when `candidate` requires `feature` directly or transitively. The
/// prerequisite table is acyclic and tiny, so a bounded walk is enough.
fn feature_requires(candidate: &str, feature: &str) -> bool {
    let mut frontier = vec![candidate];
    for _ in 0..FEATURE_PREREQUISITES.len() {
        let mut next = Vec::new();
        for current in frontier.drain(..) {
            for (dependent, prerequisite) in FEATURE_PREREQUISITES {
                if *dependent == current {
                    if *prerequisite == feature {
                        return true;
                    }
                    next.push(*prerequisite);
                }
            }
        }
        if next.is_empty() {
            return false;
        }
        frontier = next;
    }
    false
}

/// The longest prerequisite chain below the feature. Dependents order
/// before their prerequisites so a prerequisite is trialed only after its
/// dependents were removed or retained.
fn dependency_depth(feature: &str) -> usize {
    FEATURE_PREREQUISITES
        .iter()
        .filter(|(dependent, _)| *dependent == feature)
        .map(|(_, prerequisite)| dependency_depth(prerequisite).saturating_add(1))
        .max()
        .unwrap_or(0)
}

fn dependent_feature_remains(requirement: &ProcessorRequirement, feature: &str) -> bool {
    requirement
        .instruction_features
        .iter()
        .any(|other| other != feature && feature_requires(other, feature))
}

impl ProcessorConstraint {
    fn label(&self) -> String {
        match self {
            Self::InstructionFeature(value) => format!("instruction-feature.{value}"),
            Self::OsEnabledState(value) => format!("os-enabled-state.{value}"),
            Self::ProcessorIdentity => "processor-identity".to_owned(),
        }
    }

    fn present_in(&self, requirement: &ProcessorRequirement) -> bool {
        match self {
            Self::InstructionFeature(value) => {
                requirement.instruction_features.iter().any(|f| f == value)
            }
            Self::OsEnabledState(value) => requirement.os_enabled_states.iter().any(|s| s == value),
            Self::ProcessorIdentity => requirement.identity.is_some(),
        }
    }

    fn remove_from(&self, requirement: &mut ProcessorRequirement) {
        match self {
            Self::InstructionFeature(value) => {
                requirement
                    .instruction_features
                    .retain(|candidate| candidate != value);
                // The guest derives these states from the feature, so the
                // masked trial view loses them together with the feature.
                requirement.os_enabled_states.retain(|state| {
                    !OS_STATE_REQUIRED_FEATURE
                        .iter()
                        .any(|(dependent, feature)| dependent == state && feature == value)
                });
            }
            Self::OsEnabledState(value) => {
                requirement
                    .os_enabled_states
                    .retain(|candidate| candidate != value);
            }
            Self::ProcessorIdentity => requirement.identity = None,
        }
    }
}

pub trait ProcessorTrialExecutor {
    fn can_control(&self, constraint: &ProcessorConstraint) -> bool;

    fn execute_trial(
        &self,
        requirement: &ProcessorRequirement,
        limits: ProcessorTrialLimits,
    ) -> Result<ProcessorTrialResult, Error>;
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ProcessorTrialResult {
    pub cpu_milliseconds: u64,
    pub elapsed_milliseconds: u64,
    pub execution_result: ExecutionOutcome,
    pub output_bytes: u64,
    pub timed_out: bool,
    pub unstable: bool,
}

impl ProcessorTrialResult {
    fn terminal_reason(
        self,
        limits: ProcessorTrialLimits,
    ) -> Result<Option<ProcessorReductionTerminalReason>, Error> {
        if self.timed_out && self.unstable {
            return Err(Error::schema_invalid());
        }
        if self.timed_out {
            return Ok(Some(ProcessorReductionTerminalReason::Timeout));
        }
        if self.unstable {
            return Ok(Some(ProcessorReductionTerminalReason::Unstable));
        }
        if self.cpu_milliseconds > u64::from(limits.cpu_milliseconds) {
            return Ok(Some(ProcessorReductionTerminalReason::CpuLimit));
        }
        if self.elapsed_milliseconds > u64::from(limits.elapsed_milliseconds) {
            return Ok(Some(ProcessorReductionTerminalReason::ElapsedLimit));
        }
        if self.output_bytes > u64::from(limits.output_bytes) {
            return Ok(Some(ProcessorReductionTerminalReason::OutputLimit));
        }
        Ok(None)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ProcessorReductionResult {
    pub receipt: ProcessorReductionReceipt,
    pub requirement: ProcessorRequirement,
}

pub fn reduce_processor_requirements(
    observation: &ProcessorObservation,
    requirement: &ProcessorRequirement,
    policy: ProcessorReductionPolicy,
    executor: &impl ProcessorTrialExecutor,
) -> Result<ProcessorReductionResult, Error> {
    observation.validate()?;
    requirement.validate()?;
    policy.validate()?;
    if observation.architecture != requirement.architecture || observation.abi != requirement.abi {
        return Err(Error::schema_invalid());
    }
    let observation_digest = canonical::digest(observation)?;
    let mut reduced = requirement.clone();
    let constraints = constraints(requirement);
    let mut trials = Vec::new();
    let mut terminal_reason = ProcessorReductionTerminalReason::Complete;
    let mut total_cpu_milliseconds = 0_u64;
    let mut total_elapsed_milliseconds = 0_u64;
    let mut total_output_bytes = 0_u64;
    for constraint in constraints {
        // An earlier removal can cascade a dependent state away, so a
        // constraint that no longer exists consumes no trial budget.
        if !constraint.present_in(&reduced) {
            continue;
        }
        if trials.len() >= usize::from(policy.maximum_trials) {
            terminal_reason = ProcessorReductionTerminalReason::TrialLimit;
            break;
        }
        // A prerequisite with a remaining dependent is uncontrollable in
        // context: no mechanism can hide it while the dependent stays
        // application visible, so it must remain required.
        let dependency_blocked = match &constraint {
            ProcessorConstraint::InstructionFeature(feature) => {
                dependent_feature_remains(&reduced, feature)
            }
            _ => false,
        };
        if dependency_blocked || !executor.can_control(&constraint) {
            terminal_reason = ProcessorReductionTerminalReason::Uncontrollable;
            continue;
        }
        let Some(trial_limits) = remaining_trial_limits(
            policy,
            total_cpu_milliseconds,
            total_elapsed_milliseconds,
            total_output_bytes,
        ) else {
            terminal_reason = exhausted_reason(
                policy,
                total_cpu_milliseconds,
                total_elapsed_milliseconds,
                total_output_bytes,
            );
            break;
        };
        let mut candidate = reduced.clone();
        constraint.remove_from(&mut candidate);
        candidate.validate()?;
        let result = executor.execute_trial(&candidate, trial_limits)?;
        total_cpu_milliseconds = total_cpu_milliseconds.saturating_add(result.cpu_milliseconds);
        total_elapsed_milliseconds =
            total_elapsed_milliseconds.saturating_add(result.elapsed_milliseconds);
        total_output_bytes = total_output_bytes.saturating_add(result.output_bytes);
        let result_terminal_reason = result.terminal_reason(trial_limits)?;
        let decision = if result_terminal_reason.is_none()
            && result.execution_result == ExecutionOutcome::TargetReproduced
        {
            reduced = candidate.clone();
            ProcessorReductionDecision::Removed
        } else {
            ProcessorReductionDecision::Retained
        };
        trials.push(ProcessorReductionTrial {
            candidate_requirement_digest: canonical::digest(&candidate)?,
            decision,
            evidence_kind: ProcessorTrialEvidenceKind::ExactNative,
            execution_result: result.execution_result,
            tested_constraint: constraint.label(),
            trial_index: u8::try_from(trials.len()).map_err(|_| Error::schema_invalid())?,
        });
        if let Some(reason) = result_terminal_reason {
            terminal_reason = reason;
            break;
        }
        if let Some(reason) = aggregate_limit_reason(
            policy,
            total_cpu_milliseconds,
            total_elapsed_milliseconds,
            total_output_bytes,
        ) {
            terminal_reason = reason;
            break;
        }
    }
    let receipt = ProcessorReductionReceipt {
        final_requirement_digest: canonical::digest(&reduced)?,
        format: ProcessorReductionReceiptFormat::V1,
        observation_digest,
        terminal_reason,
        trials,
    };
    receipt.validate()?;
    Ok(ProcessorReductionResult {
        receipt,
        requirement: reduced,
    })
}

fn remaining_trial_limits(
    policy: ProcessorReductionPolicy,
    used_cpu_milliseconds: u64,
    used_elapsed_milliseconds: u64,
    used_output_bytes: u64,
) -> Option<ProcessorTrialLimits> {
    let cpu_milliseconds = policy
        .total_cpu_milliseconds
        .checked_sub(used_cpu_milliseconds)?
        .min(u64::from(policy.trial_limits.cpu_milliseconds));
    let elapsed_milliseconds = policy
        .total_elapsed_milliseconds
        .checked_sub(used_elapsed_milliseconds)?
        .min(u64::from(policy.trial_limits.elapsed_milliseconds));
    let output_bytes = policy
        .total_output_bytes
        .checked_sub(used_output_bytes)?
        .min(u64::from(policy.trial_limits.output_bytes));
    if cpu_milliseconds == 0 || elapsed_milliseconds == 0 || output_bytes == 0 {
        return None;
    }
    Some(ProcessorTrialLimits {
        cpu_milliseconds: u32::try_from(cpu_milliseconds).ok()?,
        elapsed_milliseconds: u32::try_from(elapsed_milliseconds).ok()?,
        memory_bytes: policy.trial_limits.memory_bytes,
        output_bytes: u32::try_from(output_bytes).ok()?,
    })
}

fn aggregate_limit_reason(
    policy: ProcessorReductionPolicy,
    cpu_milliseconds: u64,
    elapsed_milliseconds: u64,
    output_bytes: u64,
) -> Option<ProcessorReductionTerminalReason> {
    (cpu_milliseconds >= policy.total_cpu_milliseconds)
        .then_some(ProcessorReductionTerminalReason::CpuLimit)
        .or_else(|| {
            (elapsed_milliseconds >= policy.total_elapsed_milliseconds)
                .then_some(ProcessorReductionTerminalReason::ElapsedLimit)
        })
        .or_else(|| {
            (output_bytes >= policy.total_output_bytes)
                .then_some(ProcessorReductionTerminalReason::OutputLimit)
        })
}

fn exhausted_reason(
    policy: ProcessorReductionPolicy,
    cpu_milliseconds: u64,
    elapsed_milliseconds: u64,
    output_bytes: u64,
) -> ProcessorReductionTerminalReason {
    aggregate_limit_reason(policy, cpu_milliseconds, elapsed_milliseconds, output_bytes)
        .unwrap_or(ProcessorReductionTerminalReason::TrialLimit)
}

/// Resolve the captured subject architecture to the concrete processor
/// architecture. Private mode may carry the `architecture.native`
/// placeholder: the private Runtime seals on the capture host, so the
/// sealing process's own architecture is the captured one. Managed
/// candidates always name a concrete architecture at the ingress.
pub fn captured_processor_architecture(
    subject_architecture: &str,
) -> Result<ProcessorArchitecture, Error> {
    let native = if cfg!(target_arch = "aarch64") {
        ProcessorArchitecture::Arm64
    } else if cfg!(target_arch = "x86_64") {
        ProcessorArchitecture::X86_64
    } else {
        return Err(Error::schema_invalid());
    };
    match subject_architecture {
        "architecture.arm64" => Ok(ProcessorArchitecture::Arm64),
        "architecture.x86-64" => Ok(ProcessorArchitecture::X86_64),
        "architecture.native" => Ok(native),
        _ => Err(Error::schema_invalid()),
    }
}

/// Rebuild the structured processor observation from captured
/// `processor.*` capabilities. This is the one canonical decode of the SDK
/// capture rule pinned by `specs/v1/processor-capture.json`: feature
/// suffixes uppercase with hyphen back to underscore, os-state suffixes
/// byte for byte, and at most one identity token through the canonical
/// codec. A malformed token, a cross-architecture identity, or a second
/// identity fails closed, because admission must never guess a processor
/// view.
pub fn observation_from_captured_capabilities(
    architecture: ProcessorArchitecture,
    capabilities: &[String],
) -> Result<ProcessorObservation, Error> {
    let mut features = capabilities
        .iter()
        .filter_map(|capability| capability.strip_prefix("processor.feature."))
        .map(|suffix| {
            suffix
                .chars()
                .map(|character| match character {
                    'a'..='z' => character.to_ascii_uppercase(),
                    '-' => '_',
                    other => other,
                })
                .collect::<String>()
        })
        .collect::<Vec<_>>();
    features.sort();
    features.dedup();
    let mut states = capabilities
        .iter()
        .filter_map(|capability| capability.strip_prefix("processor.os-state."))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    states.sort();
    states.dedup();
    let mut tokens = capabilities
        .iter()
        .filter_map(|capability| capability.strip_prefix("processor.identity."));
    let identity = match tokens.next() {
        None => None,
        Some(token) => {
            if tokens.next().is_some() {
                return Err(Error::schema_invalid());
            }
            let identity = reproit_core::model::decode_identity_token(token)
                .ok_or_else(Error::schema_invalid)?;
            let matches_architecture = matches!(
                (&identity, architecture),
                (ProcessorIdentity::Arm(_), ProcessorArchitecture::Arm64)
                    | (ProcessorIdentity::X86(_), ProcessorArchitecture::X86_64)
            );
            if !matches_architecture {
                return Err(Error::schema_invalid());
            }
            Some(identity)
        }
    };
    let observation = ProcessorObservation {
        abi: reproit_core::model::processor_capture_abi(architecture).to_owned(),
        architecture,
        format: ProcessorObservationFormat::V1,
        identity,
        instruction_features: features,
        os_enabled_states: states,
    };
    observation.validate()?;
    Ok(observation)
}

/// The initial requirement is the complete captured observation. Static
/// inspection must not remove a captured processor requirement (spec
/// 7.8.1), so only bounded exact-native trials may remove the identity,
/// features, or operating-system state.
pub fn initial_processor_requirement(
    observation: &ProcessorObservation,
) -> Result<ProcessorRequirement, Error> {
    let requirement = ProcessorRequirement {
        abi: observation.abi.clone(),
        architecture: observation.architecture,
        format: ProcessorRequirementFormat::V1,
        identity: observation.identity.clone(),
        instruction_features: observation.instruction_features.clone(),
        os_enabled_states: observation.os_enabled_states.clone(),
    };
    requirement.validate()?;
    Ok(requirement)
}

/// Admit one candidate against the complete captured processor requirement.
///
/// Backend v1.0 defers processor reduction and World minimization, so the
/// production path retains every captured constraint and runs no trial. The
/// admitted capsule carries the captured `processor.requirement.*` and
/// `processor.identity.*` bindings and no `processor.reduction.*` binding,
/// because no reduction result exists to name.
pub fn admit_captured_processor_requirement(
    input: &mut AdmissionInput,
    requirement: &ProcessorRequirement,
    admission_executor: &impl AdmissionExecutor,
) -> Result<AdmittedCandidate, Error> {
    requirement.validate()?;
    bind_processor_requirement(input, requirement)?;
    if input
        .capsule
        .required_capabilities
        .iter()
        .any(|capability| capability.starts_with("processor.reduction."))
    {
        return Err(Error::schema_invalid());
    }
    admit(input, admission_executor)
}

pub fn reduce_and_admit(
    input: &mut AdmissionInput,
    observation: &ProcessorObservation,
    requirement: &ProcessorRequirement,
    policy: ProcessorReductionPolicy,
    trial_executor: &impl ProcessorTrialExecutor,
    admission_executor: &impl AdmissionExecutor,
) -> Result<(ProcessorReductionResult, AdmittedCandidate), Error> {
    let sealed_capsule = input.capsule.clone();
    let reduction =
        reduce_processor_requirements(observation, requirement, policy, trial_executor)?;
    bind_processor_reduction(input, &reduction.requirement, &reduction.receipt)?;
    reproit_core::model::validate_processor_reduction_capsule_binding(
        &sealed_capsule,
        &input.capsule,
        &reduction.requirement,
        &reduction.receipt,
    )?;
    let admitted = admit(input, admission_executor)?;
    Ok((reduction, admitted))
}

pub fn bind_processor_reduction(
    input: &mut AdmissionInput,
    requirement: &ProcessorRequirement,
    receipt: &ProcessorReductionReceipt,
) -> Result<(), Error> {
    if receipt.final_requirement_digest != canonical::digest(requirement)? {
        return Err(Error::schema_invalid());
    }
    bind_processor_requirement(input, requirement)?;
    input
        .capsule
        .required_capabilities
        .push(reproit_core::model::processor_reduction_capability(
            receipt,
        )?);
    input.capsule.required_capabilities.sort();
    input.capsule.required_capabilities.dedup();
    input.capsule.validate()
}

pub fn bind_processor_requirement(
    input: &mut AdmissionInput,
    requirement: &ProcessorRequirement,
) -> Result<(), Error> {
    bind_capsule_processor_requirement(&mut input.capsule, requirement)
}

/// Bind one processor requirement into a capsule's required capabilities.
/// Rebinding the same requirement is idempotent, so the Runtime can bind the
/// initial captured requirement at seal time and admission can rebind the
/// reduced requirement without a second rule.
pub fn bind_capsule_processor_requirement(
    capsule: &mut reproit_core::model::ReplayCapsule,
    requirement: &ProcessorRequirement,
) -> Result<(), Error> {
    capsule.required_capabilities =
        processor_capabilities(&capsule.required_capabilities, requirement)?;
    Ok(())
}

fn processor_capabilities(
    existing: &[String],
    requirement: &ProcessorRequirement,
) -> Result<Vec<String>, Error> {
    let mut capabilities = existing
        .iter()
        .filter(|value| !value.starts_with("architecture.") && !value.starts_with("processor."))
        .cloned()
        .collect::<Vec<_>>();
    capabilities.extend(processor_requirement_capabilities(requirement)?);
    capabilities.sort();
    capabilities.dedup();
    if capabilities.len() > 64 {
        return Err(Error::schema_invalid());
    }
    Ok(capabilities)
}

/// The canonical trial order: instruction features with dependents first
/// (descending dependency depth, then lexicographic), then
/// operating-system states, then the identity. The order is a pure
/// function of the requirement, so host availability and clock timing
/// cannot change which constraints the reducer tests (spec 7.8.1).
fn constraints(requirement: &ProcessorRequirement) -> Vec<ProcessorConstraint> {
    let mut features = requirement.instruction_features.clone();
    features.sort_by(|left, right| {
        dependency_depth(right)
            .cmp(&dependency_depth(left))
            .then_with(|| left.cmp(right))
    });
    features
        .into_iter()
        .map(ProcessorConstraint::InstructionFeature)
        .chain(
            requirement
                .os_enabled_states
                .iter()
                .cloned()
                .map(ProcessorConstraint::OsEnabledState),
        )
        .chain(
            requirement
                .identity
                .is_some()
                .then_some(ProcessorConstraint::ProcessorIdentity),
        )
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captured_x86_identity_becomes_canonical_requirement_capabilities() {
        let captured = vec![
            "processor.feature.avx2".to_owned(),
            "processor.identity.x86.genuineintel.6.143.8.0x2b000643".to_owned(),
            "processor.os-state.osxsave".to_owned(),
            "processor.os-state.xcr0.avx".to_owned(),
        ];
        let observation =
            observation_from_captured_capabilities(ProcessorArchitecture::X86_64, &captured)
                .unwrap();
        let requirement = initial_processor_requirement(&observation).unwrap();
        let requirement_digest = canonical::digest(&requirement).unwrap();

        // The identity keeps its captured token. Admission compares a retained
        // identity against the sealed captured capability set, so a digest here
        // would never match the capture.
        assert_eq!(
            processor_requirement_capabilities(&requirement).unwrap(),
            [
                "architecture.x86-64".to_owned(),
                "processor.feature.avx2".to_owned(),
                "processor.identity.x86.genuineintel.6.143.8.0x2b000643".to_owned(),
                "processor.os-state.osxsave".to_owned(),
                "processor.os-state.xcr0.avx".to_owned(),
                format!(
                    "processor.requirement.{}",
                    requirement_digest.to_string().trim_start_matches("sha256:")
                ),
            ]
        );
    }

    struct TrialFixture;

    impl ProcessorTrialExecutor for TrialFixture {
        fn can_control(&self, constraint: &ProcessorConstraint) -> bool {
            !matches!(constraint, ProcessorConstraint::ProcessorIdentity)
        }

        fn execute_trial(
            &self,
            requirement: &ProcessorRequirement,
            limits: ProcessorTrialLimits,
        ) -> Result<ProcessorTrialResult, Error> {
            assert_eq!(limits, ProcessorTrialLimits::PRODUCTION);
            let execution_result = if !requirement
                .instruction_features
                .iter()
                .any(|value| value == "AVX512BW")
                && requirement
                    .instruction_features
                    .iter()
                    .any(|value| value == "AVX512F")
            {
                ExecutionOutcome::TargetReproduced
            } else {
                ExecutionOutcome::TargetAbsent
            };
            Ok(ProcessorTrialResult {
                cpu_milliseconds: 10,
                elapsed_milliseconds: 20,
                execution_result,
                output_bytes: 32,
                timed_out: false,
                unstable: false,
            })
        }
    }

    #[test]
    fn reducer_removes_only_exact_native_reproduced_constraints() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../../../specs/v1/protocol-vectors.json")).unwrap();
        let observation = serde_json::from_value(
            vectors["positive"]["processor_observation_x86"]["value"].clone(),
        )
        .unwrap();
        let mut requirement: ProcessorRequirement = serde_json::from_value(
            vectors["positive"]["processor_requirement_x86"]["value"].clone(),
        )
        .unwrap();
        requirement
            .instruction_features
            .insert(1, "AVX512BW".to_owned());
        let result = reduce_processor_requirements(
            &observation,
            &requirement,
            ProcessorReductionPolicy::PRODUCTION,
            &TrialFixture,
        )
        .unwrap();
        // The canonical order trials AVX512BW before AVX2 and AVX512F, so
        // every constraint whose removal still reproduces is removed, and
        // AVX512F is retained because its removal trial does not reproduce.
        assert_eq!(result.requirement.instruction_features, ["AVX512F"]);
        assert!(result.requirement.os_enabled_states.is_empty());
        assert!(result.requirement.identity.is_some());
        assert_eq!(
            result.receipt.terminal_reason,
            ProcessorReductionTerminalReason::Uncontrollable
        );
        assert_eq!(
            result
                .receipt
                .trials
                .iter()
                .map(|trial| trial.tested_constraint.as_str())
                .collect::<Vec<_>>(),
            [
                "instruction-feature.AVX512BW",
                "instruction-feature.AVX2",
                "instruction-feature.AVX512F",
                "os-enabled-state.osxsave",
                "os-enabled-state.xcr0.avx",
                "os-enabled-state.xcr0.avx512",
            ]
        );
        assert!(
            result
                .receipt
                .trials
                .iter()
                .all(|trial| { trial.evidence_kind == ProcessorTrialEvidenceKind::ExactNative })
        );
    }

    /// A fixture that reproduces every trial, so removals cascade as far as
    /// the dependency rules allow.
    struct AlwaysReproducesFixture;

    impl ProcessorTrialExecutor for AlwaysReproducesFixture {
        fn can_control(&self, constraint: &ProcessorConstraint) -> bool {
            matches!(constraint, ProcessorConstraint::InstructionFeature(_))
        }

        fn execute_trial(
            &self,
            _requirement: &ProcessorRequirement,
            _limits: ProcessorTrialLimits,
        ) -> Result<ProcessorTrialResult, Error> {
            Ok(ProcessorTrialResult {
                cpu_milliseconds: 1,
                elapsed_milliseconds: 1,
                execution_result: ExecutionOutcome::TargetReproduced,
                output_bytes: 1,
                timed_out: false,
                unstable: false,
            })
        }
    }

    /// A fixture that retains every trial, so prerequisites stay blocked by
    /// their retained dependents.
    struct NeverReproducesFixture;

    impl ProcessorTrialExecutor for NeverReproducesFixture {
        fn can_control(&self, constraint: &ProcessorConstraint) -> bool {
            matches!(constraint, ProcessorConstraint::InstructionFeature(_))
        }

        fn execute_trial(
            &self,
            _requirement: &ProcessorRequirement,
            _limits: ProcessorTrialLimits,
        ) -> Result<ProcessorTrialResult, Error> {
            Ok(ProcessorTrialResult {
                cpu_milliseconds: 1,
                elapsed_milliseconds: 1,
                execution_result: ExecutionOutcome::TargetAbsent,
                output_bytes: 1,
                timed_out: false,
                unstable: false,
            })
        }
    }

    struct UncontrollableFixture(std::cell::Cell<u8>);

    impl ProcessorTrialExecutor for UncontrollableFixture {
        fn can_control(&self, _constraint: &ProcessorConstraint) -> bool {
            false
        }

        fn execute_trial(
            &self,
            _requirement: &ProcessorRequirement,
            _limits: ProcessorTrialLimits,
        ) -> Result<ProcessorTrialResult, Error> {
            self.0.set(self.0.get().saturating_add(1));
            Err(Error::schema_invalid())
        }
    }

    fn x86_requirement(features: &[&str], states: &[&str]) -> ProcessorRequirement {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../../../specs/v1/protocol-vectors.json")).unwrap();
        let mut requirement: ProcessorRequirement = serde_json::from_value(
            vectors["positive"]["processor_requirement_x86"]["value"].clone(),
        )
        .unwrap();
        requirement.identity = None;
        requirement.instruction_features = features.iter().map(ToString::to_string).collect();
        requirement.os_enabled_states = states.iter().map(ToString::to_string).collect();
        requirement
    }

    fn x86_observation(requirement: &ProcessorRequirement) -> ProcessorObservation {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../../../specs/v1/protocol-vectors.json")).unwrap();
        let mut observation: ProcessorObservation = serde_json::from_value(
            vectors["positive"]["processor_observation_x86"]["value"].clone(),
        )
        .unwrap();
        observation.instruction_features = requirement.instruction_features.clone();
        observation.os_enabled_states = requirement.os_enabled_states.clone();
        observation
    }

    #[test]
    fn a_prerequisite_with_a_retained_dependent_is_never_trialed() {
        let requirement = x86_requirement(&["AVX", "AVX2"], &[]);
        let observation = x86_observation(&requirement);
        let result = reduce_processor_requirements(
            &observation,
            &requirement,
            ProcessorReductionPolicy::PRODUCTION,
            &NeverReproducesFixture,
        )
        .unwrap();
        // AVX2 is trialed first and retained, so AVX is dependency blocked
        // and must remain required without a trial.
        assert_eq!(result.receipt.trials.len(), 1);
        assert_eq!(
            result.receipt.trials[0].tested_constraint,
            "instruction-feature.AVX2"
        );
        assert_eq!(result.requirement.instruction_features, ["AVX", "AVX2"]);
        assert_eq!(
            result.receipt.terminal_reason,
            ProcessorReductionTerminalReason::Uncontrollable
        );
    }

    #[test]
    fn an_uncontrollable_x86_view_stays_required_without_a_trial() {
        let requirement = x86_requirement(&["AVX512BW"], &[]);
        let observation = x86_observation(&requirement);
        let executor = UncontrollableFixture(std::cell::Cell::new(0));
        let result = reduce_processor_requirements(
            &observation,
            &requirement,
            ProcessorReductionPolicy::PRODUCTION,
            &executor,
        )
        .unwrap();

        assert_eq!(executor.0.get(), 0);
        assert_eq!(result.requirement, requirement);
        assert!(result.receipt.trials.is_empty());
        assert_eq!(
            result.receipt.terminal_reason,
            ProcessorReductionTerminalReason::Uncontrollable
        );
    }

    #[test]
    fn removing_a_feature_cascades_its_operating_system_state() {
        let requirement = x86_requirement(&["AVX"], &["xcr0.avx"]);
        let observation = x86_observation(&requirement);
        let result = reduce_processor_requirements(
            &observation,
            &requirement,
            ProcessorReductionPolicy::PRODUCTION,
            &AlwaysReproducesFixture,
        )
        .unwrap();
        // One trial removes AVX and the dependent state together. The state
        // constraint is then absent and consumes no second trial, so the
        // reduction is complete.
        assert_eq!(result.receipt.trials.len(), 1);
        assert!(result.requirement.instruction_features.is_empty());
        assert!(result.requirement.os_enabled_states.is_empty());
        assert_eq!(
            result.receipt.terminal_reason,
            ProcessorReductionTerminalReason::Complete
        );
    }

    #[test]
    fn arm_reduction_starts_complete_and_retains_uncontrollable_views() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../../../specs/v1/protocol-vectors.json")).unwrap();
        let observation: ProcessorObservation = serde_json::from_value(
            vectors["positive"]["processor_observation_arm64"]["value"].clone(),
        )
        .unwrap();
        let requirement = initial_processor_requirement(&observation).unwrap();
        assert_eq!(requirement.identity, observation.identity);
        assert_eq!(
            requirement.instruction_features,
            observation.instruction_features
        );
        assert_eq!(requirement.os_enabled_states, observation.os_enabled_states);

        let result = reduce_processor_requirements(
            &observation,
            &requirement,
            ProcessorReductionPolicy::PRODUCTION,
            &AlwaysReproducesFixture,
        )
        .unwrap();
        assert!(result.requirement.instruction_features.is_empty());
        assert_eq!(
            result.requirement.os_enabled_states,
            observation.os_enabled_states
        );
        assert_eq!(result.requirement.identity, observation.identity);
        assert_eq!(
            result.receipt.terminal_reason,
            ProcessorReductionTerminalReason::Uncontrollable
        );
        assert_eq!(result.receipt.trials.len(), 3);
    }

    #[test]
    fn the_canonical_order_is_dependency_depth_then_lexicographic() {
        let requirement = x86_requirement(
            &["AES", "AVX", "AVX2", "AVX512BW", "AVX512F", "AVX512VL"],
            &[],
        );
        let labels = constraints(&requirement)
            .iter()
            .map(super::ProcessorConstraint::label)
            .collect::<Vec<_>>();
        assert_eq!(
            labels,
            [
                "instruction-feature.AVX512BW",
                "instruction-feature.AVX512VL",
                "instruction-feature.AVX2",
                "instruction-feature.AVX512F",
                "instruction-feature.AES",
                "instruction-feature.AVX",
            ]
        );
    }

    #[test]
    fn reducer_rejects_one_trial_over_the_contract() {
        let policy = ProcessorReductionPolicy {
            maximum_trials: 17,
            ..ProcessorReductionPolicy::PRODUCTION
        };
        assert!(policy.validate().is_err());
    }

    struct FixedTrialFixture {
        calls: std::cell::Cell<u8>,
        result: ProcessorTrialResult,
    }

    impl ProcessorTrialExecutor for FixedTrialFixture {
        fn can_control(&self, _constraint: &ProcessorConstraint) -> bool {
            true
        }

        fn execute_trial(
            &self,
            _requirement: &ProcessorRequirement,
            limits: ProcessorTrialLimits,
        ) -> Result<ProcessorTrialResult, Error> {
            self.calls.set(self.calls.get() + 1);
            assert!(self.result.cpu_milliseconds <= u64::from(limits.cpu_milliseconds));
            assert!(self.result.elapsed_milliseconds <= u64::from(limits.elapsed_milliseconds));
            assert!(self.result.output_bytes <= u64::from(limits.output_bytes));
            Ok(self.result)
        }
    }

    #[test]
    fn reducer_stops_before_a_trial_without_an_authoritative_cpu_reservation() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../../../specs/v1/protocol-vectors.json")).unwrap();
        let observation = serde_json::from_value(
            vectors["positive"]["processor_observation_x86"]["value"].clone(),
        )
        .unwrap();
        let requirement = serde_json::from_value(
            vectors["positive"]["processor_requirement_x86"]["value"].clone(),
        )
        .unwrap();
        let executor = FixedTrialFixture {
            calls: std::cell::Cell::new(0),
            result: ProcessorTrialResult {
                cpu_milliseconds: 5_000,
                elapsed_milliseconds: 1,
                execution_result: ExecutionOutcome::TargetReproduced,
                output_bytes: 1,
                timed_out: false,
                unstable: false,
            },
        };
        let result = reduce_processor_requirements(
            &observation,
            &requirement,
            ProcessorReductionPolicy {
                total_cpu_milliseconds: 5_000,
                ..ProcessorReductionPolicy::PRODUCTION
            },
            &executor,
        )
        .unwrap();
        assert_eq!(executor.calls.get(), 1);
        assert_eq!(
            result.receipt.terminal_reason,
            ProcessorReductionTerminalReason::CpuLimit
        );
        assert_eq!(result.receipt.trials.len(), 1);
        assert_eq!(
            result.receipt.trials[0].decision,
            ProcessorReductionDecision::Removed
        );
    }

    #[test]
    fn reducer_enforces_elapsed_and_output_reservations_at_the_exact_boundary() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../../../specs/v1/protocol-vectors.json")).unwrap();
        let observation: ProcessorObservation = serde_json::from_value(
            vectors["positive"]["processor_observation_x86"]["value"].clone(),
        )
        .unwrap();
        let requirement: ProcessorRequirement = serde_json::from_value(
            vectors["positive"]["processor_requirement_x86"]["value"].clone(),
        )
        .unwrap();
        let cases = [
            (
                ProcessorReductionPolicy {
                    total_elapsed_milliseconds: 10_000,
                    ..ProcessorReductionPolicy::PRODUCTION
                },
                ProcessorTrialResult {
                    cpu_milliseconds: 1,
                    elapsed_milliseconds: 10_000,
                    execution_result: ExecutionOutcome::TargetReproduced,
                    output_bytes: 1,
                    timed_out: false,
                    unstable: false,
                },
                ProcessorReductionTerminalReason::ElapsedLimit,
            ),
            (
                ProcessorReductionPolicy {
                    total_output_bytes: 65_536,
                    ..ProcessorReductionPolicy::PRODUCTION
                },
                ProcessorTrialResult {
                    cpu_milliseconds: 1,
                    elapsed_milliseconds: 1,
                    execution_result: ExecutionOutcome::TargetReproduced,
                    output_bytes: 65_536,
                    timed_out: false,
                    unstable: false,
                },
                ProcessorReductionTerminalReason::OutputLimit,
            ),
        ];
        for (policy, trial, expected) in cases {
            let executor = FixedTrialFixture {
                calls: std::cell::Cell::new(0),
                result: trial,
            };
            let result =
                reduce_processor_requirements(&observation, &requirement, policy, &executor)
                    .unwrap();
            assert_eq!(executor.calls.get(), 1);
            assert_eq!(result.receipt.terminal_reason, expected);
            assert_eq!(result.receipt.trials.len(), 1);
        }
    }

    #[test]
    fn timeout_and_unstable_trials_retain_the_tested_constraint() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../../../specs/v1/protocol-vectors.json")).unwrap();
        let observation: ProcessorObservation = serde_json::from_value(
            vectors["positive"]["processor_observation_x86"]["value"].clone(),
        )
        .unwrap();
        let requirement: ProcessorRequirement = serde_json::from_value(
            vectors["positive"]["processor_requirement_x86"]["value"].clone(),
        )
        .unwrap();
        for (timed_out, unstable, expected) in [
            (true, false, ProcessorReductionTerminalReason::Timeout),
            (false, true, ProcessorReductionTerminalReason::Unstable),
        ] {
            let executor = FixedTrialFixture {
                calls: std::cell::Cell::new(0),
                result: ProcessorTrialResult {
                    cpu_milliseconds: 1,
                    elapsed_milliseconds: 1,
                    execution_result: ExecutionOutcome::TargetReproduced,
                    output_bytes: 1,
                    timed_out,
                    unstable,
                },
            };
            let result = reduce_processor_requirements(
                &observation,
                &requirement,
                ProcessorReductionPolicy::PRODUCTION,
                &executor,
            )
            .unwrap();
            assert_eq!(result.receipt.terminal_reason, expected);
            assert_eq!(
                result.receipt.trials[0].decision,
                ProcessorReductionDecision::Retained
            );
            assert_eq!(result.requirement, requirement);
        }
    }

    #[test]
    fn reducer_rejects_one_unit_over_every_aggregate_hard_limit() {
        for policy in [
            ProcessorReductionPolicy {
                total_cpu_milliseconds: 7_200_001,
                ..ProcessorReductionPolicy::PRODUCTION
            },
            ProcessorReductionPolicy {
                total_elapsed_milliseconds: 1_800_001,
                ..ProcessorReductionPolicy::PRODUCTION
            },
            ProcessorReductionPolicy {
                total_output_bytes: 16 * 1024 * 1024 + 1,
                ..ProcessorReductionPolicy::PRODUCTION
            },
        ] {
            assert!(policy.validate().is_err());
        }
    }

    #[test]
    fn reducer_rejects_one_unit_over_every_per_trial_policy_limit() {
        for trial_limits in [
            ProcessorTrialLimits {
                cpu_milliseconds: 60_001,
                elapsed_milliseconds: 120_000,
                ..ProcessorTrialLimits::PRODUCTION
            },
            ProcessorTrialLimits {
                elapsed_milliseconds: 120_001,
                ..ProcessorTrialLimits::PRODUCTION
            },
            ProcessorTrialLimits {
                memory_bytes: 1_073_741_825,
                ..ProcessorTrialLimits::PRODUCTION
            },
            ProcessorTrialLimits {
                output_bytes: 1_048_577,
                ..ProcessorTrialLimits::PRODUCTION
            },
        ] {
            assert!(
                ProcessorReductionPolicy {
                    trial_limits,
                    ..ProcessorReductionPolicy::PRODUCTION
                }
                .validate()
                .is_err()
            );
        }
    }

    struct ReportedLimitFixture(ProcessorTrialResult);

    impl ProcessorTrialExecutor for ReportedLimitFixture {
        fn can_control(&self, _constraint: &ProcessorConstraint) -> bool {
            true
        }

        fn execute_trial(
            &self,
            _requirement: &ProcessorRequirement,
            _limits: ProcessorTrialLimits,
        ) -> Result<ProcessorTrialResult, Error> {
            Ok(self.0)
        }
    }

    #[test]
    fn a_trial_report_over_any_reserved_limit_retains_the_constraint() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../../../specs/v1/protocol-vectors.json")).unwrap();
        let observation: ProcessorObservation = serde_json::from_value(
            vectors["positive"]["processor_observation_x86"]["value"].clone(),
        )
        .unwrap();
        let requirement = initial_processor_requirement(&observation).unwrap();
        for (result, reason) in [
            (
                ProcessorTrialResult {
                    cpu_milliseconds: 30_001,
                    elapsed_milliseconds: 1,
                    execution_result: ExecutionOutcome::TargetReproduced,
                    output_bytes: 1,
                    timed_out: false,
                    unstable: false,
                },
                ProcessorReductionTerminalReason::CpuLimit,
            ),
            (
                ProcessorTrialResult {
                    cpu_milliseconds: 1,
                    elapsed_milliseconds: 30_001,
                    execution_result: ExecutionOutcome::TargetReproduced,
                    output_bytes: 1,
                    timed_out: false,
                    unstable: false,
                },
                ProcessorReductionTerminalReason::ElapsedLimit,
            ),
            (
                ProcessorTrialResult {
                    cpu_milliseconds: 1,
                    elapsed_milliseconds: 1,
                    execution_result: ExecutionOutcome::TargetReproduced,
                    output_bytes: 65_537,
                    timed_out: false,
                    unstable: false,
                },
                ProcessorReductionTerminalReason::OutputLimit,
            ),
        ] {
            let reduced = reduce_processor_requirements(
                &observation,
                &requirement,
                ProcessorReductionPolicy::PRODUCTION,
                &ReportedLimitFixture(result),
            )
            .unwrap();
            assert_eq!(reduced.receipt.terminal_reason, reason);
            assert_eq!(reduced.requirement, requirement);
            assert_eq!(
                reduced.receipt.trials[0].decision,
                ProcessorReductionDecision::Retained
            );
        }
    }

    #[test]
    fn protocol_scenarios_cover_every_aggregate_terminal_limit() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../../../specs/v1/protocol-vectors.json")).unwrap();
        let scenarios = vectors["processor_reduction_scenarios"]
            .as_array()
            .expect("processor scenarios");
        for required in ["cpu-limit", "elapsed-limit", "output-limit"] {
            assert!(scenarios.iter().any(|scenario| {
                scenario["name"] == required && scenario["expected"] == "RETAIN_UNTESTED"
            }));
        }
    }
}

use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

use super::{ProcessingMode, Validate, valid_lower_identity, validate_capabilities};
use crate::{
    Error, ErrorCode,
    crypto::verify_signed_value,
    identity::{Digest, OrganizationId, ProjectId, ServiceId, Timestamp},
};

const MAX_EXECUTION_GRANT_SECONDS: i64 = 7_200;
const MAX_REQUESTER_IDENTITY_BYTES: usize = 512;

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutorLocality {
    Local,
    CustomerWorker,
    ManagedWorker,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutorEvidenceStatus {
    Active,
    Revoked,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum ExecutorCapabilityEvidenceFormat {
    #[serde(rename = "reproit.executor-capability-evidence.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutorCapabilityEvidence {
    pub capabilities: Vec<String>,
    pub executor_id: String,
    pub expires_at: Timestamp,
    pub format: ExecutorCapabilityEvidenceFormat,
    pub issued_at: Timestamp,
    pub locality: ExecutorLocality,
    pub organization_id: OrganizationId,
    pub platform_identity_digest: Digest,
    pub project_id: ProjectId,
    pub service_id: ServiceId,
    pub signature: String,
    pub signer_key_id: String,
    pub status: ExecutorEvidenceStatus,
}

impl Validate for ExecutorCapabilityEvidence {
    fn validate(&self) -> Result<(), Error> {
        validate_capabilities(&self.capabilities)?;
        if self.capabilities.is_empty()
            || self.executor_id.is_empty()
            || self.executor_id.len() > 128
            || !valid_lower_identity(self.executor_id.as_bytes())
            || self.signer_key_id.is_empty()
            || self.signer_key_id.len() > 256
            || self.signature.len() != 86
            || self.issued_at >= self.expires_at
        {
            return Err(Error::schema_invalid());
        }
        crate::crypto::decode_base64url::<64>(&self.signature)?;
        Ok(())
    }
}

pub struct ExecutorEvidenceScope {
    pub organization_id: OrganizationId,
    pub project_id: ProjectId,
    pub service_id: ServiceId,
}

pub fn verify_executor_capability_evidence(
    evidence: &ExecutorCapabilityEvidence,
    scope: &ExecutorEvidenceScope,
    now: &Timestamp,
    public_key: &[u8; 32],
) -> Result<(), Error> {
    evidence.validate()?;
    if evidence.status == ExecutorEvidenceStatus::Revoked {
        return Err(Error::new(
            ErrorCode::AttestationRevoked,
            "The executor capability evidence is revoked.",
        ));
    }
    if evidence.organization_id != scope.organization_id
        || evidence.project_id != scope.project_id
        || evidence.service_id != scope.service_id
    {
        return Err(Error::new(
            ErrorCode::AttestationScope,
            "The executor capability evidence does not match the requested scope.",
        ));
    }
    if now < &evidence.issued_at || now >= &evidence.expires_at {
        return Err(Error::new(
            ErrorCode::AttestationScope,
            "The executor capability evidence is outside its validity interval.",
        ));
    }
    let value = serde_json::to_value(evidence).map_err(|_| Error::schema_invalid())?;
    verify_signed_value(&value, public_key)
}

/// Verify only the structure and cryptographic signature of executor
/// capability evidence, without binding it to a scope or clock. The isolated
/// debug controller uses this: the trusted worker already bound the evidence to
/// the grant and worker identity, and the controller holds no scope or clock of
/// its own. It fails closed on any malformed or unsigned evidence.
pub fn verify_evidence_signature(
    evidence: &ExecutorCapabilityEvidence,
    public_key: &[u8; 32],
) -> Result<(), Error> {
    evidence.validate()?;
    let value = serde_json::to_value(evidence).map_err(|_| Error::schema_invalid())?;
    verify_signed_value(&value, public_key)
}

/// The bound on how many required capabilities a capsule may declare.
const MAX_REQUIRED_CAPABILITIES: usize = 64;

/// The canonical subset rule for replay-host compatibility: every required
/// capability must exist in the authenticated executor capability evidence.
/// This is the one shared comparison used by the CLI, the worker, and the
/// debug controller, so their capability policy can never diverge.
#[must_use]
pub fn required_capabilities_present(required: &[String], provided: &[String]) -> bool {
    if required.len() > MAX_REQUIRED_CAPABILITIES || provided.len() > MAX_REQUIRED_CAPABILITIES {
        return false;
    }
    required
        .iter()
        .all(|capability| provided.iter().any(|value| value == capability))
}

/// The canonical replay-selection rule: every required capability must exist
/// in the provided set, except the capsule-specific processor digest bindings
/// (`processor.requirement.*`, `processor.identity.*`, and
/// `processor.reduction.*`), which name this capsule's admission-time
/// reduction result and which no general capability evidence can declare.
/// Host-declarable `processor.feature.*` and
/// `processor.os-state.*` bindings stay in the subset. Every selection site
/// (CLI, app, worker, controller) uses this one rule.
#[must_use]
pub fn replay_capabilities_present(required: &[String], provided: &[String]) -> bool {
    if required.len() > MAX_REQUIRED_CAPABILITIES {
        return false;
    }
    let discrete: Vec<String> = required
        .iter()
        .filter(|value| {
            !value.starts_with("processor.requirement.")
                && !value.starts_with("processor.identity.")
                && !value.starts_with("processor.reduction.")
        })
        .cloned()
        .collect();
    required_capabilities_present(&discrete, provided)
}

/// The capability that names a debugger protocol.
#[must_use]
pub fn debugger_protocol_capability(protocol: super::DebuggerProtocol) -> &'static str {
    match protocol {
        super::DebuggerProtocol::ChromeDevtools => "debugger.chrome-devtools",
        super::DebuggerProtocol::DebugAdapter => "debugger.debug-adapter",
        super::DebuggerProtocol::GdbRemoteSerial => "debugger.gdb-remote",
    }
}

/// Verify that a replay host is compatible with a capsule's required
/// capabilities using the authenticated executor capability evidence as the
/// authority for the host's discrete capabilities. The subject and capsule
/// never select this evidence: the trusted worker provides it. Every check is
/// bounded and fails closed.
///
/// Discrete capabilities (architecture, operating system, executor mechanism,
/// World provider, runtime, SDK, debugger protocol, processor features, and
/// operating-system enabled state) must each exist in the evidence. Only the
/// capsule-specific digest bindings (`processor.requirement.*`,
/// `processor.identity.*`, and `processor.reduction.*`) are excluded from the
/// subset. They name this capsule's admission-time reduction result, which no
/// general evidence can declare. They are optional, and each binding's format
/// is validated when present. The required set must also name the native architecture,
/// `operating-system.linux`, the Linux executor mechanism, the World provider,
/// and the requested debugger protocol.
pub fn verify_replay_capabilities(
    required: &[String],
    evidence: &ExecutorCapabilityEvidence,
    debugger: &super::DebuggerContract,
    native_architecture_capability: &str,
) -> Result<(), Error> {
    let unsupported = || {
        Error::new(
            ErrorCode::UnsupportedCapabilitySet,
            "The replay host does not support the sealed capture bundle.",
        )
    };
    if required.len() < 4 || required.len() > MAX_REQUIRED_CAPABILITIES {
        return Err(unsupported());
    }
    if !required.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(unsupported());
    }
    // The evidence is authoritative for every discrete capability, including
    // host-declarable processor feature and operating-system-enabled-state
    // bindings: a capsule proved to need a processor feature must not replay
    // on a host that does not declare it. Only the capsule-specific digest
    // bindings (`processor.requirement.*`, `processor.identity.*`, and
    // `processor.reduction.*`) are excluded, because they name this capsule's
    // reduction result and no general evidence can declare them. Their format
    // is still validated below.
    if !replay_capabilities_present(required, &evidence.capabilities) {
        return Err(unsupported());
    }
    if !required.iter().all(|value| valid_capability_binding(value)) {
        return Err(unsupported());
    }
    let present = |capability: &str| required.iter().any(|value| value == capability);
    if !present(native_architecture_capability)
        || !present("operating-system.linux")
        || !present("executor.linux-native")
        || !present("world.sqlite")
        || !present(debugger_protocol_capability(debugger.protocol))
    {
        return Err(unsupported());
    }
    Ok(())
}

/// Validate the format of one required capability. Processor bindings carry a
/// digest or a bounded name that the controller checks even though the evidence
/// does not declare them, so a malformed processor binding fails closed.
#[must_use]
fn valid_capability_binding(capability: &str) -> bool {
    if let Some(suffix) = capability.strip_prefix("processor.requirement.") {
        return valid_digest_suffix(suffix);
    }
    if let Some(suffix) = capability.strip_prefix("processor.identity.") {
        // An identity names a captured processor, not a digest. Capture and the
        // requirement capability list share this one encoding.
        return super::decode_identity_token(suffix).is_some();
    }
    if let Some(suffix) = capability.strip_prefix("processor.reduction.") {
        return valid_digest_suffix(suffix);
    }
    if let Some(suffix) = capability.strip_prefix("processor.feature.") {
        return valid_name_suffix(suffix);
    }
    if let Some(suffix) = capability.strip_prefix("processor.os-state.") {
        return valid_name_suffix(suffix);
    }
    // A `processor.` capability with no recognized binding is rejected.
    !capability.starts_with("processor.")
}

#[must_use]
fn valid_digest_suffix(suffix: &str) -> bool {
    suffix.len() == 64
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[must_use]
fn valid_name_suffix(suffix: &str) -> bool {
    !suffix.is_empty()
        && suffix.len() <= 128
        && suffix.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionGrantOperation {
    Check,
    Debug,
    Keep,
    Replay,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExecutionWorkClass {
    Admission,
    Developer,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum ExecutionGrantFormat {
    #[serde(rename = "reproit.execution-grant.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionGrant {
    pub debugger_capability_digest: Digest,
    pub executor_id: String,
    pub expires_at: Timestamp,
    pub format: ExecutionGrantFormat,
    pub grant_id: String,
    pub issued_at: Timestamp,
    pub operation: ExecutionGrantOperation,
    pub organization_id: OrganizationId,
    pub processing_mode: ProcessingMode,
    pub project_id: ProjectId,
    pub requester_identity: String,
    pub repro_digest: Digest,
    pub service_id: ServiceId,
    pub signature: String,
    pub work_class: ExecutionWorkClass,
}

pub struct ExecutionGrantExpectation<'a> {
    pub debugger_capability_digest: Digest,
    pub now: &'a Timestamp,
    pub operation: ExecutionGrantOperation,
    pub processing_mode: ProcessingMode,
    pub requester_identity: &'a str,
    pub repro_digest: Digest,
    pub scope: &'a ExecutorEvidenceScope,
    pub work_class: ExecutionWorkClass,
}

impl Validate for ExecutionGrant {
    fn validate(&self) -> Result<(), Error> {
        if self.executor_id.is_empty()
            || self.executor_id.len() > 128
            || !valid_lower_identity(self.executor_id.as_bytes())
            || self.grant_id.is_empty()
            || self.grant_id.len() > 128
            || !valid_lower_identity(self.grant_id.as_bytes())
            || self.requester_identity.is_empty()
            || self.requester_identity.len() > MAX_REQUESTER_IDENTITY_BYTES
            || self.requester_identity.chars().any(char::is_control)
            || self.signature.len() != 86
        {
            return Err(Error::schema_invalid());
        }
        crate::crypto::decode_base64url::<64>(&self.signature)?;
        let issued_at = parse_time(&self.issued_at)?;
        let expires_at = parse_time(&self.expires_at)?;
        if expires_at <= issued_at
            || expires_at - issued_at > Duration::seconds(MAX_EXECUTION_GRANT_SECONDS)
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

pub fn verify_execution_grant(
    grant: &ExecutionGrant,
    evidence: &ExecutorCapabilityEvidence,
    expectation: &ExecutionGrantExpectation<'_>,
    public_key: &[u8; 32],
) -> Result<(), Error> {
    grant.validate()?;
    if grant.executor_id != evidence.executor_id
        || grant.organization_id != expectation.scope.organization_id
        || grant.project_id != expectation.scope.project_id
        || grant.service_id != expectation.scope.service_id
        || grant.operation != expectation.operation
        || grant.processing_mode != expectation.processing_mode
        || grant.requester_identity != expectation.requester_identity
        || grant.repro_digest != expectation.repro_digest
        || grant.debugger_capability_digest != expectation.debugger_capability_digest
        || expectation.now < &grant.issued_at
        || expectation.now >= &grant.expires_at
        || grant.work_class != expectation.work_class
    {
        return Err(Error::new(
            ErrorCode::AttestationScope,
            "The execution grant does not match the requested operation.",
        ));
    }
    let value = serde_json::to_value(grant).map_err(|_| Error::schema_invalid())?;
    verify_signed_value(&value, public_key)
}

fn parse_time(value: &Timestamp) -> Result<OffsetDateTime, Error> {
    OffsetDateTime::parse(value.as_str(), &Rfc3339).map_err(|_| Error::schema_invalid())
}

#[cfg(test)]
mod capability_tests {
    use super::*;
    use crate::{
        canonical,
        crypto::{secret_key, sign_bytes, verification_key},
        identity::Digest,
        model::{
            DebuggerContract, DebuggerContractFormat, DebuggerProtocol, DebuggerReadinessRule,
            ProcessorArchitecture,
        },
    };

    const NATIVE: &str = "architecture.x86-64";
    const DIGEST_SUFFIX: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SIGNING_SEED: [u8; 32] = [7_u8; 32];

    fn sorted(values: &[&str]) -> Vec<String> {
        let mut owned: Vec<String> = values.iter().map(|value| (*value).to_owned()).collect();
        owned.sort();
        owned.dedup();
        owned
    }

    /// A representative required set for one SDK: the invariant Linux replay
    /// capabilities plus the language runtime, SDK, and debugger protocol.
    fn required_for(runtime: &str, sdk: &str, debugger: &str) -> Vec<String> {
        sorted(&[
            NATIVE,
            "operating-system.linux",
            "executor.linux-native",
            "world.sqlite",
            &format!("processor.requirement.{DIGEST_SUFFIX}"),
            runtime,
            sdk,
            debugger,
        ])
    }

    fn rust_required() -> Vec<String> {
        required_for("runtime.rust", "sdk.rust", "debugger.gdb-remote")
    }

    fn signed_evidence(capabilities: &[String]) -> ExecutorCapabilityEvidence {
        let mut evidence = ExecutorCapabilityEvidence {
            capabilities: capabilities.to_vec(),
            executor_id: "worker-a".to_owned(),
            expires_at: "2026-08-08T12:05:00.000Z".parse().unwrap(),
            format: ExecutorCapabilityEvidenceFormat::V1,
            issued_at: "2026-08-08T12:00:00.000Z".parse().unwrap(),
            locality: ExecutorLocality::ManagedWorker,
            organization_id: "org_01890f3e-7b1c-7cc0-8a1b-123456789abd".parse().unwrap(),
            platform_identity_digest: Digest::of(b"worker-a"),
            project_id: "prj_01890f3e-7b1c-7cc0-8a1b-123456789abe".parse().unwrap(),
            service_id: "svc_01890f3e-7b1c-7cc0-8a1b-123456789abf".parse().unwrap(),
            signature: String::new(),
            signer_key_id: "executor-test-key".to_owned(),
            status: ExecutorEvidenceStatus::Active,
        };
        evidence.signature = sign_bytes(
            &canonical::canonical_bytes(&evidence).unwrap(),
            &secret_key(SIGNING_SEED),
        );
        evidence
    }

    /// Evidence whose capability set is the required set plus extra host
    /// capabilities the subject never asked for. This models a real admitted
    /// worker: it supports more than any single capsule requires.
    fn evidence_supporting(required: &[String]) -> ExecutorCapabilityEvidence {
        let mut capabilities = required.to_vec();
        capabilities.push("translation.x86-on-arm".to_owned());
        capabilities.push("processor.feature.avx2".to_owned());
        capabilities.sort();
        signed_evidence(&capabilities)
    }

    fn debugger(protocol: DebuggerProtocol) -> DebuggerContract {
        let (debugger_id, readiness_rule) = match protocol {
            DebuggerProtocol::ChromeDevtools => {
                ("node-inspector", DebuggerReadinessRule::CdpWebsocketReady)
            }
            DebuggerProtocol::DebugAdapter => ("debugpy", DebuggerReadinessRule::DapInitialized),
            DebuggerProtocol::GdbRemoteSerial => {
                ("gdbserver", DebuggerReadinessRule::GdbServerListening)
            }
        };
        DebuggerContract {
            artifact_digest: Digest::of(debugger_id.as_bytes()),
            artifact_name: debugger_id.to_owned(),
            debugger_id: debugger_id.to_owned(),
            format: DebuggerContractFormat::V1,
            launch_arguments: vec!["--quiet".to_owned()],
            protocol,
            readiness_rule,
            source_mappings: Vec::new(),
            supported_architectures: vec![ProcessorArchitecture::X86_64],
            version: "1.0.0".to_owned(),
        }
    }

    #[test]
    fn a_complete_rust_capability_set_is_supported() {
        let required = rust_required();
        let evidence = evidence_supporting(&required);
        verify_replay_capabilities(
            &required,
            &evidence,
            &debugger(DebuggerProtocol::GdbRemoteSerial),
            NATIVE,
        )
        .unwrap();
    }

    #[test]
    fn the_exact_real_rust_capsule_capabilities_are_supported() {
        // The exact required set and evidence observed in the managed Rust
        // acceptance: identical 11 discrete capabilities, no processor bindings.
        let caps: Vec<String> = [
            "architecture.x86-64",
            "core.v1",
            "debugger.gdb-remote",
            "executor.linux-native",
            "operating-system.linux",
            "operation.request-response",
            "profile.backend",
            "runtime.rust-native",
            "sdk.rust",
            "transcript.http",
            "world.sqlite",
        ]
        .iter()
        .map(|value| (*value).to_owned())
        .collect();
        let evidence = signed_evidence(&caps);
        verify_replay_capabilities(
            &caps,
            &evidence,
            &debugger(DebuggerProtocol::GdbRemoteSerial),
            "architecture.x86-64",
        )
        .unwrap();
    }

    #[test]
    fn a_capsule_without_processor_bindings_is_supported() {
        // The real Rust support bundle declares no processor constraints, so the
        // sealed required set is exactly the discrete capabilities and the
        // worker evidence matches it. Processor bindings are optional.
        let required = sorted(&[
            NATIVE,
            "operating-system.linux",
            "executor.linux-native",
            "world.sqlite",
            "runtime.rust-native",
            "sdk.rust",
            "debugger.gdb-remote",
            "core.v1",
        ]);
        assert!(
            required
                .iter()
                .all(|value| !value.starts_with("processor."))
        );
        let evidence = signed_evidence(&required);
        verify_replay_capabilities(
            &required,
            &evidence,
            &debugger(DebuggerProtocol::GdbRemoteSerial),
            NATIVE,
        )
        .unwrap();
    }

    #[test]
    fn evidence_without_processor_bindings_still_accepts_a_processor_requirement() {
        // A real managed worker declares only its discrete capabilities. The
        // capsule's processor bindings are reduced against the executor at
        // admission and are not part of the evidence, so replay must still
        // succeed when the evidence omits every `processor.*` capability.
        let required = rust_required();
        let discrete: Vec<String> = required
            .iter()
            .filter(|value| !value.starts_with("processor."))
            .cloned()
            .collect();
        let evidence = signed_evidence(&discrete);
        assert!(
            evidence
                .capabilities
                .iter()
                .all(|value| !value.starts_with("processor."))
        );
        verify_replay_capabilities(
            &required,
            &evidence,
            &debugger(DebuggerProtocol::GdbRemoteSerial),
            NATIVE,
        )
        .unwrap();
    }

    #[test]
    fn a_required_processor_feature_must_exist_in_the_evidence() {
        // A capsule proved to require a processor feature must not replay on
        // a host whose evidence does not declare that feature.
        let mut required = rust_required();
        required.push("processor.feature.avx2".to_owned());
        required.sort();
        let discrete: Vec<String> = required
            .iter()
            .filter(|value| !value.starts_with("processor."))
            .cloned()
            .collect();
        let without_feature = signed_evidence(&discrete);
        assert!(
            verify_replay_capabilities(
                &required,
                &without_feature,
                &debugger(DebuggerProtocol::GdbRemoteSerial),
                NATIVE,
            )
            .is_err()
        );
        let mut with_feature = discrete;
        with_feature.push("processor.feature.avx2".to_owned());
        with_feature.sort();
        let with_feature = signed_evidence(&with_feature);
        verify_replay_capabilities(
            &required,
            &with_feature,
            &debugger(DebuggerProtocol::GdbRemoteSerial),
            NATIVE,
        )
        .unwrap();
    }

    #[test]
    fn a_malformed_processor_binding_is_rejected() {
        // The processor requirement must be a valid digest even though the
        // evidence does not declare it.
        let mut required = sorted(&[
            NATIVE,
            "operating-system.linux",
            "executor.linux-native",
            "world.sqlite",
            "processor.requirement.not-a-digest",
            "runtime.rust",
            "sdk.rust",
            "debugger.gdb-remote",
        ]);
        let discrete: Vec<String> = required
            .iter()
            .filter(|value| !value.starts_with("processor."))
            .cloned()
            .collect();
        let evidence = signed_evidence(&discrete);
        assert!(
            verify_replay_capabilities(
                &required,
                &evidence,
                &debugger(DebuggerProtocol::GdbRemoteSerial),
                NATIVE,
            )
            .is_err()
        );
        // A valid processor requirement with the same evidence is accepted.
        required = rust_required();
        verify_replay_capabilities(
            &required,
            &signed_evidence(&discrete),
            &debugger(DebuggerProtocol::GdbRemoteSerial),
            NATIVE,
        )
        .unwrap();
    }

    #[test]
    fn every_v1_sdk_and_debugger_capability_set_is_supported() {
        let matrix = [
            (
                "runtime.rust",
                "sdk.rust",
                DebuggerProtocol::GdbRemoteSerial,
            ),
            (
                "runtime.python",
                "sdk.python",
                DebuggerProtocol::DebugAdapter,
            ),
            ("runtime.go", "sdk.go", DebuggerProtocol::DebugAdapter),
            (
                "runtime.dotnet",
                "sdk.dotnet",
                DebuggerProtocol::DebugAdapter,
            ),
            ("runtime.node", "sdk.node", DebuggerProtocol::ChromeDevtools),
        ];
        for (runtime, sdk, protocol) in matrix {
            let required = required_for(runtime, sdk, debugger_protocol_capability(protocol));
            let evidence = evidence_supporting(&required);
            verify_replay_capabilities(&required, &evidence, &debugger(protocol), NATIVE)
                .unwrap_or_else(|_| panic!("{runtime} must be supported"));
        }
    }

    #[test]
    fn a_missing_required_capability_is_rejected() {
        let required = rust_required();
        // The host does not provide the World capability the capsule requires.
        let mut host = required.clone();
        host.retain(|value| value != "world.sqlite");
        let evidence = signed_evidence(&host);
        assert!(
            verify_replay_capabilities(
                &required,
                &evidence,
                &debugger(DebuggerProtocol::GdbRemoteSerial),
                NATIVE,
            )
            .is_err()
        );
    }

    #[test]
    fn a_wrong_architecture_is_rejected() {
        let required = required_for("runtime.rust", "sdk.rust", "debugger.gdb-remote");
        // The capsule was sealed for ARM64 but this host is x86-64.
        let arm_required = sorted(&[
            "architecture.arm64",
            "operating-system.linux",
            "executor.linux-native",
            "world.sqlite",
            &format!("processor.requirement.{DIGEST_SUFFIX}"),
            "runtime.rust",
            "sdk.rust",
            "debugger.gdb-remote",
        ]);
        let evidence = evidence_supporting(&arm_required);
        assert!(
            verify_replay_capabilities(
                &arm_required,
                &evidence,
                &debugger(DebuggerProtocol::GdbRemoteSerial),
                NATIVE,
            )
            .is_err()
        );
        // The matching x86-64 set on the same host is accepted.
        let evidence = evidence_supporting(&required);
        verify_replay_capabilities(
            &required,
            &evidence,
            &debugger(DebuggerProtocol::GdbRemoteSerial),
            NATIVE,
        )
        .unwrap();
    }

    #[test]
    fn a_wrong_operating_system_is_rejected() {
        let required = sorted(&[
            NATIVE,
            "operating-system.windows",
            "executor.linux-native",
            "world.sqlite",
            &format!("processor.requirement.{DIGEST_SUFFIX}"),
            "runtime.rust",
            "sdk.rust",
            "debugger.gdb-remote",
        ]);
        let evidence = evidence_supporting(&required);
        assert!(
            verify_replay_capabilities(
                &required,
                &evidence,
                &debugger(DebuggerProtocol::GdbRemoteSerial),
                NATIVE,
            )
            .is_err()
        );
    }

    #[test]
    fn a_wrong_debugger_protocol_is_rejected() {
        // The capsule names the gdb-remote protocol, but the requested debugger
        // speaks the debug-adapter protocol.
        let required = rust_required();
        let evidence = evidence_supporting(&required);
        assert!(
            verify_replay_capabilities(
                &required,
                &evidence,
                &debugger(DebuggerProtocol::DebugAdapter),
                NATIVE,
            )
            .is_err()
        );
    }

    #[test]
    fn an_unknown_capability_is_handled_by_the_subset_rule() {
        // An unknown capability the host provides never breaks a valid subset.
        let required = rust_required();
        let mut host = required.clone();
        host.push("experimental.time-travel".to_owned());
        host.sort();
        let evidence = signed_evidence(&host);
        verify_replay_capabilities(
            &required,
            &evidence,
            &debugger(DebuggerProtocol::GdbRemoteSerial),
            NATIVE,
        )
        .unwrap();

        // An unknown capability the capsule requires but the host lacks fails.
        let mut demanding = required.clone();
        demanding.push("experimental.time-travel".to_owned());
        demanding.sort();
        let evidence = evidence_supporting(&required);
        assert!(
            verify_replay_capabilities(
                &demanding,
                &evidence,
                &debugger(DebuggerProtocol::GdbRemoteSerial),
                NATIVE,
            )
            .is_err()
        );
    }

    #[test]
    fn duplicate_and_unsorted_required_capabilities_are_rejected() {
        let mut duplicated = rust_required();
        duplicated.push("world.sqlite".to_owned());
        let evidence = evidence_supporting(&duplicated);
        assert!(
            verify_replay_capabilities(
                &duplicated,
                &evidence,
                &debugger(DebuggerProtocol::GdbRemoteSerial),
                NATIVE,
            )
            .is_err()
        );

        let mut unsorted = rust_required();
        unsorted.reverse();
        assert!(
            verify_replay_capabilities(
                &unsorted,
                &evidence,
                &debugger(DebuggerProtocol::GdbRemoteSerial),
                NATIVE,
            )
            .is_err()
        );
    }

    #[test]
    fn subject_controlled_evidence_cannot_widen_capabilities() {
        // The capsule (subject-derived) requires the full Rust set, but the
        // authenticated host evidence supports only a subset. The subject cannot
        // widen the host's capabilities, so replay is refused.
        let required = rust_required();
        let mut narrow = required.clone();
        narrow.retain(|value| value != "sdk.rust");
        let evidence = signed_evidence(&narrow);
        assert!(
            verify_replay_capabilities(
                &required,
                &evidence,
                &debugger(DebuggerProtocol::GdbRemoteSerial),
                NATIVE,
            )
            .is_err()
        );
    }

    #[test]
    fn evidence_signature_and_scope_are_authenticated() {
        let required = rust_required();
        let evidence = evidence_supporting(&required);
        let public_key = verification_key(&secret_key(SIGNING_SEED));
        verify_evidence_signature(&evidence, &public_key).unwrap();

        // A different verifying key rejects the same evidence bytes.
        let wrong_key = verification_key(&secret_key([9_u8; 32]));
        assert!(verify_evidence_signature(&evidence, &wrong_key).is_err());

        // Evidence bound to another organization does not match the scope, even
        // with a valid signature. This is how a mismatched grant or worker
        // identity is refused.
        let now: Timestamp = "2026-08-08T12:01:00.000Z".parse().unwrap();
        let scope = ExecutorEvidenceScope {
            organization_id: "org_01890f3e-7b1c-7cc0-8a1b-1234567890ff".parse().unwrap(),
            project_id: "prj_01890f3e-7b1c-7cc0-8a1b-123456789abe".parse().unwrap(),
            service_id: "svc_01890f3e-7b1c-7cc0-8a1b-123456789abf".parse().unwrap(),
        };
        assert!(verify_executor_capability_evidence(&evidence, &scope, &now, &public_key).is_err());
    }

    #[test]
    fn required_capabilities_present_is_a_bounded_subset_rule() {
        let required = vec!["a".to_owned(), "b".to_owned()];
        let provided = vec!["a".to_owned(), "b".to_owned(), "c".to_owned()];
        assert!(required_capabilities_present(&required, &provided));
        assert!(!required_capabilities_present(
            &["a".to_owned(), "z".to_owned()],
            &provided
        ));
        // An over-length input fails closed rather than scanning unbounded data.
        let oversized: Vec<String> = (0..=MAX_REQUIRED_CAPABILITIES)
            .map(|index| index.to_string())
            .collect();
        assert!(!required_capabilities_present(&oversized, &provided));
    }
}

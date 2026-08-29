use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    Error, canonical,
    crypto::{decode_base64url, verify_signed_value},
    identity::{Digest, FuzzCampaignId, FuzzCaseId, ProjectId, ServiceId, Timestamp},
};

use super::Validate;

const MAX_CASES: u64 = 1_000_000;
const MAX_CASE_SECONDS: u64 = 3_600;
const MAX_CONCURRENCY: u16 = 1_024;
const MAX_ACTIONS_PER_CASE: u16 = 4_096;
const MAX_ACTIONS_PER_SECOND: u16 = 10_000;
const MAX_PAYLOAD_BYTES: u64 = 8_388_608;
const MAX_TOTAL_BYTES: u64 = 1_099_511_627_776;
const MAX_ACTION_DURATION_MS: u64 = 3_600_000;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum FuzzCampaignFormat {
    #[serde(rename = "reproit.fuzz-campaign.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FuzzCampaignLimits {
    pub max_actions_per_case: u16,
    pub max_actions_per_second: u16,
    pub max_case_seconds: u64,
    pub max_cases: u64,
    pub max_concurrency: u16,
    pub max_payload_bytes: u64,
    pub max_total_bytes: u64,
}

impl Validate for FuzzCampaignLimits {
    fn validate(&self) -> Result<(), Error> {
        if !(1..=MAX_ACTIONS_PER_CASE).contains(&self.max_actions_per_case)
            || !(1..=MAX_ACTIONS_PER_SECOND).contains(&self.max_actions_per_second)
            || !(1..=MAX_CASE_SECONDS).contains(&self.max_case_seconds)
            || !(1..=MAX_CASES).contains(&self.max_cases)
            || !(1..=MAX_CONCURRENCY).contains(&self.max_concurrency)
            || !(1..=MAX_PAYLOAD_BYTES).contains(&self.max_payload_bytes)
            || !(1..=MAX_TOTAL_BYTES).contains(&self.max_total_bytes)
            || self.max_payload_bytes > self.max_total_bytes
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FuzzCampaign {
    pub adapter: String,
    pub campaign_id: FuzzCampaignId,
    pub fault_policy_digest: Digest,
    pub format: FuzzCampaignFormat,
    pub limits: FuzzCampaignLimits,
    pub name: String,
    pub oracle_digest: Digest,
    pub project_id: ProjectId,
    pub seed_world_digest: Digest,
    pub service_id: ServiceId,
    pub workload_digest: Digest,
}

impl Validate for FuzzCampaign {
    fn validate(&self) -> Result<(), Error> {
        self.limits.validate()?;
        if !valid_component(&self.adapter) || !valid_name(&self.name) {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum FuzzCasePlanFormat {
    #[serde(rename = "reproit.fuzz-case.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum FuzzAction {
    SendHttp {
        body_digest: Digest,
        method: String,
        path: String,
        sequence: u16,
        target: String,
    },
    SendQueue {
        payload_digest: Digest,
        queue: String,
        sequence: u16,
        target: String,
    },
    HttpDelay {
        delay_ms: u64,
        sequence: u16,
        target: String,
    },
    HttpDrop {
        sequence: u16,
        target: String,
    },
    HttpDuplicate {
        count: u16,
        sequence: u16,
        target: String,
    },
    HttpError {
        sequence: u16,
        status: u16,
        target: String,
    },
    QueueDrop {
        queue: String,
        sequence: u16,
        target: String,
    },
    QueueDuplicate {
        count: u16,
        queue: String,
        sequence: u16,
        target: String,
    },
    ProcessPause {
        duration_ms: u64,
        sequence: u16,
        target: String,
    },
    ProcessResume {
        sequence: u16,
        target: String,
    },
    ProcessRestart {
        sequence: u16,
        target: String,
    },
    ProcessTerminate {
        sequence: u16,
        target: String,
    },
}

impl FuzzAction {
    pub const fn sequence(&self) -> u16 {
        match self {
            Self::SendHttp { sequence, .. }
            | Self::SendQueue { sequence, .. }
            | Self::HttpDelay { sequence, .. }
            | Self::HttpDrop { sequence, .. }
            | Self::HttpDuplicate { sequence, .. }
            | Self::HttpError { sequence, .. }
            | Self::QueueDrop { sequence, .. }
            | Self::QueueDuplicate { sequence, .. }
            | Self::ProcessPause { sequence, .. }
            | Self::ProcessResume { sequence, .. }
            | Self::ProcessRestart { sequence, .. }
            | Self::ProcessTerminate { sequence, .. } => *sequence,
        }
    }

    pub fn target(&self) -> &str {
        match self {
            Self::SendHttp { target, .. }
            | Self::SendQueue { target, .. }
            | Self::HttpDelay { target, .. }
            | Self::HttpDrop { target, .. }
            | Self::HttpDuplicate { target, .. }
            | Self::HttpError { target, .. }
            | Self::QueueDrop { target, .. }
            | Self::QueueDuplicate { target, .. }
            | Self::ProcessPause { target, .. }
            | Self::ProcessResume { target, .. }
            | Self::ProcessRestart { target, .. }
            | Self::ProcessTerminate { target, .. } => target,
        }
    }

    fn validate(&self) -> Result<(), Error> {
        if !valid_component(self.target()) {
            return Err(Error::schema_invalid());
        }
        match self {
            Self::SendHttp { method, path, .. } => {
                if !valid_http_method(method) || !valid_relative_http_path(path) {
                    return Err(Error::schema_invalid());
                }
            }
            Self::SendQueue { queue, .. } | Self::QueueDrop { queue, .. } => {
                if !valid_component(queue) {
                    return Err(Error::schema_invalid());
                }
            }
            Self::HttpDelay { delay_ms, .. }
            | Self::ProcessPause {
                duration_ms: delay_ms,
                ..
            } => {
                if !(1..=MAX_ACTION_DURATION_MS).contains(delay_ms) {
                    return Err(Error::schema_invalid());
                }
            }
            Self::HttpDuplicate { count, .. } => {
                if !(2..=16).contains(count) {
                    return Err(Error::schema_invalid());
                }
            }
            Self::QueueDuplicate { count, queue, .. } => {
                if !(2..=16).contains(count) || !valid_component(queue) {
                    return Err(Error::schema_invalid());
                }
            }
            Self::HttpError { status, .. } => {
                if !(400..=599).contains(status) {
                    return Err(Error::schema_invalid());
                }
            }
            Self::HttpDrop { .. }
            | Self::ProcessResume { .. }
            | Self::ProcessRestart { .. }
            | Self::ProcessTerminate { .. } => {}
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FuzzCasePlan {
    pub actions: Vec<FuzzAction>,
    pub algorithm_version: u16,
    pub campaign_id: FuzzCampaignId,
    pub case_id: FuzzCaseId,
    pub format: FuzzCasePlanFormat,
    pub plan_digest: Digest,
    pub seed: u64,
    pub world_digest: Digest,
}

impl Validate for FuzzCasePlan {
    fn validate(&self) -> Result<(), Error> {
        if self.algorithm_version == 0
            || self.actions.is_empty()
            || self.actions.len() > usize::from(MAX_ACTIONS_PER_CASE)
            || self.seed > 9_007_199_254_740_991
        {
            return Err(Error::schema_invalid());
        }
        let mut targets = BTreeSet::new();
        for (index, action) in self.actions.iter().enumerate() {
            action.validate()?;
            if usize::from(action.sequence()) != index {
                return Err(Error::schema_invalid());
            }
            targets.insert(action.target());
        }
        if fuzz_plan_digest(self)? != self.plan_digest {
            return Err(Error::object_digest_mismatch());
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct FuzzPlanDigestMaterial<'a> {
    actions: &'a [FuzzAction],
    algorithm_version: u16,
    campaign_id: FuzzCampaignId,
    case_id: FuzzCaseId,
    format: FuzzCasePlanFormat,
    seed: u64,
    world_digest: Digest,
}

pub fn fuzz_plan_digest(plan: &FuzzCasePlan) -> Result<Digest, Error> {
    canonical::digest(&FuzzPlanDigestMaterial {
        actions: &plan.actions,
        algorithm_version: plan.algorithm_version,
        campaign_id: plan.campaign_id,
        case_id: plan.case_id,
        format: plan.format,
        seed: plan.seed,
        world_digest: plan.world_digest,
    })
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum FuzzContextFormat {
    #[serde(rename = "reproit.fuzz-context.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FuzzContext {
    pub campaign_id: FuzzCampaignId,
    pub case_id: FuzzCaseId,
    pub expires_at: Timestamp,
    pub format: FuzzContextFormat,
    pub project_id: ProjectId,
    pub service_id: ServiceId,
    pub signature: String,
}

impl Validate for FuzzContext {
    fn validate(&self) -> Result<(), Error> {
        if self.signature.len() != 86 {
            return Err(Error::schema_invalid());
        }
        decode_base64url::<64>(&self.signature)?;
        Ok(())
    }
}

pub fn fuzz_context_digest(context: &FuzzContext) -> Result<Digest, Error> {
    context.validate()?;
    canonical::digest(context)
}

pub fn verify_fuzz_context(
    context: &FuzzContext,
    verification_key: &[u8; 32],
    project_id: ProjectId,
    service_id: ServiceId,
    now: &Timestamp,
) -> Result<(), Error> {
    context.validate()?;
    if context.project_id != project_id
        || context.service_id != service_id
        || context.expires_at.as_str() <= now.as_str()
    {
        return Err(Error::schema_invalid());
    }
    verify_signed_value(
        &serde_json::to_value(context).map_err(|_| Error::schema_invalid())?,
        verification_key,
    )
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FuzzContextIdentity {
    pub campaign_id: FuzzCampaignId,
    pub case_id: FuzzCaseId,
    pub context_digest: Digest,
}

impl FuzzContextIdentity {
    pub fn matches(&self, context: &FuzzContext) -> Result<(), Error> {
        if self.campaign_id != context.campaign_id
            || self.case_id != context.case_id
            || self.context_digest != fuzz_context_digest(context)?
        {
            return Err(Error::object_digest_mismatch());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiscoverySource {
    Production,
    FuzzCampaign,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum FuzzResultFormat {
    #[serde(rename = "reproit.fuzz-result.v1")]
    V1,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FuzzOutcome {
    Passed,
    Found,
    Unstable,
    Incomplete,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FuzzCleanup {
    Complete,
    Incomplete,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum FuzzSignal {
    ProcessFailure { service: String },
    RequestTimeout { service: String },
    HttpStatus { service: String, status: u16 },
    InvalidHttpResponse { service: String },
    DuplicateSideEffect { service: String, signal: String },
    Invariant { service: String, signal: String },
}

impl FuzzSignal {
    fn validate(&self) -> Result<(), Error> {
        let (service, signal) = match self {
            Self::ProcessFailure { service }
            | Self::RequestTimeout { service }
            | Self::InvalidHttpResponse { service } => (service, None),
            Self::HttpStatus { service, status } => {
                if !(100..=599).contains(status) {
                    return Err(Error::schema_invalid());
                }
                (service, None)
            }
            Self::DuplicateSideEffect { service, signal } | Self::Invariant { service, signal } => {
                (service, Some(signal))
            }
        };
        if !valid_component(service)
            || signal.is_some_and(|value| value.is_empty() || value.len() > 128)
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FuzzCaseResult {
    pub campaign_id: FuzzCampaignId,
    pub capture_ids: Vec<crate::identity::CaptureId>,
    pub case_id: FuzzCaseId,
    pub cleanup: FuzzCleanup,
    pub format: FuzzResultFormat,
    pub outcome: FuzzOutcome,
    pub plan_digest: Digest,
    pub root_service: Option<String>,
    pub signals: Vec<FuzzSignal>,
}

impl Validate for FuzzCaseResult {
    fn validate(&self) -> Result<(), Error> {
        if self.capture_ids.len() > 256
            || self.signals.len() > usize::from(MAX_ACTIONS_PER_CASE)
            || self
                .root_service
                .as_ref()
                .is_some_and(|service| !valid_component(service))
            || (self.outcome == FuzzOutcome::Found
                && (self.root_service.is_none() || self.signals.is_empty()))
            || (self.outcome == FuzzOutcome::Passed
                && (self.root_service.is_some() || !self.signals.is_empty()))
        {
            return Err(Error::schema_invalid());
        }
        for signal in &self.signals {
            signal.validate()?;
        }
        let unique_capture_ids = self.capture_ids.iter().collect::<BTreeSet<_>>();
        if unique_capture_ids.len() != self.capture_ids.len() {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FuzzCampaignState {
    Created,
    Running,
    Stopping,
    Complete,
    Cancelled,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FuzzCaseState {
    Scheduled,
    Running,
    Complete,
    Found,
    Verifying,
    Verified,
    Unstable,
    Incomplete,
}

fn valid_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_lowercase()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn valid_http_method(value: &str) -> bool {
    matches!(value, "DELETE" | "GET" | "HEAD" | "PATCH" | "POST" | "PUT")
}

fn valid_relative_http_path(value: &str) -> bool {
    value.starts_with('/')
        && value.len() <= 2_048
        && !value.contains("//")
        && !value.split('/').any(|part| part == "..")
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

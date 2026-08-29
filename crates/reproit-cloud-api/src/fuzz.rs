use std::collections::BTreeSet;

use reproit_core::{
    Error,
    identity::{CaptureId, Digest, FuzzCampaignId, FuzzCaseId, ProjectId, ServiceId, Timestamp},
    model::{FuzzCampaignLimits, FuzzCampaignState, FuzzCaseResult, FuzzCaseState, Validate},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum FuzzCampaignCreateFormat {
    #[serde(rename = "reproit.fuzz-campaign-create.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FuzzCampaignCreate {
    pub adapter: String,
    pub fault_policy_digest: Digest,
    pub format: FuzzCampaignCreateFormat,
    pub limits: FuzzCampaignLimits,
    pub name: String,
    pub oracle_digest: Digest,
    pub project_id: ProjectId,
    pub seed_world_digest: Digest,
    pub service_id: ServiceId,
    pub workload_digest: Digest,
}

impl Validate for FuzzCampaignCreate {
    fn validate(&self) -> Result<(), Error> {
        self.limits.validate()?;
        if !valid_component(&self.adapter) || !valid_name(&self.name) {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum FuzzCampaignGrantFormat {
    #[serde(rename = "reproit.fuzz-campaign-grant.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FuzzCampaignGrant {
    pub campaign_id: FuzzCampaignId,
    pub expires_at: Timestamp,
    pub format: FuzzCampaignGrantFormat,
    pub grant: String,
    pub project_id: ProjectId,
    pub service_id: ServiceId,
}

impl Validate for FuzzCampaignGrant {
    fn validate(&self) -> Result<(), Error> {
        if self.grant.len() != 43
            || self
                .grant
                .bytes()
                .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')))
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FuzzCampaignCreated {
    pub accepted_limits: FuzzCampaignLimits,
    pub campaign_digest: Digest,
    pub campaign_grant: FuzzCampaignGrant,
    pub campaign_id: FuzzCampaignId,
    pub state: FuzzCampaignState,
}

impl Validate for FuzzCampaignCreated {
    fn validate(&self) -> Result<(), Error> {
        self.accepted_limits.validate()?;
        self.campaign_grant.validate()?;
        if self.campaign_id != self.campaign_grant.campaign_id
            || self.state != FuzzCampaignState::Created
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FuzzCampaignStatus {
    pub campaign_digest: Digest,
    pub campaign_id: FuzzCampaignId,
    pub cases_found: u64,
    pub cases_scheduled: u64,
    pub cases_verified: u64,
    pub created_at: Timestamp,
    pub project_id: ProjectId,
    pub service_id: ServiceId,
    pub state: FuzzCampaignState,
    pub updated_at: Timestamp,
}

impl Validate for FuzzCampaignStatus {
    fn validate(&self) -> Result<(), Error> {
        if self.cases_found > self.cases_scheduled
            || self.cases_verified > self.cases_found
            || self.updated_at < self.created_at
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FuzzCaseAccepted {
    pub campaign_id: FuzzCampaignId,
    pub case_id: FuzzCaseId,
    pub state: FuzzCaseState,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FuzzRelatedCapture {
    pub capture_id: CaptureId,
    pub case_id: FuzzCaseId,
    pub parent_capture_id: Option<CaptureId>,
    pub service_id: ServiceId,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FuzzCaseDetail {
    pub campaign_id: FuzzCampaignId,
    pub case_id: FuzzCaseId,
    pub captures: Vec<FuzzRelatedCapture>,
    pub result: FuzzCaseResult,
    pub state: FuzzCaseState,
}

impl Validate for FuzzCaseDetail {
    fn validate(&self) -> Result<(), Error> {
        self.result.validate()?;
        if self.campaign_id != self.result.campaign_id
            || self.case_id != self.result.case_id
            || self.captures.len() > 256
            || self
                .captures
                .iter()
                .any(|capture| capture.case_id != self.case_id)
        {
            return Err(Error::schema_invalid());
        }
        let capture_ids = self
            .captures
            .iter()
            .map(|capture| capture.capture_id)
            .collect::<BTreeSet<_>>();
        if capture_ids.len() != self.captures.len() {
            return Err(Error::schema_invalid());
        }
        if self.captures.iter().any(|capture| {
            capture.parent_capture_id.is_some_and(|parent| {
                parent == capture.capture_id || !capture_ids.contains(&parent)
            })
        }) {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
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

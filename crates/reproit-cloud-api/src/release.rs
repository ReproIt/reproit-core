use std::{fmt, str::FromStr};

use reproit_core::{
    Error,
    identity::{Digest, OrganizationId, ProjectId, ServiceId, Timestamp},
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use uuid::Uuid;

const MIN_IDEMPOTENCY_KEY_BYTES: usize = 16;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ReleaseJobId(Uuid);

impl ReleaseJobId {
    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }

    pub const fn uuid_bytes(&self) -> [u8; 16] {
        *self.0.as_bytes()
    }
}

impl fmt::Debug for ReleaseJobId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for ReleaseJobId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "rev_{}", self.0)
    }
}

impl FromStr for ReleaseJobId {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let uuid_text = value
            .strip_prefix("rev_")
            .ok_or_else(Error::schema_invalid)?;
        let uuid = Uuid::parse_str(uuid_text).map_err(|_| Error::schema_invalid())?;
        if uuid.get_version_num() != 7 || uuid.to_string() != uuid_text {
            return Err(Error::schema_invalid());
        }
        Ok(Self(uuid))
    }
}

impl Serialize for ReleaseJobId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ReleaseJobId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReleaseJobState {
    AwaitingConfirmation,
    Confirming,
    Complete,
    Failed,
    Expired,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReleaseDecision {
    Pass,
    Regression,
    Unknown,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseEvidenceMetadata {
    pub environment_digest: Digest,
    pub evidence_digest: Digest,
    pub runner_digest: Digest,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseJobCreateRequest {
    pub baseline_artifact_digest: Digest,
    pub candidate_artifact_digest: Digest,
    pub dataset_digest: Digest,
    pub evaluator_digest: Digest,
    pub idempotency_key: String,
    pub organization_id: OrganizationId,
    pub primary_evidence: ReleaseEvidenceMetadata,
    pub project_id: ProjectId,
    pub service_id: ServiceId,
}

impl ReleaseJobCreateRequest {
    pub fn validate(&self) -> Result<(), Error> {
        validate_idempotency_key(&self.idempotency_key)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseJobCreateResult {
    pub created_at: Timestamp,
    pub release_job_id: ReleaseJobId,
    pub state: ReleaseJobState,
}

impl ReleaseJobCreateResult {
    pub fn validate(&self) -> Result<(), Error> {
        if self.state != ReleaseJobState::AwaitingConfirmation {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseJobStatusResponse {
    pub created_at: Timestamp,
    pub decision: Option<ReleaseDecision>,
    pub release_job_id: ReleaseJobId,
    pub state: ReleaseJobState,
    pub updated_at: Timestamp,
}

impl ReleaseJobStatusResponse {
    pub fn validate(&self) -> Result<(), Error> {
        validate_status(
            self.state,
            self.decision,
            &self.created_at,
            &self.updated_at,
        )
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseJobDetailResponse {
    pub baseline_artifact_digest: Digest,
    pub candidate_artifact_digest: Digest,
    pub confirmation_evidence: Option<ReleaseEvidenceMetadata>,
    pub created_at: Timestamp,
    pub dataset_digest: Digest,
    pub decision: Option<ReleaseDecision>,
    pub evaluator_digest: Digest,
    pub organization_id: OrganizationId,
    pub primary_evidence: ReleaseEvidenceMetadata,
    pub project_id: ProjectId,
    pub release_job_id: ReleaseJobId,
    pub service_id: ServiceId,
    pub state: ReleaseJobState,
    pub updated_at: Timestamp,
}

impl ReleaseJobDetailResponse {
    pub fn validate(&self) -> Result<(), Error> {
        validate_status(
            self.state,
            self.decision,
            &self.created_at,
            &self.updated_at,
        )?;
        match (self.state, self.confirmation_evidence.as_ref()) {
            (ReleaseJobState::Complete, Some(confirmation)) => {
                if confirmation.runner_digest == self.primary_evidence.runner_digest
                    || confirmation.evidence_digest == self.primary_evidence.evidence_digest
                    || confirmation.environment_digest != self.primary_evidence.environment_digest
                {
                    return Err(Error::schema_invalid());
                }
            }
            (ReleaseJobState::Complete, None) | (_, Some(_)) => return Err(Error::schema_invalid()),
            _ => {}
        }
        Ok(())
    }
}

fn validate_idempotency_key(value: &str) -> Result<(), Error> {
    if !(MIN_IDEMPOTENCY_KEY_BYTES..=MAX_IDEMPOTENCY_KEY_BYTES).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte == b' ' || byte.is_ascii_graphic())
    {
        return Err(Error::schema_invalid());
    }
    Ok(())
}

fn validate_status(
    state: ReleaseJobState,
    decision: Option<ReleaseDecision>,
    created_at: &Timestamp,
    updated_at: &Timestamp,
) -> Result<(), Error> {
    if created_at.as_str() > updated_at.as_str()
        || matches!(state, ReleaseJobState::Complete) != decision.is_some()
    {
        return Err(Error::schema_invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        ReleaseDecision, ReleaseJobCreateRequest, ReleaseJobDetailResponse, ReleaseJobId,
        ReleaseJobState, ReleaseJobStatusResponse,
    };
    use reproit_core::{ErrorCode, canonical};
    use serde_json::json;

    const UUID_V7: &str = "01890f3e-7b1c-7cc0-8a1b-123456789abd";
    const DIGEST_A: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DIGEST_B: &str =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn release_job_id_requires_the_canonical_prefix_and_uuid_v7() {
        let id: ReleaseJobId = format!("rev_{UUID_V7}").parse().unwrap();
        assert_eq!(id.to_string(), format!("rev_{UUID_V7}"));
        for invalid in [
            UUID_V7,
            "rev_01890F3E-7B1C-7CC0-8A1B-123456789ABD",
            "rev_01890f3e-7b1c-6cc0-8a1b-123456789abd",
        ] {
            assert_eq!(
                invalid.parse::<ReleaseJobId>().unwrap_err().code,
                ErrorCode::SchemaInvalid,
            );
        }
    }

    #[test]
    fn release_decisions_have_explicit_wire_values() {
        for (decision, expected) in [
            (ReleaseDecision::Pass, "\"PASS\""),
            (ReleaseDecision::Regression, "\"REGRESSION\""),
            (ReleaseDecision::Unknown, "\"UNKNOWN\""),
        ] {
            assert_eq!(serde_json::to_string(&decision).unwrap(), expected);
        }
    }

    #[test]
    fn create_request_rejects_idempotency_key_bounds_and_controls() {
        let request = create_request(json!("0123456789abcdef"));
        request.validate().unwrap();

        for value in [
            json!("0123456789abcde"),
            json!("x".repeat(257)),
            json!("key\nwith-control12"),
            json!("unicode-key-value-é"),
        ] {
            let request = create_request(value);
            assert_eq!(
                request.validate().unwrap_err().code,
                ErrorCode::SchemaInvalid,
            );
        }
    }

    #[test]
    fn detail_requires_a_decision_and_distinct_confirmation_when_complete() {
        let mut value = detail_value();
        let detail: ReleaseJobDetailResponse =
            canonical::parse_strict(&serde_json::to_vec(&value).unwrap()).unwrap();
        detail.validate().unwrap();

        value["decision"] = json!(null);
        let detail: ReleaseJobDetailResponse =
            canonical::parse_strict(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(
            detail.validate().unwrap_err().code,
            ErrorCode::SchemaInvalid,
        );

        value["decision"] = json!("PASS");
        value["confirmation_evidence"]["runner_digest"] = json!(DIGEST_A);
        let detail: ReleaseJobDetailResponse =
            canonical::parse_strict(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(
            detail.validate().unwrap_err().code,
            ErrorCode::SchemaInvalid,
        );

        value["confirmation_evidence"]["runner_digest"] = json!(DIGEST_B);
        value["confirmation_evidence"]["environment_digest"] = json!(DIGEST_B);
        let detail: ReleaseJobDetailResponse =
            canonical::parse_strict(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(
            detail.validate().unwrap_err().code,
            ErrorCode::SchemaInvalid,
        );
    }

    #[test]
    fn noncomplete_status_rejects_a_release_decision() {
        let mut value = detail_value();
        value["state"] = json!("FAILED");
        value["confirmation_evidence"] = json!(null);
        let detail: ReleaseJobDetailResponse =
            canonical::parse_strict(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(
            detail.validate().unwrap_err().code,
            ErrorCode::SchemaInvalid,
        );
    }

    #[test]
    fn status_rejects_an_update_before_creation() {
        let value = json!({
            "created_at": "2026-01-01T00:00:01.000Z",
            "decision": null,
            "release_job_id": format!("rev_{UUID_V7}"),
            "state": "CONFIRMING",
            "updated_at": "2026-01-01T00:00:00.000Z"
        });
        let status: ReleaseJobStatusResponse =
            canonical::parse_strict(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(
            status.validate().unwrap_err().code,
            ErrorCode::SchemaInvalid,
        );
    }

    #[test]
    fn strict_parser_rejects_unknown_release_fields() {
        let mut value = detail_value();
        value["raw_evidence"] = json!("must-not-cross-this-boundary");
        assert_eq!(
            canonical::parse_strict::<ReleaseJobDetailResponse>(
                &serde_json::to_vec(&value).unwrap()
            )
            .unwrap_err()
            .code,
            ErrorCode::SchemaInvalid,
        );
    }

    fn create_request(idempotency_key: serde_json::Value) -> ReleaseJobCreateRequest {
        let mut value = create_request_value();
        value["idempotency_key"] = idempotency_key;
        canonical::parse_strict(&serde_json::to_vec(&value).unwrap()).unwrap()
    }

    fn create_request_value() -> serde_json::Value {
        json!({
            "baseline_artifact_digest": DIGEST_A,
            "candidate_artifact_digest": DIGEST_B,
            "dataset_digest": DIGEST_A,
            "evaluator_digest": DIGEST_B,
            "idempotency_key": "0123456789abcdef",
            "organization_id": "org_01890f3e-7b1c-7cc0-8a1b-123456789abc",
            "primary_evidence": {
                "environment_digest": DIGEST_A,
                "evidence_digest": DIGEST_B,
                "runner_digest": DIGEST_A
            },
            "project_id": "prj_01890f3e-7b1c-7cc0-8a1b-123456789ac0",
            "service_id": "svc_01890f3e-7b1c-7cc0-8a1b-123456789ac1"
        })
    }

    fn detail_value() -> serde_json::Value {
        let mut value = create_request_value();
        value.as_object_mut().unwrap().remove("idempotency_key");
        value["confirmation_evidence"] = json!({
            "environment_digest": DIGEST_A,
            "evidence_digest": DIGEST_A,
            "runner_digest": DIGEST_B
        });
        value["created_at"] = json!("2026-01-01T00:00:00.000Z");
        value["decision"] = json!("PASS");
        value["release_job_id"] = json!(format!("rev_{UUID_V7}"));
        value["state"] = json!("COMPLETE");
        value["updated_at"] = json!("2026-01-01T00:01:00.000Z");
        value
    }

    #[test]
    fn initial_state_has_no_decision_or_confirmation() {
        let mut value = detail_value();
        value["state"] = json!("AWAITING_CONFIRMATION");
        value["decision"] = json!(null);
        value["confirmation_evidence"] = json!(null);
        let detail: ReleaseJobDetailResponse =
            canonical::parse_strict(&serde_json::to_vec(&value).unwrap()).unwrap();
        detail.validate().unwrap();
        assert_eq!(detail.state, ReleaseJobState::AwaitingConfirmation);
    }
}

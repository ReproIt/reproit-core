use serde::{Deserialize, Serialize};

use super::Validate;
use crate::{
    Error, ErrorCode,
    identity::{Digest, ExecutionId},
};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum ExecutionResultFormat {
    #[serde(rename = "reproit.execution-result.v1")]
    V1,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum ExecutionOutcome {
    #[serde(rename = "DIFFERENT_FAILURE")]
    DifferentFailure,
    #[serde(rename = "EVALUATION_ERROR")]
    EvaluationError,
    #[serde(rename = "TARGET_ABSENT")]
    TargetAbsent,
    #[serde(rename = "TARGET_REPRODUCED")]
    TargetReproduced,
    #[serde(rename = "UNSUPPORTED")]
    Unsupported,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionResult {
    pub cleanup_complete: bool,
    pub closure_manifest_digest: Digest,
    pub error: Option<Error>,
    pub execution_id: ExecutionId,
    pub failure_digest: Option<Digest>,
    pub format: ExecutionResultFormat,
    pub result: ExecutionOutcome,
}

impl Validate for ExecutionResult {
    fn validate(&self) -> Result<(), Error> {
        match self.result {
            ExecutionOutcome::TargetReproduced | ExecutionOutcome::DifferentFailure
                if self.cleanup_complete
                    && self.error.is_none()
                    && self.failure_digest.is_some() =>
            {
                Ok(())
            }
            ExecutionOutcome::TargetAbsent
                if self.cleanup_complete
                    && self.error.is_none()
                    && self.failure_digest.is_none() =>
            {
                Ok(())
            }
            ExecutionOutcome::Unsupported
                if self.cleanup_complete
                    && self.failure_digest.is_none()
                    && self.error.as_ref().is_some_and(|error| {
                        matches!(
                            error.code,
                            ErrorCode::Unsupported | ErrorCode::UnsupportedCapabilitySet
                        )
                    }) =>
            {
                Ok(())
            }
            ExecutionOutcome::EvaluationError
                if self.error.is_some() && self.failure_digest.is_none() =>
            {
                Ok(())
            }
            _ => Err(Error::schema_invalid()),
        }
    }
}

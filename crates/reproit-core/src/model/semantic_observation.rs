use serde::{Deserialize, Serialize};

use crate::{
    Error, canonical,
    crypto::{decode_base64url_bytes, encode_base64url},
    identity::Digest,
};

use super::Validate;

pub const MAX_SEMANTIC_OBSERVATION_TARGET_BYTES: usize = 16 * 1_024;
pub const MAX_SEMANTIC_OBSERVATION_VALUE_BYTES: usize = 32 * 1_024;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum SemanticObservationRequestFormat {
    #[serde(rename = "reproit.semantic-observation-request.v1")]
    V1,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SemanticObservationOperation {
    ClockWallTime,
    EnvironmentRead,
    FilesystemRead,
    RandomBytes,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticObservationRequest {
    pub format: SemanticObservationRequestFormat,
    pub length: Option<u64>,
    pub offset: Option<u64>,
    pub operation: SemanticObservationOperation,
    pub target: Option<String>,
}

impl Validate for SemanticObservationRequest {
    fn validate(&self) -> Result<(), Error> {
        match self.operation {
            SemanticObservationOperation::ClockWallTime => {
                require_none(self.target.as_ref(), self.offset, self.length)
            }
            SemanticObservationOperation::EnvironmentRead => {
                validate_target(self.target.as_deref())?;
                require_none(None, self.offset, self.length)
            }
            SemanticObservationOperation::FilesystemRead => {
                validate_target(self.target.as_deref())?;
                if self.offset.is_none() || !valid_length(self.length) {
                    return Err(Error::schema_invalid());
                }
                Ok(())
            }
            SemanticObservationOperation::RandomBytes => {
                if self.target.is_some() || self.offset.is_some() || !valid_length(self.length) {
                    return Err(Error::schema_invalid());
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum SemanticObservationResponseFormat {
    #[serde(rename = "reproit.semantic-observation-response.v1")]
    V1,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SemanticObservationOutcome {
    Error,
    Response,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SemanticObservationErrorCode {
    Interrupted,
    InvalidInput,
    NotFound,
    Other,
    PermissionDenied,
    ResourceLimit,
    Unsupported,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticObservationResponse {
    pub error_code: Option<SemanticObservationErrorCode>,
    pub error_number: Option<u32>,
    pub format: SemanticObservationResponseFormat,
    pub operation: SemanticObservationOperation,
    pub outcome: SemanticObservationOutcome,
    pub request_digest: Digest,
    pub value: Option<String>,
}

impl Validate for SemanticObservationResponse {
    fn validate(&self) -> Result<(), Error> {
        match self.outcome {
            SemanticObservationOutcome::Error => {
                if self.error_code.is_none() || self.value.is_some() {
                    return Err(Error::schema_invalid());
                }
                Ok(())
            }
            SemanticObservationOutcome::Response => {
                if self.error_code.is_some() || self.error_number.is_some() {
                    return Err(Error::schema_invalid());
                }
                validate_response_value(self.operation, self.value.as_deref())
            }
        }
    }
}

pub fn validate_semantic_observation_pair(
    request: &SemanticObservationRequest,
    response: &SemanticObservationResponse,
) -> Result<(), Error> {
    request.validate()?;
    response.validate()?;
    if response.operation != request.operation
        || response.request_digest != canonical::digest(request)?
    {
        return Err(Error::schema_invalid());
    }
    if response.outcome == SemanticObservationOutcome::Response
        && matches!(
            request.operation,
            SemanticObservationOperation::FilesystemRead
                | SemanticObservationOperation::RandomBytes
        )
    {
        let value = response
            .value
            .as_deref()
            .ok_or_else(Error::schema_invalid)?;
        let bytes = decode_base64url_bytes(value)?;
        if bytes.len() > usize::try_from(request.length.unwrap_or_default()).unwrap_or(usize::MAX) {
            return Err(Error::schema_invalid());
        }
        if request.operation == SemanticObservationOperation::RandomBytes
            && bytes.len() != usize::try_from(request.length.unwrap_or_default()).unwrap_or(0)
        {
            return Err(Error::schema_invalid());
        }
    }
    Ok(())
}

pub fn semantic_observation_value(bytes: &[u8]) -> Result<String, Error> {
    if bytes.len() > MAX_SEMANTIC_OBSERVATION_VALUE_BYTES {
        return Err(Error::schema_invalid());
    }
    Ok(encode_base64url(bytes))
}

fn require_none(
    target: Option<&String>,
    offset: Option<u64>,
    length: Option<u64>,
) -> Result<(), Error> {
    if target.is_some() || offset.is_some() || length.is_some() {
        return Err(Error::schema_invalid());
    }
    Ok(())
}

fn valid_length(length: Option<u64>) -> bool {
    length.is_some_and(|value| {
        value > 0 && value <= u64::try_from(MAX_SEMANTIC_OBSERVATION_VALUE_BYTES).unwrap()
    })
}

fn validate_target(target: Option<&str>) -> Result<(), Error> {
    let target = target.ok_or_else(Error::schema_invalid)?;
    let bytes = decode_base64url_bytes(target)?;
    if bytes.is_empty()
        || bytes.len() > MAX_SEMANTIC_OBSERVATION_TARGET_BYTES
        || std::str::from_utf8(&bytes).is_err()
    {
        return Err(Error::schema_invalid());
    }
    Ok(())
}

fn validate_response_value(
    operation: SemanticObservationOperation,
    value: Option<&str>,
) -> Result<(), Error> {
    let Some(value) = value else {
        return if operation == SemanticObservationOperation::EnvironmentRead {
            Ok(())
        } else {
            Err(Error::schema_invalid())
        };
    };
    let bytes = decode_base64url_bytes(value)?;
    if bytes.len() > MAX_SEMANTIC_OBSERVATION_VALUE_BYTES
        || (operation == SemanticObservationOperation::ClockWallTime && bytes.len() != 8)
        || (operation == SemanticObservationOperation::RandomBytes && bytes.is_empty())
    {
        return Err(Error::schema_invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(operation: SemanticObservationOperation) -> SemanticObservationRequest {
        SemanticObservationRequest {
            format: SemanticObservationRequestFormat::V1,
            length: None,
            offset: None,
            operation,
            target: None,
        }
    }

    #[test]
    fn each_operation_accepts_only_its_exact_parameter_shape() {
        assert!(
            request(SemanticObservationOperation::ClockWallTime)
                .validate()
                .is_ok()
        );

        let mut environment = request(SemanticObservationOperation::EnvironmentRead);
        environment.target = Some(encode_base64url(b"REGION"));
        assert!(environment.validate().is_ok());

        let mut filesystem = request(SemanticObservationOperation::FilesystemRead);
        filesystem.target = Some(encode_base64url(b"/data/input"));
        filesystem.offset = Some(0);
        filesystem.length = Some(32_768);
        assert!(filesystem.validate().is_ok());
        filesystem.length = Some(32_769);
        assert!(filesystem.validate().is_err());

        let mut random = request(SemanticObservationOperation::RandomBytes);
        random.length = Some(32);
        assert!(random.validate().is_ok());
        random.target = Some(encode_base64url(b"unexpected"));
        assert!(random.validate().is_err());
    }
}

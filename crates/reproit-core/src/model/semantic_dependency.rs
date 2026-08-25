use serde::{Deserialize, Serialize};

use crate::{Error, canonical, crypto::decode_base64url_bytes, identity::Digest};

use super::{
    AutomaticObservationClass, SemanticObservationErrorCode, SemanticObservationOutcome, Validate,
    valid_component,
};

pub const MAX_SEMANTIC_DEPENDENCY_RECORD_BYTES: usize = 65_536;
pub const MAX_SEMANTIC_DEPENDENCY_TARGET_BYTES: usize = 8 * 1_024;
pub const MAX_SEMANTIC_DEPENDENCY_PAYLOAD_BYTES: usize = 24 * 1_024;
pub const MAX_SEMANTIC_DEPENDENCY_METADATA_ENTRIES: usize = 64;
pub const MAX_SEMANTIC_DEPENDENCY_METADATA_BYTES: usize = 8 * 1_024;
pub const MAX_SEMANTIC_DEPENDENCY_METADATA_NAME_BYTES: usize = 256;
pub const MAX_SEMANTIC_DEPENDENCY_METADATA_VALUE_BYTES: usize = 4 * 1_024;

const MAX_PROTOCOL_BYTES: usize = 64;
const MAX_ENCODING_BYTES: usize = 64;
const MAX_METHOD_BYTES: usize = 32;
const MAX_STATUS_BYTES: usize = 64;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum SemanticDependencyRequestFormat {
    #[serde(rename = "reproit.semantic-dependency-request.v1")]
    V1,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum SemanticDependencyResponseFormat {
    #[serde(rename = "reproit.semantic-dependency-response.v1")]
    V1,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SemanticDependencyOperation {
    DatabaseExecute,
    OutboundHttpRequest,
    QueueAcknowledge,
    QueuePublish,
    QueueReceive,
    QueueReject,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticDependencyMetadata {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticDependencyRequest {
    pub encoding: String,
    pub format: SemanticDependencyRequestFormat,
    pub metadata: Vec<SemanticDependencyMetadata>,
    pub method: Option<String>,
    pub observation_class: AutomaticObservationClass,
    pub operation: SemanticDependencyOperation,
    pub payload: String,
    pub protocol: String,
    pub target: String,
}

impl Validate for SemanticDependencyRequest {
    fn validate(&self) -> Result<(), Error> {
        validate_class_operation(self.observation_class, self.operation)?;
        validate_component_token(&self.protocol, MAX_PROTOCOL_BYTES)?;
        validate_component_token(&self.encoding, MAX_ENCODING_BYTES)?;
        validate_target(&self.target)?;
        validate_payload(&self.payload)?;
        validate_metadata(&self.metadata)?;
        match self.observation_class {
            AutomaticObservationClass::OutboundHttp => validate_method(self.method.as_deref())?,
            AutomaticObservationClass::Database | AutomaticObservationClass::Queue => {
                if self.method.is_some() {
                    return Err(Error::schema_invalid());
                }
            }
            _ => return Err(Error::schema_invalid()),
        }
        validate_record_size(self)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticDependencyResponse {
    pub error_code: Option<SemanticObservationErrorCode>,
    pub error_number: Option<u32>,
    pub format: SemanticDependencyResponseFormat,
    pub metadata: Vec<SemanticDependencyMetadata>,
    pub observation_class: AutomaticObservationClass,
    pub operation: SemanticDependencyOperation,
    pub outcome: SemanticObservationOutcome,
    pub payload: Option<String>,
    pub request_digest: Digest,
    pub status: Option<String>,
    pub status_code: Option<u16>,
}

impl Validate for SemanticDependencyResponse {
    fn validate(&self) -> Result<(), Error> {
        validate_class_operation(self.observation_class, self.operation)?;
        match self.outcome {
            SemanticObservationOutcome::Error => self.validate_error()?,
            SemanticObservationOutcome::Response => self.validate_response()?,
        }
        validate_record_size(self)
    }
}

impl SemanticDependencyResponse {
    fn validate_error(&self) -> Result<(), Error> {
        if self.error_code.is_none()
            || self.status.is_some()
            || self.status_code.is_some()
            || !self.metadata.is_empty()
            || self.payload.is_some()
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }

    fn validate_response(&self) -> Result<(), Error> {
        if self.error_code.is_some() || self.error_number.is_some() {
            return Err(Error::schema_invalid());
        }
        validate_metadata(&self.metadata)?;
        validate_payload(self.payload.as_deref().ok_or_else(Error::schema_invalid)?)?;
        match self.observation_class {
            AutomaticObservationClass::OutboundHttp => {
                if self.status.is_some() || !matches!(self.status_code, Some(100..=599)) {
                    return Err(Error::schema_invalid());
                }
            }
            AutomaticObservationClass::Database | AutomaticObservationClass::Queue => {
                if self.status_code.is_some() {
                    return Err(Error::schema_invalid());
                }
                if let Some(status) = self.status.as_deref() {
                    validate_component_token(status, MAX_STATUS_BYTES)?;
                }
            }
            _ => return Err(Error::schema_invalid()),
        }
        Ok(())
    }
}

pub fn validate_semantic_dependency_pair(
    request: &SemanticDependencyRequest,
    response: &SemanticDependencyResponse,
) -> Result<(), Error> {
    request.validate()?;
    response.validate()?;
    if response.observation_class != request.observation_class
        || response.operation != request.operation
        || response.request_digest != canonical::digest(request)?
    {
        return Err(Error::schema_invalid());
    }
    Ok(())
}

fn validate_class_operation(
    class: AutomaticObservationClass,
    operation: SemanticDependencyOperation,
) -> Result<(), Error> {
    let valid = matches!(
        (class, operation),
        (
            AutomaticObservationClass::Database,
            SemanticDependencyOperation::DatabaseExecute
        ) | (
            AutomaticObservationClass::OutboundHttp,
            SemanticDependencyOperation::OutboundHttpRequest
        ) | (
            AutomaticObservationClass::Queue,
            SemanticDependencyOperation::QueueAcknowledge
                | SemanticDependencyOperation::QueuePublish
                | SemanticDependencyOperation::QueueReceive
                | SemanticDependencyOperation::QueueReject
        )
    );
    if !valid {
        return Err(Error::schema_invalid());
    }
    Ok(())
}

fn validate_component_token(value: &str, maximum_bytes: usize) -> Result<(), Error> {
    if value.len() > maximum_bytes || !valid_component(value) {
        return Err(Error::schema_invalid());
    }
    Ok(())
}

fn validate_method(method: Option<&str>) -> Result<(), Error> {
    let method = method.ok_or_else(Error::schema_invalid)?;
    if method.is_empty()
        || method.len() > MAX_METHOD_BYTES
        || !method.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_uppercase() || (index > 0 && (byte.is_ascii_digit() || byte == b'-'))
        })
    {
        return Err(Error::schema_invalid());
    }
    Ok(())
}

fn validate_target(value: &str) -> Result<(), Error> {
    let target = decode_base64url_bytes(value)?;
    if target.is_empty()
        || target.len() > MAX_SEMANTIC_DEPENDENCY_TARGET_BYTES
        || std::str::from_utf8(&target).is_err()
    {
        return Err(Error::schema_invalid());
    }
    Ok(())
}

fn validate_payload(value: &str) -> Result<(), Error> {
    if decode_base64url_bytes(value)?.len() > MAX_SEMANTIC_DEPENDENCY_PAYLOAD_BYTES {
        return Err(Error::schema_invalid());
    }
    Ok(())
}

fn validate_metadata(metadata: &[SemanticDependencyMetadata]) -> Result<(), Error> {
    if metadata.len() > MAX_SEMANTIC_DEPENDENCY_METADATA_ENTRIES {
        return Err(Error::schema_invalid());
    }
    let mut total_bytes = 0_usize;
    for field in metadata {
        let name = decode_base64url_bytes(&field.name)?;
        let value = decode_base64url_bytes(&field.value)?;
        if name.is_empty()
            || name.len() > MAX_SEMANTIC_DEPENDENCY_METADATA_NAME_BYTES
            || std::str::from_utf8(&name).is_err()
            || value.len() > MAX_SEMANTIC_DEPENDENCY_METADATA_VALUE_BYTES
        {
            return Err(Error::schema_invalid());
        }
        total_bytes = total_bytes
            .checked_add(name.len())
            .and_then(|bytes| bytes.checked_add(value.len()))
            .ok_or_else(Error::schema_invalid)?;
        if total_bytes > MAX_SEMANTIC_DEPENDENCY_METADATA_BYTES {
            return Err(Error::schema_invalid());
        }
    }
    Ok(())
}

fn validate_record_size(value: &impl Serialize) -> Result<(), Error> {
    if canonical::canonical_bytes(value)?.len() > MAX_SEMANTIC_DEPENDENCY_RECORD_BYTES {
        return Err(Error::schema_invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::crypto::encode_base64url;

    use super::*;

    fn make_request(class: AutomaticObservationClass) -> SemanticDependencyRequest {
        let (operation, method) = match class {
            AutomaticObservationClass::Database => {
                (SemanticDependencyOperation::DatabaseExecute, None)
            }
            AutomaticObservationClass::OutboundHttp => (
                SemanticDependencyOperation::OutboundHttpRequest,
                Some("POST".to_owned()),
            ),
            AutomaticObservationClass::Queue => (SemanticDependencyOperation::QueuePublish, None),
            _ => unreachable!(),
        };
        SemanticDependencyRequest {
            encoding: "canonical-json".to_owned(),
            format: SemanticDependencyRequestFormat::V1,
            metadata: Vec::new(),
            method,
            observation_class: class,
            operation,
            payload: String::new(),
            protocol: "test-protocol".to_owned(),
            target: encode_base64url(b"test-target"),
        }
    }

    fn make_response(request: &SemanticDependencyRequest) -> SemanticDependencyResponse {
        SemanticDependencyResponse {
            error_code: None,
            error_number: None,
            format: SemanticDependencyResponseFormat::V1,
            metadata: Vec::new(),
            observation_class: request.observation_class,
            operation: request.operation,
            outcome: SemanticObservationOutcome::Response,
            payload: Some(String::new()),
            request_digest: canonical::digest(request).unwrap(),
            status: None,
            status_code: (request.observation_class == AutomaticObservationClass::OutboundHttp)
                .then_some(200),
        }
    }

    #[test]
    fn each_real_class_accepts_its_exact_shape() {
        for class in [
            AutomaticObservationClass::Database,
            AutomaticObservationClass::OutboundHttp,
            AutomaticObservationClass::Queue,
        ] {
            let request = make_request(class);
            let response = make_response(&request);
            validate_semantic_dependency_pair(&request, &response).unwrap();
        }
        for operation in [
            SemanticDependencyOperation::QueueAcknowledge,
            SemanticDependencyOperation::QueuePublish,
            SemanticDependencyOperation::QueueReceive,
            SemanticDependencyOperation::QueueReject,
        ] {
            let mut request = make_request(AutomaticObservationClass::Queue);
            request.operation = operation;
            let response = make_response(&request);
            validate_semantic_dependency_pair(&request, &response).unwrap();
        }
    }

    #[test]
    fn one_over_each_byte_bound_is_rejected() {
        let mut request = make_request(AutomaticObservationClass::Database);
        request.target = encode_base64url(&vec![b'a'; MAX_SEMANTIC_DEPENDENCY_TARGET_BYTES + 1]);
        assert!(request.validate().is_err());

        let mut request = make_request(AutomaticObservationClass::Database);
        request.payload = encode_base64url(&vec![0; MAX_SEMANTIC_DEPENDENCY_PAYLOAD_BYTES + 1]);
        assert!(request.validate().is_err());

        let mut request = make_request(AutomaticObservationClass::Database);
        request.metadata = vec![SemanticDependencyMetadata {
            name: encode_base64url(&vec![b'n'; MAX_SEMANTIC_DEPENDENCY_METADATA_NAME_BYTES + 1]),
            value: String::new(),
        }];
        assert!(request.validate().is_err());

        let mut request = make_request(AutomaticObservationClass::Database);
        request.metadata = vec![SemanticDependencyMetadata {
            name: encode_base64url(b"name"),
            value: encode_base64url(&vec![0; MAX_SEMANTIC_DEPENDENCY_METADATA_VALUE_BYTES + 1]),
        }];
        assert!(request.validate().is_err());

        let mut request = make_request(AutomaticObservationClass::Database);
        request.protocol = format!("p{}", "0".repeat(MAX_PROTOCOL_BYTES));
        assert!(request.validate().is_err());

        let mut request = make_request(AutomaticObservationClass::OutboundHttp);
        request.method = Some("A".repeat(MAX_METHOD_BYTES + 1));
        assert!(request.validate().is_err());

        let field = SemanticDependencyMetadata {
            name: encode_base64url(b"name"),
            value: String::new(),
        };
        let mut request = make_request(AutomaticObservationClass::Database);
        request.metadata = vec![field; MAX_SEMANTIC_DEPENDENCY_METADATA_ENTRIES + 1];
        assert!(request.validate().is_err());

        let mut request = make_request(AutomaticObservationClass::Database);
        request.metadata = vec![SemanticDependencyMetadata {
            name: encode_base64url(b"name"),
            value: encode_base64url(&vec![0; MAX_SEMANTIC_DEPENDENCY_METADATA_BYTES]),
        }];
        assert!(request.validate().is_err());
    }

    #[test]
    fn pair_rejects_changed_class_operation_and_digest() {
        let request = make_request(AutomaticObservationClass::OutboundHttp);
        let mut response = make_response(&request);
        response.request_digest = Digest::of(b"changed request");
        assert!(validate_semantic_dependency_pair(&request, &response).is_err());

        let mut response = make_response(&request);
        response.observation_class = AutomaticObservationClass::Queue;
        assert!(validate_semantic_dependency_pair(&request, &response).is_err());

        let mut response = make_response(&request);
        response.operation = SemanticDependencyOperation::QueuePublish;
        assert!(validate_semantic_dependency_pair(&request, &response).is_err());
    }

    #[test]
    fn errors_and_successes_have_disjoint_fields() {
        let request = make_request(AutomaticObservationClass::Database);
        let mut response = make_response(&request);
        response.outcome = SemanticObservationOutcome::Error;
        response.error_code = Some(SemanticObservationErrorCode::Other);
        response.payload = None;
        response.status = None;
        assert!(validate_semantic_dependency_pair(&request, &response).is_ok());

        response.payload = Some(String::new());
        assert!(response.validate().is_err());

        let mut response = make_response(&request);
        response.status_code = Some(200);
        assert!(response.validate().is_err());
    }

    #[test]
    fn maximum_combined_request_stays_within_the_record_bound() {
        let mut request = make_request(AutomaticObservationClass::Database);
        request.target = encode_base64url(&vec![b't'; MAX_SEMANTIC_DEPENDENCY_TARGET_BYTES]);
        request.payload = encode_base64url(&vec![0; MAX_SEMANTIC_DEPENDENCY_PAYLOAD_BYTES]);
        request.metadata = vec![
            SemanticDependencyMetadata {
                name: encode_base64url(b"name"),
                value: encode_base64url(&vec![0; 4_092]),
            },
            SemanticDependencyMetadata {
                name: encode_base64url(b"name"),
                value: encode_base64url(&vec![0; 4_092]),
            },
        ];
        request.validate().unwrap();
        assert!(canonical::canonical_bytes(&request).unwrap().len() <= 65_536);
    }
}

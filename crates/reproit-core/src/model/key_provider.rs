use serde::{Deserialize, Serialize};

use super::Validate;
use crate::{
    Error, ErrorCode,
    identity::{OrganizationId, ProjectId, ServiceId},
};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum AdmissionVerificationKeyRequestFormat {
    #[serde(rename = "reproit.admission-verification-key-request.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionVerificationKeyRequest {
    pub format: AdmissionVerificationKeyRequestFormat,
    pub organization_id: OrganizationId,
    pub project_id: ProjectId,
    pub service_id: ServiceId,
    pub signer_key_id: String,
}

impl Validate for AdmissionVerificationKeyRequest {
    fn validate(&self) -> Result<(), Error> {
        validate_signer_key_id(&self.signer_key_id)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum AdmissionVerificationKeyFormat {
    #[serde(rename = "reproit.admission-verification-key.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionVerificationKey {
    pub algorithm: String,
    pub format: AdmissionVerificationKeyFormat,
    pub organization_id: OrganizationId,
    pub project_id: ProjectId,
    pub public_key: String,
    pub service_id: ServiceId,
    pub signer_key_id: String,
}

impl Validate for AdmissionVerificationKey {
    fn validate(&self) -> Result<(), Error> {
        if self.algorithm != "Ed25519" {
            return Err(Error::schema_invalid());
        }
        validate_signer_key_id(&self.signer_key_id)?;
        crate::crypto::decode_base64url::<32>(&self.public_key)?;
        Ok(())
    }
}

pub fn validate_admission_verification_key(
    request: &AdmissionVerificationKeyRequest,
    key: &AdmissionVerificationKey,
) -> Result<[u8; 32], Error> {
    request.validate()?;
    key.validate()?;
    if request.organization_id != key.organization_id
        || request.project_id != key.project_id
        || request.service_id != key.service_id
        || request.signer_key_id != key.signer_key_id
    {
        return Err(Error::new(
            ErrorCode::AttestationScope,
            "The admission verification key has the wrong scope.",
        ));
    }
    crate::crypto::decode_base64url::<32>(&key.public_key)
}

fn validate_signer_key_id(value: &str) -> Result<(), Error> {
    if value.is_empty() || value.len() > 256 {
        return Err(Error::schema_invalid());
    }
    Ok(())
}

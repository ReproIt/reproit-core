use serde::{Deserialize, Serialize};

use crate::{
    Error, canonical,
    crypto::{decode_base64url_bytes, encode_base64url},
    identity::{CaptureId, Digest, OrganizationId, ProjectId, ServiceId, Timestamp},
};

use super::{Candidate, ProcessingMode, Validate};

pub const MAX_STAGED_CANDIDATE_BYTES: usize = 1_048_604;
pub const CANDIDATE_MAILBOX_MEDIA_TYPE: &str =
    "application/vnd.reproit.candidate-staging-ciphertext.v1";

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum CandidateStagingIdentityFormat {
    #[serde(rename = "reproit.candidate-staging-identity.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateStagingIdentity {
    pub capture_id: CaptureId,
    pub deployment_digest: Digest,
    pub expires_at: Timestamp,
    pub failure_storm_digest: Digest,
    pub format: CandidateStagingIdentityFormat,
    pub organization_id: OrganizationId,
    pub processing_mode: ProcessingMode,
    pub project_id: ProjectId,
    pub provider_lease_digest: Digest,
    pub request_digest: Digest,
    pub service_id: ServiceId,
    pub world_id: Digest,
}

impl Validate for CandidateStagingIdentity {
    fn validate(&self) -> Result<(), Error> {
        Ok(())
    }
}

impl CandidateStagingIdentity {
    pub fn for_candidate(candidate: &Candidate, expires_at: Timestamp) -> Result<Self, Error> {
        candidate.validate()?;
        let request_digest = canonical::digest(candidate)?;
        let failure_storm_digest = canonical::digest(&candidate.failure_storm_identity()?)?;
        let deployment_digest = canonical::digest(&candidate.deployment)?;
        let provider_lease_digest = canonical::digest(&ProviderLeaseBinding {
            format: "reproit.provider-lease-binding.v1",
            organization_id: candidate.deployment.organization_id,
            service_id: candidate.deployment.service_id,
            world_id: candidate.world_id,
        })?;
        Ok(Self {
            capture_id: candidate.capture_id,
            deployment_digest,
            expires_at,
            failure_storm_digest,
            format: CandidateStagingIdentityFormat::V1,
            organization_id: candidate.deployment.organization_id,
            processing_mode: candidate.processing_mode,
            project_id: candidate.deployment.project_id,
            provider_lease_digest,
            request_digest,
            service_id: candidate.deployment.service_id,
            world_id: candidate.world_id,
        })
    }

    pub fn matches_candidate(&self, candidate: &Candidate) -> Result<(), Error> {
        let expected = Self::for_candidate(candidate, self.expires_at.clone())?;
        if *self != expected {
            return Err(Error::object_digest_mismatch());
        }
        Ok(())
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderLeaseBinding {
    format: &'static str,
    organization_id: OrganizationId,
    service_id: ServiceId,
    world_id: Digest,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum CandidateStagingFormat {
    #[serde(rename = "reproit.candidate-staging-envelope.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateStagingEnvelope {
    pub cipher_digest: Digest,
    pub cipher_size: u64,
    pub ciphertext: String,
    pub format: CandidateStagingFormat,
    pub identity: CandidateStagingIdentity,
}

impl CandidateStagingEnvelope {
    pub fn new(identity: CandidateStagingIdentity, stored: &[u8]) -> Result<Self, Error> {
        let envelope = Self {
            cipher_digest: Digest::of(stored),
            cipher_size: u64::try_from(stored.len()).map_err(|_| Error::schema_invalid())?,
            ciphertext: encode_base64url(stored),
            format: CandidateStagingFormat::V1,
            identity,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn stored_bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        decode_base64url_bytes(&self.ciphertext)
    }

    pub fn aad(&self) -> Result<Vec<u8>, Error> {
        self.identity.validate()?;
        canonical::canonical_bytes(&self.identity)
    }
}

impl Validate for CandidateStagingEnvelope {
    fn validate(&self) -> Result<(), Error> {
        self.identity.validate()?;
        let stored = decode_base64url_bytes(&self.ciphertext)?;
        if !(28..=MAX_STAGED_CANDIDATE_BYTES).contains(&stored.len())
            || u64::try_from(stored.len()).ok() != Some(self.cipher_size)
            || Digest::of(&stored) != self.cipher_digest
        {
            return Err(Error::object_digest_mismatch());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CandidateDurability {
    CloudProtected,
    LocalOnly,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateStagingReceipt {
    pub capture_id: CaptureId,
    pub request_digest: Digest,
    pub state: CandidateDurability,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum CandidateMailboxFormat {
    #[serde(rename = "reproit.candidate-mailbox-item.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateMailboxObject {
    pub cipher_digest: Digest,
    pub cipher_size: u64,
    pub media_type: String,
    pub object_identity: Digest,
}

impl Validate for CandidateMailboxObject {
    fn validate(&self) -> Result<(), Error> {
        if self.media_type != CANDIDATE_MAILBOX_MEDIA_TYPE
            || self.object_identity != self.cipher_digest
            || !(28..=u64::try_from(MAX_STAGED_CANDIDATE_BYTES).unwrap_or(u64::MAX))
                .contains(&self.cipher_size)
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CandidateMailboxPayload {
    Ciphertext {
        envelope: Box<CandidateStagingEnvelope>,
    },
    Object {
        object: CandidateMailboxObject,
    },
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateMailboxItem {
    pub content: CandidateMailboxPayload,
    pub format: CandidateMailboxFormat,
    pub identity: CandidateStagingIdentity,
}

impl CandidateMailboxItem {
    pub fn inline(envelope: CandidateStagingEnvelope) -> Result<Self, Error> {
        envelope.validate()?;
        let identity = envelope.identity.clone();
        Ok(Self {
            content: CandidateMailboxPayload::Ciphertext {
                envelope: Box::new(envelope),
            },
            format: CandidateMailboxFormat::V1,
            identity,
        })
    }

    pub fn object(envelope: &CandidateStagingEnvelope) -> Result<Self, Error> {
        envelope.validate()?;
        Ok(Self {
            content: CandidateMailboxPayload::Object {
                object: CandidateMailboxObject {
                    cipher_digest: envelope.cipher_digest,
                    cipher_size: envelope.cipher_size,
                    media_type: CANDIDATE_MAILBOX_MEDIA_TYPE.to_owned(),
                    object_identity: envelope.cipher_digest,
                },
            },
            format: CandidateMailboxFormat::V1,
            identity: envelope.identity.clone(),
        })
    }
}

impl Validate for CandidateMailboxItem {
    fn validate(&self) -> Result<(), Error> {
        self.identity.validate()?;
        match &self.content {
            CandidateMailboxPayload::Ciphertext { envelope } => {
                envelope.validate()?;
                if envelope.identity != self.identity {
                    return Err(Error::object_digest_mismatch());
                }
            }
            CandidateMailboxPayload::Object { object } => object.validate()?,
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vector_matches_the_machine_contract() {
        let value: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../specs/v1/deferred-candidate-vector.json"
        ))
        .unwrap();
        let envelope: CandidateStagingEnvelope =
            serde_json::from_value(value["value"].clone()).unwrap();
        envelope.validate().unwrap();
        assert_eq!(
            canonical::digest(&envelope).unwrap().to_string(),
            value["canonical_sha256"].as_str().unwrap()
        );
    }

    #[test]
    fn mailbox_vector_matches_the_machine_contract() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../specs/v1/customer-mailbox-vector.json"
        ))
        .unwrap();
        for name in ["inline", "object"] {
            let item: CandidateMailboxItem =
                serde_json::from_value(vectors[name]["value"].clone()).unwrap();
            item.validate().unwrap();
            assert_eq!(
                canonical::digest(&item).unwrap().to_string(),
                vectors[name]["canonical_sha256"].as_str().unwrap()
            );
        }
    }
}

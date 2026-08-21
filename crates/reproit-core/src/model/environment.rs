use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

use super::{Validate, require_strict_order};
use crate::{
    Error, canonical,
    crypto::{decode_base64url, verify_signed_value},
    error::ErrorCode,
    identity::{Digest, OrganizationId, ProjectId, ServiceId, Timestamp},
};

const MAX_POLICY_BYTES: usize = 256 * 1024;
const MAX_POLICY_LIFETIME_DAYS: i64 = 30;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum EnvironmentPolicyFormat {
    #[serde(rename = "reproit.environment-policy.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentPolicyScope {
    pub organization_id: OrganizationId,
    pub project_id: ProjectId,
    pub service_id: ServiceId,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReplayHostOperation {
    Check,
    Debug,
    Keep,
    Replay,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentKeepReference {
    pub destination: String,
    pub key_reference: String,
    pub project_id: ProjectId,
    pub service_id: Option<ServiceId>,
}

impl Validate for EnvironmentKeepReference {
    fn validate(&self) -> Result<(), Error> {
        if !valid_keep_destination(&self.destination)
            || self.key_reference.is_empty()
            || self.key_reference.len() > 2_048
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentReplayHost {
    pub expires_at: Timestamp,
    pub host_id: String,
    pub operations: Vec<ReplayHostOperation>,
    pub origin: String,
    pub scopes: Vec<EnvironmentPolicyScope>,
    pub tls_identity: Digest,
}

impl EnvironmentReplayHost {
    fn validate(&self, organization_id: OrganizationId) -> Result<(), Error> {
        if !valid_host_id(&self.host_id)
            || !valid_https_origin(&self.origin)
            || self.operations.is_empty()
            || self.operations.len() > 4
            || self.scopes.is_empty()
            || self.scopes.len() > 256
            || self
                .scopes
                .iter()
                .any(|scope| scope.organization_id != organization_id)
        {
            return Err(Error::schema_invalid());
        }
        require_strict_order(
            self.operations
                .iter()
                .map(|operation| operation.label().to_owned()),
        )?;
        require_strict_order(self.scopes.iter().map(|scope| {
            format!(
                "{}/{}/{}",
                scope.organization_id, scope.project_id, scope.service_id
            )
        }))
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentPolicy {
    pub expires_at: Timestamp,
    pub format: EnvironmentPolicyFormat,
    pub issued_at: Timestamp,
    pub keep_references: Vec<EnvironmentKeepReference>,
    pub organization_id: OrganizationId,
    pub replay_hosts: Vec<EnvironmentReplayHost>,
    pub revision: u64,
    pub signature: String,
    pub signer_key_id: String,
}

impl Validate for EnvironmentPolicy {
    fn validate(&self) -> Result<(), Error> {
        if self.revision == 0
            || self.revision > 9_007_199_254_740_991
            || environment_policy_verification_key(&self.signer_key_id).is_err()
            || self.keep_references.len() > 256
            || self.replay_hosts.len() > 64
        {
            return Err(Error::schema_invalid());
        }
        decode_base64url::<64>(&self.signature)?;
        let issued_at = parse_timestamp(&self.issued_at)?;
        let expires_at = parse_timestamp(&self.expires_at)?;
        if expires_at <= issued_at
            || expires_at - issued_at > Duration::days(MAX_POLICY_LIFETIME_DAYS)
        {
            return Err(Error::schema_invalid());
        }
        require_strict_order(self.keep_references.iter().map(|reference| {
            format!(
                "{}/{}/{}",
                reference.project_id,
                reference
                    .service_id
                    .map_or_else(String::new, |service| service.to_string()),
                reference.destination
            )
        }))?;
        require_strict_order(self.replay_hosts.iter().map(|host| host.host_id.clone()))?;
        for reference in &self.keep_references {
            reference.validate()?;
        }
        for host in &self.replay_hosts {
            host.validate(self.organization_id)?;
            if host.expires_at > self.expires_at {
                return Err(Error::schema_invalid());
            }
        }
        if canonical::canonical_bytes(self)?.len() > MAX_POLICY_BYTES {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

pub fn environment_policy_verification_key(signer_key_id: &str) -> Result<[u8; 32], Error> {
    let encoded = signer_key_id
        .strip_prefix("ed25519:")
        .ok_or_else(Error::schema_invalid)?;
    decode_base64url::<32>(encoded)
}

pub fn verify_environment_policy(
    policy: &EnvironmentPolicy,
    organization_id: OrganizationId,
    pinned_signer_key_id: &str,
    current_revision: Option<u64>,
    now: &Timestamp,
    public_key: &[u8; 32],
) -> Result<(), Error> {
    if policy.organization_id != organization_id || policy.signer_key_id != pinned_signer_key_id {
        return Err(attestation_scope());
    }
    policy.validate()?;
    if current_revision.is_some_and(|revision| policy.revision <= revision) {
        return Err(Error::new(
            ErrorCode::ConfigConflict,
            "The customer environment policy revision must increase.",
        ));
    }
    if &policy.issued_at > now || &policy.expires_at <= now {
        return Err(attestation_scope());
    }
    let value = serde_json::to_value(policy).map_err(|_| Error::schema_invalid())?;
    verify_signed_value(&value, public_key)
}

fn parse_timestamp(timestamp: &Timestamp) -> Result<OffsetDateTime, Error> {
    OffsetDateTime::parse(timestamp.as_str(), &Rfc3339).map_err(|_| Error::schema_invalid())
}

fn valid_host_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || (byte.is_ascii_digit() && index > 0)
                || (matches!(byte, b'.' | b'-') && index > 0)
        })
}

impl ReplayHostOperation {
    const fn label(self) -> &'static str {
        match self {
            Self::Check => "check",
            Self::Debug => "debug",
            Self::Keep => "keep",
            Self::Replay => "replay",
        }
    }
}

fn valid_https_origin(value: &str) -> bool {
    let Some(authority) = value.strip_prefix("https://") else {
        return false;
    };
    !authority.is_empty()
        && value.len() <= 2_048
        && value.is_ascii()
        && value == value.to_ascii_lowercase()
        && !authority
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || matches!(byte, b'/' | b'?' | b'#' | b'@'))
}

fn valid_keep_destination(value: &str) -> bool {
    let remote = value.strip_prefix("oci://").is_some_and(|path| {
        !path.is_empty() && !path.bytes().any(|byte| byte.is_ascii_whitespace())
    });
    let layout = value
        .strip_prefix("oci-layout://")
        .map(|path| path.trim_end_matches('/'))
        .is_some_and(|identity| {
            !identity.is_empty()
                && identity.len() <= 128
                && identity.bytes().enumerate().all(|(index, byte)| {
                    byte.is_ascii_alphanumeric()
                        || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
                })
        });
    remote || layout
}

fn attestation_scope() -> Error {
    Error::new(
        ErrorCode::AttestationScope,
        "The customer environment policy is not valid for this scope.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_rejects_credentials_and_non_origin_paths() {
        assert!(valid_https_origin("https://worker.example:8443"));
        for value in [
            "http://worker.example",
            "https://user@worker.example",
            "https://worker.example/path",
            "https://WORKER.example",
        ] {
            assert!(!valid_https_origin(value), "{value}");
        }
    }
}

use std::fmt;

use reproit_core::{
    Error,
    identity::{Digest, OrganizationId, ProjectId, ServiceId, Timestamp},
    model::ProcessingMode,
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::RetainedQuota;

pub const FREE_V1_RETAINED_QUOTA: RetainedQuota = RetainedQuota {
    organization_ciphertext_bytes: 549_755_813_888,
    organization_occurrences: 10_000,
    organization_repros: 5,
    service_logical_ciphertext_bytes: 274_878_824_448,
    service_occurrences: 2_500,
    service_repros: 5,
};

pub const MANAGED_V1_RETAINED_QUOTA: RetainedQuota = FREE_V1_RETAINED_QUOTA;

const MAX_NAME_BYTES: usize = 80;
const MAX_REPOSITORY_ID_BYTES: usize = 256;
const MAX_CURSOR_BYTES: usize = 2_048;
const MAX_CATALOG_ENTRIES: usize = 100;
const MIN_TOKEN_LIFETIME_SECONDS: u32 = 300;
const MAX_TOKEN_LIFETIME_SECONDS: u32 = 2_592_000;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectCreateRequest {
    pub organization_name: String,
    pub project_name: String,
}

impl ProjectCreateRequest {
    pub fn validate(&self) -> Result<(), Error> {
        validate_name(&self.organization_name)?;
        validate_name(&self.project_name)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectCreateResult {
    pub organization_id: OrganizationId,
    pub organization_name: String,
    pub project_id: ProjectId,
    pub project_name: String,
}

impl ProjectCreateResult {
    pub fn validate(&self) -> Result<(), Error> {
        validate_name(&self.organization_name)?;
        validate_name(&self.project_name)
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProjectTokenId(String);

impl ProjectTokenId {
    pub fn new(value: String) -> Result<Self, Error> {
        validate_project_token_id(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ProjectTokenId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for ProjectTokenId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for ProjectTokenId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ProjectTokenId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

pub struct ProjectTokenPlaintext(SecretString);

impl ProjectTokenPlaintext {
    pub fn new(value: String) -> Result<Self, Error> {
        validate_project_token_plaintext(&value)?;
        Ok(Self(SecretString::from(value)))
    }

    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }

    pub fn verifier(&self) -> Digest {
        Digest::of(self.expose().as_bytes())
    }

    fn token_id(&self) -> &str {
        &self.expose()[5..45]
    }
}

impl Clone for ProjectTokenPlaintext {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl PartialEq for ProjectTokenPlaintext {
    fn eq(&self, other: &Self) -> bool {
        self.expose() == other.expose()
    }
}

impl Eq for ProjectTokenPlaintext {}

impl Serialize for ProjectTokenPlaintext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.expose())
    }
}

impl<'de> Deserialize<'de> for ProjectTokenPlaintext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum ProjectTokenState {
    #[serde(rename = "ACTIVE")]
    Active,
    #[serde(rename = "REVOKED")]
    Revoked,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectTokenMetadata {
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
    pub name: String,
    pub organization_id: OrganizationId,
    pub project_id: ProjectId,
    pub revoked_at: Option<Timestamp>,
    pub service_id: ServiceId,
    pub state: ProjectTokenState,
    pub token_id: ProjectTokenId,
    pub token_revision: u64,
}

impl ProjectTokenMetadata {
    pub fn validate(&self) -> Result<(), Error> {
        validate_name(&self.name)?;
        validate_token_revision(self.token_revision)?;
        if self.created_at.as_str() >= self.expires_at.as_str() {
            return Err(Error::schema_invalid());
        }
        match (self.state, &self.revoked_at) {
            (ProjectTokenState::Active, None) => Ok(()),
            (ProjectTokenState::Revoked, Some(revoked_at))
                if revoked_at.as_str() >= self.created_at.as_str() =>
            {
                Ok(())
            }
            _ => Err(Error::schema_invalid()),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectTokenIssueRequest {
    pub expires_in_seconds: u32,
    pub name: String,
    pub service_id: ServiceId,
}

impl ProjectTokenIssueRequest {
    pub fn validate(&self) -> Result<(), Error> {
        validate_token_lifetime(self.expires_in_seconds)?;
        validate_name(&self.name)
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectTokenIssueResult {
    pub plaintext_token: ProjectTokenPlaintext,
    pub token: ProjectTokenMetadata,
}

impl ProjectTokenIssueResult {
    pub fn validate(&self) -> Result<(), Error> {
        validate_plaintext_result(&self.plaintext_token, &self.token)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectTokenRotateRequest {
    pub expires_in_seconds: u32,
    pub token_revision: u64,
}

impl ProjectTokenRotateRequest {
    pub fn validate(&self) -> Result<(), Error> {
        validate_token_lifetime(self.expires_in_seconds)?;
        validate_token_revision(self.token_revision)
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectTokenRotateResult {
    pub plaintext_token: ProjectTokenPlaintext,
    pub token: ProjectTokenMetadata,
}

impl ProjectTokenRotateResult {
    pub fn validate(&self) -> Result<(), Error> {
        validate_plaintext_result(&self.plaintext_token, &self.token)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectTokenRevokeRequest {
    pub token_revision: u64,
}

impl ProjectTokenRevokeRequest {
    pub fn validate(&self) -> Result<(), Error> {
        validate_token_revision(self.token_revision)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectTokenRevokeResult {
    pub token: ProjectTokenMetadata,
}

impl ProjectTokenRevokeResult {
    pub fn validate(&self) -> Result<(), Error> {
        self.token.validate()?;
        if self.token.state != ProjectTokenState::Revoked {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum ProjectTokenVerifierAlgorithm {
    #[serde(rename = "SHA-256")]
    Sha256,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectTokenVerifierRecord {
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
    pub organization_id: OrganizationId,
    pub project_id: ProjectId,
    pub revoked_at: Option<Timestamp>,
    pub service_id: ServiceId,
    pub state: ProjectTokenState,
    pub token_id: ProjectTokenId,
    pub token_revision: u64,
    pub verifier: Digest,
    pub verifier_algorithm: ProjectTokenVerifierAlgorithm,
}

impl ProjectTokenVerifierRecord {
    pub fn validate(&self) -> Result<(), Error> {
        validate_token_revision(self.token_revision)?;
        validate_token_state(
            &self.created_at,
            &self.expires_at,
            self.state,
            self.revoked_at.as_ref(),
        )
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceCreateRequest {
    pub repository_id: String,
    pub service_name: String,
}

impl ServiceCreateRequest {
    pub fn validate(&self) -> Result<(), Error> {
        validate_repository_id(&self.repository_id)?;
        validate_name(&self.service_name)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceCreateResult {
    pub organization_id: OrganizationId,
    pub organization_name: String,
    pub processing_mode: ProcessingMode,
    pub project_id: ProjectId,
    pub project_name: String,
    pub qualified_name: String,
    pub repository_id: String,
    pub retained_quota: RetainedQuota,
    pub service_id: ServiceId,
    pub service_name: String,
}

impl ServiceCreateResult {
    pub fn validate(&self) -> Result<(), Error> {
        validate_service_fields(
            self.processing_mode,
            &self.organization_name,
            &self.project_name,
            &self.service_name,
            &self.service_id,
            &self.qualified_name,
            &self.repository_id,
        )?;
        self.retained_quota.validate()
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceCatalogEntry {
    pub organization_id: OrganizationId,
    pub organization_name: String,
    pub processing_mode: ProcessingMode,
    pub project_id: ProjectId,
    pub project_name: String,
    pub qualified_name: String,
    pub repository_id: String,
    pub service_id: ServiceId,
    pub service_name: String,
}

impl ServiceCatalogEntry {
    pub fn validate(&self) -> Result<(), Error> {
        validate_service_fields(
            self.processing_mode,
            &self.organization_name,
            &self.project_name,
            &self.service_name,
            &self.service_id,
            &self.qualified_name,
            &self.repository_id,
        )
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceCatalog {
    pub next_cursor: Option<String>,
    pub services: Vec<ServiceCatalogEntry>,
}

impl ServiceCatalog {
    pub fn validate(&self) -> Result<(), Error> {
        validate_cursor(self.next_cursor.as_deref())?;
        if self.services.len() > MAX_CATALOG_ENTRIES {
            return Err(Error::schema_invalid());
        }
        for (index, service) in self.services.iter().enumerate() {
            service.validate()?;
            if self.services[..index].contains(service) {
                return Err(Error::schema_invalid());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceCatalogQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u8>,
    pub repository_id: String,
}

impl ServiceCatalogQuery {
    pub fn validate(&self) -> Result<(), Error> {
        validate_cursor(self.cursor.as_deref())?;
        if self.limit.is_some_and(|limit| limit == 0 || limit > 100) {
            return Err(Error::schema_invalid());
        }
        validate_repository_id(&self.repository_id)
    }
}

fn validate_plaintext_result(
    plaintext_token: &ProjectTokenPlaintext,
    token: &ProjectTokenMetadata,
) -> Result<(), Error> {
    token.validate()?;
    if token.state != ProjectTokenState::Active || plaintext_token.token_id() != token.token_id.0 {
        return Err(Error::schema_invalid());
    }
    Ok(())
}

fn validate_service_fields(
    processing_mode: ProcessingMode,
    organization_name: &str,
    project_name: &str,
    service_name: &str,
    service_id: &ServiceId,
    qualified_name: &str,
    repository_id: &str,
) -> Result<(), Error> {
    if processing_mode != ProcessingMode::Managed {
        return Err(Error::schema_invalid());
    }
    validate_name(organization_name)?;
    validate_name(project_name)?;
    validate_name(service_name)?;
    validate_repository_id(repository_id)?;
    let expected = format!("{organization_name}/{project_name}/{service_name}@{service_id}");
    if qualified_name != expected || qualified_name.len() > 320 {
        return Err(Error::schema_invalid());
    }
    Ok(())
}

fn validate_name(value: &str) -> Result<(), Error> {
    let valid = !value.is_empty()
        && value.len() <= MAX_NAME_BYTES
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if !valid {
        return Err(Error::schema_invalid());
    }
    Ok(())
}

fn validate_repository_id(value: &str) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > MAX_REPOSITORY_ID_BYTES
        || value.chars().any(char::is_whitespace)
    {
        return Err(Error::schema_invalid());
    }
    Ok(())
}

fn validate_cursor(cursor: Option<&str>) -> Result<(), Error> {
    if cursor.is_some_and(|value| value.is_empty() || value.len() > MAX_CURSOR_BYTES) {
        return Err(Error::schema_invalid());
    }
    Ok(())
}

fn validate_token_lifetime(expires_in_seconds: u32) -> Result<(), Error> {
    if !(MIN_TOKEN_LIFETIME_SECONDS..=MAX_TOKEN_LIFETIME_SECONDS).contains(&expires_in_seconds) {
        return Err(Error::schema_invalid());
    }
    Ok(())
}

fn validate_token_revision(token_revision: u64) -> Result<(), Error> {
    if token_revision == 0 {
        return Err(Error::schema_invalid());
    }
    Ok(())
}

fn validate_token_state(
    created_at: &Timestamp,
    expires_at: &Timestamp,
    state: ProjectTokenState,
    revoked_at: Option<&Timestamp>,
) -> Result<(), Error> {
    if created_at.as_str() >= expires_at.as_str() {
        return Err(Error::schema_invalid());
    }
    match (state, revoked_at) {
        (ProjectTokenState::Active, None) => Ok(()),
        (ProjectTokenState::Revoked, Some(revoked_at))
            if revoked_at.as_str() >= created_at.as_str() =>
        {
            Ok(())
        }
        _ => Err(Error::schema_invalid()),
    }
}

fn validate_project_token_id(value: &str) -> Result<(), Error> {
    let Some(uuid) = value.strip_prefix("ptk_") else {
        return Err(Error::schema_invalid());
    };
    if !validate_uuid_v7(uuid) {
        return Err(Error::schema_invalid());
    }
    Ok(())
}

fn validate_project_token_plaintext(value: &str) -> Result<(), Error> {
    let Some(remainder) = value.strip_prefix("rpit_ptk_") else {
        return Err(Error::schema_invalid());
    };
    let Some((uuid, secret)) = remainder.split_once('_') else {
        return Err(Error::schema_invalid());
    };
    if !validate_uuid_v7(uuid)
        || secret.len() != 43
        || reproit_core::crypto::decode_base64url::<32>(secret).is_err()
    {
        return Err(Error::schema_invalid());
    }
    Ok(())
}

fn validate_uuid_v7(value: &str) -> bool {
    if value.len() != 36 {
        return false;
    }
    value.bytes().enumerate().all(|(index, byte)| match index {
        8 | 13 | 18 | 23 => byte == b'-',
        14 => byte == b'7',
        19 => matches!(byte, b'8' | b'9' | b'a' | b'b'),
        _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
    })
}

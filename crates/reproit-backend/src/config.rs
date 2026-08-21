use serde::{Deserialize, Serialize};

use reproit_core::{
    Error,
    identity::{OrganizationId, ProjectId, ServiceId},
    model::{ProcessingMode, Validate},
};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendSdk {
    Dotnet,
    Go,
    Nodejs,
    Python,
    Rust,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunSpec {
    pub arguments: Vec<String>,
    pub program: String,
    pub working_directory: String,
}

impl Validate for RunSpec {
    fn validate(&self) -> Result<(), Error> {
        if self.arguments.len() > 128
            || self.arguments.iter().any(|argument| argument.len() > 4_096)
            || self.program.is_empty()
            || self.program.len() > 4_096
            || !valid_relative_path(&self.working_directory, 1_024)
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectConfig {
    pub format: u8,
    pub keep: Option<ProjectKeepConfig>,
    pub organization_id: OrganizationId,
    pub profile: String,
    pub profile_format: u8,
    pub processing_mode: ProcessingMode,
    pub project_id: ProjectId,
    pub repository_id: String,
    pub run: RunSpec,
    pub sdk: BackendSdk,
    pub service_id: ServiceId,
    pub service_path: String,
    pub source: ProjectSourceConfig,
}

impl Validate for ProjectConfig {
    fn validate(&self) -> Result<(), Error> {
        if self.format != 1
            || self.profile != "backend"
            || self.profile_format != 1
            || self.repository_id.is_empty()
            || self.repository_id.len() > 256
            || !valid_relative_path(&self.service_path, 1_024)
        {
            return Err(Error::schema_invalid());
        }
        match (self.processing_mode, &self.keep) {
            (ProcessingMode::Managed, None) => {}
            (ProcessingMode::Private, Some(keep)) => keep.validate()?,
            _ => return Err(Error::schema_invalid()),
        }
        self.run.validate()?;
        self.source.validate()
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectSourceConfig {
    pub remote: String,
}

impl Validate for ProjectSourceConfig {
    fn validate(&self) -> Result<(), Error> {
        let valid = !self.remote.is_empty()
            && self.remote.len() <= 64
            && self.remote.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
            });
        valid.then_some(()).ok_or_else(Error::schema_invalid)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectKeepConfig {
    pub destination: String,
    pub key_reference: String,
}

impl Validate for ProjectKeepConfig {
    fn validate(&self) -> Result<(), Error> {
        if self.destination.len() > 2_048
            || self.key_reference.is_empty()
            || self.key_reference.len() > 2_048
            || !valid_keep_destination(&self.destination)
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

fn valid_keep_destination(value: &str) -> bool {
    let remote = value.strip_prefix("oci://").is_some_and(|path| {
        !path.is_empty() && !path.bytes().any(|byte| byte.is_ascii_whitespace())
    });
    let layout = value
        .strip_prefix("oci-layout://")
        .map(|path| path.trim_end_matches('/'))
        .is_some_and(|identity| valid_destination_identity(identity, 128));
    remote || layout
}

fn valid_relative_path(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && !value.starts_with('/')
        && !value.split('/').any(|component| component == "..")
}

fn valid_destination_identity(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
        })
}

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
        if self.processing_mode != ProcessingMode::Managed {
            return Err(Error::schema_invalid());
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

fn valid_relative_path(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && !value.starts_with('/')
        && !value.split('/').any(|component| component == "..")
}

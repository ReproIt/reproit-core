use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    Error,
    identity::Digest,
    model::{Validate, valid_environment_name},
};

const MAX_ARGUMENTS: usize = 128;
const MAX_DEBUG_ARTIFACTS: usize = 4_096;
const MAX_ENVIRONMENT_NAMES: usize = 256;
const MAX_FILES: usize = 32_767;
const MAX_MODULES: usize = 4_096;
const MAX_OBJECTS: usize = 32_767;
const MAX_PATH_BYTES: usize = 4_096;
const MAX_SUBJECT_BYTES: u64 = 274_878_824_448;

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum SubjectClosureFormat {
    #[serde(rename = "reproit.subject-closure.v1")]
    V1,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SubjectRuntimeFamily {
    Dotnet,
    Go,
    Node,
    Python,
    Rust,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SubjectObjectKind {
    Application,
    DebugArtifact,
    LaunchData,
    ModuleIdentity,
    NativeDependency,
    Runtime,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DebugArtifactKind {
    Dwarf,
    InterpretedSourceIdentity,
    PortablePdb,
    SourceMap,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectClosureObject {
    pub digest: Digest,
    pub kind: SubjectObjectKind,
    pub media_type: String,
    pub size: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectFile {
    pub executable: bool,
    pub object_digest: Digest,
    pub path: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectModule {
    pub identity: String,
    pub module_digest: Digest,
    pub path: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugArtifactBinding {
    pub artifact_digest: Digest,
    pub kind: DebugArtifactKind,
    pub module_digest: Digest,
    pub path: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectLaunch {
    pub arguments: Vec<String>,
    pub environment_names: Vec<String>,
    pub executable: String,
    pub working_directory: String,
}

impl Validate for SubjectLaunch {
    fn validate(&self) -> Result<(), Error> {
        if self.arguments.len() > MAX_ARGUMENTS
            || self.arguments.iter().any(|argument| argument.len() > 4_096)
            || self.environment_names.len() > MAX_ENVIRONMENT_NAMES
            || !valid_absolute_subject_path(&self.executable)
            || !valid_absolute_subject_path(&self.working_directory)
            || !strictly_sorted(&self.environment_names)
            || self
                .environment_names
                .iter()
                .any(|name| !valid_environment_name(name))
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectClosureManifest {
    pub architecture: String,
    pub debug_artifacts: Vec<DebugArtifactBinding>,
    pub files: Vec<SubjectFile>,
    pub format: SubjectClosureFormat,
    pub launch: SubjectLaunch,
    pub modules: Vec<SubjectModule>,
    pub objects: Vec<SubjectClosureObject>,
    pub operating_system: String,
    pub runtime_family: SubjectRuntimeFamily,
    pub total_bytes: u64,
}

impl Validate for SubjectClosureManifest {
    fn validate(&self) -> Result<(), Error> {
        self.launch.validate()?;
        if self.objects.is_empty()
            || self.objects.len() > MAX_OBJECTS
            || self.files.is_empty()
            || self.files.len() > MAX_FILES
            || self.modules.is_empty()
            || self.modules.len() > MAX_MODULES
            || self.debug_artifacts.is_empty()
            || self.debug_artifacts.len() > MAX_DEBUG_ARTIFACTS
            || self.total_bytes > MAX_SUBJECT_BYTES
            || !valid_capability(&self.architecture)
            || !valid_capability(&self.operating_system)
        {
            return Err(Error::schema_invalid());
        }

        let objects = self.validate_objects()?;
        self.validate_files(&objects)?;
        let modules = self.validate_modules(&objects)?;
        self.validate_debug_artifacts(&objects, &modules)?;
        if !self
            .files
            .iter()
            .any(|file| file.path == self.launch.executable && file.executable)
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

impl SubjectClosureManifest {
    fn validate_objects(&self) -> Result<BTreeMap<Digest, SubjectObjectKind>, Error> {
        if !self
            .objects
            .windows(2)
            .all(|pair| pair[0].digest < pair[1].digest)
        {
            return Err(Error::schema_invalid());
        }
        let mut total_bytes = 0_u64;
        let mut objects = BTreeMap::new();
        for object in &self.objects {
            if object.size > MAX_SUBJECT_BYTES
                || object.media_type.is_empty()
                || object.media_type.len() > 128
            {
                return Err(Error::schema_invalid());
            }
            total_bytes = total_bytes
                .checked_add(object.size)
                .ok_or_else(Error::schema_invalid)?;
            if objects.insert(object.digest, object.kind).is_some() {
                return Err(Error::schema_invalid());
            }
        }
        if total_bytes != self.total_bytes {
            return Err(Error::schema_invalid());
        }
        Ok(objects)
    }

    fn validate_files(&self, objects: &BTreeMap<Digest, SubjectObjectKind>) -> Result<(), Error> {
        if !self
            .files
            .windows(2)
            .all(|pair| pair[0].path < pair[1].path)
        {
            return Err(Error::schema_invalid());
        }
        for file in &self.files {
            if !valid_absolute_subject_path(&file.path)
                || !objects.contains_key(&file.object_digest)
            {
                return Err(Error::schema_invalid());
            }
        }
        Ok(())
    }

    fn validate_modules(
        &self,
        objects: &BTreeMap<Digest, SubjectObjectKind>,
    ) -> Result<BTreeSet<Digest>, Error> {
        if !self
            .modules
            .windows(2)
            .all(|pair| pair[0].path < pair[1].path)
        {
            return Err(Error::schema_invalid());
        }
        let file_digests = self
            .files
            .iter()
            .map(|file| (file.path.as_str(), file.object_digest))
            .collect::<BTreeMap<_, _>>();
        let mut modules = BTreeSet::new();
        for module in &self.modules {
            if module.identity.is_empty()
                || module.identity.len() > 512
                || !valid_absolute_subject_path(&module.path)
                || file_digests.get(module.path.as_str()) != Some(&module.module_digest)
                || !objects.contains_key(&module.module_digest)
            {
                return Err(Error::schema_invalid());
            }
            modules.insert(module.module_digest);
        }
        Ok(modules)
    }

    fn validate_debug_artifacts(
        &self,
        objects: &BTreeMap<Digest, SubjectObjectKind>,
        modules: &BTreeSet<Digest>,
    ) -> Result<(), Error> {
        if !self
            .debug_artifacts
            .windows(2)
            .all(|pair| pair[0].path < pair[1].path)
        {
            return Err(Error::schema_invalid());
        }
        let files = self
            .files
            .iter()
            .map(|file| (file.path.as_str(), file.object_digest))
            .collect::<BTreeMap<_, _>>();
        for artifact in &self.debug_artifacts {
            let artifact_kind = objects.get(&artifact.artifact_digest);
            let valid_artifact_kind = match artifact.kind {
                DebugArtifactKind::InterpretedSourceIdentity => artifact_kind.is_some(),
                DebugArtifactKind::Dwarf if artifact.artifact_digest == artifact.module_digest => {
                    artifact_kind.is_some()
                }
                _ => artifact_kind == Some(&SubjectObjectKind::DebugArtifact),
            };
            if !valid_absolute_subject_path(&artifact.path)
                || files.get(artifact.path.as_str()) != Some(&artifact.artifact_digest)
                || !valid_artifact_kind
                || !modules.contains(&artifact.module_digest)
            {
                return Err(Error::schema_invalid());
            }
        }
        Ok(())
    }
}

fn strictly_sorted(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn valid_absolute_subject_path(path: &str) -> bool {
    let Some(relative) = path.strip_prefix("/reproit/subject/") else {
        return false;
    };
    !relative.is_empty()
        && path.len() <= MAX_PATH_BYTES
        && !path.as_bytes().contains(&0)
        && relative
            .split('/')
            .all(|part| !part.is_empty() && !matches!(part, "." | ".."))
}

fn valid_capability(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit() && index > 0
                || matches!(byte, b'.' | b'-') && index > 0
        })
}

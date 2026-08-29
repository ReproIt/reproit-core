use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    path::{Component, Path, PathBuf},
};

use reproit_core::{
    Error, ErrorCode, canonical,
    identity::Digest,
    model::{
        DebugArtifactBinding, DebugArtifactKind, Subject, SubjectClosureFormat,
        SubjectClosureManifest, SubjectClosureObject, SubjectFile, SubjectLaunch, SubjectModule,
        SubjectObjectKind, SubjectRuntimeFamily, Validate,
    },
};
use sha2::{Digest as _, Sha256};

use crate::world::verify_subject_artifact;

const COPY_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct SubjectPackagingLimits {
    pub maximum_file_bytes: u64,
    pub maximum_files: usize,
    pub maximum_total_bytes: u64,
}

impl SubjectPackagingLimits {
    pub const V1: Self = Self {
        maximum_file_bytes: 4 * 1024 * 1024 * 1024,
        maximum_files: 32_767,
        maximum_total_bytes: 256 * 1024 * 1024 * 1024,
    };

    fn validate(self) -> Result<(), Error> {
        if self.maximum_file_bytes == 0
            || self.maximum_file_bytes > self.maximum_total_bytes
            || self.maximum_files == 0
            || self.maximum_files > Self::V1.maximum_files
            || self.maximum_total_bytes > Self::V1.maximum_total_bytes
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SubjectPackagingRequest {
    pub application_root: PathBuf,
    pub architecture: String,
    pub arguments: Vec<String>,
    pub entrypoint: PathBuf,
    pub environment_names: Vec<String>,
    pub limits: SubjectPackagingLimits,
    pub operating_system: String,
    pub runtime_family: SubjectRuntimeFamily,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FrozenSubjectObject {
    pub digest: Digest,
    pub embedded_dwarf: bool,
    pub path: PathBuf,
    pub size: u64,
}

#[derive(Debug)]
pub struct FrozenSubjectClosure {
    pub manifest: SubjectClosureManifest,
    pub manifest_digest: Digest,
    pub objects: Vec<FrozenSubjectObject>,
    staging_root: PathBuf,
}

impl Drop for FrozenSubjectClosure {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.staging_root);
    }
}

pub fn freeze_running_subject(
    request: &SubjectPackagingRequest,
    staging_root: &Path,
) -> Result<FrozenSubjectClosure, Error> {
    request.limits.validate()?;
    validate_new_staging_root(staging_root)?;
    fs::create_dir(staging_root).map_err(|_| subject_unavailable())?;
    let mut guard = StagingGuard::new(staging_root);
    let files = discover_subject_files(request)?;
    let frozen = freeze_files(request, staging_root, &files)?;
    guard.disarm();
    Ok(frozen)
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct DiscoveredFile {
    debug_artifact_kind: Option<DebugArtifactKind>,
    kind: SubjectObjectKind,
    media_type: String,
    module: bool,
    source: PathBuf,
    target: String,
}

fn discover_subject_files(request: &SubjectPackagingRequest) -> Result<Vec<DiscoveredFile>, Error> {
    let root = canonical_regular_directory(&request.application_root)?;
    let entrypoint = canonical_regular_file(&request.entrypoint)?;
    let mut sources = BTreeSet::new();
    let mut files = Vec::new();

    match request.runtime_family {
        SubjectRuntimeFamily::Rust | SubjectRuntimeFamily::Go => {
            push_file(
                &mut files,
                &mut sources,
                entrypoint.clone(),
                executable_target(&entrypoint)?,
                SubjectObjectKind::Application,
                true,
            )?;
            discover_native_debug_artifacts(&entrypoint, &mut files, &mut sources)?;
        }
        SubjectRuntimeFamily::Dotnet
        | SubjectRuntimeFamily::Node
        | SubjectRuntimeFamily::Python => {
            collect_tree(request, &root, &root, &mut files, &mut sources)?;
            if !sources.contains(&entrypoint) {
                push_file(
                    &mut files,
                    &mut sources,
                    entrypoint.clone(),
                    executable_target(&entrypoint)?,
                    SubjectObjectKind::Runtime,
                    true,
                )?;
            }
        }
    }

    if current_executable_matches(&entrypoint)? {
        for dependency in loaded_native_dependencies(request.limits.maximum_files)? {
            if !sources.contains(&dependency) {
                push_file(
                    &mut files,
                    &mut sources,
                    dependency.clone(),
                    dependency_target(&dependency)?,
                    SubjectObjectKind::NativeDependency,
                    true,
                )?;
            }
        }
    }
    if files.is_empty() || files.len() > request.limits.maximum_files {
        return Err(subject_unbounded());
    }
    files.sort_by(|left, right| left.target.cmp(&right.target));
    if !files.windows(2).all(|pair| pair[0].target < pair[1].target) {
        return Err(subject_incomplete());
    }
    Ok(files)
}

fn collect_tree(
    request: &SubjectPackagingRequest,
    root: &Path,
    directory: &Path,
    files: &mut Vec<DiscoveredFile>,
    sources: &mut BTreeSet<PathBuf>,
) -> Result<(), Error> {
    let mut entries = fs::read_dir(directory)
        .map_err(|_| subject_unavailable())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| subject_unavailable())?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        if files.len() >= request.limits.maximum_files {
            return Err(subject_unbounded());
        }
        let metadata = fs::symlink_metadata(entry.path()).map_err(|_| subject_unavailable())?;
        if metadata.file_type().is_symlink() {
            return Err(subject_incomplete());
        }
        if metadata.is_dir() {
            collect_tree(request, root, &entry.path(), files, sources)?;
            continue;
        }
        if !metadata.is_file() {
            return Err(subject_incomplete());
        }
        let source = canonical_regular_file(&entry.path())?;
        let relative = source
            .strip_prefix(root)
            .map_err(|_| subject_incomplete())?;
        let target = normalized_target("app", relative)?;
        let debug_artifact_kind = debug_artifact_kind(&source)?;
        let (kind, module) =
            classify_application_file(request.runtime_family, &source, debug_artifact_kind);
        push_file(files, sources, source, target, kind, module)?;
    }
    Ok(())
}

fn push_file(
    files: &mut Vec<DiscoveredFile>,
    sources: &mut BTreeSet<PathBuf>,
    source: PathBuf,
    target: String,
    kind: SubjectObjectKind,
    module: bool,
) -> Result<(), Error> {
    if !sources.insert(source.clone()) {
        return Ok(());
    }
    let debug_artifact_kind = debug_artifact_kind(&source)?;
    files.push(DiscoveredFile {
        debug_artifact_kind,
        media_type: media_type(&source, kind, debug_artifact_kind),
        kind,
        module,
        source,
        target,
    });
    Ok(())
}

fn freeze_files(
    request: &SubjectPackagingRequest,
    staging_root: &Path,
    files: &[DiscoveredFile],
) -> Result<FrozenSubjectClosure, Error> {
    let entrypoint = canonical_regular_file(&request.entrypoint)?;
    let mut frozen = FrozenFileSet::new(files.len());
    for (index, discovered) in files.iter().enumerate() {
        let object = freeze_one_file(request.limits, staging_root, index, discovered)?;
        frozen.record(
            request,
            discovered,
            &object,
            discovered.source == entrypoint,
        )?;
    }
    bind_debug_artifacts(
        files,
        &frozen.files,
        &frozen.module_by_stem,
        &mut frozen.debug_artifacts,
    )?;
    frozen
        .modules
        .sort_by(|left, right| left.path.cmp(&right.path));
    frozen
        .debug_artifacts
        .sort_by(|left, right| left.path.cmp(&right.path));
    let executable = frozen
        .files
        .iter()
        .find(|file| file.executable)
        .map(|file| file.path.clone())
        .ok_or_else(subject_incomplete)?;
    let manifest = SubjectClosureManifest {
        architecture: request.architecture.clone(),
        debug_artifacts: frozen.debug_artifacts,
        files: frozen.files,
        format: SubjectClosureFormat::V1,
        launch: SubjectLaunch {
            arguments: request.arguments.clone(),
            environment_names: request.environment_names.clone(),
            executable,
            working_directory: "/reproit/subject/app".to_owned(),
        },
        modules: frozen.modules,
        objects: frozen.objects.values().cloned().collect(),
        operating_system: request.operating_system.clone(),
        runtime_family: request.runtime_family,
        total_bytes: frozen.total_bytes,
    };
    manifest.validate()?;
    let manifest_digest = canonical::digest(&manifest)?;
    Ok(FrozenSubjectClosure {
        manifest,
        manifest_digest,
        objects: frozen.frozen_objects.into_values().collect(),
        staging_root: staging_root.to_owned(),
    })
}

struct FrozenFileSet {
    debug_artifacts: Vec<DebugArtifactBinding>,
    files: Vec<SubjectFile>,
    frozen_objects: BTreeMap<Digest, FrozenSubjectObject>,
    module_by_stem: BTreeMap<String, Digest>,
    modules: Vec<SubjectModule>,
    objects: BTreeMap<Digest, SubjectClosureObject>,
    total_bytes: u64,
}

impl FrozenFileSet {
    fn new(file_count: usize) -> Self {
        Self {
            debug_artifacts: Vec::new(),
            files: Vec::with_capacity(file_count),
            frozen_objects: BTreeMap::new(),
            module_by_stem: BTreeMap::new(),
            modules: Vec::new(),
            objects: BTreeMap::new(),
            total_bytes: 0,
        }
    }

    fn record(
        &mut self,
        request: &SubjectPackagingRequest,
        discovered: &DiscoveredFile,
        frozen: &FrozenSubjectObject,
        executable: bool,
    ) -> Result<(), Error> {
        let object = SubjectClosureObject {
            digest: frozen.digest,
            kind: discovered.kind,
            media_type: discovered.media_type.clone(),
            size: frozen.size,
        };
        if let Some(existing) = self.objects.get(&frozen.digest) {
            if existing != &object {
                return Err(subject_incomplete());
            }
        } else {
            self.total_bytes = self
                .total_bytes
                .checked_add(frozen.size)
                .filter(|total| *total <= request.limits.maximum_total_bytes)
                .ok_or_else(subject_unbounded)?;
            self.objects.insert(frozen.digest, object);
            self.frozen_objects.insert(frozen.digest, frozen.clone());
        }
        self.files.push(SubjectFile {
            executable,
            object_digest: frozen.digest,
            path: discovered.target.clone(),
        });
        if discovered.module {
            self.record_module(request.runtime_family, discovered, frozen.digest)?;
            if frozen.embedded_dwarf {
                self.debug_artifacts.push(DebugArtifactBinding {
                    artifact_digest: frozen.digest,
                    kind: DebugArtifactKind::Dwarf,
                    module_digest: frozen.digest,
                    path: discovered.target.clone(),
                });
            }
        }
        Ok(())
    }

    fn record_module(
        &mut self,
        runtime_family: SubjectRuntimeFamily,
        discovered: &DiscoveredFile,
        digest: Digest,
    ) -> Result<(), Error> {
        self.modules.push(SubjectModule {
            identity: digest.to_string(),
            module_digest: digest,
            path: discovered.target.clone(),
        });
        let stem = file_stem(&discovered.source)?;
        if let Some(existing) = self.module_by_stem.insert(stem, digest)
            && existing != digest
        {
            return Err(subject_incomplete());
        }
        if matches!(
            runtime_family,
            SubjectRuntimeFamily::Node | SubjectRuntimeFamily::Python
        ) && is_interpreted_source(&discovered.source)
        {
            self.debug_artifacts.push(DebugArtifactBinding {
                artifact_digest: digest,
                kind: DebugArtifactKind::InterpretedSourceIdentity,
                module_digest: digest,
                path: discovered.target.clone(),
            });
        }
        Ok(())
    }
}

fn freeze_one_file(
    limits: SubjectPackagingLimits,
    staging_root: &Path,
    index: usize,
    discovered: &DiscoveredFile,
) -> Result<FrozenSubjectObject, Error> {
    let before = fs::metadata(&discovered.source).map_err(|_| subject_unavailable())?;
    if !before.is_file() || before.len() > limits.maximum_file_bytes {
        return Err(subject_unbounded());
    }
    let temporary = staging_root.join(format!("object-{index:05}.partial"));
    let mut source = File::open(&discovered.source).map_err(|_| subject_unavailable())?;
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(|_| subject_unavailable())?;
    let mut hasher = Sha256::new();
    let copied = copy_bounded(
        &mut source,
        &mut output,
        &mut hasher,
        limits.maximum_file_bytes,
    )?;
    output.sync_all().map_err(|_| subject_unavailable())?;
    drop(output);
    let after = fs::metadata(&discovered.source).map_err(|_| subject_unavailable())?;
    if copied != before.len()
        || before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
    {
        return Err(subject_changed());
    }
    let digest = Digest::from_bytes(hasher.finalize().into());
    if hash_file(&discovered.source, limits.maximum_file_bytes)? != (digest, copied) {
        return Err(subject_changed());
    }
    let final_path = staging_root.join(digest.to_string().replace(':', "-"));
    if final_path.exists() {
        if hash_file(&final_path, limits.maximum_file_bytes)? != (digest, copied) {
            return Err(subject_changed());
        }
        fs::remove_file(&temporary).map_err(|_| subject_unavailable())?;
    } else {
        fs::rename(&temporary, &final_path).map_err(|_| subject_unavailable())?;
        set_file_read_only(&final_path)?;
    }
    Ok(FrozenSubjectObject {
        digest,
        embedded_dwarf: discovered.module && contains_embedded_dwarf(&final_path)?,
        path: final_path,
        size: copied,
    })
}

fn discover_native_debug_artifacts(
    entrypoint: &Path,
    files: &mut Vec<DiscoveredFile>,
    sources: &mut BTreeSet<PathBuf>,
) -> Result<(), Error> {
    let name = entrypoint
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(subject_incomplete)?;
    let adjacent = [
        entrypoint.with_file_name(format!("{name}.debug")),
        entrypoint.with_file_name(format!("{name}.dwp")),
        entrypoint.with_extension("pdb"),
    ];
    for adjacent in adjacent {
        match fs::symlink_metadata(&adjacent) {
            Ok(metadata)
                if metadata.file_type().is_file() && !metadata.file_type().is_symlink() =>
            {
                let source = canonical_regular_file(&adjacent)?;
                push_file(
                    files,
                    sources,
                    source.clone(),
                    normalized_target(
                        "debug",
                        Path::new(source.file_name().ok_or_else(subject_incomplete)?),
                    )?,
                    SubjectObjectKind::DebugArtifact,
                    false,
                )?;
            }
            Ok(_) => return Err(subject_incomplete()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(subject_unavailable()),
        }
    }
    Ok(())
}

fn contains_embedded_dwarf(path: &Path) -> Result<bool, Error> {
    let mut file = File::open(path).map_err(|_| subject_unavailable())?;
    let mut prefix = [0_u8; 4];
    if file.read_exact(&mut prefix).is_err() || prefix != [0x7f, b'E', b'L', b'F'] {
        return Ok(false);
    }
    let markers: [&[u8]; 2] = [b".debug_info", b".zdebug_info"];
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES + 16];
    let mut retained = 0_usize;
    loop {
        let read = file
            .read(&mut buffer[retained..])
            .map_err(|_| subject_unavailable())?;
        let length = retained + read;
        if markers.iter().any(|marker| {
            buffer[..length]
                .windows(marker.len())
                .any(|value| value == *marker)
        }) {
            return Ok(true);
        }
        if read == 0 {
            return Ok(false);
        }
        retained = length.min(15);
        buffer.copy_within(length - retained..length, 0);
    }
}

fn copy_bounded(
    source: &mut File,
    output: &mut impl std::io::Write,
    hasher: &mut Sha256,
    maximum_bytes: u64,
) -> Result<u64, Error> {
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES].into_boxed_slice();
    let mut total = 0_u64;
    loop {
        let read = source
            .read(&mut buffer)
            .map_err(|_| subject_unavailable())?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).map_err(|_| subject_unbounded())?)
            .filter(|value| *value <= maximum_bytes)
            .ok_or_else(subject_unbounded)?;
        hasher.update(&buffer[..read]);
        output
            .write_all(&buffer[..read])
            .map_err(|_| subject_unavailable())?;
    }
    Ok(total)
}

fn hash_file(path: &Path, maximum_bytes: u64) -> Result<(Digest, u64), Error> {
    let mut source = File::open(path).map_err(|_| subject_unavailable())?;
    let mut sink = std::io::sink();
    let mut hasher = Sha256::new();
    let size = copy_bounded(&mut source, &mut sink, &mut hasher, maximum_bytes)?;
    Ok((Digest::from_bytes(hasher.finalize().into()), size))
}

fn bind_debug_artifacts(
    discovered: &[DiscoveredFile],
    subject_files: &[SubjectFile],
    module_by_stem: &BTreeMap<String, Digest>,
    bindings: &mut Vec<DebugArtifactBinding>,
) -> Result<(), Error> {
    for (source, file) in discovered.iter().zip(subject_files) {
        let Some(kind) = source.debug_artifact_kind else {
            continue;
        };
        let stem = debug_module_stem(&source.source)?;
        let module_digest = module_by_stem
            .get(&stem)
            .or_else(|| {
                module_by_stem
                    .values()
                    .next()
                    .filter(|_| module_by_stem.len() == 1)
            })
            .copied()
            .ok_or_else(subject_incomplete)?;
        bindings.push(DebugArtifactBinding {
            artifact_digest: file.object_digest,
            kind,
            module_digest,
            path: file.path.clone(),
        });
    }
    Ok(())
}

fn classify_application_file(
    runtime: SubjectRuntimeFamily,
    path: &Path,
    debug_artifact_kind: Option<DebugArtifactKind>,
) -> (SubjectObjectKind, bool) {
    if debug_artifact_kind.is_some() {
        return (SubjectObjectKind::DebugArtifact, false);
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    if name.ends_with(".deps.json")
        || name.ends_with(".runtimeconfig.json")
        || matches!(name, "package-lock.json" | "pnpm-lock.yaml" | "yarn.lock")
    {
        return (SubjectObjectKind::LaunchData, false);
    }
    let module = match runtime {
        SubjectRuntimeFamily::Dotnet => matches!(extension(path), "dll" | "exe"),
        SubjectRuntimeFamily::Node => matches!(extension(path), "cjs" | "js" | "mjs" | "node"),
        SubjectRuntimeFamily::Python => matches!(extension(path), "py" | "pyc" | "so"),
        SubjectRuntimeFamily::Go | SubjectRuntimeFamily::Rust => true,
    };
    (SubjectObjectKind::Application, module)
}

fn debug_artifact_kind(path: &Path) -> Result<Option<DebugArtifactKind>, Error> {
    let Some(extension) = path.extension().and_then(|value| value.to_str()) else {
        return Ok(None);
    };
    if extension.eq_ignore_ascii_case("pdb") {
        classify_pdb(path).map(Some)
    } else if extension.eq_ignore_ascii_case("map") {
        Ok(Some(DebugArtifactKind::SourceMap))
    } else if extension.eq_ignore_ascii_case("debug") || extension.eq_ignore_ascii_case("dwp") {
        Ok(Some(DebugArtifactKind::Dwarf))
    } else {
        Ok(None)
    }
}

fn classify_pdb(path: &Path) -> Result<DebugArtifactKind, Error> {
    const NATIVE_PDB_SIGNATURE: &[u8; 32] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0";

    let mut file = File::open(path).map_err(|_| subject_unavailable())?;
    let mut prefix = [0_u8; 32];
    read_pdb_prefix(&mut file, &mut prefix[..4])?;
    if prefix.starts_with(b"BSJB") {
        return Ok(DebugArtifactKind::PortablePdb);
    }
    read_pdb_prefix(&mut file, &mut prefix[4..])?;
    if &prefix == NATIVE_PDB_SIGNATURE {
        return Ok(DebugArtifactKind::NativePdb);
    }
    Err(subject_incomplete())
}

fn read_pdb_prefix(file: &mut File, buffer: &mut [u8]) -> Result<(), Error> {
    file.read_exact(buffer).map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            subject_incomplete()
        } else {
            subject_unavailable()
        }
    })
}

fn debug_module_stem(path: &Path) -> Result<String, Error> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(subject_incomplete)?;
    let stem = [".pdb", ".map", ".debug", ".dwp"]
        .iter()
        .find_map(|suffix| strip_suffix_ascii_case(name, suffix))
        .ok_or_else(subject_incomplete)?;
    Ok(stem.trim_end_matches(".js").to_owned())
}

fn strip_suffix_ascii_case<'a>(value: &'a str, suffix: &str) -> Option<&'a str> {
    let suffix_start = value.len().checked_sub(suffix.len())?;
    value
        .get(suffix_start..)?
        .eq_ignore_ascii_case(suffix)
        .then(|| value.get(..suffix_start))?
}

fn file_stem(path: &Path) -> Result<String, Error> {
    path.file_stem()
        .and_then(|value| value.to_str())
        .map(str::to_owned)
        .ok_or_else(subject_incomplete)
}

fn is_interpreted_source(path: &Path) -> bool {
    matches!(extension(path), "cjs" | "js" | "mjs" | "py")
}

fn extension(path: &Path) -> &str {
    path.extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
}

fn media_type(
    path: &Path,
    kind: SubjectObjectKind,
    debug_artifact_kind: Option<DebugArtifactKind>,
) -> String {
    match (kind, debug_artifact_kind, extension(path)) {
        (SubjectObjectKind::DebugArtifact, Some(DebugArtifactKind::NativePdb), _) => {
            "application/vnd.reproit.native-pdb.v1"
        }
        (SubjectObjectKind::DebugArtifact, Some(DebugArtifactKind::PortablePdb), _) => {
            "application/vnd.reproit.portable-pdb.v1"
        }
        (SubjectObjectKind::DebugArtifact, Some(DebugArtifactKind::SourceMap), _) => {
            "application/vnd.reproit.source-map.v1"
        }
        (SubjectObjectKind::DebugArtifact, _, _) => "application/vnd.reproit.dwarf.v1",
        (SubjectObjectKind::LaunchData, _, _) => "application/vnd.reproit.launch-data.v1+json",
        (SubjectObjectKind::NativeDependency, _, _) => "application/vnd.reproit.native-library.v1",
        (SubjectObjectKind::Runtime, _, _) => "application/vnd.reproit.runtime.v1",
        (_, _, "py" | "js" | "mjs" | "cjs") => "text/plain",
        _ => "application/vnd.reproit.subject-file.v1",
    }
    .to_owned()
}

fn canonical_regular_directory(path: &Path) -> Result<PathBuf, Error> {
    let metadata = fs::symlink_metadata(path).map_err(|_| subject_unavailable())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(subject_incomplete());
    }
    fs::canonicalize(path).map_err(|_| subject_unavailable())
}

fn canonical_regular_file(path: &Path) -> Result<PathBuf, Error> {
    let metadata = fs::symlink_metadata(path).map_err(|_| subject_unavailable())?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(subject_incomplete());
    }
    fs::canonicalize(path).map_err(|_| subject_unavailable())
}

fn validate_new_staging_root(path: &Path) -> Result<(), Error> {
    if path.as_os_str().is_empty() || path.exists() {
        return Err(Error::schema_invalid());
    }
    let parent = path.parent().ok_or_else(Error::schema_invalid)?;
    let metadata = fs::symlink_metadata(parent).map_err(|_| subject_unavailable())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(subject_unavailable());
    }
    Ok(())
}

fn executable_target(path: &Path) -> Result<String, Error> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(subject_incomplete)?;
    normalized_target("bin", Path::new(name))
}

fn dependency_target(path: &Path) -> Result<String, Error> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(subject_incomplete)?;
    let digest = Digest::of(path.as_os_str().as_encoded_bytes()).to_string();
    let prefix = digest.get(7..19).ok_or_else(subject_incomplete)?;
    normalized_target("lib", Path::new(&format!("{prefix}-{name}")))
}

fn normalized_target(section: &str, relative: &Path) -> Result<String, Error> {
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(value) => {
                let value = value.to_str().ok_or_else(subject_incomplete)?;
                if value.is_empty() || value.len() > 255 {
                    return Err(subject_incomplete());
                }
                parts.push(value);
            }
            _ => return Err(subject_incomplete()),
        }
    }
    if parts.is_empty() {
        return Err(subject_incomplete());
    }
    let target = format!("/reproit/subject/{section}/{}", parts.join("/"));
    if target.len() > 4_096 {
        return Err(subject_unbounded());
    }
    Ok(target)
}

fn current_executable_matches(entrypoint: &Path) -> Result<bool, Error> {
    let current = std::env::current_exe().map_err(|_| subject_unavailable())?;
    Ok(fs::canonicalize(current).map_err(|_| subject_unavailable())? == entrypoint)
}

#[cfg(target_os = "linux")]
fn loaded_native_dependencies(maximum_files: usize) -> Result<Vec<PathBuf>, Error> {
    let text = fs::read_to_string("/proc/self/maps").map_err(|_| subject_unavailable())?;
    if text.len() > 16 * 1024 * 1024 {
        return Err(subject_unbounded());
    }
    let mut paths = BTreeSet::new();
    for line in text.lines() {
        let Some(path) = line.split_whitespace().last() else {
            continue;
        };
        if !path.starts_with('/') || path.ends_with(" (deleted)") {
            continue;
        }
        paths.insert(canonical_regular_file(Path::new(path))?);
        if paths.len() > maximum_files {
            return Err(subject_unbounded());
        }
    }
    Ok(paths.into_iter().collect())
}

#[cfg(not(target_os = "linux"))]
// The platform variants share one fallible interface.
#[allow(clippy::unnecessary_wraps)]
fn loaded_native_dependencies(_maximum_files: usize) -> Result<Vec<PathBuf>, Error> {
    Ok(Vec::new())
}

fn set_file_read_only(path: &Path) -> Result<(), Error> {
    let mut permissions = fs::metadata(path)
        .map_err(|_| subject_unavailable())?
        .permissions();
    permissions.set_readonly(true);
    fs::set_permissions(path, permissions).map_err(|_| subject_unavailable())
}

struct StagingGuard {
    armed: bool,
    path: PathBuf,
}

impl StagingGuard {
    fn new(path: &Path) -> Self {
        Self {
            armed: true,
            path: path.to_owned(),
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for StagingGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn subject_incomplete() -> Error {
    Error::new(
        ErrorCode::IncompleteCandidate,
        "Repro It could not build a complete subject package. Ensure that every required file is present.",
    )
}

fn subject_changed() -> Error {
    Error::new(
        ErrorCode::SubjectDigestMismatch,
        "The subject changed during packaging. Restart the deployed application before capture.",
    )
}

fn subject_unbounded() -> Error {
    Error::new(
        ErrorCode::UploadLimitExceeded,
        "The subject package exceeds a capture limit. Reduce the deployed subject closure.",
    )
}

fn subject_unavailable() -> Error {
    Error::new(
        ErrorCode::ArtifactNotFound,
        "Repro It could not read the deployed subject. Check file access and try again.",
    )
}

pub fn transfer_file_subject(
    subject: &Subject,
    target: &Path,
    maximum_bytes: usize,
) -> Result<Vec<u8>, Error> {
    if maximum_bytes == 0 || target.as_os_str().is_empty() || target.exists() {
        return Err(Error::schema_invalid());
    }
    let source = file_uri_path(&subject.artifact_uri)?;
    if source == target {
        return Err(Error::schema_invalid());
    }
    let metadata = fs::symlink_metadata(&source).map_err(|_| not_found())?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || usize::try_from(metadata.len()).map_or(true, |size| size > maximum_bytes)
    {
        return Err(not_found());
    }
    let bytes = fs::read(&source).map_err(|_| not_found())?;
    verify_subject_artifact(&bytes, subject.artifact_digest, maximum_bytes)?;
    write_immutable(target, &bytes)?;
    Ok(bytes)
}

fn file_uri_path(uri: &str) -> Result<PathBuf, Error> {
    let value = uri.strip_prefix("file://").ok_or_else(|| {
        Error::new(
            ErrorCode::Unsupported,
            "The subject artifact URI scheme is not supported.",
        )
    })?;
    if !value.starts_with('/')
        || value.contains(['?', '#', '%'])
        || value.as_bytes().contains(&0)
        || value.len() > 2_048
    {
        return Err(Error::schema_invalid());
    }
    Ok(PathBuf::from(value))
}

fn write_immutable(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let parent = path.parent().ok_or_else(Error::schema_invalid)?;
    let metadata = fs::symlink_metadata(parent).map_err(|_| unavailable())?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(unavailable());
    }
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    set_read_only_mode(&mut options);
    let mut file = options.open(path).map_err(|_| unavailable())?;
    if file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .is_err()
    {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(unavailable());
    }
    Ok(())
}

#[cfg(unix)]
fn set_read_only_mode(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt as _;
    options.mode(0o500);
}

#[cfg(not(unix))]
fn set_read_only_mode(_options: &mut OpenOptions) {}

fn not_found() -> Error {
    Error::new(
        ErrorCode::ArtifactNotFound,
        "The subject artifact is not available from its declared source.",
    )
}

fn unavailable() -> Error {
    Error::new(
        ErrorCode::ServiceUnavailable,
        "The subject artifact transfer is unavailable.",
    )
}

/// Canonical replay paths for the private single-file subject closure. The
/// deployment identity digest binds a manifest built with these exact paths,
/// so every producer and verifier must use the same constants.
pub const SINGLE_FILE_EXECUTABLE_PATH: &str = "/reproit/subject/bin/subject";
pub const SINGLE_FILE_DEBUG_PATH: &str = "/reproit/subject/debug/subject.debug";
pub const SINGLE_FILE_MEDIA_TYPE: &str = "application/vnd.reproit.subject-file.v1";
pub const SINGLE_FILE_DEBUG_MEDIA_TYPE: &str = "application/vnd.reproit.dwarf.v1";

/// Build the canonical subject-closure manifest for one private single-file
/// subject. The launch record mirrors the deployment subject descriptor, so
/// the resolver finds exact agreement between the capsule subject and the
/// manifest. The debug artifact is required because the manifest validator
/// requires one debug-artifact binding for the executable module.
pub fn single_file_subject_closure(
    subject: &Subject,
    binary: &[u8],
    debug_artifact: &[u8],
    family: SubjectRuntimeFamily,
) -> Result<SubjectClosureManifest, Error> {
    let binary_size = u64::try_from(binary.len()).map_err(|_| subject_incomplete())?;
    let debug_size = u64::try_from(debug_artifact.len()).map_err(|_| subject_incomplete())?;
    let binary_digest = Digest::of(binary);
    let debug_digest = Digest::of(debug_artifact);
    let mut objects = vec![
        SubjectClosureObject {
            digest: binary_digest,
            kind: SubjectObjectKind::Application,
            media_type: SINGLE_FILE_MEDIA_TYPE.to_owned(),
            size: binary_size,
        },
        SubjectClosureObject {
            digest: debug_digest,
            kind: SubjectObjectKind::DebugArtifact,
            media_type: SINGLE_FILE_DEBUG_MEDIA_TYPE.to_owned(),
            size: debug_size,
        },
    ];
    objects.sort_by_key(|object| object.digest);
    let manifest = SubjectClosureManifest {
        architecture: subject.architecture.clone(),
        debug_artifacts: vec![DebugArtifactBinding {
            artifact_digest: debug_digest,
            kind: DebugArtifactKind::Dwarf,
            module_digest: binary_digest,
            path: SINGLE_FILE_DEBUG_PATH.to_owned(),
        }],
        files: vec![
            SubjectFile {
                executable: true,
                object_digest: binary_digest,
                path: SINGLE_FILE_EXECUTABLE_PATH.to_owned(),
            },
            SubjectFile {
                executable: false,
                object_digest: debug_digest,
                path: SINGLE_FILE_DEBUG_PATH.to_owned(),
            },
        ],
        format: SubjectClosureFormat::V1,
        launch: SubjectLaunch {
            arguments: subject.arguments.clone(),
            environment_names: subject.environment_names.clone(),
            executable: subject.executable.clone(),
            working_directory: subject.working_directory.clone(),
        },
        modules: vec![SubjectModule {
            identity: binary_digest.to_string(),
            module_digest: binary_digest,
            path: SINGLE_FILE_EXECUTABLE_PATH.to_owned(),
        }],
        objects,
        operating_system: subject.operating_system.clone(),
        runtime_family: family,
        total_bytes: binary_size
            .checked_add(debug_size)
            .ok_or_else(subject_incomplete)?,
    };
    manifest.validate()?;
    Ok(manifest)
}

/// Verify that the single-file subject bytes still bind the sealed deployment
/// identity. A replaced or modified binary changes the manifest digest, so
/// this check fails closed with the exact spec error for a subject that no
/// longer matches its sealed binding.
pub fn verify_single_file_subject(
    subject: &Subject,
    binary: &[u8],
    debug_artifact: &[u8],
    family: SubjectRuntimeFamily,
) -> Result<SubjectClosureManifest, Error> {
    let manifest = single_file_subject_closure(subject, binary, debug_artifact, family)?;
    if canonical::digest(&manifest)? != subject.artifact_digest {
        return Err(Error::new(
            ErrorCode::SubjectDigestMismatch,
            "The subject artifact does not match the sealed capsule.",
        ));
    }
    Ok(manifest)
}

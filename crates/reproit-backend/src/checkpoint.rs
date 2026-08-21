use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
    str::FromStr as _,
    sync::{Mutex, PoisonError},
};

use reproit_core::{
    Error, ErrorCode, canonical,
    identity::{CaptureId, Digest, ExecutionId, LeaseId, ServiceId, Timestamp},
    model::{ProviderResourceClaim, Validate},
    resource_model::{ProviderCapacity, ProviderReservationModel, ProviderServiceCapacity},
};
use serde::Serialize;

use crate::world::{
    CheckpointScope, ProviderLease, ProviderMaterialization, ProviderVerification,
    RecoverablePoint, StateProvider,
};

const LOCK_FILE: &str = "checkpoint-provider.lock";

#[derive(Debug, Clone)]
pub struct FileCheckpointConfig {
    pub engine_identity: String,
    pub engine_version: String,
    pub history_root: PathBuf,
    pub maximum_active_leases: usize,
    pub maximum_checkpoint_bytes: u64,
    pub maximum_resource_claim: ProviderResourceClaim,
    pub provider_id: String,
    pub service_id: ServiceId,
    pub workspace_root: PathBuf,
}

impl FileCheckpointConfig {
    pub fn production(
        history_root: PathBuf,
        workspace_root: PathBuf,
        provider_id: String,
        service_id: ServiceId,
        engine_identity: String,
        engine_version: String,
    ) -> Self {
        let aggregate_bytes = maximum_aggregate(maximum_checkpoint_bytes(), 64);
        Self {
            engine_identity,
            engine_version,
            history_root,
            maximum_active_leases: 64,
            maximum_checkpoint_bytes: maximum_checkpoint_bytes(),
            maximum_resource_claim: ProviderResourceClaim {
                materialized_bytes: aggregate_bytes,
                objects: 64,
                pinned_bytes: aggregate_bytes,
                temporary_bytes: aggregate_bytes,
            },
            provider_id,
            service_id,
            workspace_root,
        }
    }

    fn validate(&self) -> Result<(), Error> {
        if !self.history_root.is_absolute()
            || !self.workspace_root.is_absolute()
            || self.history_root == self.workspace_root
            || !valid_component_id(&self.provider_id)
            || self.engine_identity.is_empty()
            || self.engine_identity.len() > 256
            || self.engine_version.is_empty()
            || self.engine_version.len() > 128
            || self.maximum_active_leases == 0
            || self.maximum_active_leases > 1024
            || self.maximum_checkpoint_bytes == 0
        {
            return Err(Error::schema_invalid());
        }
        self.maximum_resource_claim.validate()?;
        Ok(())
    }
}

pub struct FileCheckpointProvider {
    config: FileCheckpointConfig,
    configuration_digest: Digest,
    leases: Mutex<BTreeMap<LeaseId, ActiveLease>>,
    _lock: File,
}

struct ActiveLease {
    artifact: PathBuf,
    execution_targets: BTreeMap<ExecutionId, PathBuf>,
    lease: ProviderLease,
    resource_claim: ProviderResourceClaim,
}

#[derive(Serialize)]
struct ConfigurationIdentity<'a> {
    engine_identity: &'a str,
    engine_version: &'a str,
    maximum_active_leases: usize,
    maximum_checkpoint_bytes: u64,
    maximum_resource_claim: &'a ProviderResourceClaim,
    provider_id: &'a str,
    service_id: ServiceId,
}

#[derive(Serialize)]
struct PointIdentity<'a> {
    artifact_digest: Digest,
    configuration_digest: Digest,
    generation: u64,
    provider_id: &'a str,
    published_at: &'a Timestamp,
    recoverable_until: &'a Timestamp,
}

impl FileCheckpointProvider {
    pub fn open(config: FileCheckpointConfig) -> Result<Self, Error> {
        config.validate()?;
        create_private_directory(&config.history_root)?;
        let lock = open_lock(&config.history_root.join(LOCK_FILE))?;
        lock.try_lock().map_err(|_| unavailable())?;
        create_private_directory(&config.workspace_root)?;
        clear_workspace(&config.workspace_root)?;
        let configuration_digest = canonical::digest(&ConfigurationIdentity {
            engine_identity: &config.engine_identity,
            engine_version: &config.engine_version,
            maximum_active_leases: config.maximum_active_leases,
            maximum_checkpoint_bytes: config.maximum_checkpoint_bytes,
            maximum_resource_claim: &config.maximum_resource_claim,
            provider_id: &config.provider_id,
            service_id: config.service_id,
        })?;
        Ok(Self {
            config,
            configuration_digest,
            leases: Mutex::new(BTreeMap::new()),
            _lock: lock,
        })
    }

    pub fn publish(
        &self,
        source: &Path,
        generation: u64,
        published_at: Timestamp,
        recoverable_until: Timestamp,
    ) -> Result<RecoverablePoint, Error> {
        if generation == 0 || published_at > recoverable_until {
            return Err(Error::schema_invalid());
        }
        let bytes = read_checkpoint(source, self.config.maximum_checkpoint_bytes)?;
        let digest = Digest::of(&bytes);
        let artifact = self.artifact_path(digest);
        if artifact.exists() {
            if read_checkpoint(&artifact, self.config.maximum_checkpoint_bytes)? != bytes {
                return Err(Error::object_digest_mismatch());
            }
        } else {
            write_read_only(&artifact, &bytes)?;
        }
        let point_digest = canonical::digest(&PointIdentity {
            artifact_digest: digest,
            configuration_digest: self.configuration_digest,
            generation,
            provider_id: &self.config.provider_id,
            published_at: &published_at,
            recoverable_until: &recoverable_until,
        })?;
        Ok(RecoverablePoint {
            artifacts: BTreeMap::from([(
                digest,
                u64::try_from(bytes.len()).map_err(|_| Error::schema_invalid())?,
            )]),
            capabilities: std::collections::BTreeSet::from(["checkpoint.file".to_owned()]),
            configuration_digest: self.configuration_digest,
            engine_identity: self.config.engine_identity.clone(),
            engine_version: self.config.engine_version.clone(),
            generation,
            point_digest,
            provider_id: self.config.provider_id.clone(),
            published_at,
            recoverable_until,
            resource_claim: ProviderResourceClaim {
                materialized_bytes: u64::try_from(bytes.len())
                    .map_err(|_| Error::schema_invalid())?,
                objects: 1,
                pinned_bytes: u64::try_from(bytes.len()).map_err(|_| Error::schema_invalid())?,
                temporary_bytes: u64::try_from(bytes.len()).map_err(|_| Error::schema_invalid())?,
            },
            scope: CheckpointScope::Full,
        })
    }

    fn artifact_path(&self, digest: Digest) -> PathBuf {
        self.config.history_root.join(format!(
            "{}.checkpoint",
            digest.to_string().trim_start_matches("sha256:")
        ))
    }
}

impl StateProvider for FileCheckpointProvider {
    fn pin(
        &self,
        point: &RecoverablePoint,
        capture_id: CaptureId,
        world_id: Digest,
    ) -> Result<ProviderLease, Error> {
        if point.provider_id != self.config.provider_id
            || point.configuration_digest != self.configuration_digest
            || point.scope != CheckpointScope::Full
            || point.artifacts.len() != 1
        {
            return Err(provider_missing());
        }
        point.resource_claim.validate()?;
        let (&digest, &size) = point
            .artifacts
            .first_key_value()
            .ok_or_else(provider_missing)?;
        if size > self.config.maximum_checkpoint_bytes {
            return Err(provider_missing());
        }
        if size > point.resource_claim.pinned_bytes || point.resource_claim.objects < 1 {
            return Err(quota());
        }
        let artifact = self.artifact_path(digest);
        let lease_id = lease_id(capture_id, point.point_digest, world_id)?;
        let lease = ProviderLease {
            capture_id,
            expires_at: point.recoverable_until.clone(),
            lease_id,
            point_digest: point.point_digest,
            provider_id: point.provider_id.clone(),
            world_id,
        };
        let mut leases = self.leases.lock().unwrap_or_else(PoisonError::into_inner);
        if leases.len() >= self.config.maximum_active_leases && !leases.contains_key(&lease_id) {
            return Err(quota());
        }
        if let Some(active) = leases.get(&lease_id) {
            return if active.lease == lease {
                Ok(lease)
            } else {
                Err(Error::schema_invalid())
            };
        }
        reserve_claim(
            &self.config,
            leases.values(),
            lease_id,
            &point.resource_claim,
        )?;
        leases.insert(
            lease_id,
            ActiveLease {
                artifact: artifact.clone(),
                execution_targets: BTreeMap::new(),
                lease: lease.clone(),
                resource_claim: point.resource_claim.clone(),
            },
        );
        drop(leases);
        let verified = read_checkpoint(&artifact, self.config.maximum_checkpoint_bytes)
            .is_ok_and(|bytes| Digest::of(&bytes) == digest);
        if !verified {
            self.leases
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&lease_id);
            return Err(Error::object_digest_mismatch());
        }
        Ok(lease)
    }

    fn materialize(
        &self,
        lease: &ProviderLease,
        execution_id: ExecutionId,
        target_reference: &str,
    ) -> Result<ProviderMaterialization, Error> {
        let target = PathBuf::from(target_reference);
        if !target.is_absolute() || target.parent() != Some(self.config.workspace_root.as_path()) {
            return Err(Error::new(
                ErrorCode::StateScopeViolation,
                "The checkpoint target is outside the provider workspace.",
            ));
        }
        let mut leases = self.leases.lock().unwrap_or_else(PoisonError::into_inner);
        let active = leases
            .get_mut(&lease.lease_id)
            .ok_or_else(provider_missing)?;
        if active.lease != *lease || active.execution_targets.contains_key(&execution_id) {
            return Err(Error::schema_invalid());
        }
        let bytes = read_checkpoint(&active.artifact, self.config.maximum_checkpoint_bytes)?;
        let bytes_len = u64::try_from(bytes.len()).map_err(|_| quota())?;
        if bytes_len > active.resource_claim.materialized_bytes
            || bytes_len > active.resource_claim.temporary_bytes
        {
            return Err(quota());
        }
        let parent = target.parent().ok_or_else(Error::schema_invalid)?;
        create_private_directory(parent)?;
        write_private(&target, &bytes)?;
        let evidence_digest = Digest::of(&bytes);
        active.execution_targets.insert(execution_id, target);
        Ok(ProviderMaterialization {
            evidence_digest,
            execution_id,
            lease_id: lease.lease_id,
            provider_id: lease.provider_id.clone(),
        })
    }

    fn verify(
        &self,
        lease: &ProviderLease,
        materialization: &ProviderMaterialization,
    ) -> Result<ProviderVerification, Error> {
        let leases = self.leases.lock().unwrap_or_else(PoisonError::into_inner);
        let active = leases.get(&lease.lease_id).ok_or_else(provider_missing)?;
        let target = active
            .execution_targets
            .get(&materialization.execution_id)
            .ok_or_else(provider_missing)?;
        let evidence_digest = Digest::of(&read_checkpoint(
            target,
            self.config.maximum_checkpoint_bytes,
        )?);
        if evidence_digest != materialization.evidence_digest {
            return Err(Error::object_digest_mismatch());
        }
        Ok(ProviderVerification {
            evidence_digest,
            execution_id: materialization.execution_id,
            lease_id: lease.lease_id,
            provider_id: lease.provider_id.clone(),
        })
    }

    fn release(&self, lease: &ProviderLease) -> Result<(), Error> {
        let active = self
            .leases
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&lease.lease_id)
            .ok_or_else(provider_missing)?;
        if active.lease != *lease {
            return Err(Error::schema_invalid());
        }
        for target in active.execution_targets.values() {
            fs::remove_file(target).map_err(|_| unavailable())?;
        }
        Ok(())
    }
}

fn lease_id(
    capture_id: CaptureId,
    point_digest: Digest,
    world_id: Digest,
) -> Result<LeaseId, Error> {
    let digest = Digest::of(format!("{capture_id}\0{point_digest}\0{world_id}").as_bytes());
    let mut bytes = *digest.as_bytes();
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = lowercase_hex(&bytes[..16]);
    LeaseId::from_str(&format!(
        "lse_{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    ))
}

fn lowercase_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

fn read_checkpoint(path: &Path, maximum_bytes: u64) -> Result<Vec<u8>, Error> {
    let metadata = fs::symlink_metadata(path).map_err(|_| provider_missing())?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > maximum_bytes
    {
        return Err(provider_missing());
    }
    fs::read(path).map_err(|_| provider_missing())
}

fn write_read_only(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    write_file(path, bytes, true)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    write_file(path, bytes, false)
}

fn write_file(path: &Path, bytes: &[u8], read_only: bool) -> Result<(), Error> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    set_mode(&mut options, read_only);
    let mut file = options.open(path).map_err(|_| unavailable())?;
    file.write_all(bytes).map_err(|_| unavailable())?;
    file.sync_all().map_err(|_| unavailable())
}

#[cfg(unix)]
fn set_mode(options: &mut OpenOptions, read_only: bool) {
    use std::os::unix::fs::OpenOptionsExt as _;
    options.mode(if read_only { 0o400 } else { 0o600 });
}

#[cfg(not(unix))]
fn set_mode(_options: &mut OpenOptions, _read_only: bool) {}

fn open_lock(path: &Path) -> Result<File, Error> {
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    set_mode(&mut options, false);
    options.open(path).map_err(|_| unavailable())
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> Result<(), Error> {
    fs::create_dir_all(path).map_err(|_| unavailable())?;
    set_private_directory_mode(path)
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> Result<(), Error> {
    fs::create_dir_all(path).map_err(|_| unavailable())
}

#[cfg(unix)]
fn set_private_directory_mode(path: &Path) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| unavailable())
}

fn clear_workspace(root: &Path) -> Result<(), Error> {
    let mut paths = fs::read_dir(root)
        .map_err(|_| unavailable())?
        .map(|entry| entry.map(|value| value.path()).map_err(|_| unavailable()))
        .collect::<Result<Vec<_>, _>>()?;
    paths.sort();
    for path in paths {
        let metadata = fs::symlink_metadata(&path).map_err(|_| unavailable())?;
        if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
            fs::remove_dir_all(path).map_err(|_| unavailable())?;
        } else if metadata.file_type().is_file() && !metadata.file_type().is_symlink() {
            fs::remove_file(path).map_err(|_| unavailable())?;
        } else {
            return Err(unavailable());
        }
    }
    Ok(())
}

fn valid_component_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_lowercase()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
}

const fn maximum_checkpoint_bytes() -> u64 {
    1_024 * 1_024 * 1_024
}

const fn maximum_aggregate(bytes: u64, leases: u64) -> u64 {
    bytes * leases
}

fn reserve_claim<'a>(
    config: &FileCheckpointConfig,
    active: impl Iterator<Item = &'a ActiveLease>,
    lease_id: LeaseId,
    requested: &ProviderResourceClaim,
) -> Result<(), Error> {
    let service_capacity = ProviderServiceCapacity {
        maximum_active_leases: u64::try_from(config.maximum_active_leases).map_err(|_| quota())?,
        maximum_resource_claim: config.maximum_resource_claim.clone(),
    };
    let mut model = ProviderReservationModel::new(ProviderCapacity {
        maximum_active_leases: service_capacity.maximum_active_leases,
        maximum_resource_claim: service_capacity.maximum_resource_claim.clone(),
        service_shares: BTreeMap::from([(config.service_id, service_capacity)]),
    })?;
    for lease in active {
        model.reserve(
            Digest::of(lease.lease.lease_id.to_string().as_bytes()),
            config.service_id,
            lease.resource_claim.clone(),
        )?;
    }
    model.reserve(
        Digest::of(lease_id.to_string().as_bytes()),
        config.service_id,
        requested.clone(),
    )?;
    Ok(())
}

fn provider_missing() -> Error {
    Error::new(
        ErrorCode::WorldProviderMissing,
        "The file checkpoint provider cannot supply the selected World point.",
    )
}

fn quota() -> Error {
    Error::new(
        ErrorCode::RuntimeQuota,
        "The file checkpoint provider lease quota is full.",
    )
}

fn unavailable() -> Error {
    Error::new(
        ErrorCode::ServiceUnavailable,
        "The file checkpoint provider is unavailable.",
    )
}

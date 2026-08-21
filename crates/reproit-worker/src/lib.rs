#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use reproit_core::{
    identity::{Digest, ObjectId, OrganizationId, ProjectId, ReproId, ServiceId},
    model::{
        DebuggerContract, ExecutionGrant, ExecutionGrantOperation, ExecutionWorkClass,
        ExecutorCapabilityEvidence, ProcessingMode, ReplayCapsule,
    },
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerJobObservation {
    Running,
    ResultReady,
    Failed,
    Cancelled,
    TimedOut,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerExecutionRequest {
    pub attach_debugger: bool,
    pub capsule: ReplayCapsule,
    pub debugger: DebuggerContract,
    pub debugger_capability: String,
    pub evidence: ExecutorCapabilityEvidence,
    pub grant: ExecutionGrant,
    pub objects: BTreeMap<ObjectId, Vec<u8>>,
    pub profile_configuration: String,
    pub repro_id: ReproId,
    pub source: WorkerSource,
    pub subject: WorkerSubject,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedWorkerExecutionRequest {
    pub attach_debugger: bool,
    pub debugger_capability: String,
    pub grant: reproit_cloud_api::ManagedOciGrant,
    pub profile_configuration: String,
    pub repro_id: ReproId,
    pub source: WorkerSource,
    pub subject: WorkerSubject,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerSource {
    pub files: Vec<WorkerSourceFile>,
    pub repository_id: String,
    pub source_revision: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerSourceFile {
    pub bytes: String,
    pub executable: bool,
    pub path: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkerSubject {
    Captured,
    Changed,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GrantRequest {
    pub debugger_capability_digest: Digest,
    pub expires_in_seconds: u16,
    pub operation: ExecutionGrantOperation,
    pub organization_id: OrganizationId,
    pub processing_mode: ProcessingMode,
    pub project_id: ProjectId,
    pub requester_identity: String,
    pub repro_digest: Digest,
    pub service_id: ServiceId,
    pub work_class: ExecutionWorkClass,
}

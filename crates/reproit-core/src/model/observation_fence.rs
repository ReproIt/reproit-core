use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    Error, ErrorCode, canonical,
    crypto::{decode_base64url, verify_signed_value},
    identity::{Digest, OperationId},
    proof::validate_world_closure,
};

use super::{
    Candidate, ClosurePolicy, EventKind, ObservationClass, OperationBeginPayload, Validate,
    WorldClosure, canonical_payload, valid_boundary_id, valid_component,
};

const MAX_OBSERVATIONS: usize = 1_024;
const MAX_OWNERSHIPS: usize = 64;

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AutomaticObservationClass {
    Clock,
    Database,
    Environment,
    Filesystem,
    OutboundHttp,
    Queue,
    Randomness,
}

impl AutomaticObservationClass {
    const ALL: [Self; 7] = [
        Self::Clock,
        Self::Database,
        Self::Environment,
        Self::Filesystem,
        Self::OutboundHttp,
        Self::Queue,
        Self::Randomness,
    ];

    const fn closure_class(self) -> ObservationClass {
        match self {
            Self::Clock | Self::Randomness => ObservationClass::ClockRandomIdentity,
            Self::Database => ObservationClass::StateService,
            Self::Environment | Self::Filesystem => ObservationClass::FilesystemEnvironment,
            Self::OutboundHttp | Self::Queue => ObservationClass::NetworkIpcSignal,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticAdapterOwnership {
    pub adapter_id: String,
    pub adapter_version: String,
    pub boundary_id: String,
    pub implementation_digest: Digest,
    pub observation_class: AutomaticObservationClass,
}

impl Validate for SemanticAdapterOwnership {
    fn validate(&self) -> Result<(), Error> {
        if !valid_component(&self.adapter_id)
            || self.adapter_version.is_empty()
            || self.adapter_version.len() > 64
            || !valid_boundary_id(&self.boundary_id)
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum AutomaticObservationPayloadFormat {
    #[serde(rename = "reproit.automatic-observation.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomaticObservationPayload {
    pub boundary_id: String,
    pub causal_parent_id: Option<OperationId>,
    pub evidence_digest: Digest,
    pub format: AutomaticObservationPayloadFormat,
    pub observation_class: AutomaticObservationClass,
    pub observation_sequence: u16,
    pub operation_id: OperationId,
    pub owner_adapter_id: Option<String>,
}

impl Validate for AutomaticObservationPayload {
    fn validate(&self) -> Result<(), Error> {
        if !valid_boundary_id(&self.boundary_id)
            || usize::from(self.observation_sequence) >= MAX_OBSERVATIONS
            || self
                .owner_adapter_id
                .as_ref()
                .is_some_and(|adapter_id| !valid_component(adapter_id))
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum NativeObservationFenceReceiptFormat {
    #[serde(rename = "reproit.native-observation-fence-receipt.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeObservationFenceReceipt {
    pub adapter_ownership: Vec<SemanticAdapterOwnership>,
    pub deployment_digest: Digest,
    pub dropped_observation_count: u64,
    pub fence_id: String,
    pub fence_version: String,
    pub format: NativeObservationFenceReceiptFormat,
    pub observation_count: u16,
    pub observations_digest: Digest,
    pub operation_id: OperationId,
    pub overflowed: bool,
    pub signature: String,
    pub signer_key_id: String,
    pub subject_digest: Digest,
    pub unowned_observation_count: u16,
    pub world_closure: WorldClosure,
}

impl Validate for NativeObservationFenceReceipt {
    fn validate(&self) -> Result<(), Error> {
        if !valid_component(&self.fence_id)
            || self.fence_version.is_empty()
            || self.fence_version.len() > 64
            || self.signer_key_id.is_empty()
            || self.signer_key_id.len() > 256
            || self.signature.len() != 86
            || usize::from(self.observation_count) > MAX_OBSERVATIONS
            || usize::from(self.unowned_observation_count) > MAX_OBSERVATIONS
        {
            return Err(Error::schema_invalid());
        }
        decode_base64url::<64>(&self.signature)?;
        self.world_closure.validate()?;
        validate_ownership(&self.adapter_ownership, &self.world_closure)
    }
}

pub fn verify_automatic_capture(
    candidate: &Candidate,
    closure_policy: &ClosurePolicy,
    expected_fence_signer_key_id: &str,
    fence_public_key: &[u8; 32],
) -> Result<(), Error> {
    candidate.validate()?;
    let records = automatic_records(candidate)?;
    validate_scope(candidate, &records.begin, &records.observations)?;
    validate_fence_binding(candidate, &records.observations, &records.fence)?;
    validate_world_closure(closure_policy, &records.fence.world_closure)?;
    if records.fence.signer_key_id != expected_fence_signer_key_id {
        return Err(attestation_scope());
    }
    let value = serde_json::to_value(&records.fence).map_err(|_| Error::schema_invalid())?;
    verify_signed_value(&value, fence_public_key)
}

struct AutomaticRecords {
    begin: OperationBeginPayload,
    fence: NativeObservationFenceReceipt,
    observations: Vec<AutomaticObservationPayload>,
}

fn automatic_records(candidate: &Candidate) -> Result<AutomaticRecords, Error> {
    let begin_bytes = canonical_payload(&candidate.records[0])?;
    let begin = canonical::parse_strict(&begin_bytes)?;
    let fence_index = candidate
        .records
        .iter()
        .position(|record| record.kind == EventKind::ObservationFence)
        .ok_or_else(world_not_closed)?;
    if fence_index + 2 != candidate.records.len() - 1
        || candidate.records[fence_index + 1].kind != EventKind::Failure
        || candidate
            .records
            .iter()
            .filter(|record| record.kind == EventKind::ObservationFence)
            .count()
            != 1
    {
        return Err(world_not_closed());
    }
    let fence_bytes = canonical_payload(&candidate.records[fence_index])?;
    let fence = canonical::parse_strict(&fence_bytes)?;
    let observations = candidate.records[..fence_index]
        .iter()
        .filter(|record| record.kind == EventKind::Observation)
        .map(|record| canonical_payload(record).and_then(|bytes| canonical::parse_strict(&bytes)))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(AutomaticRecords {
        begin,
        fence,
        observations,
    })
}

fn validate_scope(
    candidate: &Candidate,
    begin: &OperationBeginPayload,
    observations: &[AutomaticObservationPayload],
) -> Result<(), Error> {
    for (index, observation) in observations.iter().enumerate() {
        if usize::from(observation.observation_sequence) != index {
            return Err(Error::new(
                ErrorCode::IncompleteRecordSequence,
                "The automatic observation sequence is incomplete.",
            ));
        }
        if observation.operation_id != candidate.operation_id
            || observation
                .causal_parent_id
                .is_some_and(|parent| !begin.causal_parent_ids.contains(&parent))
        {
            return Err(world_not_closed());
        }
    }
    Ok(())
}

fn validate_fence_binding(
    candidate: &Candidate,
    observations: &[AutomaticObservationPayload],
    fence: &NativeObservationFenceReceipt,
) -> Result<(), Error> {
    fence.validate()?;
    let deployment_digest = canonical::digest(&candidate.deployment)?;
    let subject_digest = canonical::digest(&candidate.deployment.subject)?;
    if fence.subject_digest != subject_digest {
        return Err(Error::new(
            ErrorCode::SubjectDigestMismatch,
            "The observation fence does not match the captured subject.",
        ));
    }
    if fence.deployment_digest != deployment_digest || fence.operation_id != candidate.operation_id
    {
        return Err(attestation_scope());
    }
    let unowned_count = observations
        .iter()
        .filter(|observation| observation.owner_adapter_id.is_none())
        .count();
    if usize::from(fence.observation_count) != observations.len()
        || usize::from(fence.unowned_observation_count) != unowned_count
        || fence.observations_digest != canonical::digest(&observations)?
    {
        return Err(world_not_closed());
    }
    if fence.overflowed || fence.dropped_observation_count != 0 || unowned_count != 0 {
        return Err(world_not_closed());
    }
    validate_observation_owners(observations, &fence.adapter_ownership)
}

fn validate_ownership(
    ownerships: &[SemanticAdapterOwnership],
    closure: &WorldClosure,
) -> Result<(), Error> {
    if ownerships.len() < AutomaticObservationClass::ALL.len() || ownerships.len() > MAX_OWNERSHIPS
    {
        return Err(Error::schema_invalid());
    }
    let mut identities = BTreeMap::new();
    let mut classes = BTreeSet::new();
    for (index, ownership) in ownerships.iter().enumerate() {
        ownership.validate()?;
        if index > 0 && ownerships[index - 1].boundary_id >= ownership.boundary_id {
            return Err(Error::schema_invalid());
        }
        let identity = (&ownership.adapter_version, ownership.implementation_digest);
        if identities
            .insert(&ownership.adapter_id, identity)
            .is_some_and(|existing| existing != identity)
        {
            return Err(Error::schema_invalid());
        }
        classes.insert(ownership.observation_class);
    }
    if classes != AutomaticObservationClass::ALL.into_iter().collect() {
        return Err(world_not_closed());
    }
    if closure.receipts.len() != ownerships.len() {
        return Err(world_not_closed());
    }
    for (ownership, receipt) in ownerships.iter().zip(&closure.receipts) {
        if ownership.boundary_id != receipt.boundary_id
            || ownership.observation_class.closure_class() != receipt.observation_class
        {
            return Err(world_not_closed());
        }
    }
    Ok(())
}

fn validate_observation_owners(
    observations: &[AutomaticObservationPayload],
    ownerships: &[SemanticAdapterOwnership],
) -> Result<(), Error> {
    for observation in observations {
        let Some(owner_adapter_id) = observation.owner_adapter_id.as_deref() else {
            return Err(world_not_closed());
        };
        let owned = ownerships.iter().any(|ownership| {
            ownership.adapter_id == owner_adapter_id
                && ownership.boundary_id == observation.boundary_id
                && ownership.observation_class == observation.observation_class
        });
        if !owned {
            return Err(world_not_closed());
        }
    }
    Ok(())
}

fn world_not_closed() -> Error {
    Error::new(
        ErrorCode::WorldNotClosed,
        "Repro It could not own every automatic application observation.",
    )
}

fn attestation_scope() -> Error {
    Error::new(
        ErrorCode::AttestationScope,
        "The observation fence does not match the capture scope.",
    )
}

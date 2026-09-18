//! Decode the automatic World contract in `specs/v1/automatic-replay.md`.

use std::collections::BTreeMap;

use reproit_core::{
    Error, ErrorCode, canonical,
    crypto::decode_base64url_bytes,
    identity::{Digest, Timestamp},
    model::{
        AutomaticObservationClass as Class, DependencyOutcome, LogicalObject,
        ResolvedReplayCapsule, SemanticDependencyRequest, SemanticDependencyResponse,
        SemanticObservationOperation, SemanticObservationOutcome, SemanticObservationRequest,
        SemanticObservationResponse, Validate as _, validate_semantic_dependency_pair,
        validate_semantic_observation_pair,
    },
};
use serde::{Serialize, de::DeserializeOwned};

const MAX_OBSERVATIONS: usize = 1_024;
const MAX_RECORD_BYTES: u64 = 65_536;
const MAX_ENVIRONMENT_OBJECT_BYTES: u64 = 1_048_576;
const MAX_ENVIRONMENT_BYTES: usize = 524_288;
const MAX_ENVIRONMENT_ENTRIES: usize = 4_096;

/// Verified payloads. Environment values and response bodies can contain secrets.
pub struct AutomaticReplay {
    environment: BTreeMap<Vec<u8>, Vec<u8>>,
    boundary_clock: Timestamp,
    observations: BTreeMap<(Class, u64), RecordedObservation>,
}

pub struct RecordedObservation {
    pub outcome: DependencyOutcome,
    pub response: Vec<u8>,
    request_digest: Digest,
}

impl AutomaticReplay {
    pub fn environment(&self) -> &BTreeMap<Vec<u8>, Vec<u8>> {
        &self.environment
    }

    pub fn boundary_clock(&self) -> &Timestamp {
        &self.boundary_clock
    }

    /// Baseline observations occupy position zero before application execution.
    pub const fn first_position(class: Class) -> u64 {
        match class {
            Class::Clock | Class::Environment => 1,
            _ => 0,
        }
    }

    pub fn take_response(
        &mut self,
        class: Class,
        position: u64,
        request: &[u8],
    ) -> Result<RecordedObservation, Error> {
        let key = (class, position);
        let recorded = self.observations.get(&key).ok_or_else(replay_mismatch)?;
        if request.len() as u64 > MAX_RECORD_BYTES || Digest::of(request) != recorded.request_digest
        {
            return Err(replay_mismatch());
        }
        let (observed_class, outcome) = validate_pair(request, &recorded.response)?;
        if observed_class != class || outcome != recorded.outcome {
            return Err(replay_mismatch());
        }
        self.observations.remove(&key).ok_or_else(replay_mismatch)
    }

    /// Call after all dispatched sessions finish and native coverage succeeds.
    pub fn require_complete(&self) -> Result<(), Error> {
        if self.observations.is_empty() {
            Ok(())
        } else {
            Err(replay_mismatch())
        }
    }
}

/// The reader must honor the descriptor size before allocating or reading bytes.
pub fn resolve_automatic_replay(
    resolved: &ResolvedReplayCapsule,
    read: &mut dyn FnMut(&LogicalObject) -> Result<Vec<u8>, Error>,
) -> Result<AutomaticReplay, Error> {
    resolved.world.validate()?;
    let [point] = resolved.world.points.as_slice() else {
        return Err(unsupported());
    };
    if point.provider_id != "automatic-world"
        || point.engine_identity != "reproit-native"
        || point.engine_version != "1.0.0"
        || point.capabilities != ["capture.automatic-world.v1"]
    {
        return Err(unsupported());
    }
    let dependency = resolved.dependency.as_ref().ok_or_else(replay_mismatch)?;
    dependency.transcript.validate()?;
    if dependency.transcript.adapter_id != "reproit-native"
        || dependency.transcript.adapter_version != "1.0.0"
    {
        return Err(unsupported());
    }
    if resolved.world_artifacts.len() != point.artifacts.len()
        || dependency.interactions.len() != dependency.transcript.interactions.len()
        || resolved.world_artifacts.len() + dependency.interactions.len() > MAX_OBSERVATIONS
    {
        return Err(replay_mismatch());
    }
    let mut observations = BTreeMap::new();
    for artifact in &resolved.world_artifacts {
        if artifact.point_index != 0 {
            return Err(replay_mismatch());
        }
        let (class, position, request_digest, outcome) = state_identity(&artifact.artifact.uri)?;
        let baseline = class == Class::Environment && position == 0;
        let limit = if baseline {
            MAX_ENVIRONMENT_OBJECT_BYTES
        } else {
            MAX_RECORD_BYTES
        };
        let response = read_payload(&artifact.object, limit, read)?;
        if !baseline {
            let value: SemanticObservationResponse = parse_canonical(&response)?;
            value.validate()?;
            if observation_class(value.operation) != class
                || value.request_digest != request_digest
                || dependency_outcome(value.outcome) != outcome
            {
                return Err(replay_mismatch());
            }
        }
        insert(
            &mut observations,
            class,
            position,
            request_digest,
            outcome,
            response,
        )?;
    }
    read_dependencies(resolved, read, &mut observations)?;
    require_contiguous_positions(&observations)?;
    let environment = take_baseline(
        &mut observations,
        Class::Environment,
        b"process-environment",
    )?;
    let clock = take_baseline(&mut observations, Class::Clock, b"wall-clock")?;
    Ok(AutomaticReplay {
        environment: decode_environment(&environment)?,
        boundary_clock: std::str::from_utf8(&clock)
            .map_err(|_| Error::schema_invalid())?
            .parse()?,
        observations,
    })
}

fn read_dependencies(
    resolved: &ResolvedReplayCapsule,
    read: &mut dyn FnMut(&LogicalObject) -> Result<Vec<u8>, Error>,
    observations: &mut BTreeMap<(Class, u64), RecordedObservation>,
) -> Result<(), Error> {
    let dependency = resolved.dependency.as_ref().ok_or_else(replay_mismatch)?;
    for (interaction, objects) in dependency
        .transcript
        .interactions
        .iter()
        .zip(&dependency.interactions)
    {
        if interaction.operation_id != resolved.trigger.operation_id {
            return Err(replay_mismatch());
        }
        let request = read_payload(&objects.request, MAX_RECORD_BYTES, read)?;
        let response = read_payload(&objects.response, MAX_RECORD_BYTES, read)?;
        if Digest::of(&request) != interaction.request_digest
            || Digest::of(&response) != interaction.response_digest
        {
            return Err(Error::object_digest_mismatch());
        }
        let class = if request == b"wall-clock" {
            if interaction.session_position != 0
                || interaction.outcome != DependencyOutcome::Response
            {
                return Err(replay_mismatch());
            }
            Class::Clock
        } else {
            let (class, outcome) = validate_pair(&request, &response)?;
            if matches!(class, Class::Environment | Class::Filesystem)
                || outcome != interaction.outcome
            {
                return Err(replay_mismatch());
            }
            class
        };
        insert(
            observations,
            class,
            interaction.session_position,
            interaction.request_digest,
            interaction.outcome,
            response,
        )?;
    }
    Ok(())
}

fn state_identity(uri: &str) -> Result<(Class, u64, Digest, DependencyOutcome), Error> {
    let suffix = uri
        .strip_prefix("reproit-managed://automatic-world/")
        .ok_or_else(replay_mismatch)?;
    let mut fields = suffix.split('/');
    let class = match fields.next() {
        Some("automatic.environment") => Class::Environment,
        Some("automatic.filesystem") => Class::Filesystem,
        _ => return Err(replay_mismatch()),
    };
    let request_digest = fields.next().ok_or_else(replay_mismatch)?.parse()?;
    let position_text = fields.next().ok_or_else(replay_mismatch)?;
    let position: u64 = position_text.parse().map_err(|_| replay_mismatch())?;
    if position.to_string() != position_text || position >= MAX_OBSERVATIONS as u64 {
        return Err(replay_mismatch());
    }
    let outcome = match fields.next() {
        Some("response") => DependencyOutcome::Response,
        Some("error") => DependencyOutcome::Error,
        _ => return Err(replay_mismatch()),
    };
    if fields.next().is_some() {
        return Err(replay_mismatch());
    }
    Ok((class, position, request_digest, outcome))
}

fn validate_pair(request: &[u8], response: &[u8]) -> Result<(Class, DependencyOutcome), Error> {
    // The format selects one existing contract. Parsing never permits extra fields.
    let value: serde_json::Value = canonical::parse_strict(request)?;
    match value.get("format").and_then(serde_json::Value::as_str) {
        Some("reproit.semantic-observation-request.v1") => {
            let request: SemanticObservationRequest = parse_canonical(request)?;
            let response: SemanticObservationResponse = parse_canonical(response)?;
            validate_semantic_observation_pair(&request, &response)?;
            Ok((
                observation_class(request.operation),
                dependency_outcome(response.outcome),
            ))
        }
        Some("reproit.semantic-dependency-request.v1") => {
            let request: SemanticDependencyRequest = parse_canonical(request)?;
            let response: SemanticDependencyResponse = parse_canonical(response)?;
            validate_semantic_dependency_pair(&request, &response)?;
            Ok((
                request.observation_class,
                dependency_outcome(response.outcome),
            ))
        }
        _ => Err(Error::schema_invalid()),
    }
}

fn parse_canonical<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T, Error> {
    let value = canonical::parse_strict(bytes)?;
    if canonical::canonical_bytes(&value)? != bytes {
        return Err(Error::schema_invalid());
    }
    Ok(value)
}

fn read_payload(
    object: &LogicalObject,
    limit: u64,
    read: &mut dyn FnMut(&LogicalObject) -> Result<Vec<u8>, Error>,
) -> Result<Vec<u8>, Error> {
    if object.media_type != "application/octet-stream" || object.plain_size > limit {
        return Err(Error::schema_invalid());
    }
    let bytes = read(object)?;
    if bytes.len() as u64 != object.plain_size || Digest::of(&bytes) != object.plain_digest {
        return Err(Error::object_digest_mismatch());
    }
    Ok(bytes)
}

fn insert(
    observations: &mut BTreeMap<(Class, u64), RecordedObservation>,
    class: Class,
    position: u64,
    request_digest: Digest,
    outcome: DependencyOutcome,
    response: Vec<u8>,
) -> Result<(), Error> {
    if observations
        .insert(
            (class, position),
            RecordedObservation {
                outcome,
                response,
                request_digest,
            },
        )
        .is_some()
    {
        return Err(replay_mismatch());
    }
    Ok(())
}

fn require_contiguous_positions(
    observations: &BTreeMap<(Class, u64), RecordedObservation>,
) -> Result<(), Error> {
    let mut next = BTreeMap::<Class, u64>::new();
    for &(class, position) in observations.keys() {
        let expected = next.entry(class).or_default();
        if position != *expected {
            return Err(replay_mismatch());
        }
        *expected += 1;
    }
    Ok(())
}

fn take_baseline(
    observations: &mut BTreeMap<(Class, u64), RecordedObservation>,
    class: Class,
    request: &[u8],
) -> Result<Vec<u8>, Error> {
    let record = observations
        .remove(&(class, 0))
        .ok_or_else(replay_mismatch)?;
    if record.request_digest != Digest::of(request) || record.outcome != DependencyOutcome::Response
    {
        return Err(replay_mismatch());
    }
    Ok(record.response)
}

fn decode_environment(bytes: &[u8]) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, Error> {
    let encoded: BTreeMap<String, String> = parse_canonical(bytes)?;
    if encoded.len() > MAX_ENVIRONMENT_ENTRIES {
        return Err(Error::schema_invalid());
    }
    let mut environment = BTreeMap::new();
    let mut total = 0;
    for (name, value) in encoded {
        let name = decode_base64url_bytes(&name)?;
        let value = decode_base64url_bytes(&value)?;
        total += name.len() + value.len();
        if name.is_empty()
            || name.contains(&0)
            || name.contains(&b'=')
            || value.contains(&0)
            || total > MAX_ENVIRONMENT_BYTES
            || environment.insert(name, value).is_some()
        {
            return Err(Error::schema_invalid());
        }
    }
    Ok(environment)
}

const fn observation_class(operation: SemanticObservationOperation) -> Class {
    match operation {
        SemanticObservationOperation::ClockWallTime => Class::Clock,
        SemanticObservationOperation::EnvironmentRead => Class::Environment,
        SemanticObservationOperation::FilesystemRead => Class::Filesystem,
        SemanticObservationOperation::RandomBytes => Class::Randomness,
    }
}

const fn dependency_outcome(outcome: SemanticObservationOutcome) -> DependencyOutcome {
    match outcome {
        SemanticObservationOutcome::Error => DependencyOutcome::Error,
        SemanticObservationOutcome::Response => DependencyOutcome::Response,
    }
}

fn replay_mismatch() -> Error {
    Error::new(
        ErrorCode::WorldNotClosed,
        "The automatic replay observations do not match the capture.",
    )
}

fn unsupported() -> Error {
    Error::new(
        ErrorCode::UnsupportedCapabilitySet,
        "The automatic replay provider or version is unsupported.",
    )
}

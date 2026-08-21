use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use reproit_core::{
    Error, ErrorCode,
    identity::{ObjectId, OperationId},
    model::{DependencyLimits, Validate},
};

use crate::world::{TranscriptInteraction, verify_dependency_transcript};

pub struct HttpTranscriptProvider {
    created_at: Instant,
    maximum_bytes: usize,
    maximum_interactions: usize,
    pool: DependencyTranscriptPool,
    reservation: Mutex<Option<DependencyOperationReservation>>,
    state: Mutex<TranscriptState>,
}

#[derive(Clone)]
pub struct DependencyTranscriptPool {
    inner: Arc<Mutex<DependencyPoolState>>,
    limits: DependencyLimits,
}

#[derive(Default)]
struct DependencyPoolState {
    active_close_requests: u64,
    active_operations: u64,
    durable_bytes: u64,
    memory_bytes: u64,
    sessions: u64,
}

struct DependencyOperationReservation {
    bytes: u64,
    pool: DependencyTranscriptPool,
}

struct DependencyCloseReservation {
    pool: DependencyTranscriptPool,
}

#[derive(Default)]
struct TranscriptState {
    bytes: usize,
    interactions: Vec<TranscriptInteraction>,
    objects: BTreeMap<ObjectId, Vec<u8>>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ClosedDependencyTranscript {
    pub interactions: Vec<TranscriptInteraction>,
    pub objects: BTreeMap<ObjectId, Vec<u8>>,
}

pub struct HttpTranscriptReplay {
    failed: bool,
    next_interaction: usize,
    operation_id: OperationId,
    transcript: ClosedDependencyTranscript,
}

impl ClosedDependencyTranscript {
    pub fn validate(&self, operation_id: OperationId) -> Result<(), Error> {
        verify_dependency_transcript(operation_id, &self.interactions, &self.objects)?;
        let object_byte_limit =
            usize::try_from(DependencyLimits::V1.object_bytes).map_err(|_| mismatch())?;
        let candidate_byte_limit =
            usize::try_from(DependencyLimits::V1.candidate_bytes).map_err(|_| mismatch())?;
        let mut object_ids = BTreeSet::new();
        let mut total_bytes = 0_usize;
        for interaction in &self.interactions {
            if interaction.request_object_id == interaction.response_object_id
                || !object_ids.insert(interaction.request_object_id)
                || !object_ids.insert(interaction.response_object_id)
            {
                return Err(mismatch());
            }
        }
        if object_ids.len() != self.objects.len() {
            return Err(mismatch());
        }
        for (object_id, bytes) in &self.objects {
            if !object_ids.contains(object_id) || bytes.len() > object_byte_limit {
                return Err(mismatch());
            }
            total_bytes = total_bytes.checked_add(bytes.len()).ok_or_else(mismatch)?;
        }
        if total_bytes > candidate_byte_limit {
            return Err(mismatch());
        }
        Ok(())
    }
}

impl HttpTranscriptReplay {
    pub fn new(
        operation_id: OperationId,
        transcript: ClosedDependencyTranscript,
    ) -> Result<Self, Error> {
        transcript.validate(operation_id)?;
        Ok(Self {
            failed: false,
            next_interaction: 0,
            operation_id,
            transcript,
        })
    }

    pub fn exchange(
        &mut self,
        operation_id: OperationId,
        request: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if self.failed || operation_id != self.operation_id {
            return self.reject();
        }
        let Some(interaction) = self.transcript.interactions.get(self.next_interaction) else {
            return self.reject();
        };
        let request_matches = self
            .transcript
            .objects
            .get(&interaction.request_object_id)
            .is_some_and(|expected| expected.as_slice() == request)
            && interaction.request_digest == reproit_core::identity::Digest::of(request);
        if !request_matches {
            return self.reject();
        }
        let response = self
            .transcript
            .objects
            .get(&interaction.response_object_id)
            .cloned()
            .ok_or_else(mismatch)?;
        self.next_interaction += 1;
        Ok(response)
    }

    pub fn finish(self) -> Result<(), Error> {
        if self.failed || self.next_interaction != self.transcript.interactions.len() {
            return Err(mismatch());
        }
        Ok(())
    }

    pub fn consumed_interactions(&self) -> usize {
        self.next_interaction
    }

    fn reject<T>(&mut self) -> Result<T, Error> {
        self.failed = true;
        Err(mismatch())
    }
}

impl HttpTranscriptProvider {
    pub fn new(maximum_interactions: usize, maximum_bytes: usize) -> Result<Self, Error> {
        DependencyTranscriptPool::production()?.open(maximum_interactions, maximum_bytes)
    }

    fn reserved(
        pool: DependencyTranscriptPool,
        reservation: DependencyOperationReservation,
        maximum_interactions: usize,
        maximum_bytes: usize,
    ) -> Self {
        Self {
            created_at: Instant::now(),
            maximum_bytes,
            maximum_interactions,
            pool,
            reservation: Mutex::new(Some(reservation)),
            state: Mutex::new(TranscriptState::default()),
        }
    }

    fn validate_bounds(maximum_interactions: usize, maximum_bytes: usize) -> Result<(), Error> {
        let interaction_limit = usize::try_from(DependencyLimits::V1.interactions_per_operation)
            .map_err(|_| Error::schema_invalid())?;
        let candidate_byte_limit = usize::try_from(DependencyLimits::V1.candidate_bytes)
            .map_err(|_| Error::schema_invalid())?;
        if maximum_interactions == 0
            || maximum_interactions > interaction_limit
            || maximum_bytes == 0
            || maximum_bytes > candidate_byte_limit
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }

    pub fn record(
        &self,
        interaction: TranscriptInteraction,
        request: Vec<u8>,
        response: Vec<u8>,
    ) -> Result<(), Error> {
        self.require_active()?;
        let object_byte_limit =
            usize::try_from(DependencyLimits::V1.object_bytes).map_err(|_| quota())?;
        if request.len() > object_byte_limit || response.len() > object_byte_limit {
            return Err(quota());
        }
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let next_sequence =
            u16::try_from(state.interactions.len()).map_err(|_| Error::schema_invalid())?;
        let added_bytes = request
            .len()
            .checked_add(response.len())
            .ok_or_else(quota)?;
        if state.interactions.len() >= self.maximum_interactions
            || state
                .bytes
                .checked_add(added_bytes)
                .is_none_or(|total| total > self.maximum_bytes)
        {
            return Err(quota());
        }
        if interaction.sequence != next_sequence
            || interaction.session_position != u64::from(next_sequence)
            || interaction.request_digest != reproit_core::identity::Digest::of(&request)
            || interaction.response_digest != reproit_core::identity::Digest::of(&response)
            || interaction.request_object_id == interaction.response_object_id
            || state.objects.contains_key(&interaction.request_object_id)
            || state.objects.contains_key(&interaction.response_object_id)
        {
            return Err(mismatch());
        }
        state.bytes += added_bytes;
        state.objects.insert(interaction.request_object_id, request);
        state
            .objects
            .insert(interaction.response_object_id, response);
        state.interactions.push(interaction);
        Ok(())
    }

    pub fn close(&self, operation_id: OperationId) -> Result<ClosedDependencyTranscript, Error> {
        let close = match self.pool.reserve_close() {
            Ok(close) => close,
            Err(error) => {
                self.discard();
                return Err(error);
            }
        };
        if self.created_at.elapsed() > Duration::from_millis(self.pool.limits.cursor_lifetime_ms) {
            drop(close);
            self.discard();
            return Err(quota());
        }
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let result =
            verify_dependency_transcript(operation_id, &state.interactions, &state.objects).map(
                |()| ClosedDependencyTranscript {
                    interactions: std::mem::take(&mut state.interactions),
                    objects: std::mem::take(&mut state.objects),
                },
            );
        if result.is_err() {
            *state = TranscriptState::default();
        } else {
            state.bytes = 0;
        }
        drop(state);
        drop(close);
        self.release_operation();
        result
    }

    pub fn discard(&self) {
        *self.state.lock().unwrap_or_else(PoisonError::into_inner) = TranscriptState::default();
        self.release_operation();
    }

    fn require_active(&self) -> Result<(), Error> {
        if self
            .reservation
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_none()
            || self.created_at.elapsed()
                > Duration::from_millis(self.pool.limits.cursor_lifetime_ms)
        {
            self.release_operation();
            return Err(quota());
        }
        Ok(())
    }

    fn release_operation(&self) {
        self.reservation
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    }

    pub fn captured_bytes(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .bytes
    }
}

impl DependencyTranscriptPool {
    pub fn production() -> Result<Self, Error> {
        Self::new(DependencyLimits::V1)
    }

    pub fn new(limits: DependencyLimits) -> Result<Self, Error> {
        limits.validate()?;
        Ok(Self {
            inner: Arc::new(Mutex::new(DependencyPoolState::default())),
            limits,
        })
    }

    pub fn open(
        &self,
        maximum_interactions: usize,
        maximum_bytes: usize,
    ) -> Result<HttpTranscriptProvider, Error> {
        HttpTranscriptProvider::validate_bounds(maximum_interactions, maximum_bytes)?;
        let bytes = u64::try_from(maximum_bytes).map_err(|_| quota())?;
        if u64::try_from(maximum_interactions).map_err(|_| quota())?
            > self.limits.interactions_per_operation
            || bytes > self.limits.candidate_bytes
        {
            return Err(quota());
        }
        let mut state = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if state.sessions >= self.limits.sessions
            || state.active_operations >= self.limits.active_operations
            || state
                .memory_bytes
                .checked_add(bytes)
                .is_none_or(|total| total > self.limits.memory_bytes)
            || state
                .durable_bytes
                .checked_add(bytes)
                .is_none_or(|total| total > self.limits.durable_bytes)
        {
            return Err(quota());
        }
        state.sessions += 1;
        state.active_operations += 1;
        state.memory_bytes += bytes;
        state.durable_bytes += bytes;
        drop(state);
        let pool = self.clone();
        Ok(HttpTranscriptProvider::reserved(
            pool.clone(),
            DependencyOperationReservation { bytes, pool },
            maximum_interactions,
            maximum_bytes,
        ))
    }

    fn reserve_close(&self) -> Result<DependencyCloseReservation, Error> {
        let mut state = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if state.active_close_requests >= self.limits.concurrent_close_requests {
            return Err(quota());
        }
        state.active_close_requests += 1;
        Ok(DependencyCloseReservation { pool: self.clone() })
    }
}

impl Drop for DependencyOperationReservation {
    fn drop(&mut self) {
        let mut state = self
            .pool
            .inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        state.sessions = state.sessions.saturating_sub(1);
        state.active_operations = state.active_operations.saturating_sub(1);
        state.memory_bytes = state.memory_bytes.saturating_sub(self.bytes);
        state.durable_bytes = state.durable_bytes.saturating_sub(self.bytes);
    }
}

impl Drop for DependencyCloseReservation {
    fn drop(&mut self) {
        let mut state = self
            .pool
            .inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        state.active_close_requests = state.active_close_requests.saturating_sub(1);
    }
}

fn quota() -> Error {
    Error::new(
        ErrorCode::RuntimeQuota,
        "The dependency transcript capture bound is full.",
    )
}

fn mismatch() -> Error {
    Error::new(
        ErrorCode::DependencyTranscriptMismatch,
        "The dependency transcript event does not match its captured bytes.",
    )
}

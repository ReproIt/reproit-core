#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailureFrame {
    pub function: String,
    pub module: String,
    pub source: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperationKind {
    DeliveredWork,
    RequestResponse,
    Stream,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExceptionCategory {
    Exception,
    Panic,
    VisibleError,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContractCategory {
    Explicit,
    Postcondition,
    ResponseContract,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExceptionFailureIdentity {
    pub category: ExceptionCategory,
    pub cause_types: Vec<String>,
    pub frames: Vec<FailureFrame>,
    pub operation_kind: OperationKind,
    pub operation_name: String,
    pub runtime_family: String,
    pub schema: String,
    pub stable_code: Option<String>,
    #[serde(rename = "type")]
    pub type_name: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractFailureIdentity {
    pub category: ContractCategory,
    pub contract_id: String,
    pub contract_version: String,
    pub expected_digest: Digest,
    pub observed_digest: Digest,
    pub operation_kind: OperationKind,
    pub operation_name: String,
    pub runtime_family: String,
    pub schema: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FailureIdentity {
    Exception(ExceptionFailureIdentity),
    Contract(ContractFailureIdentity),
}

impl Validate for FailureIdentity {
    fn validate(&self) -> Result<(), Error> {
        match self {
            Self::Exception(identity) => validate_exception_identity(identity),
            Self::Contract(identity) => validate_contract_identity(identity),
        }
    }
}

impl FailureIdentity {
    pub fn operation(&self) -> (OperationKind, &str) {
        match self {
            Self::Exception(identity) => (identity.operation_kind, &identity.operation_name),
            Self::Contract(identity) => (identity.operation_kind, &identity.operation_name),
        }
    }

    pub fn matches(&self, observed: &Self) -> bool {
        self == observed
    }

    pub fn grouping(&self) -> Result<FailureGrouping, Error> {
        self.validate()?;
        let identity_digest = crate::canonical::digest(self)?;
        let (category, matcher) = match self {
            Self::Exception(identity) => (
                FailureCategory::from(identity.category),
                FailureMatcher::ExceptionExactV1,
            ),
            Self::Contract(identity) => (
                FailureCategory::from(identity.category),
                FailureMatcher::ContractDigestV1,
            ),
        };
        Ok(FailureGrouping {
            category,
            format: FailureGroupingFormat::V1,
            identity_digest,
            matcher,
        })
    }

    pub fn safe_summaries(
        &self,
        processing_mode: ProcessingMode,
    ) -> (FailureSummary, TriggerSummary) {
        match self {
            Self::Exception(identity) => {
                let category = FailureCategory::from(identity.category);
                (
                    FailureSummary {
                        category,
                        operation: safe_operation(processing_mode, &identity.operation_name),
                        stable_code: match processing_mode {
                            ProcessingMode::Managed => None,
                            ProcessingMode::Private => identity.stable_code.clone(),
                        },
                        type_name: match processing_mode {
                            ProcessingMode::Managed => category.fixed_label().to_owned(),
                            ProcessingMode::Private => identity.type_name.clone(),
                        },
                    },
                    TriggerSummary {
                        kind: identity.operation_kind,
                        operation: safe_operation(processing_mode, &identity.operation_name),
                    },
                )
            }
            Self::Contract(identity) => {
                let category = FailureCategory::from(identity.category);
                (
                    FailureSummary {
                        category,
                        operation: safe_operation(processing_mode, &identity.operation_name),
                        stable_code: None,
                        type_name: match processing_mode {
                            ProcessingMode::Managed => category.fixed_label().to_owned(),
                            ProcessingMode::Private => identity.contract_id.clone(),
                        },
                    },
                    TriggerSummary {
                        kind: identity.operation_kind,
                        operation: safe_operation(processing_mode, &identity.operation_name),
                    },
                )
            }
        }
    }
}

fn safe_operation(processing_mode: ProcessingMode, operation: &str) -> String {
    match processing_mode {
        ProcessingMode::Managed => "captured-operation".to_owned(),
        ProcessingMode::Private => operation.to_owned(),
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FailureCategory {
    Exception,
    Explicit,
    Panic,
    Postcondition,
    ResponseContract,
    VisibleError,
}

impl FailureCategory {
    pub fn fixed_label(self) -> &'static str {
        match self {
            Self::Exception => "exception",
            Self::Explicit => "explicit",
            Self::Panic => "panic",
            Self::Postcondition => "postcondition",
            Self::ResponseContract => "response-contract",
            Self::VisibleError => "visible-error",
        }
    }
}

impl From<ExceptionCategory> for FailureCategory {
    fn from(category: ExceptionCategory) -> Self {
        match category {
            ExceptionCategory::Exception => Self::Exception,
            ExceptionCategory::Panic => Self::Panic,
            ExceptionCategory::VisibleError => Self::VisibleError,
        }
    }
}

impl From<ContractCategory> for FailureCategory {
    fn from(category: ContractCategory) -> Self {
        match category {
            ContractCategory::Explicit => Self::Explicit,
            ContractCategory::Postcondition => Self::Postcondition,
            ContractCategory::ResponseContract => Self::ResponseContract,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FailureMatcher {
    ContractDigestV1,
    ExceptionExactV1,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum FailureGroupingFormat {
    #[serde(rename = "reproit.failure-grouping.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailureGrouping {
    pub category: FailureCategory,
    pub format: FailureGroupingFormat,
    pub identity_digest: Digest,
    pub matcher: FailureMatcher,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailureReference {
    pub category: FailureCategory,
    pub identity: Digest,
    pub matcher: FailureMatcher,
    pub object_id: ObjectId,
    pub schema: String,
}

impl Validate for FailureReference {
    fn validate(&self) -> Result<(), Error> {
        let matcher_matches = matches!(
            (self.category, self.matcher),
            (
                FailureCategory::Exception | FailureCategory::Panic | FailureCategory::VisibleError,
                FailureMatcher::ExceptionExactV1
            ) | (
                FailureCategory::Explicit
                    | FailureCategory::Postcondition
                    | FailureCategory::ResponseContract,
                FailureMatcher::ContractDigestV1
            )
        );
        if self.schema != "reproit.failure.v1" || !matcher_matches {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EventKind {
    Begin,
    Dependency,
    Failure,
    Input,
    Observation,
    ObservationFence,
    Terminal,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventRecord {
    pub kind: EventKind,
    pub payload: String,
    pub sequence: u16,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum DependencyCursorFormat {
    #[serde(rename = "reproit.dependency-cursor.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyCursorPayload {
    pub adapter_id: String,
    pub adapter_version: String,
    pub causal_parent_id: Option<OperationId>,
    pub cursor: String,
    pub cursor_digest: Digest,
    pub format: DependencyCursorFormat,
}

impl Validate for DependencyCursorPayload {
    fn validate(&self) -> Result<(), Error> {
        if !valid_component(&self.adapter_id)
            || self.adapter_version.is_empty()
            || self.adapter_version.len() > 64
            || self.cursor.is_empty()
            || self.cursor.len() > 16_384
            || self.cursor.bytes().any(|byte| {
                !byte.is_ascii_alphanumeric() && !matches!(byte, b'-' | b'_')
            })
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum DependencyTranscriptFormat {
    #[serde(rename = "reproit.dependency-transcript.v1")]
    V1,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DependencyOutcome {
    Error,
    Response,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyTranscriptInteraction {
    pub causal_parent_id: Option<OperationId>,
    pub operation_id: OperationId,
    pub outcome: DependencyOutcome,
    pub request_digest: Digest,
    pub request_object_id: ObjectId,
    pub response_digest: Digest,
    pub response_object_id: ObjectId,
    pub sequence: u16,
    pub session_position: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyTranscript {
    pub adapter_id: String,
    pub adapter_version: String,
    pub format: DependencyTranscriptFormat,
    pub interactions: Vec<DependencyTranscriptInteraction>,
}

impl Validate for DependencyTranscript {
    fn validate(&self) -> Result<(), Error> {
        if !valid_component(&self.adapter_id)
            || self.adapter_version.is_empty()
            || self.adapter_version.len() > 64
            || self.interactions.is_empty()
            || self.interactions.len() > 1_024
        {
            return Err(Error::schema_invalid());
        }
        for (index, interaction) in self.interactions.iter().enumerate() {
            if usize::from(interaction.sequence) != index
                || interaction.session_position > 9_007_199_254_740_991
            {
                return Err(Error::schema_invalid());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum OperationBeginFormat {
    #[serde(rename = "reproit.operation-begin.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationBeginPayload {
    pub adapter_id: String,
    pub adapter_version: String,
    pub causal_parent_ids: Vec<OperationId>,
    pub format: OperationBeginFormat,
    pub operation_kind: OperationKind,
    pub operation_name: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InputChannel {
    Control,
    Input,
    Metadata,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum OperationInputFormat {
    #[serde(rename = "reproit.operation-input.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationInputPayload {
    pub channel: InputChannel,
    pub content_type: String,
    pub format: OperationInputFormat,
    pub input_index: u16,
    pub value: String,
    pub value_digest: Digest,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum TriggerFormat {
    #[serde(rename = "reproit.trigger.v1")]
    V1,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TriggerCompletion {
    Acknowledgment,
    Return,
    StreamEnd,
    TaskEnd,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TriggerInput {
    pub channel: InputChannel,
    pub object_id: ObjectId,
    pub plain_digest: Digest,
    pub sequence: u16,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trigger {
    pub adapter_id: String,
    pub adapter_version: String,
    pub causal_parent_ids: Vec<OperationId>,
    pub completion: TriggerCompletion,
    pub format: TriggerFormat,
    pub inputs: Vec<TriggerInput>,
    pub operation_id: OperationId,
    pub operation_kind: OperationKind,
    pub operation_name: String,
}

impl Validate for Trigger {
    fn validate(&self) -> Result<(), Error> {
        let completion_matches = matches!(
            (self.operation_kind, self.completion),
            (OperationKind::RequestResponse, TriggerCompletion::Return)
                | (OperationKind::Stream, TriggerCompletion::StreamEnd)
                | (
                    OperationKind::DeliveredWork,
                    TriggerCompletion::Acknowledgment | TriggerCompletion::TaskEnd
                )
        );
        if self.adapter_id.is_empty()
            || self.adapter_id.len() > 128
            || self.adapter_version.is_empty()
            || self.adapter_version.len() > 64
            || self.operation_name.is_empty()
            || self.operation_name.len() > 128
            || self.causal_parent_ids.len() > 32
            || self.causal_parent_ids.iter().collect::<BTreeSet<_>>().len()
                != self.causal_parent_ids.len()
            || self.inputs.is_empty()
            || self.inputs.len() > 1_024
            || !completion_matches
        {
            return Err(Error::schema_invalid());
        }
        for (index, input) in self.inputs.iter().enumerate() {
            if usize::from(input.sequence) != index {
                return Err(Error::schema_invalid());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum FailurePayloadFormat {
    #[serde(rename = "reproit.failure-payload.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailurePayload {
    pub failure: FailureReference,
    pub format: FailurePayloadFormat,
    pub identity: FailureIdentity,
}

impl Validate for FailurePayload {
    fn validate(&self) -> Result<(), Error> {
        self.failure.validate()?;
        self.identity.validate()?;
        // The reference names the identity it points at. A payload whose
        // reference binds a different identity digest carries two meanings.
        if self.failure.identity != crate::canonical::digest(&self.identity)? {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum TerminalFormat {
    #[serde(rename = "reproit.terminal.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalPayload {
    pub complete: bool,
    pub event_count: u16,
    pub format: TerminalFormat,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum CandidateFormat {
    #[serde(rename = "reproit.candidate.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub capture_id: CaptureId,
    pub deployment: Deployment,
    pub failure: FailureReference,
    pub format: CandidateFormat,
    pub operation_id: OperationId,
    pub processing_mode: ProcessingMode,
    pub records: Vec<EventRecord>,
    pub world_id: Digest,
}

impl Validate for Candidate {
    fn validate(&self) -> Result<(), Error> {
        self.deployment.validate()?;
        self.failure.validate()?;
        if self.processing_mode != self.deployment.processing_mode {
            return Err(Error::schema_invalid());
        }
        if !(2..=1_025).contains(&self.records.len()) {
            return Err(incomplete_candidate());
        }
        for (index, record) in self.records.iter().enumerate() {
            if usize::from(record.sequence) != index {
                return Err(incomplete_record_sequence());
            }
        }
        if self.records.first().map(|record| record.kind) != Some(EventKind::Begin)
            || self.records.last().map(|record| record.kind) != Some(EventKind::Terminal)
            || self
                .records
                .iter()
                .filter(|record| record.kind == EventKind::Failure)
                .count()
                != 1
            || self.records[..self.records.len() - 1]
                .iter()
                .any(|record| record.kind == EventKind::Terminal)
        {
            return Err(incomplete_candidate());
        }

        for record in &self.records {
            let bytes = canonical_payload(record)?;
            self.validate_record(record.kind, &bytes)?;
        }
        Ok(())
    }
}

impl Candidate {
    pub fn failure_storm_identity(&self) -> Result<FailureStormIdentity, Error> {
        self.validate()?;
        let record = self
            .records
            .iter()
            .find(|record| record.kind == EventKind::Failure)
            .ok_or_else(incomplete_candidate)?;
        let bytes = canonical_payload(record)?;
        let payload: FailurePayload = crate::canonical::parse_strict(&bytes)?;
        let (operation_kind, operation_name) = payload.identity.operation();
        let identity = FailureStormIdentity {
            failure_identity_digest: self.failure.identity,
            format: FailureStormIdentityFormat::V1,
            operation_kind,
            operation_name: operation_name.to_owned(),
            service_id: self.deployment.service_id,
            source_revision: self.deployment.source_revision.clone(),
            subject_artifact_digest: self.deployment.subject.artifact_digest,
        };
        identity.validate()?;
        Ok(identity)
    }

    fn validate_record(&self, kind: EventKind, bytes: &[u8]) -> Result<(), Error> {
        match kind {
            EventKind::Begin => {
                let begin: OperationBeginPayload = crate::canonical::parse_strict(bytes)?;
                if begin.adapter_id.is_empty()
                    || begin.adapter_version.is_empty()
                    || begin.operation_name.is_empty()
                    || begin.causal_parent_ids.len() > 32
                    || begin
                        .causal_parent_ids
                        .iter()
                        .collect::<BTreeSet<_>>()
                        .len()
                        != begin.causal_parent_ids.len()
                {
                    return Err(Error::schema_invalid());
                }
            }
            EventKind::Input => {
                let input: OperationInputPayload = crate::canonical::parse_strict(bytes)?;
                if input.content_type.is_empty() || input.input_index > 1_023 {
                    return Err(Error::schema_invalid());
                }
                let value = crate::crypto::decode_base64url_bytes(&input.value)?;
                if value.len() > 65_536 || Digest::of(&value) != input.value_digest {
                    return Err(Error::object_digest_mismatch());
                }
            }
            EventKind::Failure => {
                let payload: FailurePayload = crate::canonical::parse_strict(bytes)?;
                payload.identity.validate()?;
                payload.failure.validate()?;
                if payload.failure != self.failure
                    || crate::canonical::digest(&payload.identity)? != self.failure.identity
                {
                    return Err(incomplete_candidate());
                }
            }
            EventKind::Terminal => {
                let terminal: TerminalPayload = crate::canonical::parse_strict(bytes)?;
                if !terminal.complete || usize::from(terminal.event_count) != self.records.len() - 1
                {
                    return Err(incomplete_candidate());
                }
            }
            EventKind::Dependency => {
                let cursor: DependencyCursorPayload = crate::canonical::parse_strict(bytes)?;
                cursor.validate()?;
            }
            EventKind::Observation => {
                let observation: AutomaticObservationPayload =
                    crate::canonical::parse_strict(bytes)?;
                observation.validate()?;
            }
            EventKind::ObservationFence => {
                let fence: NativeObservationFenceReceipt =
                    crate::canonical::parse_strict(bytes)?;
                fence.validate()?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailureSummary {
    pub category: FailureCategory,
    pub operation: String,
    pub stable_code: Option<String>,
    #[serde(rename = "type")]
    pub type_name: String,
}

impl FailureSummary {
    pub fn validate_for_mode(&self, processing_mode: ProcessingMode) -> Result<(), Error> {
        if self.operation.is_empty()
            || self.operation.len() > 128
            || self.type_name.is_empty()
            || self.type_name.len() > 256
            || self
                .stable_code
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > 128)
        {
            return Err(Error::schema_invalid());
        }
        if processing_mode == ProcessingMode::Managed
            && (self.operation != "captured-operation"
                || self.stable_code.is_some()
                || self.type_name != self.category.fixed_label())
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TriggerSummary {
    pub kind: OperationKind,
    pub operation: String,
}

impl TriggerSummary {
    pub fn validate_for_mode(&self, processing_mode: ProcessingMode) -> Result<(), Error> {
        if self.operation.is_empty()
            || self.operation.len() > 128
            || (processing_mode == ProcessingMode::Managed
                && self.operation != "captured-operation")
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

fn validate_exception_identity(identity: &ExceptionFailureIdentity) -> Result<(), Error> {
    if identity.schema != "reproit.failure.v1"
        || identity.operation_name.is_empty()
        || identity.runtime_family.is_empty()
        || identity.type_name.is_empty()
        || (identity.frames.is_empty() && identity.stable_code.is_none())
        || identity.cause_types.len() > 32
        || identity.frames.len() > 64
    {
        return Err(Error::schema_invalid());
    }
    for frame in &identity.frames {
        if frame.function.is_empty()
            || frame.module.is_empty()
            || frame.source.is_empty()
            || frame.source.starts_with('/')
            || frame.source.split('/').any(|part| part == "..")
            || frame.source.contains('\\')
        {
            return Err(Error::schema_invalid());
        }
    }
    Ok(())
}

fn validate_contract_identity(identity: &ContractFailureIdentity) -> Result<(), Error> {
    if identity.schema != "reproit.failure.v1"
        || identity.contract_id.is_empty()
        || identity.contract_version.is_empty()
        || identity.operation_name.is_empty()
        || identity.runtime_family.is_empty()
    {
        return Err(Error::schema_invalid());
    }
    Ok(())
}

fn valid_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_lowercase()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
}


fn canonical_payload(record: &EventRecord) -> Result<Vec<u8>, Error> {
    if record.payload.len() > 87_382 {
        return Err(Error::schema_invalid());
    }
    let bytes = crate::crypto::decode_base64url_bytes(&record.payload)?;
    if bytes.len() > 65_536 {
        return Err(Error::schema_invalid());
    }
    let value: serde_json::Value = crate::canonical::parse_strict(&bytes)?;
    if crate::canonical::canonical_bytes(&value)? != bytes {
        return Err(Error::schema_invalid());
    }
    Ok(bytes)
}

fn incomplete_candidate() -> Error {
    Error::new(
        ErrorCode::IncompleteCandidate,
        "The candidate does not contain a complete terminal record.",
    )
}

fn incomplete_record_sequence() -> Error {
    Error::new(
        ErrorCode::IncompleteRecordSequence,
        "The candidate record sequence is incomplete.",
    )
}

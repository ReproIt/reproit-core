use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    AdmissionProofBinding,
    AdmissionProofCount,
    AssigneeNotAuthorized,
    ArtifactNotFound,
    AttestationRevoked,
    AttestationScope,
    AuthenticationRequired,
    AuthorizationDenied,
    CaptureIdConflict,
    ConfigConflict,
    CrossTenantScope,
    DecryptionAuthentication,
    DependencyTranscriptMismatch,
    DifferentFailure,
    EvaluationError,
    Forbidden,
    IncompleteCandidate,
    IncompleteRecordSequence,
    LiveEgressBlocked,
    KeyProviderUnavailable,
    KeyUnwrapFailed,
    KeepDestinationUnavailable,
    LegalDeletionConflict,
    NonceReuse,
    NotFound,
    ObjectDigestMismatch,
    PriorityInvalid,
    RateLimited,
    RuntimeQuota,
    SchemaInvalid,
    ServiceUnavailable,
    SourceAccessDenied,
    SourceCheckoutFailed,
    SourceDependencyMissing,
    SourceRevisionMissing,
    StateScopeViolation,
    SubjectDigestMismatch,
    TriageConflict,
    Unsupported,
    UnsupportedCapabilitySet,
    UploadExpired,
    UploadIncomplete,
    UploadLimitExceeded,
    WorldNotClosed,
    WorldPointExpired,
    WorldProviderMissing,
}

impl ErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AdmissionProofBinding => "ADMISSION_PROOF_BINDING",
            Self::AdmissionProofCount => "ADMISSION_PROOF_COUNT",
            Self::AssigneeNotAuthorized => "ASSIGNEE_NOT_AUTHORIZED",
            Self::ArtifactNotFound => "ARTIFACT_NOT_FOUND",
            Self::AttestationRevoked => "ATTESTATION_REVOKED",
            Self::AttestationScope => "ATTESTATION_SCOPE",
            Self::AuthenticationRequired => "AUTHENTICATION_REQUIRED",
            Self::AuthorizationDenied => "AUTHORIZATION_DENIED",
            Self::CaptureIdConflict => "CAPTURE_ID_CONFLICT",
            Self::ConfigConflict => "CONFIG_CONFLICT",
            Self::CrossTenantScope => "CROSS_TENANT_SCOPE",
            Self::DecryptionAuthentication => "DECRYPTION_AUTHENTICATION",
            Self::DependencyTranscriptMismatch => "DEPENDENCY_TRANSCRIPT_MISMATCH",
            Self::DifferentFailure => "DIFFERENT_FAILURE",
            Self::EvaluationError => "EVALUATION_ERROR",
            Self::Forbidden => "FORBIDDEN",
            Self::IncompleteCandidate => "INCOMPLETE_CANDIDATE",
            Self::IncompleteRecordSequence => "INCOMPLETE_RECORD_SEQUENCE",
            Self::LiveEgressBlocked => "LIVE_EGRESS_BLOCKED",
            Self::KeyProviderUnavailable => "KEY_PROVIDER_UNAVAILABLE",
            Self::KeyUnwrapFailed => "KEY_UNWRAP_FAILED",
            Self::KeepDestinationUnavailable => "KEEP_DESTINATION_UNAVAILABLE",
            Self::LegalDeletionConflict => "LEGAL_DELETION_CONFLICT",
            Self::NonceReuse => "NONCE_REUSE",
            Self::NotFound => "NOT_FOUND",
            Self::ObjectDigestMismatch => "OBJECT_DIGEST_MISMATCH",
            Self::PriorityInvalid => "PRIORITY_INVALID",
            Self::RateLimited => "RATE_LIMITED",
            Self::RuntimeQuota => "RUNTIME_QUOTA",
            Self::SchemaInvalid => "SCHEMA_INVALID",
            Self::ServiceUnavailable => "SERVICE_UNAVAILABLE",
            Self::SourceAccessDenied => "SOURCE_ACCESS_DENIED",
            Self::SourceCheckoutFailed => "SOURCE_CHECKOUT_FAILED",
            Self::SourceDependencyMissing => "SOURCE_DEPENDENCY_MISSING",
            Self::SourceRevisionMissing => "SOURCE_REVISION_MISSING",
            Self::StateScopeViolation => "STATE_SCOPE_VIOLATION",
            Self::SubjectDigestMismatch => "SUBJECT_DIGEST_MISMATCH",
            Self::TriageConflict => "TRIAGE_CONFLICT",
            Self::Unsupported => "UNSUPPORTED",
            Self::UnsupportedCapabilitySet => "UNSUPPORTED_CAPABILITY_SET",
            Self::UploadExpired => "UPLOAD_EXPIRED",
            Self::UploadIncomplete => "UPLOAD_INCOMPLETE",
            Self::UploadLimitExceeded => "UPLOAD_LIMIT_EXCEEDED",
            Self::WorldNotClosed => "WORLD_NOT_CLOSED",
            Self::WorldPointExpired => "WORLD_POINT_EXPIRED",
            Self::WorldProviderMissing => "WORLD_PROVIDER_MISSING",
        }
    }

    pub const fn retryable(self) -> bool {
        matches!(
            self,
            Self::KeyProviderUnavailable
                | Self::KeepDestinationUnavailable
                | Self::RateLimited
                | Self::RuntimeQuota
                | Self::ServiceUnavailable
                | Self::SourceCheckoutFailed
                | Self::UploadExpired
                | Self::UploadIncomplete
        )
    }
}

#[cfg(test)]
mod tests {
    use super::ErrorCode;

    #[test]
    fn stable_code_matches_the_wire_value() {
        let code = ErrorCode::UnsupportedCapabilitySet;
        assert_eq!(code.as_str(), "UNSUPPORTED_CAPABILITY_SET");
        assert_eq!(
            serde_json::to_string(&code).unwrap(),
            "\"UNSUPPORTED_CAPABILITY_SET\""
        );
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Error)]
#[error("{message}")]
#[serde(deny_unknown_fields)]
pub struct Error {
    pub code: ErrorCode,
    pub message: String,
    pub retryable: bool,
}

impl Error {
    pub fn new(code: ErrorCode, message: &'static str) -> Self {
        Self {
            code,
            message: message.to_owned(),
            retryable: code.retryable(),
        }
    }

    /// Build an error whose bounded message is composed at the boundary, for
    /// example a remote stable code inside a local diagnostic. The message
    /// must stay a bounded safe fact and must not carry customer values.
    pub fn new_owned(code: ErrorCode, message: String) -> Self {
        Self {
            code,
            message,
            retryable: code.retryable(),
        }
    }

    pub fn schema_invalid() -> Self {
        Self::new(
            ErrorCode::SchemaInvalid,
            "The value does not match the v1 schema.",
        )
    }

    pub fn object_digest_mismatch() -> Self {
        Self::new(
            ErrorCode::ObjectDigestMismatch,
            "The object digest does not match its content.",
        )
    }
}

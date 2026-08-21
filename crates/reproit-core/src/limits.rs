//! Product limits that canonical machine contracts own.

// Generated from specs/v1/kept-set-limits.json. The conformance test rejects drift.
pub const MAX_KEPT_REFERENCES: usize = 10_000;
pub const MAX_KEPT_PREPARATIONS: usize = 8;

/// One admission job's complete plaintext object closure. Managed retrieval
/// and the private Runtime sealing stage share this one bound, so both
/// processing modes reject an oversized capsule at the same limit.
pub const MAX_ADMISSION_PLAINTEXT_BYTES: u64 = 536_870_912;

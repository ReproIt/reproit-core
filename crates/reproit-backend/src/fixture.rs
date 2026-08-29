//! Canonical closure-shaped admission fixture for acceptance gates.
//!
//! This module is a validation fixture, never a production path. It compiles
//! only when the `acceptance-fixture` feature is enabled, which stays off by
//! default, so production builds cannot select it. The backend integration
//! tests and the validation gates use it as the one canonical construction of
//! a sealed, closure-shaped `AdmissionInput`.
//!
//! The spec vector values it needs are inlined below as constants. The
//! packaged crate cannot reach `specs/` from `src/`, so this module must not
//! use `include_str!` with paths outside the crate. The constants are exact
//! copies of the named vectors in `specs/v1/vectors.json` and
//! `specs/v1/protocol-vectors.json`.

use std::collections::BTreeMap;

use reproit_core::{
    Error, canonical,
    crypto::{SecretKey, secret_key, sign_bytes, verification_key},
    identity::{Digest, ObjectId, Timestamp},
    model::{
        Candidate, ClosurePolicy, DebugArtifactBinding, DebugArtifactKind, DebuggerContract,
        FailurePayload, LogicalObject, LogicalObjectRole, ProcessingMode, ProcessorArchitecture,
        SubjectClosureFormat, SubjectClosureManifest, SubjectClosureObject, SubjectFile,
        SubjectLaunch, SubjectModule, SubjectObjectKind, SubjectRuntimeFamily, SupportBundle,
        Trigger, Validate as _, WorldCheckpoint, WorldClosure, WrappedKey,
    },
};

use crate::{
    AdmissionInput, AdmittedCandidate, ObjectClosure,
    closure::{CandidateClosureRequest, close_replay_capsule},
    config::BackendSdk,
    seal::{
        AdmissionSigner, NonceSource, SealRequest, SealedUpload, SealingIds, UploadMetadata,
        seal_upload,
    },
    support::build_backend_support_package,
};

/// Inline copy of the protocol `candidate` vector from `specs/v1`.
const CANDIDATE_JSON: &str = r#"
{
  "capture_id": "cap_01890f3e-7b1c-7cc0-8a1b-123456789abc",
  "deployment": {
    "format": "reproit.deployment.v1",
    "organization_id": "org_01890f3e-7b1c-7cc0-8a1b-123456789abd",
    "processing_mode": "private",
    "project_id": "prj_01890f3e-7b1c-7cc0-8a1b-123456789abe",
    "repository_id": "source.example/acme/commerce",
    "runtime_capabilities": [
      "architecture.native",
      "operating-system.linux",
      "runtime.rust-native"
    ],
    "runtime_endpoint": "https://runtime.customer.example",
    "service_id": "svc_01890f3e-7b1c-7cc0-8a1b-123456789abf",
    "service_path": "services/orders",
    "signature": "XCHurZtzMjzIW3JXBb6RXGK4JKnSSihb1P-NsCVCKrYhS6jVSR9vBWdQi2xeGwUZmNm3XHWGTOAEROr-F7tbDQ",
    "signed_at": "2026-01-01T00:00:00.000Z",
    "signer_key_id": "customer-deployment-test",
    "source_revision": "0123456789abcdef",
    "subject": {
      "architecture": "architecture.native",
      "arguments": [],
      "artifact_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
      "artifact_media_type": "application/vnd.reproit.native-executable.v1",
      "artifact_uri": "oci://customer.example/orders@sha256:1111111111111111111111111111111111111111111111111111111111111111",
      "environment_names": [
        "RUST_LOG"
      ],
      "executable": "/reproit/subject/orders",
      "format": "reproit.subject.v1",
      "operating_system": "operating-system.linux",
      "working_directory": "/reproit/subject"
    }
  },
  "failure": {
    "category": "exception",
    "identity": "sha256:60ec32fae961fab36e8f4814492bef4911056954ea98ba6d556bbd851c0cc9c5",
    "matcher": "exception-exact-v1",
    "object_id": "obj_01890f3e-7b1c-7cc0-8a1b-123456789ab7",
    "schema": "reproit.failure.v1"
  },
  "format": "reproit.candidate.v1",
  "operation_id": "op_01890f3e-7b1c-7cc0-8a1b-123456789ab1",
  "processing_mode": "private",
  "records": [
    {
      "kind": "begin",
      "payload": "eyJhZGFwdGVyX2lkIjoiYXh1bSIsImFkYXB0ZXJfdmVyc2lvbiI6IjAuOC45IiwiY2F1c2FsX3BhcmVudF9pZHMiOltdLCJmb3JtYXQiOiJyZXByb2l0Lm9wZXJhdGlvbi1iZWdpbi52MSIsIm9wZXJhdGlvbl9raW5kIjoicmVxdWVzdC1yZXNwb25zZSIsIm9wZXJhdGlvbl9uYW1lIjoib3JkZXJzLmluY3JlbWVudCJ9",
      "sequence": 0
    },
    {
      "kind": "input",
      "payload": "eyJjaGFubmVsIjoiaW5wdXQiLCJjb250ZW50X3R5cGUiOiJhcHBsaWNhdGlvbi9qc29uIiwiZm9ybWF0IjoicmVwcm9pdC5vcGVyYXRpb24taW5wdXQudjEiLCJpbnB1dF9pbmRleCI6MCwidmFsdWUiOiJleUpoYlc5MWJuUWlPakV3ZlEiLCJ2YWx1ZV9kaWdlc3QiOiJzaGEyNTY6YThiODhiODJmZTkwYTE2MDQ4ZWI4ODUxZmUzODI0MDUzOTVjZDM5NWRhZmFhN2NhOWJlOTBlYzAwZjgyYTcyYiJ9",
      "sequence": 1
    },
    {
      "kind": "failure",
      "payload": "eyJmYWlsdXJlIjp7ImNhdGVnb3J5IjoiZXhjZXB0aW9uIiwiaWRlbnRpdHkiOiJzaGEyNTY6NjBlYzMyZmFlOTYxZmFiMzZlOGY0ODE0NDkyYmVmNDkxMTA1Njk1NGVhOThiYTZkNTU2YmJkODUxYzBjYzljNSIsIm1hdGNoZXIiOiJleGNlcHRpb24tZXhhY3QtdjEiLCJvYmplY3RfaWQiOiJvYmpfMDE4OTBmM2UtN2IxYy03Y2MwLThhMWItMTIzNDU2Nzg5YWI3Iiwic2NoZW1hIjoicmVwcm9pdC5mYWlsdXJlLnYxIn0sImZvcm1hdCI6InJlcHJvaXQuZmFpbHVyZS1wYXlsb2FkLnYxIiwiaWRlbnRpdHkiOnsiY2F0ZWdvcnkiOiJleGNlcHRpb24iLCJjYXVzZV90eXBlcyI6W10sImZyYW1lcyI6W3siZnVuY3Rpb24iOiJvcmRlcnM6OmluY3JlbWVudCIsIm1vZHVsZSI6Im9yZGVycyIsInNvdXJjZSI6InNyYy9vcmRlcnMucnMifV0sIm9wZXJhdGlvbl9raW5kIjoicmVxdWVzdC1yZXNwb25zZSIsIm9wZXJhdGlvbl9uYW1lIjoib3JkZXJzLmluY3JlbWVudCIsInJ1bnRpbWVfZmFtaWx5IjoicnVzdCIsInNjaGVtYSI6InJlcHJvaXQuZmFpbHVyZS52MSIsInN0YWJsZV9jb2RlIjpudWxsLCJ0eXBlIjoiQ291bnRlckludmFyaWFudCJ9fQ",
      "sequence": 2
    },
    {
      "kind": "terminal",
      "payload": "eyJjb21wbGV0ZSI6dHJ1ZSwiZXZlbnRfY291bnQiOjMsImZvcm1hdCI6InJlcHJvaXQudGVybWluYWwudjEifQ",
      "sequence": 3
    }
  ],
  "world_id": "sha256:07aca8a9c203a224dca879a84148fad0c9e38462672a0176aa7028d8f44e5774"
}
"#;

/// Inline copy of the core `closure_policy` vector from `specs/v1`.
const CLOSURE_POLICY_JSON: &str = r#"
{
  "format": "reproit.closure-policy.v1",
  "rules": [
    {
      "allowed_mechanisms": [
        "fixed-executor-capability"
      ],
      "boundary_id": "clock",
      "observation_class": "clock-random-identity"
    },
    {
      "allowed_mechanisms": [
        "exact-transcript"
      ],
      "boundary_id": "dependency-http",
      "observation_class": "network-ipc-signal"
    },
    {
      "allowed_mechanisms": [
        "immutable-object"
      ],
      "boundary_id": "filesystem",
      "observation_class": "filesystem-environment"
    },
    {
      "allowed_mechanisms": [
        "blocked"
      ],
      "boundary_id": "network-egress",
      "observation_class": "network-ipc-signal"
    },
    {
      "allowed_mechanisms": [
        "fixed-executor-capability"
      ],
      "boundary_id": "platform",
      "observation_class": "operating-system-hardware"
    },
    {
      "allowed_mechanisms": [
        "fixed-executor-capability"
      ],
      "boundary_id": "scheduler",
      "observation_class": "ordering-concurrency"
    },
    {
      "allowed_mechanisms": [
        "immutable-object"
      ],
      "boundary_id": "sqlite",
      "observation_class": "state-service"
    }
  ]
}
"#;

/// Inline copy of the protocol `debugger_contract` vector from `specs/v1`.
const DEBUGGER_CONTRACT_JSON: &str = r#"
{
  "artifact_digest": "sha256:fd0056ae6b4b58b98f06776ccf6f68e938beb35d6dede1f6b292eb9c66afb316",
  "artifact_name": "gdbserver_13.1-3_amd64.deb",
  "debugger_id": "gdbserver",
  "format": "reproit.debugger-contract.v1",
  "launch_arguments": [
    "--once",
    "127.0.0.1:0",
    "{subject}"
  ],
  "protocol": "gdb-remote-serial",
  "readiness_rule": "gdb-server-listening",
  "source_mappings": [
    {
      "developer_root": "/workspace",
      "replay_root": "/source"
    }
  ],
  "supported_architectures": [
    "architecture.x86-64"
  ],
  "version": "13.1-3"
}
"#;

/// Inline copy of the protocol `failure_payload` vector from `specs/v1`.
const FAILURE_PAYLOAD_JSON: &str = r#"
{
  "failure": {
    "category": "exception",
    "identity": "sha256:60ec32fae961fab36e8f4814492bef4911056954ea98ba6d556bbd851c0cc9c5",
    "matcher": "exception-exact-v1",
    "object_id": "obj_01890f3e-7b1c-7cc0-8a1b-123456789ab7",
    "schema": "reproit.failure.v1"
  },
  "format": "reproit.failure-payload.v1",
  "identity": {
    "category": "exception",
    "cause_types": [],
    "frames": [
      {
        "function": "orders::increment",
        "module": "orders",
        "source": "src/orders.rs"
      }
    ],
    "operation_kind": "request-response",
    "operation_name": "orders.increment",
    "runtime_family": "rust",
    "schema": "reproit.failure.v1",
    "stable_code": null,
    "type": "CounterInvariant"
  }
}
"#;

/// Inline copy of the core `perturbations` vector array from `specs/v1`.
const PERTURBATIONS_JSON: &str = r#"
[
  {
    "ambient_identity_digest": "sha256:a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0",
    "case": "baseline",
    "format": "reproit.perturbation.v1",
    "run_index": 0,
    "suite": "reproit.controlled-perturbation.v1"
  },
  {
    "ambient_identity_digest": "sha256:b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0",
    "case": "cold-ambient",
    "format": "reproit.perturbation.v1",
    "run_index": 1,
    "suite": "reproit.controlled-perturbation.v1"
  },
  {
    "ambient_identity_digest": "sha256:c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0",
    "case": "timing-ambient",
    "format": "reproit.perturbation.v1",
    "run_index": 2,
    "suite": "reproit.controlled-perturbation.v1"
  }
]
"#;

/// Inline copy of the core `support_bundle` vector from `specs/v1`.
const SUPPORT_BUNDLE_JSON: &str = r#"
{
  "closure_policy_digest": "sha256:125f47d5cf4bf5eb8979ae536de9583daed6d7f0fc5598b4f7a0dea6d81f6f71",
  "components": [
    {
      "capabilities": [
        "architecture.native"
      ],
      "component_id": "x86-64",
      "component_kind": "architecture",
      "conformance_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
      "identity_digest": "sha256:1010101010101010101010101010101010101010101010101010101010101010",
      "protocol_max": 1,
      "protocol_min": 1,
      "version": "1"
    },
    {
      "capabilities": [
        "operation.request-response"
      ],
      "component_id": "axum",
      "component_kind": "boundary-adapter",
      "conformance_digest": "sha256:2121212121212121212121212121212121212121212121212121212121212121",
      "identity_digest": "sha256:2020202020202020202020202020202020202020202020202020202020202020",
      "protocol_max": 1,
      "protocol_min": 1,
      "version": "0.8.9"
    },
    {
      "capabilities": [
        "core.v1"
      ],
      "component_id": "reproit-core",
      "component_kind": "core",
      "conformance_digest": "sha256:3131313131313131313131313131313131313131313131313131313131313131",
      "identity_digest": "sha256:3030303030303030303030303030303030303030303030303030303030303030",
      "protocol_max": 1,
      "protocol_min": 1,
      "version": "1.0.0"
    },
    {
      "capabilities": [
        "transcript.http"
      ],
      "component_id": "http-transcript",
      "component_kind": "dependency-adapter",
      "conformance_digest": "sha256:4141414141414141414141414141414141414141414141414141414141414141",
      "identity_digest": "sha256:4040404040404040404040404040404040404040404040404040404040404040",
      "protocol_max": 1,
      "protocol_min": 1,
      "version": "1.0.0"
    },
    {
      "capabilities": [
        "executor.linux-native"
      ],
      "component_id": "linux-contained",
      "component_kind": "executor",
      "conformance_digest": "sha256:5151515151515151515151515151515151515151515151515151515151515151",
      "identity_digest": "sha256:5050505050505050505050505050505050505050505050505050505050505050",
      "protocol_max": 1,
      "protocol_min": 1,
      "version": "1.0.0"
    },
    {
      "capabilities": [
        "operating-system.linux"
      ],
      "component_id": "linux",
      "component_kind": "operating-system",
      "conformance_digest": "sha256:6161616161616161616161616161616161616161616161616161616161616161",
      "identity_digest": "sha256:6060606060606060606060606060606060606060606060606060606060606060",
      "protocol_max": 1,
      "protocol_min": 1,
      "version": "fixture"
    },
    {
      "capabilities": [
        "profile.backend"
      ],
      "component_id": "backend",
      "component_kind": "profile",
      "conformance_digest": "sha256:7171717171717171717171717171717171717171717171717171717171717171",
      "identity_digest": "sha256:7070707070707070707070707070707070707070707070707070707070707070",
      "protocol_max": 1,
      "protocol_min": 1,
      "version": "1.0.0"
    },
    {
      "capabilities": [
        "sdk.rust"
      ],
      "component_id": "rust",
      "component_kind": "sdk",
      "conformance_digest": "sha256:8181818181818181818181818181818181818181818181818181818181818181",
      "identity_digest": "sha256:8080808080808080808080808080808080808080808080808080808080808080",
      "protocol_max": 1,
      "protocol_min": 1,
      "version": "1.0.0"
    },
    {
      "capabilities": [
        "world.sqlite"
      ],
      "component_id": "sqlite",
      "component_kind": "state-provider",
      "conformance_digest": "sha256:9191919191919191919191919191919191919191919191919191919191919191",
      "identity_digest": "sha256:9090909090909090909090909090909090909090909090909090909090909090",
      "protocol_max": 1,
      "protocol_min": 1,
      "version": "3.53.4"
    },
    {
      "capabilities": [
        "runtime.rust-native"
      ],
      "component_id": "rust-native",
      "component_kind": "subject-runtime",
      "conformance_digest": "sha256:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
      "identity_digest": "sha256:a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0",
      "protocol_max": 1,
      "protocol_min": 1,
      "version": "fixture"
    }
  ],
  "format": "reproit.support-bundle.v1"
}
"#;

/// Inline copy of the protocol `trigger` vector from `specs/v1`.
const TRIGGER_JSON: &str = r#"
{
  "adapter_id": "axum",
  "adapter_version": "0.8.9",
  "causal_parent_ids": [],
  "completion": "return",
  "format": "reproit.trigger.v1",
  "inputs": [
    {
      "channel": "input",
      "object_id": "obj_01890f3e-7b1c-7cc0-8a1b-123456789ab6",
      "plain_digest": "sha256:a8b88b82fe90a16048eb8851fe382405395cd395dafaa7ca9be90ec00f82a72b",
      "sequence": 0
    }
  ],
  "operation_id": "op_01890f3e-7b1c-7cc0-8a1b-123456789ab1",
  "operation_kind": "request-response",
  "operation_name": "orders.increment"
}
"#;

/// Inline copy of the protocol `world_checkpoint` vector from `specs/v1`.
const WORLD_CHECKPOINT_JSON: &str = r#"
{
  "created_at": "2026-01-01T00:00:00.000Z",
  "format": "reproit.world-checkpoint.v1",
  "points": [
    {
      "artifacts": [
        {
          "digest": "sha256:e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5",
          "media_type": "application/vnd.reproit.sqlite-checkpoint.v1",
          "size": 4096,
          "uri": "oci://customer.example/state/orders@sha256:e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5"
        }
      ],
      "capabilities": [
        "world.sqlite"
      ],
      "configuration_digest": "sha256:f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6",
      "engine_identity": "sqlite",
      "engine_version": "3.53.4",
      "format": "reproit.recoverable-point.v1",
      "generation": 1,
      "point": "cG9pbnQtMQ",
      "provider_id": "orders-state",
      "published_at": "2026-01-01T00:00:00.000Z",
      "recoverable_until": "2026-01-01T00:01:00.000Z",
      "resource_claim": {
        "materialized_bytes": 1073741824,
        "objects": 1,
        "pinned_bytes": 1073741824,
        "temporary_bytes": 1073741824
      },
      "scope": {
        "kind": "full",
        "rules": []
      }
    }
  ]
}
"#;

/// Inline copy of the core `world_closure` vector from `specs/v1`.
const WORLD_CLOSURE_JSON: &str = r#"
{
  "format": "reproit.world-closure.v1",
  "policy_digest": "sha256:125f47d5cf4bf5eb8979ae536de9583daed6d7f0fc5598b4f7a0dea6d81f6f71",
  "receipts": [
    {
      "boundary_id": "clock",
      "evidence_digest": "sha256:0101010101010101010101010101010101010101010101010101010101010101",
      "mechanism": "fixed-executor-capability",
      "observation_class": "clock-random-identity",
      "version": 1
    },
    {
      "boundary_id": "dependency-http",
      "evidence_digest": "sha256:0202020202020202020202020202020202020202020202020202020202020202",
      "mechanism": "exact-transcript",
      "observation_class": "network-ipc-signal",
      "version": 1
    },
    {
      "boundary_id": "filesystem",
      "evidence_digest": "sha256:0303030303030303030303030303030303030303030303030303030303030303",
      "mechanism": "immutable-object",
      "observation_class": "filesystem-environment",
      "version": 1
    },
    {
      "boundary_id": "network-egress",
      "evidence_digest": "sha256:0404040404040404040404040404040404040404040404040404040404040404",
      "mechanism": "blocked",
      "observation_class": "network-ipc-signal",
      "version": 1
    },
    {
      "boundary_id": "platform",
      "evidence_digest": "sha256:0505050505050505050505050505050505050505050505050505050505050505",
      "mechanism": "fixed-executor-capability",
      "observation_class": "operating-system-hardware",
      "version": 1
    },
    {
      "boundary_id": "scheduler",
      "evidence_digest": "sha256:0606060606060606060606060606060606060606060606060606060606060606",
      "mechanism": "fixed-executor-capability",
      "observation_class": "ordering-concurrency",
      "version": 1
    },
    {
      "boundary_id": "sqlite",
      "evidence_digest": "sha256:0707070707070707070707070707070707070707070707070707070707070707",
      "mechanism": "immutable-object",
      "observation_class": "state-service",
      "version": 1
    }
  ]
}
"#;

struct FixedSigner {
    key: SecretKey,
    key_id: String,
}

impl AdmissionSigner for FixedSigner {
    fn signer_key_id(&self) -> &str {
        &self.key_id
    }

    fn sign(&self, canonical_unsigned_envelope: &[u8]) -> Result<String, Error> {
        Ok(sign_bytes(canonical_unsigned_envelope, &self.key))
    }
}

struct SequentialNonces {
    next: u8,
}

impl NonceSource for SequentialNonces {
    fn next_nonce(&mut self) -> Result<[u8; 12], Error> {
        let mut nonce = [0_u8; 12];
        nonce[11] = self.next;
        self.next = self.next.checked_add(1).ok_or_else(Error::schema_invalid)?;
        Ok(nonce)
    }
}

/// Seal the admitted fixture capture with fixed keys and sequential nonces.
/// The sealing object ids live in the `...90f0` to `...90f4` range so they
/// can never collide with the capsule object ids of the fixture closure.
pub fn seal_fixture(
    input: &AdmissionInput,
    admitted: &AdmittedCandidate,
) -> (SealedUpload, SecretKey, [u8; 32]) {
    let grouping_key = secret_key([0xAA; 32]);
    let occurrence_key = secret_key(std::array::from_fn(|index| u8::try_from(index).unwrap()));
    let signer = FixedSigner {
        key: secret_key([0x44; 32]),
        key_id: "customer-admission-test".to_owned(),
    };
    let public_key = verification_key(&signer.key);
    let sealed = seal_upload(
        SealRequest {
            admitted,
            grouping_key: &grouping_key,
            ids: SealingIds {
                capsule_object_id: object_id("obj_01890f3e-7b1c-7cc0-8a1b-1234567890f0"),
                manifest_object_id: object_id("obj_01890f3e-7b1c-7cc0-8a1b-1234567890f1"),
                proof_object_ids: [
                    object_id("obj_01890f3e-7b1c-7cc0-8a1b-1234567890f2"),
                    object_id("obj_01890f3e-7b1c-7cc0-8a1b-1234567890f3"),
                    object_id("obj_01890f3e-7b1c-7cc0-8a1b-1234567890f4"),
                ],
            },
            input,
            metadata: upload_metadata(),
            occurrence_key: &occurrence_key,
            signer: &signer,
        },
        &mut SequentialNonces { next: 1 },
    )
    .expect("the admitted capture must seal");
    (sealed, occurrence_key, public_key)
}

/// Build one canonical closure-shaped admission fixture through the real
/// managed producer. The subject closure holds one application object with
/// embedded DWARF, the World holds one sqlite checkpoint artifact, and every
/// object carries its exact fixture bytes, so the sealed capsule resolves
/// through the canonical capsule resolver.
pub fn input() -> AdmissionInput {
    canonical_fixture().1
}

/// The exact candidate that the canonical fixture capsule closed over.
/// Consumers that exercise candidate binding must use this candidate, not the
/// raw vector, because the fixture rebinds the subject closure and World.
pub fn candidate() -> Candidate {
    canonical_fixture().0
}

#[allow(clippy::too_many_lines)]
fn canonical_fixture() -> (Candidate, AdmissionInput) {
    let application_bytes = fixture_elf();
    let subject_manifest = subject_closure_manifest(&application_bytes);
    let subject_manifest_bytes = canonical::canonical_bytes(&subject_manifest).unwrap();
    let subject_digest = Digest::of(&subject_manifest_bytes);

    let world_bytes = b"sqlite checkpoint with counter 5".to_vec();
    let mut world: WorldCheckpoint = decode(WORLD_CHECKPOINT_JSON);
    world.points[0].artifacts[0].digest = Digest::of(&world_bytes);
    world.points[0].artifacts[0].size = u64::try_from(world_bytes.len()).unwrap();
    let world_manifest_bytes = canonical::canonical_bytes(&world).unwrap();

    let trigger_input_bytes = br#"{"item":"widget"}"#.to_vec();
    let mut trigger: Trigger = decode(TRIGGER_JSON);
    trigger.inputs[0].plain_digest = Digest::of(&trigger_input_bytes);
    let trigger_bytes = canonical::canonical_bytes(&trigger).unwrap();

    let failure: FailurePayload = decode(FAILURE_PAYLOAD_JSON);
    let failure_bytes = canonical::canonical_bytes(&failure).unwrap();
    let expected_failure = failure.identity.clone();

    let mut candidate: Candidate = decode(CANDIDATE_JSON);
    candidate.processing_mode = ProcessingMode::Managed;
    candidate.deployment.processing_mode = ProcessingMode::Managed;
    candidate.world_id = world.world_id().unwrap();
    let subject = &mut candidate.deployment.subject;
    subject
        .architecture
        .clone_from(&subject_manifest.architecture);
    subject
        .operating_system
        .clone_from(&subject_manifest.operating_system);
    subject
        .executable
        .clone_from(&subject_manifest.launch.executable);
    subject
        .arguments
        .clone_from(&subject_manifest.launch.arguments);
    subject
        .working_directory
        .clone_from(&subject_manifest.launch.working_directory);
    subject
        .environment_names
        .clone_from(&subject_manifest.launch.environment_names);
    subject.artifact_digest = subject_digest;
    "application/vnd.reproit.subject-closure.v1+json".clone_into(&mut subject.artifact_media_type);
    subject.artifact_uri = format!("reproit-managed://{subject_digest}");
    candidate.deployment.runtime_capabilities = vec![
        "architecture.x86-64".to_owned(),
        "operating-system.linux".to_owned(),
        "runtime.rust-native".to_owned(),
        "sdk.rust".to_owned(),
    ];
    candidate.validate().unwrap();
    let candidate_bytes = canonical::canonical_bytes(&candidate).unwrap();

    let mut bytes_by_id: BTreeMap<ObjectId, Vec<u8>> = BTreeMap::new();
    let mut descriptors = Vec::new();
    let mut push = |object_id: ObjectId, role: LogicalObjectRole, media: &str, bytes: Vec<u8>| {
        descriptors.push(LogicalObject {
            media_type: media.to_owned(),
            object_id,
            plain_digest: Digest::of(&bytes),
            plain_size: u64::try_from(bytes.len()).unwrap(),
            role,
        });
        bytes_by_id.insert(object_id, bytes);
    };
    push(
        object_id("obj_01890f3e-7b1c-7cc0-8a1b-1234567890c0"),
        LogicalObjectRole::Candidate,
        "application/vnd.reproit.candidate.v1+json",
        candidate_bytes,
    );
    push(
        object_id("obj_01890f3e-7b1c-7cc0-8a1b-1234567890a0"),
        LogicalObjectRole::Subject,
        "application/vnd.reproit.subject-closure.v1+json",
        subject_manifest_bytes,
    );
    push(
        object_id("obj_01890f3e-7b1c-7cc0-8a1b-1234567890a1"),
        LogicalObjectRole::Subject,
        "application/vnd.reproit.subject-file.v1",
        application_bytes,
    );
    push(
        object_id("obj_01890f3e-7b1c-7cc0-8a1b-1234567890b0"),
        LogicalObjectRole::Trigger,
        "application/vnd.reproit.trigger.v1+json",
        trigger_bytes,
    );
    push(
        trigger.inputs[0].object_id,
        LogicalObjectRole::Trigger,
        "application/json",
        trigger_input_bytes,
    );
    push(
        failure.failure.object_id,
        LogicalObjectRole::Failure,
        "application/vnd.reproit.failure.v1+json",
        failure_bytes,
    );
    push(
        object_id("obj_01890f3e-7b1c-7cc0-8a1b-1234567890e0"),
        LogicalObjectRole::WorldManifest,
        "application/vnd.reproit.world-manifest.v1+json",
        world_manifest_bytes,
    );
    let world_media = world.points[0].artifacts[0].media_type.clone();
    push(
        object_id("obj_01890f3e-7b1c-7cc0-8a1b-1234567890e1"),
        LogicalObjectRole::WorldState,
        &world_media,
        world_bytes,
    );

    let closure_policy: ClosurePolicy = decode(CLOSURE_POLICY_JSON);
    let support = build_backend_support_package(
        decode::<SupportBundle>(SUPPORT_BUNDLE_JSON),
        closure_policy.clone(),
        BackendSdk::Rust,
        ProcessorArchitecture::X86_64,
        decode::<DebuggerContract>(DEBUGGER_CONTRACT_JSON),
        Digest::of(b"backend admission fixture"),
    )
    .unwrap();
    let closure: WorldClosure = decode(WORLD_CLOSURE_JSON);
    let capsule = close_replay_capsule(&CandidateClosureRequest {
        candidate: &candidate,
        candidate_objects: &descriptors,
        closure: &closure,
        failure: &failure,
        support: &support,
        trigger: &trigger,
        world: &world,
    })
    .unwrap();
    bytes_by_id.remove(&object_id("obj_01890f3e-7b1c-7cc0-8a1b-1234567890c0"));
    let objects = ObjectClosure::new(&capsule.objects, bytes_by_id).unwrap();
    let input = AdmissionInput {
        capsule,
        closure,
        closure_policy,
        expected_failure,
        objects,
        perturbations: decode(PERTURBATIONS_JSON),
    };
    (candidate, input)
}

fn fixture_elf() -> Vec<u8> {
    let mut bytes = vec![0_u8; 64];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
    bytes.extend_from_slice(b"backend admission fixture subject");
    bytes
}

fn subject_closure_manifest(application_bytes: &[u8]) -> SubjectClosureManifest {
    let application_digest = Digest::of(application_bytes);
    let path = "/reproit/subject/bin/orders".to_owned();
    let manifest = SubjectClosureManifest {
        architecture: "architecture.x86-64".to_owned(),
        debug_artifacts: vec![DebugArtifactBinding {
            artifact_digest: application_digest,
            kind: DebugArtifactKind::Dwarf,
            module_digest: application_digest,
            path: path.clone(),
        }],
        files: vec![SubjectFile {
            executable: true,
            object_digest: application_digest,
            path: path.clone(),
        }],
        format: SubjectClosureFormat::V1,
        launch: SubjectLaunch {
            arguments: Vec::new(),
            environment_names: vec!["RUST_LOG".to_owned()],
            executable: path.clone(),
            working_directory: "/reproit/subject/app".to_owned(),
        },
        modules: vec![SubjectModule {
            identity: "orders".to_owned(),
            module_digest: application_digest,
            path,
        }],
        objects: vec![SubjectClosureObject {
            digest: application_digest,
            kind: SubjectObjectKind::Application,
            media_type: "application/vnd.reproit.subject-file.v1".to_owned(),
            size: u64::try_from(application_bytes.len()).unwrap(),
        }],
        operating_system: "operating-system.linux".to_owned(),
        runtime_family: SubjectRuntimeFamily::Rust,
        total_bytes: u64::try_from(application_bytes.len()).unwrap(),
    };
    manifest.validate().unwrap();
    manifest
}

fn upload_metadata() -> UploadMetadata {
    UploadMetadata {
        campaign_context: None,
        causal_parent_ids: Vec::new(),
        capture_id: "cap_01890f3e-7b1c-7cc0-8a1b-123456789abc".parse().unwrap(),
        operation_id: None,
        organization_id: "org_01890f3e-7b1c-7cc0-8a1b-123456789abd".parse().unwrap(),
        project_id: "prj_01890f3e-7b1c-7cc0-8a1b-123456789abe".parse().unwrap(),
        repository_id: "source.example/acme/commerce".to_owned(),
        service_id: "svc_01890f3e-7b1c-7cc0-8a1b-123456789abf".parse().unwrap(),
        service_path: "services/orders".to_owned(),
        signature_time: "2026-01-01T00:00:00.000Z".parse::<Timestamp>().unwrap(),
        source_revision: "0123456789abcdef".to_owned(),
        wrapped_key: WrappedKey {
            algorithm: "fixture".to_owned(),
            context_version: 1,
            key_reference: "fixture://key".to_owned(),
            provider_id: "fixture".to_owned(),
            wrapped_bytes: "AA".to_owned(),
        },
    }
}

fn object_id(value: &str) -> ObjectId {
    value.parse().unwrap()
}

fn decode<T>(json: &str) -> T
where
    T: for<'de> serde::Deserialize<'de>,
{
    canonical::parse_strict(json.as_bytes()).unwrap()
}

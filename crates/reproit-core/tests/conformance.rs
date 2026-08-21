use std::collections::BTreeMap;

use jsonschema::{Registry, Validator};
use reproit_core::{
    Error, ErrorCode, canonical,
    crypto::decode_base64url,
    identity::Digest,
    model::{
        AdmissionVerificationKey, AdmissionVerificationKeyRequest, AuthenticationContext,
        Candidate, CandidateMailboxItem, CaptureBatchIdentity, CaptureBatchManifest,
        ChunkKeyContext, ClosurePolicy, DebuggerContract, DependencyCursorPayload,
        DependencyLimits, DependencyTranscript, EnvironmentPolicy, ExecutionGrant,
        ExecutionGrantOperation, ExecutionPolicy, ExecutionResult, ExecutionWorkClass,
        ExecutorCapabilityEvidence, ExecutorEvidenceScope, FailureGrouping, FailureIdentity,
        FailureStormIdentity, KeptReference, KeyOperationLimits, ManagedCandidateCaptureGrant,
        ManagedCandidateCaptureGrantExpectation, ManagedCandidateCiphertextIdentity,
        ManagedCandidateIdentity, ManagedCandidateManifest, ObjectKeyContext, OciOperationLimits,
        Perturbation, ProcessingMode, ProcessorObservation, ProcessorReductionReceipt,
        ProcessorRequirement, Proof, ProviderResourceClaim, ReplayCapsule, SourcePreparationPolicy,
        Subject, SubjectClosureManifest, SupportBundle, SupportRegistry, UploadEnvelope, Validate,
        VerifiedSupportRegistry, WorldCheckpoint, WorldClosure, WorldHistoryLimits, WorldToken,
        validate_admission_verification_key, verify_environment_policy, verify_execution_grant,
        verify_executor_capability_evidence, verify_managed_candidate_capture_grant,
        verify_support_registry,
    },
    proof,
};
use serde_json::{Value, json};

const CORE_SCHEMA: &str = include_str!("../../../specs/v1/schemas.json");
const CLOUD_SCHEMA: &str = include_str!("../../../specs/v1/cloud-api-schemas.json");
const DEFERRED_CANDIDATE_SCHEMA: &str =
    include_str!("../../../specs/v1/deferred-candidate-schema.json");
const DEFERRED_CANDIDATE_VECTOR: &str =
    include_str!("../../../specs/v1/deferred-candidate-vector.json");
const CUSTOMER_MAILBOX_SCHEMA: &str =
    include_str!("../../../specs/v1/customer-mailbox-schema.json");
const CUSTOMER_MAILBOX_VECTOR: &str =
    include_str!("../../../specs/v1/customer-mailbox-vector.json");
const RUNTIME_CAPACITY_STATUS_SCHEMA: &str =
    include_str!("../../../specs/v1/runtime-capacity-status-schema.json");
const RUNTIME_CAPACITY_STATUS_VECTOR: &str =
    include_str!("../../../specs/v1/runtime-capacity-status-vector.json");
const CORE_VECTORS: &str = include_str!("../../../specs/v1/vectors.json");
const PROTOCOL_VECTORS: &str = include_str!("../../../specs/v1/protocol-vectors.json");
const CLOUD_VECTORS: &str = include_str!("../../../specs/v1/cloud-api-vectors.json");
const CRYPTO_VECTORS: &str = include_str!("../../../specs/v1/crypto-vectors.json");

const CORE_ID: &str = "https://reproit.dev/spec/v1/schemas.json";
const CLOUD_ID: &str = "https://reproit.dev/spec/v1/cloud-api-schemas.json";

#[test]
fn schemas_are_valid_draft_2020_12() {
    for schema in [
        CORE_SCHEMA,
        CLOUD_SCHEMA,
        DEFERRED_CANDIDATE_SCHEMA,
        CUSTOMER_MAILBOX_SCHEMA,
        RUNTIME_CAPACITY_STATUS_SCHEMA,
    ] {
        let schema = parse(schema);
        jsonschema::meta::validate(&schema).expect("the normative schema must be valid");
    }
}

#[test]
fn runtime_capacity_status_vector_is_strict_and_payload_free() {
    let schema = parse(RUNTIME_CAPACITY_STATUS_SCHEMA);
    let vector = parse(RUNTIME_CAPACITY_STATUS_VECTOR);
    let validator = jsonschema::validator_for(&schema).expect("Runtime status schema");
    assert!(validator.is_valid(&vector["value"]));
    let mut unknown = vector["value"].clone();
    unknown["customer_value"] = json!("secret");
    assert!(!validator.is_valid(&unknown));
    let mut overflow = vector["value"].clone();
    overflow["recall"]["candidate_queue_full"] = json!(9_223_372_036_854_775_808_u64);
    assert!(!validator.is_valid(&overflow));
}

#[test]
fn customer_mailbox_vectors_match_the_strict_schema_and_models() {
    let schema = parse(CUSTOMER_MAILBOX_SCHEMA);
    let vectors = parse(CUSTOMER_MAILBOX_VECTOR);
    let validator = jsonschema::validator_for(&schema).expect("customer mailbox schema");
    for name in ["inline", "object"] {
        let entry = &vectors[name];
        assert!(validator.is_valid(&entry["value"]), "{name}");
        let item: CandidateMailboxItem = decode(&entry["value"]);
        item.validate().expect("valid customer mailbox item");
        assert_eq!(
            canonical::digest(&item)
                .expect("mailbox digest")
                .to_string(),
            string(&entry["canonical_sha256"]),
        );
    }

    let mut mismatched_identity = vectors["inline"]["value"].clone();
    mismatched_identity["identity"]["world_id"] =
        json!("sha256:6666666666666666666666666666666666666666666666666666666666666666");
    let item: CandidateMailboxItem = decode(&mismatched_identity);
    assert_eq!(
        item.validate().expect_err("mismatched identity").code,
        ErrorCode::ObjectDigestMismatch,
    );

    let mut unknown = vectors["object"]["value"].clone();
    unknown["unknown"] = json!(true);
    assert!(!validator.is_valid(&unknown));
}

#[test]
fn deferred_candidate_vector_matches_its_strict_schema() {
    let schema = parse(DEFERRED_CANDIDATE_SCHEMA);
    let vector = parse(DEFERRED_CANDIDATE_VECTOR);
    let validator = jsonschema::validator_for(&schema).expect("deferred candidate schema");
    assert!(validator.is_valid(&vector["value"]));

    let mut unknown = vector["value"].clone();
    unknown["unknown"] = json!(true);
    assert!(!validator.is_valid(&unknown));

    let mut oversized = vector["value"].clone();
    oversized["cipher_size"] = json!(1_048_605);
    assert!(!validator.is_valid(&oversized));
}

#[test]
fn v1_contract_has_one_admitted_capsule_and_no_representation_api() {
    let core = parse(CORE_SCHEMA);
    let cloud = parse(CLOUD_SCHEMA);
    let core_definitions = object(&core["$defs"]);
    let cloud_definitions = object(&cloud["$defs"]);
    for removed in [
        "capsule_optimization_envelope",
        "clean_download_proof",
        "reduction_group",
        "reduction_group_manifest",
        "representation_id",
        "world_reduction_bounds",
        "world_reduction_receipt",
        "world_reduction_trial",
    ] {
        assert!(
            !core_definitions.contains_key(removed),
            "removed Core contract: {removed}"
        );
    }
    for removed in [
        "representation_cancelled",
        "representation_commit",
        "representation_id",
        "representation_pending",
        "representation_promotion",
        "representation_promotion_request",
        "representation_start",
        "representation_state",
    ] {
        assert!(
            !cloud_definitions.contains_key(removed),
            "removed Cloud contract: {removed}"
        );
    }
    let grant = &cloud_definitions["download_grant"];
    assert_eq!(
        grant["properties"]["capsule_digest"]["$ref"],
        "schemas.json#/$defs/digest"
    );
}

#[test]
fn duplicate_object_identities_and_chunk_indexes_are_rejected() {
    let vectors: Value = serde_json::from_str(CORE_VECTORS).expect("Core vectors");
    let mut duplicate_object: CaptureBatchManifest =
        decode(&vectors["capture_batch_manifest"]["value"]);
    duplicate_object.objects[1].descriptor.object_id =
        duplicate_object.objects[0].descriptor.object_id;
    assert_eq!(
        duplicate_object
            .validate()
            .expect_err("duplicate object identity"),
        Error::schema_invalid()
    );

    let mut duplicate_chunk: CaptureBatchManifest =
        decode(&vectors["capture_batch_manifest"]["value"]);
    let repeated = duplicate_chunk.objects[0].chunks[0].clone();
    duplicate_chunk.objects[0].chunks.push(repeated);
    assert_eq!(
        duplicate_chunk
            .validate()
            .expect_err("duplicate chunk index"),
        Error::schema_invalid()
    );
}

#[test]
fn all_positive_schema_vectors_validate() {
    let schemas = schemas();
    let registry = registry(&schemas);
    for (bundle, schema_id) in [(PROTOCOL_VECTORS, CORE_ID), (CLOUD_VECTORS, CLOUD_ID)] {
        let bundle = parse(bundle);
        for (name, entry) in object(&bundle["positive"]) {
            let schema_name = string(&entry["schema"]);
            let validator = validator(&registry, schema_id, schema_name);
            assert!(
                validator.is_valid(&entry["value"]),
                "positive vector {name} must match {schema_name}"
            );
        }
    }
}

#[test]
fn subject_launch_arguments_obey_the_schema_byte_bound() {
    let vectors = parse(PROTOCOL_VECTORS);
    let mut subject: Subject = decode(&vectors["positive"]["subject"]["value"]);
    subject.arguments.push("x".repeat(4_097));
    assert_eq!(subject.validate().unwrap_err(), Error::schema_invalid());

    let mut closure: SubjectClosureManifest =
        decode(&vectors["positive"]["subject_closure_manifest"]["value"]);
    closure.launch.arguments.push("x".repeat(4_097));
    assert_eq!(closure.validate().unwrap_err(), Error::schema_invalid());
}

#[test]
fn subject_closure_preserves_zero_byte_files_and_total_integrity() {
    let vectors = parse(PROTOCOL_VECTORS);
    let mut closure: SubjectClosureManifest =
        decode(&vectors["positive"]["subject_closure_manifest"]["value"]);
    let empty_digest = Digest::of(&[]);
    let empty = closure
        .objects
        .iter()
        .find(|object| object.digest == empty_digest)
        .expect("the subject closure must include the empty runtime file");
    assert_eq!(empty.size, 0);
    closure.validate().expect("zero-byte subject file");

    closure.total_bytes += 1;
    assert_eq!(
        closure
            .validate()
            .expect_err("the declared total must bind every object size"),
        Error::schema_invalid()
    );
}

#[test]
fn schema_negative_vectors_fail_before_semantics() {
    let schemas = schemas();
    let registry = registry(&schemas);
    for (bundle, schema_id) in [(PROTOCOL_VECTORS, CORE_ID), (CLOUD_VECTORS, CLOUD_ID)] {
        let bundle = parse(bundle);
        for mutation in array(&bundle["negative"]) {
            if mutation["layer"] == "semantic" {
                continue;
            }
            let expected = string(&mutation["expected"]);
            if !matches!(expected, "SCHEMA_INVALID" | "PRIORITY_INVALID") {
                continue;
            }
            let base = string(&mutation["base"]);
            let schema_name = string(&mutation["schema"]);
            let mut value = bundle["positive"][base]["value"].clone();
            apply_mutation(&mut value, mutation);
            let validator = validator(&registry, schema_id, schema_name);
            assert!(
                !validator.is_valid(&value),
                "negative vector {} must fail schema validation",
                string(&mutation["name"])
            );
        }
    }
}

#[test]
fn environment_policy_vector_verifies_scope_revision_time_and_signature() {
    let vectors = parse(PROTOCOL_VECTORS);
    let policy: EnvironmentPolicy = decode(&vectors["positive"]["environment_policy"]["value"]);
    let public_key = decode_base64url::<32>(string(
        &vectors["verification_keys"]["environment-policy-test"],
    ))
    .expect("environment policy verification key");
    let now = "2026-08-08T12:01:00.000Z".parse().expect("timestamp");
    verify_environment_policy(
        &policy,
        policy.organization_id,
        &policy.signer_key_id,
        Some(6),
        &now,
        &public_key,
    )
    .expect("the environment policy must verify");

    for mutation in array(&vectors["negative"])
        .iter()
        .filter(|mutation| string(&mutation["base"]) == "environment_policy")
    {
        let mut changed = vectors["positive"]["environment_policy"]["value"].clone();
        apply_mutation(&mut changed, mutation);
        if string(&mutation["name"]) == "environment-policy-expired" {
            changed["replay_hosts"][0]["expires_at"] = mutation["value"].clone();
        }
        let Ok(changed) = serde_json::from_value::<EnvironmentPolicy>(changed) else {
            assert_eq!(string(&mutation["expected"]), "SCHEMA_INVALID");
            continue;
        };
        let expected: ErrorCode =
            serde_json::from_value(mutation["expected"].clone()).expect("expected error code");
        let error = verify_environment_policy(
            &changed,
            policy.organization_id,
            &policy.signer_key_id,
            Some(6),
            &now,
            &public_key,
        )
        .expect_err("a changed environment policy must fail");
        assert_eq!(error.code, expected, "{}", string(&mutation["name"]));
    }
}

#[test]
fn managed_candidate_vectors_bind_identity_key_reference_and_capture_grant() {
    let vectors = parse(PROTOCOL_VECTORS);
    let identity: ManagedCandidateIdentity =
        decode(&vectors["positive"]["managed_candidate_identity"]["value"]);
    let manifest: ManagedCandidateManifest =
        decode(&vectors["positive"]["managed_candidate_manifest"]["value"]);
    let ciphertext: ManagedCandidateCiphertextIdentity =
        decode(&vectors["positive"]["managed_candidate_ciphertext_identity"]["value"]);
    let grant: ManagedCandidateCaptureGrant =
        decode(&vectors["positive"]["managed_candidate_capture_grant"]["value"]);
    identity.validate().expect("managed candidate identity");
    manifest.validate().expect("managed candidate manifest");
    ciphertext
        .validate()
        .expect("managed candidate ciphertext identity");
    let expectation = ManagedCandidateCaptureGrantExpectation {
        candidate_identity_digest: manifest.candidate_identity_digest,
        candidate_key_reference: manifest.candidate_key_reference.clone(),
        capture_id: identity.capture_id,
        organization_id: identity.organization_id,
        project_id: identity.project_id,
        service_id: identity.service_id,
        signer_key_id: grant.signer_key_id.clone(),
    };
    let now = "2026-01-01T00:00:30.000Z".parse().unwrap();
    let public_key = decode_base64url::<32>(string(
        &vectors["verification_keys"]["managed-candidate-capture-test"],
    ))
    .unwrap();
    verify_managed_candidate_capture_grant(&grant, &expectation, &now, &public_key).unwrap();

    for name in [
        "managed-candidate-capture-grant-wrong-key-reference",
        "managed-candidate-capture-grant-expired",
        "managed-candidate-capture-grant-wrong-service",
    ] {
        let mutation = array(&vectors["negative"])
            .iter()
            .find(|mutation| string(&mutation["name"]) == name)
            .unwrap();
        let mut changed = vectors["positive"]["managed_candidate_capture_grant"]["value"].clone();
        apply_mutation(&mut changed, mutation);
        let changed: ManagedCandidateCaptureGrant = decode(&changed);
        assert_eq!(
            verify_managed_candidate_capture_grant(&changed, &expectation, &now, &public_key,)
                .unwrap_err()
                .code,
            ErrorCode::AttestationScope,
            "{name}"
        );
    }
}

#[test]
fn environment_policy_enforces_host_scope_and_fleet_bounds() {
    let vectors = parse(PROTOCOL_VECTORS);
    let policy: EnvironmentPolicy = decode(&vectors["positive"]["environment_policy"]["value"]);

    let mut duplicate_host = policy.clone();
    let mut changed_host = duplicate_host.replay_hosts[0].clone();
    changed_host.tls_identity = Digest::of(b"another TLS identity");
    duplicate_host.replay_hosts.push(changed_host);
    assert_eq!(
        duplicate_host.validate().expect_err("duplicate host").code,
        ErrorCode::SchemaInvalid
    );

    let mut host_overflow = policy.clone();
    host_overflow.replay_hosts = (0_u8..65)
        .map(|index| {
            let mut host = policy.replay_hosts[0].clone();
            host.host_id = format!("host-{index:02}");
            host
        })
        .collect();
    assert_eq!(
        host_overflow.validate().expect_err("host overflow").code,
        ErrorCode::SchemaInvalid
    );

    let mut scope_overflow = policy.clone();
    let scope = scope_overflow.replay_hosts[0].scopes[0].clone();
    scope_overflow.replay_hosts[0].scopes = vec![scope; 257];
    assert_eq!(
        scope_overflow.validate().expect_err("scope overflow").code,
        ErrorCode::SchemaInvalid
    );

    let mut wrong_scope = policy.clone();
    wrong_scope.replay_hosts[0].scopes[0].organization_id =
        "org_01890f3e-7b1c-7cc0-8a1b-123456789999"
            .parse()
            .expect("organization ID");
    assert_eq!(
        wrong_scope.validate().expect_err("wrong organization").code,
        ErrorCode::SchemaInvalid
    );
}

#[test]
fn processor_vectors_validate_exact_native_reduction_evidence() {
    let vectors = parse(PROTOCOL_VECTORS);
    let positive = &vectors["positive"];
    for name in ["processor_observation_arm64", "processor_observation_x86"] {
        let observation: ProcessorObservation = decode(&positive[name]["value"]);
        observation.validate().expect("processor observation");
    }
    for name in ["processor_requirement_arm64", "processor_requirement_x86"] {
        let requirement: ProcessorRequirement = decode(&positive[name]["value"]);
        requirement.validate().expect("processor requirement");
    }
    let receipt: ProcessorReductionReceipt =
        decode(&positive["processor_reduction_receipt"]["value"]);
    receipt.validate().expect("processor reduction receipt");

    let mut out_of_order: ProcessorObservation =
        decode(&positive["processor_observation_x86"]["value"]);
    out_of_order.instruction_features.swap(0, 1);
    assert_eq!(
        out_of_order.validate().expect_err("feature order").code,
        ErrorCode::SchemaInvalid
    );

    let mut too_many_trials = receipt.clone();
    let trial = too_many_trials.trials[0].clone();
    too_many_trials.trials = vec![trial; 17];
    assert_eq!(
        too_many_trials.validate().expect_err("trial limit").code,
        ErrorCode::SchemaInvalid
    );
}

#[test]
fn debugger_contract_binds_protocol_artifact_and_architectures() {
    let vectors = parse(PROTOCOL_VECTORS);
    for name in [
        "debugger_contract",
        "debugger_contract_gdbserver_arm64",
        "debugger_contract_debugpy",
        "debugger_contract_delve",
        "debugger_contract_delve_arm64",
        "debugger_contract_netcoredbg",
        "debugger_contract_netcoredbg_arm64",
        "debugger_contract_node",
        "debugger_contract_node_arm64",
    ] {
        let contract: DebuggerContract = decode(&vectors["positive"][name]["value"]);
        contract.validate().expect("debugger contract");
    }
    let contract: DebuggerContract = decode(&vectors["positive"]["debugger_contract"]["value"]);

    let mut wrong_protocol = contract.clone();
    wrong_protocol.protocol = reproit_core::model::DebuggerProtocol::DebugAdapter;
    assert_eq!(
        wrong_protocol
            .validate()
            .expect_err("debugger protocol")
            .code,
        ErrorCode::SchemaInvalid
    );

    let mut unsafe_mapping = contract;
    unsafe_mapping.source_mappings[0].replay_root = "/source/../private".to_owned();
    assert_eq!(
        unsafe_mapping.validate().expect_err("source mapping").code,
        ErrorCode::SchemaInvalid
    );
}

#[test]
fn every_published_canonical_digest_matches() {
    let core = parse(CORE_VECTORS);
    for name in [
        "closure_policy",
        "capture_batch_identity",
        "capture_batch_manifest",
        "proof",
        "replay_capsule",
        "subject_closure",
        "support_bundle",
        "world_closure",
    ] {
        assert_digest(
            &core[name]["value"],
            string(&core[name]["canonical_sha256"]),
        );
    }
    for bundle in [PROTOCOL_VECTORS, CLOUD_VECTORS] {
        let bundle = parse(bundle);
        for (name, expected) in object(&bundle["canonical_sha256"]) {
            assert_digest(&bundle["positive"][name]["value"], string(expected));
        }
    }
    let crypto = parse(CRYPTO_VECTORS);
    for (name, expected) in object(&crypto["canonical_sha256"]) {
        assert_digest(&crypto[name], string(expected));
    }
}

#[test]
fn typed_core_vectors_validate() {
    let vectors = parse(CORE_VECTORS);
    let capsule: ReplayCapsule = decode(&vectors["replay_capsule"]["value"]);
    let policy: ClosurePolicy = decode(&vectors["closure_policy"]["value"]);
    let closure: WorldClosure = decode(&vectors["world_closure"]["value"]);
    let proof_record: Proof = decode(&vectors["proof"]["value"]);
    let identity: CaptureBatchIdentity = decode(&vectors["capture_batch_identity"]["value"]);
    let manifest: CaptureBatchManifest = decode(&vectors["capture_batch_manifest"]["value"]);
    let support_bundle: SupportBundle = decode(&vectors["support_bundle"]["value"]);
    let subject_closure: SubjectClosureManifest = decode(&vectors["subject_closure"]["value"]);

    capsule.validate().expect("the capsule must be valid");
    proof_record.validate().expect("the proof must be valid");
    identity
        .validate()
        .expect("the batch identity must be valid");
    manifest
        .validate()
        .expect("the batch manifest must be valid");
    support_bundle
        .validate()
        .expect("the support bundle must be valid");
    subject_closure
        .validate()
        .expect("the subject closure must be valid");
    proof::validate_world_closure(&policy, &closure).expect("the World must be closed");
    assert_eq!(
        canonical::digest(&capsule)
            .expect("the capsule must canonicalize")
            .to_string(),
        string(&vectors["replay_capsule"]["canonical_sha256"])
    );
}

#[test]
fn subject_closure_binds_files_modules_debug_artifacts_and_total_bytes() {
    let vectors = parse(CORE_VECTORS);
    let closure: SubjectClosureManifest = decode(&vectors["subject_closure"]["value"]);

    let mut missing_object = closure.clone();
    missing_object.objects.remove(0);
    assert_eq!(
        missing_object.validate().expect_err("missing object").code,
        ErrorCode::SchemaInvalid
    );

    let mut changed_module = closure.clone();
    changed_module.modules[0].module_digest = Digest::of(b"changed module");
    assert_eq!(
        changed_module.validate().expect_err("changed module").code,
        ErrorCode::SchemaInvalid
    );

    let mut unbound_debug_artifact = closure.clone();
    unbound_debug_artifact.debug_artifacts[0].module_digest = Digest::of(b"unknown module");
    assert_eq!(
        unbound_debug_artifact
            .validate()
            .expect_err("unbound debug artifact")
            .code,
        ErrorCode::SchemaInvalid
    );

    let mut wrong_total = closure;
    wrong_total.total_bytes += 1;
    assert_eq!(
        wrong_total.validate().expect_err("wrong byte total").code,
        ErrorCode::SchemaInvalid
    );
}

#[test]
fn typed_protocol_identity_vectors_validate() {
    let vectors = parse(PROTOCOL_VECTORS);
    let authentication: AuthenticationContext =
        decode(&vectors["positive"]["authentication_context"]["value"]);
    let exception: FailureIdentity =
        decode(&vectors["positive"]["exception_failure_identity"]["value"]);
    let contract: FailureIdentity =
        decode(&vectors["positive"]["contract_failure_identity"]["value"]);
    let grouping: FailureGrouping = decode(&vectors["positive"]["failure_grouping"]["value"]);
    let object_context: ObjectKeyContext =
        decode(&vectors["positive"]["object_key_context"]["value"]);
    let chunk_context: ChunkKeyContext = decode(&vectors["positive"]["chunk_key_context"]["value"]);
    let registry: SupportRegistry = decode(&vectors["positive"]["support_registry"]["value"]);
    let kept: KeptReference = decode(&vectors["positive"]["kept_reference"]["value"]);
    let kept_layout: KeptReference =
        decode(&vectors["positive"]["kept_reference_oci_layout"]["value"]);
    let candidate: Candidate = decode(&vectors["positive"]["candidate"]["value"]);
    let upload: UploadEnvelope = decode(&vectors["positive"]["upload_envelope"]["value"]);
    let key_request: AdmissionVerificationKeyRequest =
        decode(&vectors["positive"]["admission_verification_key_request"]["value"]);
    let key: AdmissionVerificationKey =
        decode(&vectors["positive"]["admission_verification_key"]["value"]);
    let execution: ExecutionResult = decode(&vectors["positive"]["execution_result"]["value"]);

    authentication
        .validate()
        .expect("the authentication context must be valid");
    exception.validate().expect("the exception must be valid");
    contract.validate().expect("the contract must be valid");
    object_context
        .validate()
        .expect("the object context must be valid");
    chunk_context
        .validate()
        .expect("the chunk context must be valid");
    registry.validate().expect("the registry must be valid");
    kept.validate().expect("the kept reference must be valid");
    kept_layout
        .validate()
        .expect("the OCI Image Layout kept reference must be valid");
    let release_key = decode_base64url::<32>(string(
        &vectors["verification_keys"]["reproit-release-test"],
    ))
    .expect("the release verification key must decode");
    verify_support_registry(&registry, "1.0.0", "reproit-release-test", &release_key)
        .expect("the signed support registry must be authorized");
    candidate
        .validate()
        .expect("the candidate must be complete");
    upload.validate().expect("the upload must be complete");
    validate_admission_verification_key(&key_request, &key)
        .expect("the admission verification key must match its request");
    execution
        .validate()
        .expect("the execution result must be valid");
    assert_eq!(
        exception.grouping().expect("grouping must derive"),
        grouping
    );
    assert!(!exception.matches(&contract));
}

#[test]
fn common_envelopes_validate_profile_identity_without_backend_policy() {
    let vectors = parse(PROTOCOL_VECTORS);
    let mut upload: UploadEnvelope = decode(&vectors["positive"]["upload_envelope"]["value"]);
    upload.profile = "command-line".to_owned();
    upload.profile_format = 2;
    upload
        .validate()
        .expect("a common profile identity must validate");

    upload.profile = "Backend".to_owned();
    let error = upload
        .validate()
        .expect_err("an invalid common profile identity must fail");
    assert_eq!(error.code, ErrorCode::SchemaInvalid);
}

#[test]
fn managed_upload_summary_rejects_subject_controlled_cloud_metadata() {
    let vectors = parse(PROTOCOL_VECTORS);
    let mut upload: UploadEnvelope = decode(&vectors["positive"]["upload_envelope"]["value"]);
    upload.processing_mode = ProcessingMode::Managed;
    upload.failure_summary.operation = "captured-operation".to_owned();
    upload.failure_summary.type_name = "exception".to_owned();
    upload.failure_summary.stable_code = None;
    upload.trigger_summary.operation = "captured-operation".to_owned();
    upload.capture_batch_digest = canonical::digest(&CaptureBatchIdentity {
        capture_id: upload.capture_id,
        cipher_suite: upload.cipher_suite.clone(),
        format: reproit_core::model::CaptureBatchIdentityFormat::V1,
        manifest_object: upload.manifest_object.clone(),
        objects: upload.objects.clone(),
        processing_mode: upload.processing_mode,
    })
    .expect("the managed capture identity must digest");
    upload
        .validate()
        .expect("a managed envelope with a fixed summary must validate");

    let schemas = schemas();
    let registry = registry(&schemas);
    let schema = validator(&registry, CORE_ID, "upload_envelope");
    let value = serde_json::to_value(&upload).expect("the managed envelope must serialize");
    assert!(schema.is_valid(&value));

    let secret = "managed-secret-must-not-escape";
    let mut secret_type = upload.clone();
    secret_type.failure_summary.type_name = secret.to_owned();
    assert_eq!(
        secret_type
            .validate()
            .expect_err("a subject-controlled failure type must fail")
            .code,
        ErrorCode::SchemaInvalid
    );
    assert!(!schema.is_valid(
        &serde_json::to_value(secret_type).expect("the mutated envelope must serialize")
    ));

    let mut secret_code = upload.clone();
    secret_code.failure_summary.stable_code = Some(secret.to_owned());
    assert_eq!(
        secret_code
            .validate()
            .expect_err("a subject-controlled stable code must fail")
            .code,
        ErrorCode::SchemaInvalid
    );
    assert!(!schema.is_valid(
        &serde_json::to_value(secret_code).expect("the mutated envelope must serialize")
    ));

    let mut secret_operation = upload;
    secret_operation.failure_summary.operation = secret.to_owned();
    secret_operation.trigger_summary.operation = secret.to_owned();
    assert_eq!(
        secret_operation
            .validate()
            .expect_err("a subject-controlled operation label must fail")
            .code,
        ErrorCode::SchemaInvalid
    );
    assert!(!schema.is_valid(
        &serde_json::to_value(secret_operation).expect("the mutated envelope must serialize")
    ));
}

#[test]
fn unsigned_support_registry_is_an_unsupported_bundle_set() {
    let vectors = parse(PROTOCOL_VECTORS);
    let mut registry: SupportRegistry = decode(&vectors["positive"]["support_registry"]["value"]);
    registry.signature = "A".repeat(86);
    let release_key = decode_base64url::<32>(string(
        &vectors["verification_keys"]["reproit-release-test"],
    ))
    .expect("the release verification key must decode");
    let error = verify_support_registry(&registry, "1.0.0", "reproit-release-test", &release_key)
        .expect_err("the unsigned registry must fail closed");
    assert_eq!(
        error.code,
        reproit_core::ErrorCode::UnsupportedCapabilitySet
    );
}

#[test]
fn signed_registry_authorizes_only_its_exact_profile_and_bundle() {
    let vectors = parse(PROTOCOL_VECTORS);
    let registry: SupportRegistry = decode(&vectors["positive"]["support_registry"]["value"]);
    let release_key = decode_base64url::<32>(string(
        &vectors["verification_keys"]["reproit-release-test"],
    ))
    .expect("the release verification key must decode");
    let verified = VerifiedSupportRegistry::new(
        registry.clone(),
        "1.0.0",
        "reproit-release-test",
        &release_key,
    )
    .expect("the support registry must verify");
    let bundle = registry.bundle_digests[0];

    verified
        .require_bundle("backend", 1, bundle)
        .expect("the registered Backend bundle must be authorized");
    for result in [
        verified.require_profile("unknown", 1),
        verified.require_profile("backend", 2),
        verified.require_bundle("backend", 1, Digest::of(b"unknown bundle")),
    ] {
        assert_eq!(
            result
                .expect_err("unregistered profile input must fail")
                .code,
            ErrorCode::UnsupportedCapabilitySet
        );
    }
}

#[test]
fn amended_resource_vectors_have_one_typed_contract() {
    let vectors = parse(PROTOCOL_VECTORS);
    let positive = &vectors["positive"];
    let storm: FailureStormIdentity = decode(&positive["failure_storm_identity"]["value"]);
    let dependency: DependencyLimits = decode(&positive["dependency_limits"]["value"]);
    let dependency_cursor: DependencyCursorPayload =
        decode(&positive["dependency_close_request"]["value"]["cursor"]);
    let dependency_transcript: DependencyTranscript =
        decode(&positive["dependency_transcript"]["value"]);
    let execution: ExecutionPolicy = decode(&positive["execution_policy"]["value"]);
    let key: KeyOperationLimits = decode(&positive["key_operation_limits"]["value"]);
    let oci: OciOperationLimits = decode(&positive["oci_operation_limits"]["value"]);
    let provider: ProviderResourceClaim = decode(&positive["provider_resource_claim"]["value"]);
    let source: SourcePreparationPolicy = decode(&positive["source_preparation_policy"]["value"]);
    let history: WorldHistoryLimits = decode(&positive["world_history_limits"]["value"]);
    let checkpoint: WorldCheckpoint = decode(&positive["world_checkpoint"]["value"]);
    let world_token: WorldToken = decode(&positive["world_token"]["value"]);

    for result in [
        storm.validate(),
        dependency.validate(),
        dependency_cursor.validate(),
        dependency_transcript.validate(),
        execution.validate(),
        key.validate(),
        oci.validate(),
        provider.validate(),
        source.validate(),
        history.validate(),
        checkpoint.validate(),
        world_token.validate(),
    ] {
        result.expect("the amended resource vector must validate");
    }
    assert_eq!(
        storm
            .key()
            .expect("the storm identity must hash")
            .to_string(),
        string(&vectors["canonical_sha256"]["failure_storm_identity"])
    );
    assert!(storm.key().is_ok());
}

#[test]
fn failure_storm_identity_cannot_include_world_identity() {
    let schemas = schemas();
    let registry = registry(&schemas);
    let vectors = parse(PROTOCOL_VECTORS);
    let mutation = array(&vectors["negative"])
        .iter()
        .find(|value| string(&value["name"]) == "failure-storm-world-identity-forbidden")
        .expect("the World exclusion vector must exist");
    let mut value = vectors["positive"]["failure_storm_identity"]["value"].clone();
    apply_mutation(&mut value, mutation);
    assert!(!validator(&registry, CORE_ID, "failure_storm_identity").is_valid(&value));
}

#[test]
fn one_world_cannot_reference_more_than_sixty_four_providers() {
    let schemas = schemas();
    let registry = registry(&schemas);
    let vectors = parse(PROTOCOL_VECTORS);
    let mut checkpoint = vectors["positive"]["world_checkpoint"]["value"].clone();
    let point = checkpoint["points"][0].clone();
    checkpoint["points"] = Value::Array(vec![point; 65]);
    assert!(!validator(&registry, CORE_ID, "world_checkpoint").is_valid(&checkpoint));
}

#[test]
fn admission_verification_key_scope_is_exact() {
    let vectors = parse(PROTOCOL_VECTORS);
    let key: AdmissionVerificationKey =
        decode(&vectors["positive"]["admission_verification_key"]["value"]);
    let mutation = array(&vectors["negative"])
        .iter()
        .find(|value| string(&value["name"]) == "admission-verification-key-wrong-service")
        .expect("the wrong-service vector must exist");
    let mut request_value =
        vectors["positive"]["admission_verification_key_request"]["value"].clone();
    apply_mutation(&mut request_value, mutation);
    let request: AdmissionVerificationKeyRequest = decode(&request_value);
    let error = validate_admission_verification_key(&request, &key)
        .expect_err("a service substitution must fail");
    assert_eq!(error.code, ErrorCode::AttestationScope);
}

#[test]
fn executor_evidence_and_grant_vectors_verify_exact_scope() {
    let vectors = parse(PROTOCOL_VECTORS);
    let evidence: ExecutorCapabilityEvidence =
        decode(&vectors["positive"]["executor_capability_evidence"]["value"]);
    let grant: ExecutionGrant = decode(&vectors["positive"]["execution_grant"]["value"]);
    let scope = ExecutorEvidenceScope {
        organization_id: evidence.organization_id,
        project_id: evidence.project_id,
        service_id: evidence.service_id,
    };
    let public_key = decode_base64url::<32>(string(
        &vectors["executor_verification_keys"]["executor-test-key"],
    ))
    .expect("executor verification key");
    let now = "2026-08-08T12:01:00.000Z".parse().expect("timestamp");
    verify_executor_capability_evidence(&evidence, &scope, &now, &public_key)
        .expect("executor evidence");
    verify_execution_grant(
        &grant,
        &evidence,
        &reproit_core::model::ExecutionGrantExpectation {
            debugger_capability_digest: grant.debugger_capability_digest,
            now: &now,
            operation: ExecutionGrantOperation::Debug,
            processing_mode: grant.processing_mode,
            requester_identity: &grant.requester_identity,
            repro_digest: grant.repro_digest,
            scope: &scope,
            work_class: grant.work_class,
        },
        &public_key,
    )
    .expect("execution grant");
    let error = verify_execution_grant(
        &grant,
        &evidence,
        &reproit_core::model::ExecutionGrantExpectation {
            debugger_capability_digest: Digest::of(b"wrong debugger capability"),
            now: &now,
            operation: ExecutionGrantOperation::Debug,
            processing_mode: grant.processing_mode,
            requester_identity: &grant.requester_identity,
            repro_digest: grant.repro_digest,
            scope: &scope,
            work_class: grant.work_class,
        },
        &public_key,
    )
    .expect_err("a debugger capability substitution must fail");
    assert_eq!(error.code, ErrorCode::AttestationScope);

    let error = verify_execution_grant(
        &grant,
        &evidence,
        &reproit_core::model::ExecutionGrantExpectation {
            debugger_capability_digest: grant.debugger_capability_digest,
            now: &now,
            operation: ExecutionGrantOperation::Debug,
            processing_mode: grant.processing_mode,
            requester_identity: "another-developer",
            repro_digest: grant.repro_digest,
            scope: &scope,
            work_class: grant.work_class,
        },
        &public_key,
    )
    .expect_err("a requester identity substitution must fail");
    assert_eq!(error.code, ErrorCode::AttestationScope);

    let error = verify_execution_grant(
        &grant,
        &evidence,
        &reproit_core::model::ExecutionGrantExpectation {
            debugger_capability_digest: grant.debugger_capability_digest,
            now: &now,
            operation: ExecutionGrantOperation::Debug,
            processing_mode: grant.processing_mode,
            requester_identity: &grant.requester_identity,
            repro_digest: grant.repro_digest,
            scope: &scope,
            work_class: ExecutionWorkClass::Admission,
        },
        &public_key,
    )
    .expect_err("a work-class substitution must fail");
    assert_eq!(error.code, ErrorCode::AttestationScope);
}

#[test]
fn executor_evidence_negative_vectors_fail_closed() {
    let vectors = parse(PROTOCOL_VECTORS);
    let base = &vectors["positive"]["executor_capability_evidence"]["value"];
    let evidence: ExecutorCapabilityEvidence = decode(base);
    let scope = ExecutorEvidenceScope {
        organization_id: evidence.organization_id,
        project_id: evidence.project_id,
        service_id: evidence.service_id,
    };
    let public_key = decode_base64url::<32>(string(
        &vectors["executor_verification_keys"]["executor-test-key"],
    ))
    .expect("executor verification key");
    let now = "2026-08-08T12:01:00.000Z".parse().expect("timestamp");
    for mutation in array(&vectors["negative"])
        .iter()
        .filter(|mutation| string(&mutation["base"]) == "executor_capability_evidence")
    {
        let mut value = base.clone();
        apply_mutation(&mut value, mutation);
        let changed: ExecutorCapabilityEvidence = decode(&value);
        let error = verify_executor_capability_evidence(&changed, &scope, &now, &public_key)
            .expect_err("changed executor evidence");
        let expected: ErrorCode =
            serde_json::from_value(mutation["expected"].clone()).expect("expected error code");
        assert_eq!(error.code, expected, "{}", string(&mutation["name"]));
    }
}

#[test]
fn candidate_sequence_gap_fails_with_stable_error() {
    let vectors = parse(PROTOCOL_VECTORS);
    let mut candidate: Candidate = decode(&vectors["positive"]["candidate"]["value"]);
    candidate.records[1].sequence = 2;
    let error = candidate
        .validate()
        .expect_err("a sequence gap must be rejected");
    assert_eq!(error.code, ErrorCode::IncompleteRecordSequence);
}

#[test]
fn candidate_processing_mode_must_match_its_deployment() {
    let vectors = parse(PROTOCOL_VECTORS);
    let mutation = array(&vectors["negative"])
        .iter()
        .find(|value| string(&value["name"]) == "processing-mode-candidate-deployment-mismatch")
        .expect("candidate mode mutation");
    let mut value = vectors["positive"]["candidate"]["value"].clone();
    apply_mutation(&mut value, mutation);
    let candidate: Candidate = decode(&value);
    assert_eq!(
        candidate
            .validate()
            .expect_err("the candidate mode must bind its deployment")
            .code,
        ErrorCode::SchemaInvalid,
    );
}

#[test]
fn candidate_missing_terminal_fails_locally() {
    let vectors = parse(PROTOCOL_VECTORS);
    let mut candidate: Candidate = decode(&vectors["positive"]["candidate"]["value"]);
    candidate.records.pop();
    let error = candidate
        .validate()
        .expect_err("a missing terminal record must be rejected");
    assert_eq!(error.code, ErrorCode::IncompleteCandidate);
}

#[test]
fn duplicate_capture_nonce_fails_with_stable_error() {
    let vectors = parse(CORE_VECTORS);
    let mut identity: CaptureBatchIdentity = decode(&vectors["capture_batch_identity"]["value"]);
    identity.objects[1].nonce = identity.objects[0].nonce.clone();
    let error = identity
        .validate()
        .expect_err("a duplicate nonce must be rejected");
    assert_eq!(error.code, ErrorCode::NonceReuse);
}

#[test]
fn subject_artifact_must_match_capsule_digest() {
    let vectors = parse(CORE_VECTORS);
    let mutation = array(&vectors["foundation_mutations"])
        .iter()
        .find(|mutation| string(&mutation["name"]) == "subject-artifact-digest-mismatch")
        .expect("the subject digest mutation must exist");
    let mut value = vectors["replay_capsule"]["value"].clone();
    apply_mutation(&mut value, mutation);
    let capsule: ReplayCapsule = decode(&value);
    let error = capsule
        .validate()
        .expect_err("a changed subject artifact digest must fail");
    assert_eq!(error.code, ErrorCode::SubjectDigestMismatch);
}

#[test]
fn three_proofs_bind_the_same_sealed_capsule() {
    let vectors = parse(CORE_VECTORS);
    let capsule: ReplayCapsule = decode(&vectors["replay_capsule"]["value"]);
    let base_proof: Proof = decode(&vectors["proof"]["value"]);
    let perturbations = array(&vectors["perturbations"])
        .iter()
        .map(decode::<Perturbation>)
        .collect::<Vec<_>>();
    let capsule_digest = canonical::digest(&capsule).expect("the capsule must canonicalize");
    let proofs = perturbations
        .iter()
        .enumerate()
        .map(|(run_index, perturbation)| {
            let mut proof = base_proof.clone();
            proof.run_index = u8::try_from(run_index).unwrap();
            proof.capsule_digest = capsule_digest;
            proof.perturbation_digest =
                canonical::digest(perturbation).expect("the perturbation must canonicalize");
            proof
        })
        .collect::<Vec<_>>();

    assert_eq!(
        proof::validate_proof_set(&capsule, &proofs, &perturbations)
            .expect("the proof set must bind"),
        capsule_digest
    );

    let mut changed = proofs;
    changed[2].failure_digest = changed[2].subject_digest;
    let error = proof::validate_proof_set(&capsule, &changed, &perturbations)
        .expect_err("a changed binding must fail");
    assert_eq!(error.code, ErrorCode::AdmissionProofBinding);
}

#[test]
fn processing_mode_substitutions_break_every_cross_object_binding() {
    let vectors = parse(CORE_VECTORS);
    let protocol = parse(PROTOCOL_VECTORS);
    let mutations = array(&vectors["processing_mode_mutations"]);
    let perturbations = array(&vectors["perturbations"])
        .iter()
        .map(decode::<Perturbation>)
        .collect::<Vec<_>>();
    let base_proof: Proof = decode(&vectors["proof"]["value"]);

    let capsule_mutation = mutations
        .iter()
        .find(|value| string(&value["base"]) == "replay_capsule")
        .expect("capsule mode mutation");
    let mut capsule_value = vectors["replay_capsule"]["value"].clone();
    apply_mutation(&mut capsule_value, capsule_mutation);
    let capsule: ReplayCapsule = decode(&capsule_value);
    let capsule_digest = canonical::digest(&capsule).expect("capsule digest");
    let proofs = perturbations
        .iter()
        .enumerate()
        .map(|(run_index, perturbation)| {
            let mut proof = base_proof.clone();
            proof.run_index = u8::try_from(run_index).expect("bounded run index");
            proof.capsule_digest = capsule_digest;
            proof.perturbation_digest = canonical::digest(perturbation).expect("perturbation");
            proof
        })
        .collect::<Vec<_>>();
    assert_eq!(
        proof::validate_proof_set(&capsule, &proofs, &perturbations)
            .expect_err("the proof mode must bind the capsule")
            .code,
        ErrorCode::AdmissionProofBinding,
    );

    let manifest_mutation = mutations
        .iter()
        .find(|value| string(&value["base"]) == "capture_batch_manifest")
        .expect("manifest mode mutation");
    let mut manifest_value = vectors["capture_batch_manifest"]["value"].clone();
    apply_mutation(&mut manifest_value, manifest_mutation);
    let manifest: CaptureBatchManifest = decode(&manifest_value);
    assert_eq!(
        proof::validate_capture_manifest(
            &manifest,
            manifest.replay_capsule_digest,
            &[base_proof.clone(), base_proof.clone(), base_proof],
        )
        .expect_err("the proof mode must bind the capture batch")
        .code,
        ErrorCode::AdmissionProofBinding,
    );

    let identity_mutation = mutations
        .iter()
        .find(|value| string(&value["base"]) == "capture_batch_identity")
        .expect("capture batch identity mode mutation");
    let mut identity_value = vectors["capture_batch_identity"]["value"].clone();
    apply_mutation(&mut identity_value, identity_mutation);
    let changed_identity: CaptureBatchIdentity = decode(&identity_value);
    let envelope: UploadEnvelope = decode(&protocol["positive"]["upload_envelope"]["value"]);
    assert_ne!(
        canonical::digest(&changed_identity).expect("changed identity digest"),
        envelope.capture_batch_digest,
    );
}

#[test]
fn core_schema_mutations_are_rejected() {
    let schemas = schemas();
    let registry = registry(&schemas);
    let vectors = parse(CORE_VECTORS);
    let schema_names = BTreeMap::from([
        ("capture_batch_identity", "capture_batch_identity"),
        ("capture_batch_manifest", "capture_batch_manifest"),
        ("proof", "proof"),
        ("replay_capsule", "replay_capsule"),
        ("support_bundle", "support_bundle"),
        ("world_closure", "world_closure"),
    ]);

    for mutation in array(&vectors["proof_mutations"]) {
        let mut value = vectors["proof"]["value"].clone();
        apply_mutation(&mut value, mutation);
        assert!(!validator(&registry, CORE_ID, "proof").is_valid(&value));
    }
    for mutation in array(&vectors["foundation_mutations"]) {
        if string(&mutation["expected"]) != "SCHEMA_INVALID" {
            continue;
        }
        let base = string(&mutation["base"]);
        let mut value = vectors[base]["value"].clone();
        apply_mutation(&mut value, mutation);
        assert!(!validator(&registry, CORE_ID, schema_names[base]).is_valid(&value));
    }
}

#[test]
fn missing_closure_receipt_fails_closed() {
    let vectors = parse(CORE_VECTORS);
    let policy: ClosurePolicy = decode(&vectors["closure_policy"]["value"]);
    let mut closure: WorldClosure = decode(&vectors["world_closure"]["value"]);
    closure.receipts.pop();
    let error = proof::validate_world_closure(&policy, &closure)
        .expect_err("a missing receipt must fail closure");
    assert_eq!(error.code, ErrorCode::WorldNotClosed);
}

fn schemas() -> [Value; 2] {
    [parse(CORE_SCHEMA), parse(CLOUD_SCHEMA)]
}

fn registry(schemas: &[Value; 2]) -> Registry<'_> {
    Registry::new()
        .add(CORE_ID, &schemas[0])
        .expect("the Core schema must register")
        .add(CLOUD_ID, &schemas[1])
        .expect("the Cloud schema must register")
        .prepare()
        .expect("the schema registry must resolve")
}

fn validator(registry: &Registry<'_>, schema_id: &str, definition: &str) -> Validator {
    let reference = json!({"$ref": format!("{schema_id}#/$defs/{definition}")});
    jsonschema::options()
        .with_registry(registry)
        .build(&reference)
        .expect("the definition must compile")
}

fn apply_mutation(value: &mut Value, mutation: &Value) {
    let path = string(&mutation["path"]);
    let (parent_path, key) = path
        .rsplit_once('/')
        .expect("the mutation path must have a key");
    let parent = if parent_path.is_empty() {
        value
    } else {
        value
            .pointer_mut(parent_path)
            .expect("the mutation parent must exist")
    };
    match string(&mutation["operation"]) {
        "remove" => remove_value(parent, key),
        "add" | "replace" => replace_value(parent, key, mutation["value"].clone()),
        operation => panic!("unsupported mutation {operation}"),
    }
}

fn remove_value(parent: &mut Value, key: &str) {
    if let Some(array) = parent.as_array_mut() {
        array.remove(key.parse::<usize>().expect("the index must be numeric"));
    } else {
        parent
            .as_object_mut()
            .expect("the parent must be an object")
            .remove(key);
    }
}

fn replace_value(parent: &mut Value, key: &str, replacement: Value) {
    if let Some(array) = parent.as_array_mut() {
        array[key.parse::<usize>().expect("the index must be numeric")] = replacement;
    } else {
        parent
            .as_object_mut()
            .expect("the parent must be an object")
            .insert(key.to_owned(), replacement);
    }
}

fn assert_digest(value: &Value, expected: &str) {
    assert_eq!(
        canonical::digest_value(value)
            .expect("the vector must canonicalize")
            .to_string(),
        expected
    );
}

fn decode<T>(value: &Value) -> T
where
    T: for<'de> serde::Deserialize<'de>,
{
    canonical::parse_strict(&serde_json::to_vec(value).expect("the vector must serialize"))
        .expect("the vector must decode")
}

fn parse(value: &str) -> Value {
    serde_json::from_str(value).expect("the checked-in JSON must parse")
}

fn object(value: &Value) -> &serde_json::Map<String, Value> {
    value.as_object().expect("the value must be an object")
}

fn array(value: &Value) -> &[Value] {
    value.as_array().expect("the value must be an array")
}

fn string(value: &Value) -> &str {
    value.as_str().expect("the value must be a string")
}

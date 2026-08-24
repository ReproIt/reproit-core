use reproit_cloud_api::{
    AdminRetention, ConfigConflict, DownloadGrant, DownloadGrantLimits, DownloadLimits,
    LegalDeletion, LegalDeletionAcceptance, LifecycleLease, LifecycleLimits,
    ManagedCandidateCommit, ManagedCandidateEncryptionGrantRequest,
    ManagedCandidateEncryptionResponse, ManagedCandidateKeyRequest, ManagedCandidateKeyResponse,
    ManagedCandidateLimits, ManagedCandidateObjectRequest, ManagedCandidateStart,
    ManagedCandidateStatus, ManagedCandidateUploadRequest, ManagedExecutionMaterial,
    ManagedExecutionMaterialRequest, ManagedKeyGrant, ManagedOccurrenceKeyOpenRequest,
    ManagedOccurrenceKeyOpenResponse, ManagedOccurrenceKeyWrapRequest,
    ManagedOccurrenceKeyWrapResponse, ManagedOciGrant, ManagedOciGrantRequest, ManagedWorkerGrant,
    OciLinkRequest, OciLinkStatus, ProjectCreateRequest, ProjectCreateResult,
    ProjectTokenIssueRequest, ProjectTokenIssueResult, ProjectTokenMetadata,
    ProjectTokenRevokeRequest, ProjectTokenRevokeResult, ProjectTokenRotateRequest,
    ProjectTokenRotateResult, ProjectTokenVerifierRecord, ReproList, RetainedQuota, ServiceCatalog,
    ServiceCatalogQuery, ServiceCreateRequest, ServiceCreateResult, UploadCancelled, UploadExpired,
    UploadMissingPage, UploadMissingQuery, UploadSessionLimits, UploadStart,
    WorkloadKeyRegistration, WorkloadKeyRegistrationResult, managed_workload_key_id,
    validate_managed_workload_key_id, verify_managed_worker_key_grants,
};
use reproit_core::{
    ErrorCode, canonical,
    crypto::{encode_base64url, secret_key, verification_key, verify_signed_value},
    model::ProcessingMode,
};
use serde_json::{Value, json};

const VECTORS: &str = include_str!("../../../specs/v1/cloud-api-vectors.json");
const PROTOCOL_VECTORS: &str = include_str!("../../../specs/v1/protocol-vectors.json");

#[test]
fn cloud_responses_reject_unknown_fields_at_the_typed_boundary() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let mut list = vectors["positive"]["repro_list"]["value"].clone();
    list.as_object_mut()
        .unwrap()
        .insert("unrecognized".to_owned(), json!(true));
    let error =
        canonical::parse_strict::<ReproList>(&serde_json::to_vec(&list).unwrap()).unwrap_err();
    assert_eq!(error.code, ErrorCode::SchemaInvalid);

    let mut grant = vectors["positive"]["download_grant"]["value"].clone();
    grant
        .as_object_mut()
        .unwrap()
        .insert("another_occurrence".to_owned(), json!(true));
    let error = canonical::parse_strict::<DownloadGrant>(&serde_json::to_vec(&grant).unwrap())
        .err()
        .unwrap();
    assert_eq!(error.code, ErrorCode::SchemaInvalid);
}

#[test]
fn administration_and_resource_vectors_have_exact_typed_canonical_forms() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    assert_administration_vectors(&vectors);
    assert_managed_vectors(&vectors);
}

fn assert_administration_vectors(vectors: &Value) {
    assert_vector::<AdminRetention>(vectors, "admin_retention");
    assert_vector::<ConfigConflict>(vectors, "config_conflict");
    assert_vector::<DownloadGrantLimits>(vectors, "download_grant_limits");
    assert_vector::<DownloadLimits>(vectors, "download_limits");
    assert_vector::<LegalDeletion>(vectors, "legal_deletion");
    assert_vector::<LegalDeletionAcceptance>(vectors, "legal_deletion_acceptance");
    assert_vector::<LifecycleLease>(vectors, "lifecycle_lease");
    assert_vector::<LifecycleLimits>(vectors, "lifecycle_limits");
    assert_vector::<RetainedQuota>(vectors, "retained_quota");
    assert_onboarding_vectors(vectors);
    assert_vector::<ServiceCatalog>(vectors, "service_catalog");
    assert_vector::<ServiceCatalogQuery>(vectors, "service_catalog_query");
    assert_vector::<UploadCancelled>(vectors, "upload_cancelled");
    assert_vector::<UploadExpired>(vectors, "upload_expired");
    assert_vector::<UploadMissingPage>(vectors, "upload_missing_page");
    assert_vector::<UploadMissingQuery>(vectors, "upload_missing_query");
    assert_vector::<UploadSessionLimits>(vectors, "upload_session_limits");
    assert_vector::<UploadStart>(vectors, "upload_start");
    assert_vector::<OciLinkRequest>(vectors, "oci_link_request");
    assert_vector::<OciLinkStatus>(vectors, "oci_link_status");
    let link: OciLinkRequest = canonical::parse_strict(
        &serde_json::to_vec(&vectors["positive"]["oci_link_request"]["value"]).unwrap(),
    )
    .unwrap();
    link.validate().unwrap();
    let mut embedded_credential = vectors["positive"]["oci_link_request"]["value"].clone();
    embedded_credential["destination"] = vectors["negative"]
        .as_array()
        .unwrap()
        .iter()
        .find(|value| value["name"] == "oci-link-embedded-credential")
        .unwrap()["value"]
        .clone();
    let embedded_credential: OciLinkRequest =
        canonical::parse_strict(&serde_json::to_vec(&embedded_credential).unwrap()).unwrap();
    assert_eq!(
        embedded_credential.validate().unwrap_err().code,
        reproit_core::ErrorCode::SchemaInvalid,
    );
}

fn assert_onboarding_vectors(vectors: &Value) {
    assert_vector::<ProjectCreateRequest>(vectors, "project_create_request");
    assert_vector::<ProjectCreateResult>(vectors, "project_create_result");
    assert_vector::<ProjectTokenIssueRequest>(vectors, "project_token_issue_request");
    assert_vector::<ProjectTokenIssueResult>(vectors, "project_token_issue_result");
    assert_vector::<ProjectTokenMetadata>(vectors, "project_token_metadata");
    assert_vector::<ProjectTokenRevokeRequest>(vectors, "project_token_revoke_request");
    assert_vector::<ProjectTokenRevokeResult>(vectors, "project_token_revoke_result");
    assert_vector::<ProjectTokenRotateRequest>(vectors, "project_token_rotate_request");
    assert_vector::<ProjectTokenRotateResult>(vectors, "project_token_rotate_result");
    assert_vector::<ProjectTokenVerifierRecord>(vectors, "project_token_verifier_record");
    assert_vector::<ServiceCreateRequest>(vectors, "service_create_request");
    assert_vector::<ServiceCreateResult>(vectors, "service_create_result");

    parse_vector::<ProjectCreateRequest>(vectors, "project_create_request")
        .validate()
        .unwrap();
    parse_vector::<ProjectCreateResult>(vectors, "project_create_result")
        .validate()
        .unwrap();
    parse_vector::<ProjectTokenIssueRequest>(vectors, "project_token_issue_request")
        .validate()
        .unwrap();
    parse_vector::<ProjectTokenIssueResult>(vectors, "project_token_issue_result")
        .validate()
        .unwrap();
    parse_vector::<ProjectTokenMetadata>(vectors, "project_token_metadata")
        .validate()
        .unwrap();
    parse_vector::<ProjectTokenRevokeRequest>(vectors, "project_token_revoke_request")
        .validate()
        .unwrap();
    parse_vector::<ProjectTokenRevokeResult>(vectors, "project_token_revoke_result")
        .validate()
        .unwrap();
    parse_vector::<ProjectTokenRotateRequest>(vectors, "project_token_rotate_request")
        .validate()
        .unwrap();
    parse_vector::<ProjectTokenRotateResult>(vectors, "project_token_rotate_result")
        .validate()
        .unwrap();
    parse_vector::<ProjectTokenVerifierRecord>(vectors, "project_token_verifier_record")
        .validate()
        .unwrap();
    parse_vector::<ServiceCreateRequest>(vectors, "service_create_request")
        .validate()
        .unwrap();
    parse_vector::<ServiceCreateResult>(vectors, "service_create_result")
        .validate()
        .unwrap();
    parse_vector::<ServiceCatalog>(vectors, "service_catalog")
        .validate()
        .unwrap();
    parse_vector::<ServiceCatalogQuery>(vectors, "service_catalog_query")
        .validate()
        .unwrap();
}

#[test]
fn onboarding_types_reject_bounds_scope_drift_and_secret_storage() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();

    let mut expiry = vectors["positive"]["project_token_issue_request"]["value"].clone();
    expiry["expires_in_seconds"] = json!(2_592_001);
    let expiry: ProjectTokenIssueRequest =
        canonical::parse_strict(&serde_json::to_vec(&expiry).unwrap()).unwrap();
    assert_eq!(
        expiry.validate().unwrap_err().code,
        ErrorCode::SchemaInvalid
    );

    let mut catalog = vectors["positive"]["service_catalog"]["value"].clone();
    catalog["services"][0]["processing_mode"] = json!("private");
    let catalog: ServiceCatalog =
        canonical::parse_strict(&serde_json::to_vec(&catalog).unwrap()).unwrap();
    assert_eq!(
        catalog.validate().unwrap_err().code,
        ErrorCode::SchemaInvalid
    );

    let mut stored = vectors["positive"]["project_token_verifier_record"]["value"].clone();
    stored["plaintext_token"] =
        vectors["positive"]["project_token_issue_result"]["value"]["plaintext_token"].clone();
    let error = canonical::parse_strict::<ProjectTokenVerifierRecord>(
        &serde_json::to_vec(&stored).unwrap(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::SchemaInvalid);

    let mut noncanonical = vectors["positive"]["project_token_issue_result"]["value"].clone();
    noncanonical["plaintext_token"] = vectors["negative"]
        .as_array()
        .unwrap()
        .iter()
        .find(|value| value["name"] == "project-token-plaintext-noncanonical-base64url")
        .unwrap()["value"]
        .clone();
    let error = canonical::parse_strict::<ProjectTokenIssueResult>(
        &serde_json::to_vec(&noncanonical).unwrap(),
    )
    .err()
    .unwrap();
    assert_eq!(error.code, ErrorCode::SchemaInvalid);

    let mut invalid_quota = parse_vector::<RetainedQuota>(&vectors, "retained_quota");
    invalid_quota.service_repros = invalid_quota.organization_repros + 1;
    assert_eq!(
        invalid_quota.validate().unwrap_err().code,
        ErrorCode::SchemaInvalid
    );

    let mut negotiated_quota =
        parse_vector::<ServiceCreateResult>(&vectors, "service_create_result");
    negotiated_quota.retained_quota.organization_repros = 100;
    negotiated_quota.retained_quota.service_repros = 25;
    negotiated_quota.validate().unwrap();
}

fn assert_managed_vectors(vectors: &Value) {
    assert_vector::<ManagedCandidateLimits>(vectors, "managed_candidate_limits");
    assert_vector::<ManagedCandidateStart>(vectors, "managed_candidate_start");
    assert_vector::<ManagedCandidateCommit>(vectors, "managed_candidate_commit");
    assert_vector::<ManagedCandidateStatus>(vectors, "managed_candidate_status");
    assert_vector::<ManagedCandidateEncryptionGrantRequest>(
        vectors,
        "managed_candidate_encryption_grant_request",
    );
    assert_vector::<ManagedCandidateEncryptionResponse>(
        vectors,
        "managed_candidate_encryption_response",
    );
    assert_vector::<ManagedCandidateKeyResponse>(vectors, "managed_candidate_key_response");
    assert_vector::<ManagedCandidateKeyRequest>(vectors, "managed_candidate_key_request");
    assert_vector::<ManagedOccurrenceKeyWrapRequest>(
        vectors,
        "managed_occurrence_key_wrap_request",
    );
    assert_vector::<ManagedOccurrenceKeyWrapResponse>(
        vectors,
        "managed_occurrence_key_wrap_response",
    );
    assert_vector::<ManagedOccurrenceKeyOpenRequest>(
        vectors,
        "managed_occurrence_key_open_request",
    );
    assert_vector::<ManagedOccurrenceKeyOpenResponse>(
        vectors,
        "managed_occurrence_key_open_response",
    );
    assert_vector::<ManagedCandidateObjectRequest>(vectors, "managed_candidate_object_request");
    assert_vector::<ManagedCandidateUploadRequest>(vectors, "managed_candidate_upload_request");
    assert_vector::<WorkloadKeyRegistration>(vectors, "workload_key_registration");
    assert_vector::<WorkloadKeyRegistrationResult>(vectors, "workload_key_registration_result");
    assert_vector::<ManagedWorkerGrant>(vectors, "managed_worker_grant");
    assert_vector::<ManagedKeyGrant>(vectors, "managed_key_grant");
    assert_vector::<ManagedOciGrant>(vectors, "managed_oci_grant");
    assert_vector::<ManagedOciGrantRequest>(vectors, "managed_oci_grant_request");
    assert_vector::<ManagedExecutionMaterial>(vectors, "managed_execution_material");
    assert_vector::<ManagedExecutionMaterialRequest>(vectors, "managed_execution_material_request");
    assert_signed_workload_vectors(vectors);

    let upload: ManagedCandidateUploadRequest = canonical::parse_strict(
        &serde_json::to_vec(&vectors["positive"]["managed_candidate_upload_request"]["value"])
            .unwrap(),
    )
    .unwrap();
    upload.validate().unwrap();
    let managed_oci: ManagedOciGrant = canonical::parse_strict(
        &serde_json::to_vec(&vectors["positive"]["managed_oci_grant"]["value"]).unwrap(),
    )
    .unwrap();
    managed_oci.validate().unwrap();
    let open: ManagedOccurrenceKeyOpenRequest = canonical::parse_strict(
        &serde_json::to_vec(&vectors["positive"]["managed_occurrence_key_open_request"]["value"])
            .unwrap(),
    )
    .unwrap();
    open.validate().unwrap();
    let mut admission_grant = managed_oci.clone();
    admission_grant.operation = reproit_cloud_api::ManagedOperation::Admission;
    assert_eq!(
        admission_grant.validate().unwrap_err().code,
        ErrorCode::SchemaInvalid
    );
    for (name, seed) in [
        ("managed_worker_grant", 0x84),
        ("managed_key_grant", 0x85),
        ("managed_oci_grant", 0x84),
    ] {
        verify_signed_value(
            &vectors["positive"][name]["value"],
            &verification_key(&secret_key([seed; 32])),
        )
        .unwrap();
    }
    assert_eq!(
        vectors["positive"]["managed_key_grant"]["value"]["worker_grant_digest"],
        canonical::digest(&vectors["positive"]["managed_worker_grant"]["value"])
            .unwrap()
            .to_string()
    );
    let worker: ManagedWorkerGrant = canonical::parse_strict(
        &serde_json::to_vec(&vectors["positive"]["managed_worker_grant"]["value"]).unwrap(),
    )
    .unwrap();
    let key: ManagedKeyGrant = canonical::parse_strict(
        &serde_json::to_vec(&vectors["positive"]["managed_key_grant"]["value"]).unwrap(),
    )
    .unwrap();
    let now = "2026-01-01T00:00:30.000Z".parse().unwrap();
    verify_managed_worker_key_grants(
        &worker,
        &key,
        &now,
        &verification_key(&secret_key([0x84; 32])),
        &verification_key(&secret_key([0x85; 32])),
    )
    .unwrap();
}

fn assert_signed_workload_vectors(vectors: &Value) {
    let registration =
        parse_vector::<WorkloadKeyRegistration>(vectors, "workload_key_registration");
    registration.validate().unwrap();
    let registration_result =
        parse_vector::<WorkloadKeyRegistrationResult>(vectors, "workload_key_registration_result");
    registration_result
        .validate_for_registration(&registration)
        .unwrap();
    let encryption_request = parse_vector::<ManagedCandidateEncryptionGrantRequest>(
        vectors,
        "managed_candidate_encryption_grant_request",
    );
    encryption_request
        .validate_for_registration(&registration)
        .unwrap();
}

#[test]
fn managed_workload_key_id_matches_the_registration_vectors() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let registration =
        parse_vector::<WorkloadKeyRegistration>(&vectors, "workload_key_registration");
    let result =
        parse_vector::<WorkloadKeyRegistrationResult>(&vectors, "workload_key_registration_result");

    assert_eq!(registration.service_id, result.service_id);
    assert_eq!(
        registration.deployment_digest().unwrap(),
        result.deployment_digest
    );
    assert_eq!(
        managed_workload_key_id(&registration.public_key).unwrap(),
        result.key_id
    );
    validate_managed_workload_key_id(&result.key_id).unwrap();
}

#[test]
fn managed_candidate_vector_binds_the_signed_managed_deployment() {
    let cloud_vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let protocol_vectors: Value = serde_json::from_str(PROTOCOL_VECTORS).unwrap();

    assert_eq!(
        protocol_vectors["positive"]["managed_candidate_identity"]["value"]["deployment_digest"],
        cloud_vectors["positive"]["workload_key_registration_result"]["value"]["deployment_digest"]
    );
}

#[test]
fn managed_workload_key_id_rejects_noncanonical_or_wrong_size_keys() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let public_key = vectors["positive"]["workload_key_registration"]["value"]["public_key"]
        .as_str()
        .unwrap();
    let mut padded = public_key.to_owned();
    padded.push('=');
    let mut too_long = public_key.to_owned();
    too_long.push('A');
    let noncanonical_tail = format!("{}B", &public_key[..public_key.len() - 1]);

    for invalid in [
        "",
        &public_key[..public_key.len() - 1],
        too_long.as_str(),
        padded.as_str(),
        "1238bj1eePRsVOlCHJedzcDZ0DmBthqGWrICsYCNzp+",
        noncanonical_tail.as_str(),
    ] {
        assert_eq!(
            managed_workload_key_id(invalid).unwrap_err().code,
            ErrorCode::SchemaInvalid
        );
    }
}

#[test]
fn signed_workload_requests_reject_missing_or_malformed_authentication_fields() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    for (name, fields) in [
        ("workload_key_registration", &["deployment"][..]),
        (
            "workload_key_registration_result",
            &["deployment_digest"][..],
        ),
        (
            "managed_candidate_encryption_grant_request",
            &["deployment_digest", "signer_key_id", "signature"][..],
        ),
    ] {
        for field in fields {
            let mut value = vectors["positive"][name]["value"].clone();
            value.as_object_mut().unwrap().remove(*field);
            assert_eq!(
                canonical::parse_strict::<Value>(&serde_json::to_vec(&value).unwrap()).unwrap(),
                value
            );
            let error = match name {
                "workload_key_registration" => canonical::parse_strict::<WorkloadKeyRegistration>(
                    &serde_json::to_vec(&value).unwrap(),
                )
                .unwrap_err(),
                "workload_key_registration_result" => {
                    canonical::parse_strict::<WorkloadKeyRegistrationResult>(
                        &serde_json::to_vec(&value).unwrap(),
                    )
                    .unwrap_err()
                }
                _ => canonical::parse_strict::<ManagedCandidateEncryptionGrantRequest>(
                    &serde_json::to_vec(&value).unwrap(),
                )
                .unwrap_err(),
            };
            assert_eq!(error.code, ErrorCode::SchemaInvalid);
        }
    }

    let registration =
        parse_vector::<WorkloadKeyRegistration>(&vectors, "workload_key_registration");
    let mut malformed_key = registration.clone();
    malformed_key.deployment.signer_key_id = "managed-workload-sha256:ABC".to_owned();
    assert_eq!(
        malformed_key.validate().unwrap_err().code,
        ErrorCode::SchemaInvalid
    );

    let mut request = parse_vector::<ManagedCandidateEncryptionGrantRequest>(
        &vectors,
        "managed_candidate_encryption_grant_request",
    );
    request.signature = "AA".to_owned();
    assert_eq!(
        request.validate().unwrap_err().code,
        ErrorCode::SchemaInvalid
    );
    request = parse_vector(&vectors, "managed_candidate_encryption_grant_request");
    request.signer_key_id = "managed-workload-sha256:ABC".to_owned();
    assert_eq!(
        request.validate().unwrap_err().code,
        ErrorCode::SchemaInvalid
    );
}

#[test]
fn signed_workload_requests_reject_binding_signature_scope_and_mode_failures() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let registration =
        parse_vector::<WorkloadKeyRegistration>(&vectors, "workload_key_registration");
    let request = parse_vector::<ManagedCandidateEncryptionGrantRequest>(
        &vectors,
        "managed_candidate_encryption_grant_request",
    );
    let other_key_id = managed_workload_key_id(&encode_base64url(&verification_key(&secret_key(
        [0x82; 32],
    ))))
    .unwrap();

    let mut wrong_signer = registration.clone();
    wrong_signer.deployment.signer_key_id = other_key_id.clone();
    assert_eq!(
        wrong_signer.validate().unwrap_err().code,
        ErrorCode::AttestationScope
    );
    let mut invalid_signature = registration.clone();
    invalid_signature.deployment.signature = encode_base64url(&[0; 64]);
    assert_eq!(
        invalid_signature.validate().unwrap_err().code,
        ErrorCode::AttestationScope
    );
    let mut wrong_service = registration.clone();
    wrong_service.deployment.service_id =
        "svc_01890f3e-7b1c-7cc0-8a1b-123456789ac0".parse().unwrap();
    assert_eq!(
        wrong_service.validate().unwrap_err().code,
        ErrorCode::AttestationScope
    );
    let mut private_registration = registration.clone();
    private_registration.deployment.processing_mode = ProcessingMode::Private;
    assert_eq!(
        private_registration.validate().unwrap_err().code,
        ErrorCode::SchemaInvalid
    );

    let mut wrong_signer = request.clone();
    wrong_signer.signer_key_id = other_key_id;
    assert_eq!(
        wrong_signer
            .validate_for_registration(&registration)
            .unwrap_err()
            .code,
        ErrorCode::AttestationScope
    );
    let mut invalid_signature = request.clone();
    invalid_signature.signature = encode_base64url(&[0; 64]);
    assert_eq!(
        invalid_signature
            .validate_for_registration(&registration)
            .unwrap_err()
            .code,
        ErrorCode::AttestationScope
    );
    let mut wrong_project = request.clone();
    wrong_project.project_id = "prj_01890f3e-7b1c-7cc0-8a1b-123456789ac0".parse().unwrap();
    assert_eq!(
        wrong_project
            .validate_for_registration(&registration)
            .unwrap_err()
            .code,
        ErrorCode::AttestationScope
    );
    let mut private_request = request;
    private_request.processing_mode = ProcessingMode::Private;
    assert_eq!(
        private_request.validate().unwrap_err().code,
        ErrorCode::SchemaInvalid
    );
}

#[test]
fn managed_candidate_negative_controls_fail_before_upload_or_key_release() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let mut upload = vectors["positive"]["managed_candidate_upload_request"]["value"].clone();
    upload["ciphertext_identity"]["candidate_key_reference"] =
        json!("lpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpY");
    let upload: ManagedCandidateUploadRequest =
        canonical::parse_strict(&serde_json::to_vec(&upload).unwrap()).unwrap();
    assert_eq!(
        upload.validate().unwrap_err().code,
        ErrorCode::AttestationScope
    );

    let worker: ManagedWorkerGrant = canonical::parse_strict(
        &serde_json::to_vec(&vectors["positive"]["managed_worker_grant"]["value"]).unwrap(),
    )
    .unwrap();
    let mut key_value = vectors["positive"]["managed_key_grant"]["value"].clone();
    key_value["lease_id"] = json!("lse_01890f3e-7b1c-7cc0-8a1b-123456789ac3");
    let key: ManagedKeyGrant =
        canonical::parse_strict(&serde_json::to_vec(&key_value).unwrap()).unwrap();
    let now = "2026-01-01T00:00:30.000Z".parse().unwrap();
    assert_eq!(
        verify_managed_worker_key_grants(
            &worker,
            &key,
            &now,
            &verification_key(&secret_key([0x84; 32])),
            &verification_key(&secret_key([0x85; 32])),
        )
        .unwrap_err()
        .code,
        ErrorCode::AttestationScope
    );
}

#[test]
fn candidate_key_is_absent_from_every_safe_vector_projection() {
    let cloud: Value = serde_json::from_str(VECTORS).unwrap();
    let protocol: Value = serde_json::from_str(PROTOCOL_VECTORS).unwrap();
    let synthetic_key =
        cloud["positive"]["managed_candidate_encryption_response"]["value"]["candidate_key"]
            .as_str()
            .unwrap();
    for name in [
        "managed_candidate_commit",
        "managed_candidate_encryption_grant_request",
        "managed_candidate_status",
        "managed_candidate_upload_request",
        "managed_key_grant",
        "managed_worker_grant",
    ] {
        assert!(
            !serde_json::to_string(&cloud["positive"][name]["value"])
                .unwrap()
                .contains(synthetic_key),
            "{name}"
        );
    }
    for name in [
        "managed_candidate_capture_grant",
        "managed_candidate_ciphertext_identity",
        "managed_candidate_identity",
        "managed_candidate_manifest",
    ] {
        assert!(
            !serde_json::to_string(&protocol["positive"][name]["value"])
                .unwrap()
                .contains(synthetic_key),
            "{name}"
        );
    }
}

fn assert_vector<T>(vectors: &Value, name: &str)
where
    T: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    let value = &vectors["positive"][name]["value"];
    let typed: T = canonical::parse_strict(&serde_json::to_vec(value).unwrap()).unwrap();
    assert_eq!(
        canonical::digest(&typed).unwrap().to_string(),
        vectors["canonical_sha256"][name]
    );
    assert_eq!(serde_json::to_value(typed).unwrap(), *value);
}

fn parse_vector<T>(vectors: &Value, name: &str) -> T
where
    T: for<'de> serde::Deserialize<'de>,
{
    canonical::parse_strict(&serde_json::to_vec(&vectors["positive"][name]["value"]).unwrap())
        .unwrap()
}

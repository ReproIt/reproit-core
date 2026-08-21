use std::{collections::BTreeMap, env, fs};

use reproit_cloud_api::managed_workload_key_id;
use reproit_core::{
    canonical,
    crypto::{encode_base64url, secret_key, sign_bytes, verification_key},
};
use serde_json::{Map, Value, json};

fn main() {
    let generated = generated_vectors();
    match env::args().nth(1).as_deref() {
        Some("--write") => write_bundles(&generated, true),
        Some("--write-cloud") => write_bundles(&generated, false),
        _ => println!("{}", serde_json::to_string_pretty(&generated).unwrap()),
    }
}

struct ManagedFixture {
    capture_grant: Value,
    ciphertext_identity: Value,
    deployment: Value,
    deployment_digest: String,
    encrypted_candidate_digest: String,
    identity_digest: String,
    key_grant: Value,
    key_reference: String,
    manifest: Value,
    scope: Value,
    workload_key_id: String,
    workload_public_key: String,
    worker_grant: Value,
}

fn generated_vectors() -> Value {
    let fixture = managed_fixture();
    let mut positive = BTreeMap::new();
    add_core_vectors(&mut positive, &fixture);
    add_cloud_vectors(&mut positive, &fixture);
    let canonical_sha256 = positive
        .iter()
        .map(|(name, entry)| (name.clone(), digest(&entry["value"])))
        .collect::<BTreeMap<_, _>>();
    json!({
        "canonical_sha256": canonical_sha256,
        "positive": positive,
        "verification_keys": {
            "managed-candidate-capture-test": encode_base64url(
                &verification_key(&secret_key([0x83; 32]))
            ),
            "managed-key-test": encode_base64url(
                &verification_key(&secret_key([0x85; 32]))
            ),
            "managed-worker-test": encode_base64url(
                &verification_key(&secret_key([0x84; 32]))
            )
        }
    })
}

fn managed_fixture() -> ManagedFixture {
    let scope = json!({
        "capture_id": "cap_01890f3e-7b1c-7cc0-8a1b-123456789abc",
        "organization_id": "org_01890f3e-7b1c-7cc0-8a1b-123456789abd",
        "project_id": "prj_01890f3e-7b1c-7cc0-8a1b-123456789abe",
        "service_id": "svc_01890f3e-7b1c-7cc0-8a1b-123456789abf"
    });
    let workload_public_key = encode_base64url(&verification_key(&secret_key([0x83; 32])));
    let workload_key_id = managed_workload_key_id(&workload_public_key).unwrap();
    let deployment = signed_deployment(&scope, &workload_key_id);
    let deployment_digest = digest(&deployment);
    let identity = candidate_identity(&scope, &deployment_digest);
    let identity_digest = digest(&identity);
    let key_reference = encode_base64url(&[0x91; 32]);
    let manifest = json!({
        "candidate_identity": identity,
        "candidate_identity_digest": identity_digest,
        "candidate_key_reference": key_reference,
        "cipher_suite": "AES-256-GCM+HKDF-SHA-256",
        "format": "reproit.managed-candidate-manifest.v1"
    });
    let ciphertext_identity = ciphertext_identity(&scope, &identity_digest, &key_reference);
    let encrypted_candidate_digest = digest(&ciphertext_identity);
    let capture_grant = signed_capture_grant(&scope, &identity_digest, &key_reference);
    let worker_grant = signed_worker_grant(
        &scope,
        &identity_digest,
        &key_reference,
        &encrypted_candidate_digest,
    );
    let key_grant = signed_key_grant(
        &scope,
        &identity_digest,
        &key_reference,
        &encrypted_candidate_digest,
        &worker_grant,
    );
    ManagedFixture {
        capture_grant,
        ciphertext_identity,
        deployment,
        deployment_digest,
        encrypted_candidate_digest,
        identity_digest,
        key_grant,
        key_reference,
        manifest,
        scope,
        workload_key_id,
        workload_public_key,
        worker_grant,
    }
}

fn add_core_vectors(positive: &mut BTreeMap<String, Value>, fixture: &ManagedFixture) {
    add(
        positive,
        "managed_candidate_identity",
        "managed_candidate_identity",
        fixture.manifest["candidate_identity"].clone(),
    );
    add(
        positive,
        "managed_candidate_manifest",
        "managed_candidate_manifest",
        fixture.manifest.clone(),
    );
    add(
        positive,
        "managed_candidate_ciphertext_identity",
        "managed_candidate_ciphertext_identity",
        fixture.ciphertext_identity.clone(),
    );
    add(
        positive,
        "managed_candidate_capture_grant",
        "managed_candidate_capture_grant",
        fixture.capture_grant.clone(),
    );
}

fn add_cloud_vectors(positive: &mut BTreeMap<String, Value>, fixture: &ManagedFixture) {
    let grant_request = sign(
        merge_scope(
            &fixture.scope,
            json!({
                "candidate_identity_digest": fixture.identity_digest,
                "cipher_suite": "AES-256-GCM+HKDF-SHA-256",
                "deployment_digest": fixture.deployment_digest,
                "processing_mode": "managed",
                "signature": "",
                "signer_key_id": fixture.workload_key_id
            }),
        ),
        0x83,
    );
    add(
        positive,
        "managed_candidate_encryption_grant_request",
        "managed_candidate_encryption_grant_request",
        grant_request,
    );
    add(
        positive,
        "managed_candidate_encryption_response",
        "managed_candidate_encryption_response",
        json!({
            "candidate_key": encode_base64url(&[0x93; 32]),
            "capture_grant": fixture.capture_grant
        }),
    );
    add(
        positive,
        "managed_candidate_upload_request",
        "managed_candidate_upload_request",
        json!({
            "capture_grant": fixture.capture_grant,
            "ciphertext_identity": fixture.ciphertext_identity,
            "encrypted_candidate_digest": fixture.encrypted_candidate_digest
        }),
    );
    add(
        positive,
        "managed_candidate_commit",
        "managed_candidate_commit",
        merge_scope(
            &fixture.scope,
            json!({
                "candidate_identity_digest": fixture.identity_digest,
                "candidate_key_reference": fixture.key_reference,
                "encrypted_candidate_digest": fixture.encrypted_candidate_digest,
                "state": "CLOUD_PROTECTED",
                "upload_id": "upl_01890f3e-7b1c-7cc0-8a1b-123456789ac1"
            }),
        ),
    );
    let commit = &mut positive.get_mut("managed_candidate_commit").unwrap()["value"];
    for field in ["organization_id", "project_id", "service_id"] {
        commit.as_object_mut().unwrap().remove(field);
    }
    add(
        positive,
        "workload_key_registration",
        "workload_key_registration",
        json!({
            "algorithm": "Ed25519",
            "deployment": fixture.deployment,
            "public_key": fixture.workload_public_key,
            "service_id": fixture.scope["service_id"]
        }),
    );
    add(
        positive,
        "workload_key_registration_result",
        "workload_key_registration_result",
        json!({
            "deployment_digest": fixture.deployment_digest,
            "key_id": fixture.workload_key_id,
            "service_id": fixture.scope["service_id"]
        }),
    );
    add(
        positive,
        "managed_candidate_status",
        "managed_candidate_status",
        json!({
            "candidate_identity_digest": fixture.identity_digest,
            "candidate_key_reference": fixture.key_reference,
            "capture_id": fixture.scope["capture_id"],
            "encrypted_candidate_digest": fixture.encrypted_candidate_digest,
            "expires_at": null,
            "missing_digests": [],
            "state": "COMMITTED",
            "upload_id": "upl_01890f3e-7b1c-7cc0-8a1b-123456789ac1"
        }),
    );
    add_managed_worker_vectors(positive, fixture);
}

fn add_managed_worker_vectors(positive: &mut BTreeMap<String, Value>, fixture: &ManagedFixture) {
    add(
        positive,
        "managed_worker_grant",
        "managed_worker_grant",
        fixture.worker_grant.clone(),
    );
    add(
        positive,
        "managed_key_grant",
        "managed_key_grant",
        fixture.key_grant.clone(),
    );
    add(
        positive,
        "managed_candidate_key_request",
        "managed_candidate_key_request",
        json!({
            "key_grant": fixture.key_grant,
            "worker_grant": fixture.worker_grant
        }),
    );
    add(
        positive,
        "managed_candidate_key_response",
        "managed_candidate_key_response",
        json!({
            "candidate_key": encode_base64url(&[0x93; 32]),
            "candidate_key_reference": fixture.key_reference
        }),
    );
    add(
        positive,
        "managed_occurrence_key_wrap_request",
        "managed_occurrence_key_wrap_request",
        json!({
            "grants": {
                "key_grant": fixture.key_grant,
                "worker_grant": fixture.worker_grant
            },
            "occurrence_key": encode_base64url(&[0x94; 32])
        }),
    );
    add(
        positive,
        "managed_occurrence_key_wrap_response",
        "managed_occurrence_key_wrap_response",
        json!({
            "wrapped_key": {
                "algorithm": "AES-256-GCM+HKDF-SHA-256",
                "context_version": 1,
                "key_reference": format!(
                    "managed-occurrence:{}:wrapping-test",
                    fixture.scope["organization_id"]
                        .as_str()
                        .expect("fixture organization id")
                ),
                "provider_id": "reproit-managed-key-service",
                "wrapped_bytes": encode_base64url(&[0x95; 60])
            }
        }),
    );
    add_managed_execution_vectors(positive, fixture);
}

fn add_managed_execution_vectors(positive: &mut BTreeMap<String, Value>, fixture: &ManagedFixture) {
    let managed_oci_grant = sign(
        json!({
            "capture_id": fixture.scope["capture_id"],
            "capture_batch_digest": digest_value('a'),
            "capsule_digest": digest_value('b'),
            "debugger_capability_digest": digest_value('e'),
            "expires_at": "2026-01-01T00:01:00.000Z",
            "grant_id": encode_base64url(&[0x96; 32]),
            "not_before": "2026-01-01T00:00:00.000Z",
            "operation": "check",
            "organization_id": fixture.scope["organization_id"],
            "processing_mode": "managed",
            "project_id": fixture.scope["project_id"],
            "repro_id": "rpr_01890f3e-7b1c-7cc0-8a1b-123456789ac2",
            "requester_identity": "developer-test",
            "service_id": fixture.scope["service_id"],
            "signature": "",
            "signer_key_id": "managed-worker-test",
            "worker_id": "managed-worker-x86-ad2",
            "worker_release": digest_value('c')
        }),
        0x84,
    );
    add(
        positive,
        "managed_oci_grant",
        "managed_oci_grant",
        managed_oci_grant.clone(),
    );
    add(
        positive,
        "managed_oci_grant_request",
        "managed_oci_grant_request",
        json!({
            "capture_batch_digest": digest_value('a'),
            "debugger_capability_digest": digest_value('e'),
            "operation": "check"
        }),
    );
    add(
        positive,
        "managed_execution_material_request",
        "managed_execution_material_request",
        json!({"grant": managed_oci_grant.clone()}),
    );
    add(
        positive,
        "managed_execution_material",
        "managed_execution_material",
        json!({
            "admission_key": {
                "algorithm": "Ed25519",
                "format": "reproit.admission-verification-key.v1",
                "organization_id": fixture.scope["organization_id"],
                "project_id": fixture.scope["project_id"],
                "public_key": encode_base64url(&[0x82; 32]),
                "service_id": fixture.scope["service_id"],
                "signer_key_id": "managed-admission-test"
            },
            "ciphertext": {
                digest_value('d'): encode_base64url(b"managed encrypted capture object")
            },
            "envelope": encode_base64url(b"{}")
        }),
    );
    add_managed_keep_vectors(positive, fixture, &managed_oci_grant);
    let wrapped_key =
        positive["managed_occurrence_key_wrap_response"]["value"]["wrapped_key"].clone();
    add(
        positive,
        "managed_occurrence_key_open_request",
        "managed_occurrence_key_open_request",
        json!({
            "capture_id": fixture.scope["capture_id"],
            "grant": managed_oci_grant,
            "wrapped_key": wrapped_key
        }),
    );
    add(
        positive,
        "managed_occurrence_key_open_response",
        "managed_occurrence_key_open_response",
        json!({"occurrence_key": encode_base64url(&[0x94; 32])}),
    );
}

fn add_managed_keep_vectors(
    positive: &mut BTreeMap<String, Value>,
    fixture: &ManagedFixture,
    managed_oci_grant: &Value,
) {
    let execution_result = json!({
        "cleanup_complete": true,
        "closure_manifest_digest": digest_value('f'),
        "error": null,
        "execution_id": "exe_01890f3e-7b1c-7cc0-8a1b-123456789ab2",
        "failure_digest": null,
        "format": "reproit.execution-result.v1",
        "result": "TARGET_ABSENT"
    });
    add(
        positive,
        "managed_execution_result_report",
        "managed_execution_result_report",
        json!({
            "grant": managed_oci_grant,
            "result": execution_result
        }),
    );
    let mut managed_keep_grant = managed_oci_grant.clone();
    managed_keep_grant["operation"] = json!("keep");
    managed_keep_grant["signature"] = json!("");
    managed_keep_grant = sign(managed_keep_grant, 0x84);
    add(
        positive,
        "managed_keep_request",
        "managed_keep_request",
        json!({"grant": managed_keep_grant}),
    );
    add(
        positive,
        "managed_keep_result",
        "managed_keep_result",
        json!({
            "reference": {
                "capsule_digest": digest_value('b'),
                "capture_batch": format!(
                    "oci://managed-reproit/repros/{}@{}",
                    "rpr_01890f3e-7b1c-7cc0-8a1b-123456789ac2",
                    digest_value('c')
                ),
                "capture_batch_digest": digest_value('a'),
                "capture_id": fixture.scope["capture_id"],
                "format": 1,
                "key_reference": "managed-occurrence:test:key",
                "processing_mode": "managed",
                "profile": "backend",
                "profile_format": 1,
                "repro_id": "rpr_01890f3e-7b1c-7cc0-8a1b-123456789ac2"
            }
        }),
    );
}

fn write_bundles(generated: &Value, write_protocol: bool) {
    let protocol_names = [
        "managed_candidate_capture_grant",
        "managed_candidate_ciphertext_identity",
        "managed_candidate_identity",
        "managed_candidate_manifest",
    ];
    let cloud_names = [
        "managed_candidate_commit",
        "managed_candidate_encryption_grant_request",
        "managed_candidate_encryption_response",
        "managed_candidate_key_request",
        "managed_candidate_key_response",
        "managed_occurrence_key_wrap_request",
        "managed_occurrence_key_wrap_response",
        "managed_occurrence_key_open_request",
        "managed_occurrence_key_open_response",
        "managed_candidate_status",
        "managed_candidate_upload_request",
        "managed_key_grant",
        "managed_oci_grant",
        "managed_oci_grant_request",
        "managed_execution_material",
        "managed_execution_material_request",
        "managed_execution_result_report",
        "managed_keep_request",
        "managed_keep_result",
        "managed_worker_grant",
        "workload_key_registration",
        "workload_key_registration_result",
    ];
    if write_protocol {
        update_bundle(
            "specs/v1/protocol-vectors.json",
            generated,
            &protocol_names,
            protocol_negatives(),
        );
    }
    update_bundle(
        "specs/v1/cloud-api-vectors.json",
        generated,
        &cloud_names,
        cloud_negatives(),
    );
}

fn update_bundle(path: &str, generated: &Value, names: &[&str], negatives: Vec<Value>) {
    let mut bundle: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    let obsolete = [
        "capture_grant",
        "capture_grant_request",
        "managed_candidate_capture_grant",
        "managed_candidate_ciphertext_identity",
        "managed_candidate_commit",
        "managed_candidate_encryption_grant_request",
        "managed_candidate_encryption_response",
        "managed_candidate_identity",
        "managed_candidate_key_request",
        "managed_candidate_key_response",
        "managed_oci_grant_request",
        "managed_execution_material",
        "managed_execution_material_request",
        "managed_execution_result_report",
        "managed_keep_request",
        "managed_keep_result",
        "managed_occurrence_key_wrap_request",
        "managed_occurrence_key_wrap_response",
        "managed_occurrence_key_open_request",
        "managed_occurrence_key_open_response",
        "managed_candidate_manifest",
        "managed_candidate_status",
        "managed_candidate_upload_request",
        "managed_key_grant",
        "managed_oci_grant",
        "managed_worker_grant",
        "workload_key_registration",
        "workload_key_registration_result",
    ];
    for name in obsolete {
        bundle["canonical_sha256"]
            .as_object_mut()
            .unwrap()
            .remove(name);
        bundle["positive"].as_object_mut().unwrap().remove(name);
    }
    for name in names {
        bundle["canonical_sha256"][*name] = generated["canonical_sha256"][*name].clone();
        bundle["positive"][*name] = generated["positive"][*name].clone();
    }
    bundle["negative"]
        .as_array_mut()
        .unwrap()
        .retain(|mutation| {
            !mutation["base"]
                .as_str()
                .is_some_and(|base| obsolete.contains(&base))
        });
    bundle["negative"].as_array_mut().unwrap().extend(negatives);
    if path.ends_with("protocol-vectors.json") {
        bundle["verification_keys"]["managed-candidate-capture-test"] =
            generated["verification_keys"]["managed-candidate-capture-test"].clone();
    }
    let canonical_sha256 = bundle["positive"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, entry)| (name.clone(), Value::String(digest(&entry["value"]))))
        .collect::<Map<_, _>>();
    bundle["canonical_sha256"] = Value::Object(canonical_sha256);
    let mut encoded = serde_json::to_string_pretty(&bundle).unwrap();
    encoded.push('\n');
    fs::write(path, encoded).unwrap();
}

fn protocol_negatives() -> Vec<Value> {
    vec![
        mutation(
            "managed-candidate-capture-grant-wrong-key-reference",
            "managed_candidate_capture_grant",
            "managed_candidate_capture_grant",
            "/candidate_key_reference",
            json!(encode_base64url(&[0x96; 32])),
            "ATTESTATION_SCOPE",
            "semantic",
        ),
        mutation(
            "managed-candidate-capture-grant-expired",
            "managed_candidate_capture_grant",
            "managed_candidate_capture_grant",
            "/expires_at",
            json!("2026-01-01T00:00:15.000Z"),
            "ATTESTATION_SCOPE",
            "semantic",
        ),
        mutation(
            "managed-candidate-capture-grant-wrong-service",
            "managed_candidate_capture_grant",
            "managed_candidate_capture_grant",
            "/service_id",
            json!("svc_01890f3e-7b1c-7cc0-8a1b-123456789ac0"),
            "ATTESTATION_SCOPE",
            "semantic",
        ),
    ]
}

fn workload_schema_negatives() -> Vec<Value> {
    vec![
        removal(
            "workload-key-registration-missing-deployment",
            "workload_key_registration",
            "workload_key_registration",
            "/deployment",
        ),
        removal(
            "workload-key-registration-result-missing-deployment-digest",
            "workload_key_registration_result",
            "workload_key_registration_result",
            "/deployment_digest",
        ),
        removal(
            "managed-grant-missing-deployment-digest",
            "managed_candidate_encryption_grant_request",
            "managed_candidate_encryption_grant_request",
            "/deployment_digest",
        ),
        removal(
            "managed-grant-missing-signer-key-id",
            "managed_candidate_encryption_grant_request",
            "managed_candidate_encryption_grant_request",
            "/signer_key_id",
        ),
        removal(
            "managed-grant-missing-signature",
            "managed_candidate_encryption_grant_request",
            "managed_candidate_encryption_grant_request",
            "/signature",
        ),
        mutation(
            "workload-registration-malformed-signer-key-id",
            "workload_key_registration",
            "workload_key_registration",
            "/deployment/signer_key_id",
            json!("managed-workload-sha256:ABC"),
            "SCHEMA_INVALID",
            "schema",
        ),
        mutation(
            "workload-registration-result-malformed-key-id",
            "workload_key_registration_result",
            "workload_key_registration_result",
            "/key_id",
            json!("managed-workload-sha256:ABC"),
            "SCHEMA_INVALID",
            "schema",
        ),
        mutation(
            "managed-grant-malformed-signer-key-id",
            "managed_candidate_encryption_grant_request",
            "managed_candidate_encryption_grant_request",
            "/signer_key_id",
            json!("managed-workload-sha256:ABC"),
            "SCHEMA_INVALID",
            "schema",
        ),
        mutation(
            "managed-grant-malformed-signature",
            "managed_candidate_encryption_grant_request",
            "managed_candidate_encryption_grant_request",
            "/signature",
            json!("AA"),
            "SCHEMA_INVALID",
            "schema",
        ),
        mutation(
            "workload-registration-malformed-signature",
            "workload_key_registration",
            "workload_key_registration",
            "/deployment/signature",
            json!("AA"),
            "SCHEMA_INVALID",
            "schema",
        ),
    ]
}

fn workload_semantic_negatives() -> Vec<Value> {
    let other_public_key = encode_base64url(&verification_key(&secret_key([0x82; 32])));
    let other_workload_key_id = managed_workload_key_id(&other_public_key).unwrap();
    vec![
        mutation(
            "workload-registration-signer-mismatch",
            "workload_key_registration",
            "workload_key_registration",
            "/deployment/signer_key_id",
            json!(other_workload_key_id),
            "ATTESTATION_SCOPE",
            "semantic",
        ),
        mutation(
            "workload-registration-invalid-signature",
            "workload_key_registration",
            "workload_key_registration",
            "/deployment/signature",
            json!(encode_base64url(&[0; 64])),
            "ATTESTATION_SCOPE",
            "semantic",
        ),
        mutation(
            "workload-registration-service-scope-mismatch",
            "workload_key_registration",
            "workload_key_registration",
            "/deployment/service_id",
            json!("svc_01890f3e-7b1c-7cc0-8a1b-123456789ac0"),
            "ATTESTATION_SCOPE",
            "semantic",
        ),
        mutation(
            "workload-registration-non-managed-deployment",
            "workload_key_registration",
            "workload_key_registration",
            "/deployment/processing_mode",
            json!("private"),
            "SCHEMA_INVALID",
            "schema",
        ),
        mutation(
            "managed-grant-signer-mismatch",
            "managed_candidate_encryption_grant_request",
            "managed_candidate_encryption_grant_request",
            "/signer_key_id",
            json!(managed_workload_key_id(&other_public_key).unwrap()),
            "ATTESTATION_SCOPE",
            "semantic",
        ),
        mutation(
            "managed-grant-invalid-signature",
            "managed_candidate_encryption_grant_request",
            "managed_candidate_encryption_grant_request",
            "/signature",
            json!(encode_base64url(&[0; 64])),
            "ATTESTATION_SCOPE",
            "semantic",
        ),
        mutation(
            "managed-grant-project-scope-mismatch",
            "managed_candidate_encryption_grant_request",
            "managed_candidate_encryption_grant_request",
            "/project_id",
            json!("prj_01890f3e-7b1c-7cc0-8a1b-123456789ac0"),
            "ATTESTATION_SCOPE",
            "semantic",
        ),
        mutation(
            "managed-grant-non-managed-mode",
            "managed_candidate_encryption_grant_request",
            "managed_candidate_encryption_grant_request",
            "/processing_mode",
            json!("private"),
            "SCHEMA_INVALID",
            "schema",
        ),
        state_negative_for(
            "managed-grant-revoked-deployment",
            "managed_candidate_encryption_grant_request",
            "managed_candidate_encryption_grant_request",
            "ATTESTATION_REVOKED",
        ),
        state_negative_for(
            "managed-grant-project-token-reuse",
            "managed_candidate_encryption_grant_request",
            "managed_candidate_encryption_grant_request",
            "AUTHORIZATION_DENIED",
        ),
        state_negative_for(
            "workload-registration-project-token-reuse-with-changed-deployment",
            "workload_key_registration",
            "workload_key_registration",
            "AUTHORIZATION_DENIED",
        ),
    ]
}

fn cloud_negatives() -> Vec<Value> {
    let mut negatives = workload_schema_negatives();
    negatives.extend(workload_semantic_negatives());
    negatives.extend([
        mutation(
            "managed-candidate-key-reference-differs-from-capture-grant",
            "managed_candidate_upload_request",
            "managed_candidate_upload_request",
            "/ciphertext_identity/candidate_key_reference",
            json!(encode_base64url(&[0x96; 32])),
            "ATTESTATION_SCOPE",
            "semantic",
        ),
        mutation(
            "managed-candidate-identity-differs-from-key-record",
            "managed_candidate_encryption_grant_request",
            "managed_candidate_encryption_grant_request",
            "/candidate_identity_digest",
            json!(digest_value('9')),
            "CAPTURE_ID_CONFLICT",
            "semantic",
        ),
        state_negative(
            "managed-candidate-key-request-before-local-completeness",
            "NO_NETWORK_REQUEST",
        ),
        state_negative(
            "managed-candidate-terminal-with-active-lease",
            "RETAIN_PROTECTED_KEY",
        ),
        state_negative(
            "managed-candidate-terminal-without-active-lease",
            "DELETE_PROTECTED_KEY",
        ),
        mutation(
            "managed-worker-key-grant-differs-from-worker-lease",
            "managed_key_grant",
            "managed_key_grant",
            "/lease_id",
            json!("lse_01890f3e-7b1c-7cc0-8a1b-123456789ac3"),
            "ATTESTATION_SCOPE",
            "semantic",
        ),
        mutation(
            "managed-occurrence-key-has-the-wrong-size",
            "managed_occurrence_key_wrap_request",
            "managed_occurrence_key_wrap_request",
            "/occurrence_key",
            json!(encode_base64url(&[0x94; 31])),
            "SCHEMA_INVALID",
            "schema",
        ),
        mutation(
            "managed-execution-grant-selects-a-different-capture-batch",
            "managed_oci_grant_request",
            "managed_oci_grant_request",
            "/capture_batch_digest",
            json!(digest_value('9')),
            "ATTESTATION_SCOPE",
            "semantic",
        ),
        mutation(
            "managed-execution-result-reports-incomplete-cleanup",
            "managed_execution_result_report",
            "managed_execution_result_report",
            "/result/cleanup_complete",
            json!(false),
            "SCHEMA_INVALID",
            "semantic",
        ),
        mutation(
            "managed-keep-request-uses-a-check-grant",
            "managed_keep_request",
            "managed_keep_request",
            "/grant/operation",
            json!("check"),
            "SCHEMA_INVALID",
            "semantic",
        ),
        state_negative_for(
            "managed-occurrence-key-wrap-without-active-lease",
            "managed_occurrence_key_wrap_request",
            "managed_occurrence_key_wrap_request",
            "ATTESTATION_SCOPE",
        ),
        state_negative(
            "managed-candidate-key-in-log-metadata-manifest-output-or-crash",
            "REJECT_SECRET_EXPOSURE",
        ),
    ]);
    negatives
}

fn mutation(
    name: &str,
    base: &str,
    schema: &str,
    path: &str,
    value: Value,
    expected: &str,
    layer: &str,
) -> Value {
    let mut mutation = json!({
        "base": base,
        "expected": expected,
        "layer": layer,
        "name": name,
        "operation": "replace",
        "path": path,
        "schema": schema
    });
    mutation["value"] = value;
    mutation
}

fn removal(name: &str, base: &str, schema: &str, path: &str) -> Value {
    json!({
        "base": base,
        "expected": "SCHEMA_INVALID",
        "layer": "schema",
        "name": name,
        "operation": "remove",
        "path": path,
        "schema": schema
    })
}

fn state_negative(name: &str, expected: &str) -> Value {
    state_negative_for(
        name,
        "managed_candidate_encryption_grant_request",
        "managed_candidate_encryption_grant_request",
        expected,
    )
}

fn state_negative_for(name: &str, base: &str, schema: &str, expected: &str) -> Value {
    json!({
        "base": base,
        "expected": expected,
        "layer": "state-machine",
        "name": name,
        "operation": "semantic",
        "schema": schema
    })
}

fn candidate_identity(scope: &Value, deployment_digest: &str) -> Value {
    merge_scope(
        scope,
        json!({
            "candidate_digest": digest_value('a'),
            "deployment_digest": deployment_digest,
            "format": "reproit.managed-candidate-identity.v1",
            "objects": [
                descriptor('0', 'a', "candidate", "application/vnd.reproit.candidate.v1+json"),
                descriptor('1', 'b', "subject", "application/vnd.reproit.subject-closure.v1+json"),
                descriptor('2', 'c', "trigger", "application/vnd.reproit.trigger.v1+json"),
                descriptor('3', 'd', "failure", "application/vnd.reproit.failure.v1+json"),
                descriptor('4', 'e', "world-manifest", "application/vnd.reproit.world-manifest.v1+json"),
                descriptor('5', 'f', "subject", "application/vnd.reproit.subject-file.v1")
            ],
            "processing_mode": "managed",
            "required_capabilities": ["executor.linux-native"],
            "subject_digest": digest_value('b'),
            "total_plaintext_bytes": 6
        }),
    )
}

fn ciphertext_identity(scope: &Value, identity_digest: &str, key_reference: &str) -> Value {
    let roles = [
        (
            '0',
            'a',
            '1',
            0_u8,
            "candidate",
            "application/vnd.reproit.candidate.v1+json",
        ),
        (
            '1',
            'b',
            '2',
            1,
            "subject",
            "application/vnd.reproit.subject-closure.v1+json",
        ),
        (
            '2',
            'c',
            '3',
            2,
            "trigger",
            "application/vnd.reproit.trigger.v1+json",
        ),
        (
            '3',
            'd',
            '4',
            3,
            "failure",
            "application/vnd.reproit.failure.v1+json",
        ),
        (
            '4',
            'e',
            '5',
            4,
            "world-manifest",
            "application/vnd.reproit.world-manifest.v1+json",
        ),
        (
            '5',
            'f',
            '7',
            6,
            "subject",
            "application/vnd.reproit.subject-file.v1",
        ),
    ];
    let objects = roles.map(|(object, plain, cipher, nonce, role, media_type)| {
        json!({
            "chunks": [{
                "cipher_digest": digest_value(cipher),
                "cipher_size": 28,
                "index": 0,
                "nonce": encode_base64url(&[nonce; 12])
            }],
            "descriptor": descriptor(object, plain, role, media_type)
        })
    });
    merge_scope(
        scope,
        json!({
            "candidate_identity_digest": identity_digest,
            "candidate_key_reference": key_reference,
            "cipher_suite": "AES-256-GCM+HKDF-SHA-256",
            "format": "reproit.managed-candidate-ciphertext-identity.v1",
            "manifest_object": {
                "cipher_digest": digest_value('6'),
                "cipher_size": 28,
                "nonce": encode_base64url(&[5; 12]),
                "object_id": "obj_01890f3e-7b1c-7cc0-8a1b-123456789ab6"
            },
            "objects": objects,
            "processing_mode": "managed",
            "required_capabilities": [
                "architecture.x86-64",
                "executor.linux-native"
            ],
            "total_ciphertext_bytes": 196
        }),
    )
}

fn signed_capture_grant(scope: &Value, identity_digest: &str, key_reference: &str) -> Value {
    sign(
        merge_scope(
            scope,
            json!({
                "candidate_identity_digest": identity_digest,
                "candidate_key_reference": key_reference,
                "cipher_suite": "AES-256-GCM+HKDF-SHA-256",
                "expires_at": "2026-01-01T00:01:00.000Z",
                "format": "reproit.managed-candidate-capture-grant.v1",
                "grant_id": encode_base64url(&[0x92; 32]),
                "not_before": "2026-01-01T00:00:00.000Z",
                "operation": "encrypt-and-upload-candidate",
                "processing_mode": "managed",
                "signature": "",
                "signer_key_id": "managed-candidate-capture-test"
            }),
        ),
        0x83,
    )
}

fn signed_deployment(scope: &Value, workload_key_id: &str) -> Value {
    let mut deployment = merge_scope(
        scope,
        json!({
                "format": "reproit.deployment.v1",
                "processing_mode": "managed",
                "repository_id": "source.example/acme/commerce",
                "runtime_capabilities": [
                    "architecture.x86-64",
                    "operating-system.linux",
                    "runtime.rust-native"
                ],
                "runtime_endpoint": "https://capture.reproit.example",
                "service_path": "services/orders",
                "signature": "",
                "signed_at": "2026-01-01T00:00:00.000Z",
                "signer_key_id": workload_key_id,
                "source_revision": "0123456789abcdef",
                "subject": {
                    "architecture": "architecture.x86-64",
                    "arguments": [],
                    "artifact_digest": digest_value('1'),
                    "artifact_media_type": "application/vnd.reproit.native-executable.v1",
                    "artifact_uri": concat!(
                        "reproit-managed://sha256:",
                        "1111111111111111111111111111111111111111111111111111111111111111"
                    ),
                    "environment_names": ["RUST_LOG"],
                    "executable": "/reproit/subject/orders",
                    "format": "reproit.subject.v1",
                    "operating_system": "operating-system.linux",
                    "working_directory": "/reproit/subject"
                }
        }),
    );
    deployment.as_object_mut().unwrap().remove("capture_id");
    sign(deployment, 0x83)
}

fn signed_worker_grant(
    scope: &Value,
    identity_digest: &str,
    key_reference: &str,
    encrypted_digest: &str,
) -> Value {
    sign(
        merge_scope(
            scope,
            json!({
                "candidate_identity_digest": identity_digest,
                "candidate_key_reference": key_reference,
                "capabilities": ["architecture.x86-64", "executor.linux-native"],
                "encrypted_candidate_digest": encrypted_digest,
                "expires_at": "2026-01-01T00:01:00.000Z",
                "format": "reproit.managed-worker-grant.v1",
                "grant_id": encode_base64url(&[0x94; 32]),
                "lease_id": "lse_01890f3e-7b1c-7cc0-8a1b-123456789ac2",
                "not_before": "2026-01-01T00:00:00.000Z",
                "operation": "admission",
                "processing_mode": "managed",
                "signature": "",
                "signer_key_id": "managed-worker-test",
                "worker_id": "managed-worker-x86-01",
                "worker_release": digest_value('f')
            }),
        ),
        0x84,
    )
}

fn signed_key_grant(
    scope: &Value,
    identity_digest: &str,
    key_reference: &str,
    encrypted_digest: &str,
    worker_grant: &Value,
) -> Value {
    sign(
        merge_scope(
            scope,
            json!({
                "candidate_identity_digest": identity_digest,
                "candidate_key_reference": key_reference,
                "capabilities": ["architecture.x86-64", "executor.linux-native"],
                "encrypted_candidate_digest": encrypted_digest,
                // The key grant carries the same lease expiration as its
                // worker grant. validate_lease_scope rejects a divergent pair.
                "expires_at": "2026-01-01T00:01:00.000Z",
                "format": "reproit.managed-key-grant.v1",
                "grant_id": encode_base64url(&[0x95; 32]),
                "lease_id": "lse_01890f3e-7b1c-7cc0-8a1b-123456789ac2",
                "not_before": "2026-01-01T00:00:00.000Z",
                "operation": "admission",
                "processing_mode": "managed",
                "signature": "",
                "signer_key_id": "managed-key-test",
                "worker_grant_digest": digest(worker_grant),
                "worker_id": "managed-worker-x86-01",
                "worker_release": digest_value('f')
            }),
        ),
        0x85,
    )
}

fn descriptor(object: char, plain: char, role: &str, media_type: &str) -> Value {
    json!({
        "media_type": media_type,
        "object_id": format!("obj_01890f3e-7b1c-7cc0-8a1b-123456789ab{object}"),
        "plain_digest": digest_value(plain),
        "plain_size": 1,
        "role": role
    })
}

fn add(positive: &mut BTreeMap<String, Value>, name: &str, schema: &str, value: Value) {
    let mut entry = Map::new();
    entry.insert("schema".to_owned(), Value::String(schema.to_owned()));
    entry.insert("value".to_owned(), value);
    positive.insert(name.to_owned(), Value::Object(entry));
}

fn merge_scope(scope: &Value, extra: Value) -> Value {
    let mut merged = scope.as_object().unwrap().clone();
    let Value::Object(extra) = extra else {
        unreachable!();
    };
    merged.extend(extra);
    Value::Object(merged)
}

fn sign(mut value: Value, seed: u8) -> Value {
    let signature = sign_bytes(
        &canonical::canonical_bytes(&value).unwrap(),
        &secret_key([seed; 32]),
    );
    value["signature"] = Value::String(signature);
    value
}

fn digest(value: &Value) -> String {
    canonical::digest(value).unwrap().to_string()
}

fn digest_value(value: char) -> String {
    format!("sha256:{}", value.to_string().repeat(64))
}

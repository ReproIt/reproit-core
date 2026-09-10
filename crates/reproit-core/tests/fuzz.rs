use std::str::FromStr;

use reproit_core::{
    canonical,
    crypto::{encode_base64url, secret_key, sign_bytes, verification_key},
    identity::{Digest, FuzzCampaignId, FuzzCaseId, ProjectId, ServiceId, Timestamp},
    model::{
        Candidate, DiscoverySource, FuzzAction, FuzzCampaign, FuzzCampaignFormat,
        FuzzCampaignLimits, FuzzCasePlan, FuzzCasePlanFormat, FuzzCaseResult, FuzzCleanup,
        FuzzContext, FuzzContextFormat, FuzzContextIdentity, FuzzOutcome, FuzzResultFormat,
        FuzzSignal, OperationBeginFormat, OperationBeginPayload, OperationKind, UploadEnvelope,
        Validate, fuzz_context_digest, fuzz_plan_digest, verify_fuzz_context,
    },
};

const SCHEMAS: &str = include_str!("../../../specs/v1/schemas.json");
const VECTORS: &str = include_str!("../../../specs/v1/protocol-vectors.json");

const CAMPAIGN_ID: &str = "fc_01890f3e-7b1c-7cc0-8a1b-123456789abc";
const CASE_ID: &str = "case_01890f3e-7b1d-7cc0-8a1b-123456789abc";
const PROJECT_ID: &str = "prj_01890f3e-7b1e-7cc0-8a1b-123456789abc";
const SERVICE_ID: &str = "svc_01890f3e-7b1f-7cc0-8a1b-123456789abc";

#[test]
fn campaign_limits_reject_zero_and_unbounded_values() {
    let mut campaign = campaign();
    campaign.validate().expect("valid campaign");

    campaign.limits.max_cases = 0;
    assert!(campaign.validate().is_err());
    campaign.limits.max_cases = 1_000_001;
    assert!(campaign.validate().is_err());
}

#[test]
fn case_plan_digest_binds_order_seed_and_referenced_values() {
    let mut plan = case_plan();
    plan.plan_digest = fuzz_plan_digest(&plan).expect("plan digest");
    plan.validate().expect("valid case plan");

    plan.actions.swap(0, 1);
    assert!(plan.validate().is_err());
}

#[test]
fn signed_context_requires_exact_scope_and_expiry() {
    let signing_key = secret_key([7_u8; 32]);
    let mut context = context();
    context.signature = sign_bytes(
        &canonical::canonical_bytes(&context).expect("unsigned context"),
        &signing_key,
    );
    let key = verification_key(&signing_key);
    let now = Timestamp::from_str("2026-08-29T00:00:00.000Z").expect("timestamp");
    verify_fuzz_context(
        &context,
        &key,
        ProjectId::from_str(PROJECT_ID).expect("project ID"),
        ServiceId::from_str(SERVICE_ID).expect("service ID"),
        &now,
    )
    .expect("valid context");

    let other_service =
        ServiceId::from_str("svc_01890f3e-7b20-7cc0-8a1b-123456789abc").expect("service ID");
    assert!(
        verify_fuzz_context(
            &context,
            &key,
            ProjectId::from_str(PROJECT_ID).expect("project ID"),
            other_service,
            &now,
        )
        .is_err()
    );
    let expired = Timestamp::from_str("2026-08-30T00:00:00.000Z").expect("timestamp");
    assert!(
        verify_fuzz_context(
            &context,
            &key,
            ProjectId::from_str(PROJECT_ID).expect("project ID"),
            ServiceId::from_str(SERVICE_ID).expect("service ID"),
            &expired,
        )
        .is_err()
    );
}

#[test]
fn operation_v1_stays_production_and_v2_derives_fuzz_provenance() {
    let production: OperationBeginPayload = canonical::parse_strict(
        br#"{
            "adapter_id":"http",
            "adapter_version":"1",
            "causal_parent_ids":[],
            "format":"reproit.operation-begin.v1",
            "operation_kind":"request-response",
            "operation_name":"checkout"
        }"#,
    )
    .expect("v1 operation");
    assert_eq!(production.discovery_source(), DiscoverySource::Production);

    let fuzz = OperationBeginPayload {
        adapter_id: "http".to_owned(),
        adapter_version: "1".to_owned(),
        campaign_context: Some(FuzzContextIdentity {
            campaign_id: FuzzCampaignId::from_str(CAMPAIGN_ID).expect("campaign ID"),
            case_id: FuzzCaseId::from_str(CASE_ID).expect("case ID"),
            context_digest: fuzz_context_digest(&signed_context()).expect("context digest"),
        }),
        causal_parent_ids: Vec::new(),
        format: OperationBeginFormat::V2,
        operation_kind: OperationKind::RequestResponse,
        operation_name: "checkout".to_owned(),
    };
    assert_eq!(fuzz.discovery_source(), DiscoverySource::FuzzCampaign);
    fuzz.validate().expect("valid v2 operation");

    let mut incomplete_v2 = fuzz;
    incomplete_v2.campaign_context = None;
    assert!(incomplete_v2.validate().is_err());
}

#[test]
fn candidate_binds_the_exact_fuzz_context_to_the_begin_record() {
    let vectors: serde_json::Value = serde_json::from_str(VECTORS).expect("vectors");
    let mut candidate: Candidate =
        serde_json::from_value(vectors["positive"]["candidate"]["value"].clone())
            .expect("candidate");
    let context = signed_context_for_scope(
        candidate.deployment.project_id,
        candidate.deployment.service_id,
    );
    let identity = FuzzContextIdentity {
        campaign_id: context.campaign_id,
        case_id: context.case_id,
        context_digest: fuzz_context_digest(&context).expect("context digest"),
    };
    let begin_bytes = reproit_core::crypto::decode_base64url_bytes(&candidate.records[0].payload)
        .expect("begin payload");
    let mut begin: OperationBeginPayload =
        canonical::parse_strict(&begin_bytes).expect("operation begin");
    begin.format = OperationBeginFormat::V2;
    begin.campaign_context = Some(identity);
    candidate.records[0].payload =
        encode_base64url(&canonical::canonical_bytes(&begin).expect("operation begin"));
    candidate.campaign_context = Some(context);
    candidate.validate().expect("fuzz candidate");
    candidate.discovery_source = Some(DiscoverySource::Production);
    assert!(candidate.validate().is_err());
    candidate.discovery_source = None;

    candidate
        .campaign_context
        .as_mut()
        .expect("context")
        .case_id = "case_01890f3e-7b21-7cc0-8a1b-123456789abc"
        .parse()
        .expect("case ID");
    assert!(candidate.validate().is_err());
}

#[test]
fn candidate_can_mark_fuzz_discovery_without_campaign_context() {
    let vectors: serde_json::Value = serde_json::from_str(VECTORS).expect("vectors");
    let mut candidate: Candidate =
        serde_json::from_value(vectors["positive"]["candidate"]["value"].clone())
            .expect("candidate");
    candidate.discovery_source = Some(DiscoverySource::FuzzCampaign);
    candidate.validate().expect("fuzz candidate");
    assert_eq!(
        candidate.discovery_source().expect("discovery source"),
        DiscoverySource::FuzzCampaign
    );
}

#[test]
fn upload_envelope_rejects_a_campaign_context_for_another_project() {
    let vectors: serde_json::Value = serde_json::from_str(VECTORS).expect("vectors");
    let mut envelope: UploadEnvelope =
        serde_json::from_value(vectors["positive"]["upload_envelope"]["value"].clone())
            .expect("upload envelope");
    let mut context = signed_context_for_scope(envelope.project_id, envelope.service_id);
    envelope.operation_id = Some(
        "op_01890f3e-7b1c-7cc0-8a1b-123456789ab1"
            .parse()
            .expect("operation ID"),
    );
    envelope.campaign_context = Some(context.clone());
    envelope.validate().expect("fuzz upload envelope");
    envelope.discovery_source = Some(DiscoverySource::Production);
    assert!(envelope.validate().is_err());
    envelope.discovery_source = Some(DiscoverySource::FuzzCampaign);
    envelope.validate().expect("explicit fuzz discovery");

    context.project_id =
        ProjectId::from_str("prj_01890f3e-7b22-7cc0-8a1b-123456789abc").expect("project ID");
    envelope.campaign_context = Some(context);
    assert!(envelope.validate().is_err());
}

#[test]
fn fuzz_contracts_match_the_normative_shared_schema() {
    let mut plan = case_plan();
    plan.actions.extend([
        FuzzAction::HttpReset {
            sequence: 4,
            target: "payments".to_owned(),
        },
        FuzzAction::HttpPartial {
            maximum_bytes: 1,
            sequence: 5,
            target: "payments".to_owned(),
        },
        FuzzAction::HttpTruncate {
            maximum_bytes: 8_388_608,
            sequence: 6,
            target: "payments".to_owned(),
        },
        FuzzAction::HttpTimeout {
            maximum_ms: 1,
            sequence: 7,
            target: "payments".to_owned(),
        },
        FuzzAction::QueueReorder {
            queue: "events".to_owned(),
            sequence: 8,
            target: "payments".to_owned(),
        },
    ]);
    plan.validate()
        .expect_err("The changed plan has an old digest.");
    plan.plan_digest = fuzz_plan_digest(&plan).expect("plan digest");
    plan.validate().expect("extended plan");
    let result = FuzzCaseResult {
        campaign_id: plan.campaign_id,
        capture_ids: Vec::new(),
        case_id: plan.case_id,
        cleanup: FuzzCleanup::Complete,
        format: FuzzResultFormat::V1,
        outcome: FuzzOutcome::Found,
        plan_digest: plan.plan_digest,
        root_service: Some("payments".to_owned()),
        signals: vec![FuzzSignal::HttpStatus {
            service: "payments".to_owned(),
            status: 500,
        }],
    };
    let schema: serde_json::Value = serde_json::from_str(SCHEMAS).expect("schema");
    let registry = jsonschema::Registry::new()
        .add("https://reproit.dev/spec/v1/schemas.json", &schema)
        .expect("schema registry")
        .prepare()
        .expect("resolved schema registry");
    for (definition, value) in [
        (
            "fuzz_campaign",
            serde_json::to_value(campaign()).expect("campaign"),
        ),
        (
            "fuzz_case_plan",
            serde_json::to_value(plan).expect("case plan"),
        ),
        (
            "fuzz_context",
            serde_json::to_value(signed_context()).expect("context"),
        ),
        ("fuzz_result", serde_json::to_value(result).expect("result")),
    ] {
        let reference = serde_json::json!({
            "$ref": format!(
                "https://reproit.dev/spec/v1/schemas.json#/$defs/{definition}"
            )
        });
        let validator = jsonschema::options()
            .with_registry(&registry)
            .build(&reference)
            .expect("validator");
        assert!(validator.is_valid(&value), "{definition}");
    }
}

fn campaign() -> FuzzCampaign {
    FuzzCampaign {
        adapter: "native-process".to_owned(),
        campaign_id: FuzzCampaignId::from_str(CAMPAIGN_ID).expect("campaign ID"),
        fault_policy_digest: Digest::of(b"faults"),
        format: FuzzCampaignFormat::V1,
        limits: FuzzCampaignLimits {
            max_actions_per_case: 100,
            max_actions_per_second: 50,
            max_case_seconds: 30,
            max_cases: 1_000,
            max_concurrency: 4,
            max_payload_bytes: 65_536,
            max_total_bytes: 1_073_741_824,
        },
        name: "checkout-distributed".to_owned(),
        oracle_digest: Digest::of(b"oracles"),
        project_id: ProjectId::from_str(PROJECT_ID).expect("project ID"),
        seed_world_digest: Digest::of(b"world"),
        service_id: ServiceId::from_str(SERVICE_ID).expect("service ID"),
        workload_digest: Digest::of(b"workload"),
    }
}

fn case_plan() -> FuzzCasePlan {
    FuzzCasePlan {
        actions: vec![
            FuzzAction::SendHttp {
                body_digest: Digest::of(b"body"),
                method: "POST".to_owned(),
                path: "/checkout".to_owned(),
                sequence: 0,
                target: "orders".to_owned(),
            },
            FuzzAction::HttpDelay {
                delay_ms: 250,
                sequence: 1,
                target: "payments".to_owned(),
            },
            FuzzAction::SendQueue {
                payload_digest: Digest::of(b"work"),
                queue: "payments-events".to_owned(),
                sequence: 2,
                target: "payments".to_owned(),
            },
            FuzzAction::QueueDuplicate {
                count: 2,
                queue: "payments-events".to_owned(),
                sequence: 3,
                target: "payments".to_owned(),
            },
        ],
        algorithm_version: 1,
        campaign_id: FuzzCampaignId::from_str(CAMPAIGN_ID).expect("campaign ID"),
        case_id: FuzzCaseId::from_str(CASE_ID).expect("case ID"),
        format: FuzzCasePlanFormat::V1,
        plan_digest: Digest::of(b"pending"),
        seed: 8_821,
        world_digest: Digest::of(b"world"),
    }
}

fn context() -> FuzzContext {
    FuzzContext {
        campaign_id: FuzzCampaignId::from_str(CAMPAIGN_ID).expect("campaign ID"),
        case_id: FuzzCaseId::from_str(CASE_ID).expect("case ID"),
        expires_at: Timestamp::from_str("2026-08-30T00:00:00.000Z").expect("timestamp"),
        format: FuzzContextFormat::V1,
        project_id: ProjectId::from_str(PROJECT_ID).expect("project ID"),
        service_id: ServiceId::from_str(SERVICE_ID).expect("service ID"),
        signature: String::new(),
    }
}

fn signed_context() -> FuzzContext {
    let signing_key = secret_key([7_u8; 32]);
    let mut context = context();
    context.signature = sign_bytes(
        &canonical::canonical_bytes(&context).expect("unsigned context"),
        &signing_key,
    );
    context
}

fn signed_context_for_scope(project_id: ProjectId, service_id: ServiceId) -> FuzzContext {
    let signing_key = secret_key([8_u8; 32]);
    let mut context = FuzzContext {
        campaign_id: FuzzCampaignId::from_str(CAMPAIGN_ID).expect("campaign ID"),
        case_id: FuzzCaseId::from_str(CASE_ID).expect("case ID"),
        expires_at: Timestamp::from_str("2026-08-30T00:00:00.000Z").expect("timestamp"),
        format: FuzzContextFormat::V1,
        project_id,
        service_id,
        signature: String::new(),
    };
    context.signature = sign_bytes(
        &canonical::canonical_bytes(&context).expect("unsigned context"),
        &signing_key,
    );
    context
}

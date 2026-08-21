use reproit_backend::{
    config::ProjectConfig,
    support::{
        BackendSupportPackage, VerifiedBackendSupportCatalog, validate_backend_support_bundle,
        validate_backend_support_package,
    },
};
use reproit_core::{
    ErrorCode, canonical,
    crypto::{secret_key, sign_bytes, verification_key},
    identity::Digest,
    model::{
        ClosurePolicy, ComponentIdentity, ComponentKind, DebuggerContract, KeptReference,
        SupportBundle, SupportRegistry, SupportRegistryFormat, SupportedProfile, Validate,
        VerifiedSupportRegistry,
    },
};
use serde::de::DeserializeOwned;
use serde_json::Value;

const CORE_VECTORS: &str = include_str!("../../../specs/v1/vectors.json");
const PROTOCOL_VECTORS: &str = include_str!("../../../specs/v1/protocol-vectors.json");

#[test]
fn backend_configuration_vectors_use_the_backend_profile_boundary() {
    let vectors = parse(PROTOCOL_VECTORS);
    let config: ProjectConfig = decode(&vectors["positive"]["project_config"]["value"]);
    let kept: KeptReference = decode(&vectors["positive"]["kept_reference"]["value"]);
    config.validate().expect("the project config must be valid");
    kept.validate().expect("the kept reference must be valid");
}

#[test]
fn backend_bundle_requires_one_digest_bound_standard_debugger() {
    let core = parse(CORE_VECTORS);
    let protocol = parse(PROTOCOL_VECTORS);
    let mut bundle: SupportBundle = decode(&core["support_bundle"]["value"]);
    let debugger: DebuggerContract = decode(&protocol["positive"]["debugger_contract"]["value"]);
    let debugger_component = ComponentIdentity {
        capabilities: vec!["debugger.gdb-remote".to_owned()],
        component_id: debugger.debugger_id.clone(),
        component_kind: ComponentKind::Debugger,
        conformance_digest: Digest::of(b"debugger conformance"),
        identity_digest: canonical::digest(&debugger).expect("debugger digest"),
        protocol_max: 1,
        protocol_min: 1,
        version: debugger.version.clone(),
    };
    let index = bundle
        .components
        .iter()
        .position(|component| component.component_kind > ComponentKind::Debugger)
        .expect("a component follows the debugger");
    bundle.components.insert(index, debugger_component);
    validate_backend_support_bundle(&bundle, &debugger).expect("complete backend bundle");

    let mut wrong = debugger;
    wrong.artifact_digest = Digest::of(b"another debugger artifact");
    assert_eq!(
        validate_backend_support_bundle(&bundle, &wrong)
            .expect_err("the debugger identity must match")
            .code,
        ErrorCode::UnsupportedCapabilitySet
    );
}

#[test]
fn backend_bundle_rejects_a_debugger_for_another_subject_runtime() {
    let protocol = parse(PROTOCOL_VECTORS);
    let mut package = rust_x86_package();
    let debugger: DebuggerContract =
        decode(&protocol["positive"]["debugger_contract_debugpy"]["value"]);
    let component = package
        .bundle
        .components
        .iter_mut()
        .find(|component| component.component_kind == ComponentKind::Debugger)
        .expect("the debugger component must exist");
    component.capabilities = vec!["debugger.debug-adapter".to_owned()];
    component.component_id.clone_from(&debugger.debugger_id);
    component.identity_digest = canonical::digest(&debugger).expect("debugger digest");
    component.version.clone_from(&debugger.version);
    package.debugger = debugger;

    let error = validate_backend_support_bundle(&package.bundle, &package.debugger)
        .expect_err("a Rust subject runtime must reject debugpy");
    assert_eq!(error.code, ErrorCode::UnsupportedCapabilitySet);
}

#[test]
fn backend_package_rejects_policy_bytes_that_do_not_match_the_bundle() {
    let mut package = rust_x86_package();
    package.closure_policy.rules[0].boundary_id = "changed-clock".to_owned();
    assert_eq!(
        validate_backend_support_package(&package)
            .expect_err("the closure policy digest must match")
            .code,
        ErrorCode::UnsupportedCapabilitySet
    );
}

#[test]
fn signed_catalog_selects_one_exact_sdk_and_architecture_package() {
    let package = rust_x86_package();
    let digest = package.digest().unwrap();
    let registry_key = secret_key([0x91; 32]);
    let mut registry = SupportRegistry {
        bundle_digests: vec![digest],
        format: SupportRegistryFormat::V1,
        profiles: vec![SupportedProfile {
            capabilities: vec!["profile.backend".to_owned()],
            implementation_digest: Digest::of(b"backend implementation"),
            profile: "backend".to_owned(),
            profile_format: 1,
            support_bundle_digests: vec![digest],
        }],
        release_version: "1.0.0".to_owned(),
        signature: String::new(),
        signer_key_id: "release-test".to_owned(),
    };
    registry.signature = sign_bytes(
        &canonical::canonical_bytes(&registry).unwrap(),
        &registry_key,
    );
    let registry = VerifiedSupportRegistry::new(
        registry,
        "1.0.0",
        "release-test",
        &verification_key(&registry_key),
    )
    .unwrap();

    let catalog = VerifiedBackendSupportCatalog::new(vec![package], &registry).unwrap();
    let selected = catalog.select("sdk.rust", "architecture.x86-64").unwrap();
    assert_eq!(selected.digest().unwrap(), digest);
    assert_eq!(catalog.require_digest(digest).unwrap(), selected);
    assert_eq!(
        catalog
            .require_digest(Digest::of(b"unknown support bundle"))
            .unwrap_err()
            .code,
        ErrorCode::UnsupportedCapabilitySet
    );
    assert_eq!(
        catalog
            .select("sdk.rust", "architecture.arm64")
            .unwrap_err()
            .code,
        ErrorCode::UnsupportedCapabilitySet
    );
}

fn rust_x86_package() -> BackendSupportPackage {
    let core = parse(CORE_VECTORS);
    let protocol = parse(PROTOCOL_VECTORS);
    let mut bundle: SupportBundle = decode(&core["support_bundle"]["value"]);
    let closure_policy: ClosurePolicy = decode(&core["closure_policy"]["value"]);
    let debugger: DebuggerContract = decode(&protocol["positive"]["debugger_contract"]["value"]);
    let architecture = bundle
        .components
        .iter_mut()
        .find(|component| component.component_kind == ComponentKind::Architecture)
        .unwrap();
    architecture.capabilities = vec!["architecture.x86-64".to_owned()];
    let debugger_component = ComponentIdentity {
        capabilities: vec!["debugger.gdb-remote".to_owned()],
        component_id: debugger.debugger_id.clone(),
        component_kind: ComponentKind::Debugger,
        conformance_digest: Digest::of(b"debugger conformance"),
        identity_digest: canonical::digest(&debugger).unwrap(),
        protocol_max: 1,
        protocol_min: 1,
        version: debugger.version.clone(),
    };
    let index = bundle
        .components
        .iter()
        .position(|component| component.component_kind > ComponentKind::Debugger)
        .unwrap();
    bundle.components.insert(index, debugger_component);
    BackendSupportPackage {
        bundle,
        closure_policy,
        debugger,
    }
}

fn parse(text: &str) -> Value {
    serde_json::from_str(text).expect("valid vectors")
}

fn decode<T: DeserializeOwned>(value: &Value) -> T {
    serde_json::from_value(value.clone()).expect("typed vector")
}

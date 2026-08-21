use std::{env, fs};

use reproit_backend::{
    config::BackendSdk,
    support::{BackendSupportPackage, build_backend_support_package},
};
use reproit_core::{
    canonical,
    crypto::{decode_base64url, encode_base64url, secret_key, sign_bytes, verification_key},
    identity::Digest,
    model::{ClosurePolicy, ComponentKind, DebuggerContract, ProcessorArchitecture, SupportBundle},
};
use serde_json::Value;

const CORE_PATH: &str = "specs/v1/vectors.json";
const PROTOCOL_PATH: &str = "specs/v1/protocol-vectors.json";
const RELEASE_SIGNER: &str = "reproit-release-test";
const SUPPORT_INDEX_PATH: &str = "conformance/sdk/support-bundles.json";

fn main() {
    let mut protocol = read_json(PROTOCOL_PATH);
    let core = read_json(CORE_PATH);
    let packages = build_packages(&core, &protocol);
    let signing_seed = release_signing_seed(&protocol);
    update_registry(&mut protocol, &packages, signing_seed);
    verify_packages(&protocol, packages.clone());
    if env::args().nth(1).as_deref() == Some("--write") {
        let mut bytes = serde_json::to_string_pretty(&protocol).unwrap();
        bytes.push('\n');
        fs::write(PROTOCOL_PATH, bytes).unwrap();
        write_support_index(&packages);
    } else {
        println!("{}", serde_json::to_string_pretty(&protocol).unwrap());
    }
}

fn write_support_index(packages: &[BackendSupportPackage]) {
    let mut bundles = packages
        .iter()
        .map(|package| {
            let sdk = component_capability(&package.bundle, ComponentKind::Sdk, "sdk.");
            let architecture = component_capability(
                &package.bundle,
                ComponentKind::Architecture,
                "architecture.",
            );
            let architecture_name = match architecture {
                "architecture.arm64" => "arm64",
                "architecture.x86-64" => "x86_64",
                _ => panic!("unexpected architecture capability"),
            };
            let sdk_name = sdk.strip_prefix("sdk.").unwrap();
            serde_json::json!({
                "name": format!("linux-{architecture_name}-backend-{sdk_name}-v1"),
                "sdk_capability": sdk,
                "support_bundle_digest": package.digest().unwrap(),
            })
        })
        .collect::<Vec<_>>();
    bundles.sort_by(|left, right| left["name"].as_str().cmp(&right["name"].as_str()));
    let index = serde_json::json!({
        "bundles": bundles,
        "format": "reproit.support-bundle-manifest-index.v1",
    });
    let mut bytes = serde_json::to_string_pretty(&index).unwrap();
    bytes.push('\n');
    fs::write(SUPPORT_INDEX_PATH, bytes).unwrap();
}

fn component_capability<'a>(
    bundle: &'a SupportBundle,
    kind: ComponentKind,
    prefix: &str,
) -> &'a str {
    bundle
        .components
        .iter()
        .filter(|component| component.component_kind == kind)
        .flat_map(|component| component.capabilities.iter())
        .find(|capability| capability.starts_with(prefix))
        .map(String::as_str)
        .expect("support package capability")
}

fn build_packages(core: &Value, protocol: &Value) -> Vec<BackendSupportPackage> {
    let base: SupportBundle =
        serde_json::from_value(core["support_bundle"]["value"].clone()).unwrap();
    let closure_policy: ClosurePolicy =
        serde_json::from_value(core["closure_policy"]["value"].clone()).unwrap();
    let conformance_digest = support_conformance_digest(protocol);
    let mut packages = Vec::with_capacity(10);
    for architecture in [ProcessorArchitecture::Arm64, ProcessorArchitecture::X86_64] {
        for sdk in [
            BackendSdk::Dotnet,
            BackendSdk::Go,
            BackendSdk::Nodejs,
            BackendSdk::Python,
            BackendSdk::Rust,
        ] {
            let debugger: DebuggerContract = serde_json::from_value(
                protocol["positive"][debugger_vector(sdk, architecture)]["value"].clone(),
            )
            .unwrap();
            packages.push(
                build_backend_support_package(
                    base.clone(),
                    closure_policy.clone(),
                    sdk,
                    architecture,
                    debugger,
                    conformance_digest,
                )
                .unwrap(),
            );
        }
    }
    packages.sort_by_key(|package| package.digest().unwrap());
    packages
}

fn update_registry(protocol: &mut Value, packages: &[BackendSupportPackage], seed: u8) {
    let digests = packages
        .iter()
        .map(|package| Value::String(package.digest().unwrap().to_string()))
        .collect::<Vec<_>>();
    let registry = &mut protocol["positive"]["support_registry"]["value"];
    registry["bundle_digests"] = Value::Array(digests.clone());
    registry["profiles"][0]["support_bundle_digests"] = Value::Array(digests);
    registry["signature"] = Value::String(String::new());
    registry["signature"] = Value::String(sign_bytes(
        &canonical::canonical_bytes(registry).unwrap(),
        &secret_key([seed; 32]),
    ));
    protocol["canonical_sha256"]["support_registry"] =
        Value::String(canonical::digest(registry).unwrap().to_string());
}

fn verify_packages(protocol: &Value, packages: Vec<BackendSupportPackage>) {
    let registry = canonical::parse_strict(
        &serde_json::to_vec(&protocol["positive"]["support_registry"]["value"]).unwrap(),
    )
    .unwrap();
    let key = decode_base64url::<32>(
        protocol["verification_keys"][RELEASE_SIGNER]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let verified =
        reproit_core::model::VerifiedSupportRegistry::new(registry, "1.0.0", RELEASE_SIGNER, &key)
            .unwrap();
    reproit_backend::support::VerifiedBackendSupportCatalog::new(packages, &verified).unwrap();
}

fn release_signing_seed(protocol: &Value) -> u8 {
    let expected = protocol["verification_keys"][RELEASE_SIGNER]
        .as_str()
        .unwrap();
    (0_u16..=255)
        .map(|value| u8::try_from(value).unwrap())
        .find(|seed| encode_base64url(&verification_key(&secret_key([*seed; 32]))) == expected)
        .expect("The test release key must use one documented repeated-byte seed")
}

fn support_conformance_digest(protocol: &Value) -> Digest {
    let mut vectors = protocol.clone();
    let root = vectors.as_object_mut().unwrap();
    root["canonical_sha256"]
        .as_object_mut()
        .unwrap()
        .remove("support_registry");
    root["positive"]
        .as_object_mut()
        .unwrap()
        .remove("support_registry");
    root["verification_keys"]
        .as_object_mut()
        .unwrap()
        .remove(RELEASE_SIGNER);
    root["negative"]
        .as_array_mut()
        .unwrap()
        .retain(|vector| vector["schema"] != "support_registry");
    Digest::of(&serde_json::to_vec(&vectors).unwrap())
}

fn read_json(path: &str) -> Value {
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

const fn debugger_vector(sdk: BackendSdk, architecture: ProcessorArchitecture) -> &'static str {
    match (sdk, architecture) {
        (BackendSdk::Dotnet, ProcessorArchitecture::Arm64) => "debugger_contract_netcoredbg_arm64",
        (BackendSdk::Dotnet, ProcessorArchitecture::X86_64) => "debugger_contract_netcoredbg",
        (BackendSdk::Go, ProcessorArchitecture::Arm64) => "debugger_contract_delve_arm64",
        (BackendSdk::Go, ProcessorArchitecture::X86_64) => "debugger_contract_delve",
        (BackendSdk::Nodejs, ProcessorArchitecture::Arm64) => "debugger_contract_node_arm64",
        (BackendSdk::Nodejs, ProcessorArchitecture::X86_64) => "debugger_contract_node",
        (BackendSdk::Python, _) => "debugger_contract_debugpy",
        (BackendSdk::Rust, ProcessorArchitecture::Arm64) => "debugger_contract_gdbserver_arm64",
        (BackendSdk::Rust, ProcessorArchitecture::X86_64) => "debugger_contract",
    }
}
